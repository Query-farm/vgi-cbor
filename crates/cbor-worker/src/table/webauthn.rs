//! `webauthn_attestation(att_obj)` — LATERAL table function that decodes a CTAP2
//! attestation object and shreds its format-specific statement into one typed row
//! (zero rows if the blob is not a valid attestation object).

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, BooleanBuilder, StringBuilder, UInt32Builder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use cbor_core::security::webauthn;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io;

pub struct WebauthnAttestation;

/// A self-contained `packed` CTAP2 attestation object (CBOR), as hex, used by the
/// function's example so vgi-lint can execute it without an external fixture. It
/// carries `fmt = "packed"`, an EC2/ES256 credential, AAGUID
/// `11111111-…`, sign_count 7, a `sig`, and a one-cert `x5c` chain — so the
/// example returns exactly one shredded row.
const SAMPLE_ATTESTATION_HEX: &str = "a363666d74667061636b65646761747453746d74a363616c67266373696742dead637835638143300100686175746844617461588700000000000000000000000000000000000000000000000000000000000000004100000007111111111111111111111111111111110003cafe01a5010203262001215820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa225820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("fmt", DataType::Utf8, true),
        Field::new("aaguid", DataType::Utf8, true),
        Field::new("sign_count", DataType::UInt32, true),
        Field::new("rp_id_hash", DataType::Binary, true),
        Field::new("up", DataType::Boolean, true),
        Field::new("uv", DataType::Boolean, true),
        Field::new("cred_id", DataType::Binary, true),
        Field::new("alg", DataType::Utf8, true),
        Field::new("sig", DataType::Binary, true),
        Field::new(
            "x5c",
            DataType::List(Arc::new(Field::new("item", DataType::Binary, true))),
            true,
        ),
        Field::new("att_stmt", arrow_io::json_type(), true),
    ]))
}

impl TableFunction for WebauthnAttestation {
    fn name(&self) -> &str {
        "webauthn_attestation"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "WebAuthn Attestation Shred",
            "Decode a CTAP2 / WebAuthn attestation OBJECT ({fmt, attStmt, authData}) and shred it \
             into typed columns: fmt, aaguid, sign_count, rp_id_hash, up, uv, cred_id, alg, sig, \
             x5c (LIST<BLOB>), att_stmt (JSON). Parses the embedded authenticatorData and the \
             format-specific attStmt (packed, fido-u2f, tpm, android-key, android-safetynet, \
             apple, none). The `x5c` certificate chain is the join key to `vgi-x509` for AAGUID / \
             vendor trust-anchor checks. Use as a LATERAL table function over an enrollment \
             column. Structural only — NO signature verification. Emits zero rows for a blob that \
             is not a valid attestation object.",
            "LATERAL: decode a WebAuthn attestation object → one row of (fmt, aaguid, sign_count, \
             rp_id_hash, up, uv, cred_id, alg, sig, x5c, att_stmt). Join `x5c` to `vgi-x509`.",
            "webauthn, fido2, ctap2, attestation, attstmt, packed, fido-u2f, tpm, apple, aaguid, \
             x5c, x509, fan-out, lateral",
            "webauthn",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "One row per attestation object (zero rows if it is not a valid attestation \
             object):\n\n\
             | column | type | description |\n\
             |---|---|---|\n\
             | `fmt` | VARCHAR | Attestation statement format (`packed`, `fido-u2f`, `tpm`, …). |\n\
             | `aaguid` | VARCHAR | Authenticator AAGUID (canonical UUID). |\n\
             | `sign_count` | UINTEGER | Signature counter. |\n\
             | `rp_id_hash` | BLOB | SHA-256 of the RP ID. |\n\
             | `up` / `uv` | BOOLEAN | User-present / user-verified flags. |\n\
             | `cred_id` | BLOB | Credential ID. |\n\
             | `alg` | VARCHAR | Signature algorithm name. |\n\
             | `sig` | BLOB | Attestation signature. |\n\
             | `x5c` | BLOB[] | Attestation certificate chain (join key to `vgi-x509`). |\n\
             | `att_stmt` | JSON | The full attestation statement. |"
                .into(),
        ));
        FunctionMetadata {
            description: "Decode a WebAuthn attestation object into typed columns (LATERAL)".into(),
            examples: vec![FunctionExample {
                sql: format!(
                    "SELECT fmt, aaguid, sign_count, alg \
                     FROM cbor.main.webauthn_attestation(from_hex('{SAMPLE_ATTESTATION_HEX}'));"
                ),
                description: "Shred a packed CTAP2 attestation object into one typed row.".into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::const_arg(
            "att_obj",
            0,
            "blob",
            "A CTAP2 / WebAuthn attestation object ({fmt, attStmt, authData}). Use with \
             LATERAL over an enrollment column.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let bytes = params.arguments.const_bytes(0);
        Ok(Box::new(AttProducer {
            schema: params.output_schema.clone(),
            bytes,
            done: false,
        }))
    }
}

struct AttProducer {
    schema: SchemaRef,
    bytes: Option<Vec<u8>>,
    done: bool,
}

impl TableProducer for AttProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;

        let mut fmt = StringBuilder::new();
        let mut aaguid = StringBuilder::new();
        let mut sign_count = UInt32Builder::new();
        let mut rp_id_hash = BinaryBuilder::new();
        let mut up = BooleanBuilder::new();
        let mut uv = BooleanBuilder::new();
        let mut cred_id = BinaryBuilder::new();
        let mut alg = StringBuilder::new();
        let mut sig = BinaryBuilder::new();
        let mut x5c_rows: Vec<Option<Vec<Vec<u8>>>> = Vec::new();
        let mut att_stmt = StringBuilder::new();

        if let Some(row) = self
            .bytes
            .as_ref()
            .and_then(|b| webauthn::webauthn_attestation(b).ok())
        {
            fmt.append_value(&row.fmt);
            match &row.aaguid {
                Some(a) => aaguid.append_value(a),
                None => aaguid.append_null(),
            }
            sign_count.append_value(row.sign_count);
            rp_id_hash.append_value(&row.rp_id_hash);
            up.append_value(row.up);
            uv.append_value(row.uv);
            match &row.cred_id {
                Some(c) => cred_id.append_value(c),
                None => cred_id.append_null(),
            }
            match &row.alg {
                Some(a) => alg.append_value(a),
                None => alg.append_null(),
            }
            match &row.sig {
                Some(s) => sig.append_value(s),
                None => sig.append_null(),
            }
            x5c_rows.push(Some(row.x5c.clone()));
            att_stmt.append_value(&row.att_stmt);
        }

        let columns: Vec<ArrayRef> = vec![
            Arc::new(fmt.finish()),
            Arc::new(aaguid.finish()),
            Arc::new(sign_count.finish()),
            Arc::new(rp_id_hash.finish()),
            Arc::new(up.finish()),
            Arc::new(uv.finish()),
            Arc::new(cred_id.finish()),
            Arc::new(alg.finish()),
            Arc::new(sig.finish()),
            arrow_io::list_binary_array(&x5c_rows),
            Arc::new(att_stmt.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), columns)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
