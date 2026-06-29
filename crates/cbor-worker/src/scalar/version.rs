//! `cbor_version()` — return the worker's version string.

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

pub struct CborVersion;

impl ScalarFunction for CborVersion {
    fn name(&self) -> &str {
        "cbor_version"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "CBOR Worker Version",
            "Return the semantic version string of the running cbor worker binary (the worker's \
             own build version, not the SDK/protocol version). The string is MAJOR.MINOR.PATCH \
             (e.g. '0.1.0'). Takes no arguments and is deterministic — it always returns the same \
             single VARCHAR value (never NULL) for a given build. Useful for diagnostics and \
             confirming which build is attached.",
            "Return the cbor worker version string, e.g. `cbor_version()` → '0.1.0'. \
             Argument-free, deterministic, single semver VARCHAR.",
            "version, build version, cbor_version, diagnostics, worker version, semver",
        );
        tags.push((
            "vgi.example_queries".into(),
            "[{\"description\":\"Return the worker version string.\",\"sql\":\"SELECT cbor.main.cbor_version() AS version\"}]".into(),
        ));
        // VGI509: ship at least one guaranteed-runnable, verified example. These
        // need no external file or backend, so they execute cleanly in the lint
        // sandbox (and double as a smoke test of the codec round-trip).
        tags.push((
            "vgi.executable_examples".into(),
            r#"[
  {
    "description": "Return the worker version string.",
    "sql": "SELECT cbor.main.cbor_version() AS version"
  },
  {
    "description": "Decode the CBOR array [1,2,3] to JSON.",
    "sql": "SELECT cbor.main.to_json(from_hex('83010203')) AS j",
    "expected_result": [{"j": "[1,2,3]"}]
  },
  {
    "description": "Round-trip a JSON array through deterministic CBOR.",
    "sql": "SELECT to_hex(cbor.main.from_json('[1,2,3]')) AS h",
    "expected_result": [{"h": "83010203"}]
  },
  {
    "description": "Structurally decode a COSE_Sign1 and read its algorithm name.",
    "sql": "SELECT (cbor.main.cose_headers(from_hex('d28443a10126a04044deadbeef'))).alg AS alg",
    "expected_result": [{"alg": "ES256"}]
  }
]"#
            .into(),
        ));
        FunctionMetadata {
            description: "Returns the cbor worker version string".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT cbor.main.cbor_version();".into(),
                description: "Return the cbor worker version string.".into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let rows = batch.num_rows();
        let out: ArrayRef = Arc::new(StringArray::from(vec![cbor_core::version(); rows]));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
