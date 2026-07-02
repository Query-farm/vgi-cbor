//! WebAuthn scalar: `webauthn_authdata`. Parses the fixed authenticatorData byte
//! layout, including the embedded COSE_Key credential public key.

use std::sync::Arc;

use arrow_array::{ArrayRef, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use cbor_core::security::cose_key::CoseKeyInfo;
use cbor_core::security::webauthn::{self, AuthData};

use crate::arrow_io;
use crate::blob_scalar;

/// The `webauthn_authdata` STRUCT return type.
pub fn authdata_type() -> DataType {
    DataType::Struct(Fields::from(vec![
        Field::new("rp_id_hash", DataType::Binary, true),
        Field::new("up", DataType::Boolean, true),
        Field::new("uv", DataType::Boolean, true),
        Field::new("be", DataType::Boolean, true),
        Field::new("bs", DataType::Boolean, true),
        Field::new("at", DataType::Boolean, true),
        Field::new("ed", DataType::Boolean, true),
        Field::new("sign_count", DataType::UInt32, true),
        Field::new("aaguid", DataType::Utf8, true),
        Field::new("cred_id", DataType::Binary, true),
        Field::new(
            "cred_public_key",
            DataType::Struct(arrow_io::cose_key_fields()),
            true,
        ),
        Field::new("extensions", arrow_io::json_type(), true),
    ]))
}

fn build_authdata(rows: &[Option<&[u8]>]) -> vgi_rpc::Result<ArrayRef> {
    let parsed: Vec<Option<AuthData>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| webauthn::webauthn_authdata(bytes).ok()))
        .collect();

    let flag = |f: fn(&AuthData) -> bool| -> Vec<Option<bool>> {
        parsed.iter().map(|a| a.as_ref().map(f)).collect()
    };

    let rp_id_hash: Vec<Option<Vec<u8>>> = parsed
        .iter()
        .map(|a| a.as_ref().map(|a| a.rp_id_hash.clone()))
        .collect();
    let sign_count: Vec<Option<u32>> = parsed
        .iter()
        .map(|a| a.as_ref().map(|a| a.sign_count))
        .collect();
    let aaguid: Vec<Option<String>> = parsed
        .iter()
        .map(|a| a.as_ref().and_then(|a| a.aaguid.clone()))
        .collect();
    let cred_id: Vec<Option<Vec<u8>>> = parsed
        .iter()
        .map(|a| a.as_ref().and_then(|a| a.cred_id.clone()))
        .collect();
    let cred_key: Vec<Option<CoseKeyInfo>> = parsed
        .iter()
        .map(|a| a.as_ref().and_then(|a| a.cred_public_key.clone()))
        .collect();
    let extensions: Vec<Option<String>> = parsed
        .iter()
        .map(|a| a.as_ref().and_then(|a| a.extensions.clone()))
        .collect();
    let valid: Vec<bool> = parsed.iter().map(|a| a.is_some()).collect();

    let DataType::Struct(fields) = authdata_type() else {
        unreachable!()
    };
    let arrays: Vec<ArrayRef> = vec![
        arrow_io::binary_array(&rp_id_hash),
        arrow_io::bool_opt_array(&flag(|a| a.up)),
        arrow_io::bool_opt_array(&flag(|a| a.uv)),
        arrow_io::bool_opt_array(&flag(|a| a.be)),
        arrow_io::bool_opt_array(&flag(|a| a.bs)),
        arrow_io::bool_opt_array(&flag(|a| a.at)),
        arrow_io::bool_opt_array(&flag(|a| a.ed)),
        arrow_io::u32_opt_array(&sign_count),
        arrow_io::string_array(&aaguid),
        arrow_io::binary_array(&cred_id),
        arrow_io::cose_key_array(&cred_key),
        arrow_io::string_array(&extensions),
    ];
    Ok(Arc::new(StructArray::new(
        fields,
        arrays,
        Some(NullBuffer::from(valid)),
    )))
}

blob_scalar! {
    struct WebauthnAuthdata,
    sql_name = "webauthn_authdata",
    ret = authdata_type(),
    arg_doc = "A WebAuthn authenticatorData BLOB (the fixed rpIdHash/flags/signCount[+attested] layout).",
    description = "Parse WebAuthn authenticatorData into a typed STRUCT (flags, AAGUID, cred key, …)",
    title = "WebAuthn authenticatorData",
    category = "webauthn",
    doc_llm = "Parse the fixed WebAuthn authenticatorData byte layout into STRUCT(rp_id_hash BLOB, \
        up BOOL, uv BOOL, be BOOL, bs BOOL, at BOOL, ed BOOL, sign_count UINTEGER, aaguid VARCHAR, \
        cred_id BLOB, cred_public_key STRUCT, extensions JSON). The first 37 bytes are rpIdHash \
        (32) + flags (1) + signCount (4, big-endian). When the AT flag is set, the attested \
        credential data (AAGUID as a canonical UUID, credentialId, and the COSE_Key \
        credentialPublicKey) is decoded; when ED is set, the extension map is rendered as JSON. \
        NULL for a malformed / too-short blob.",
    doc_md = "Parse authenticatorData → `STRUCT(rp_id_hash, up, uv, be, bs, at, ed, sign_count, \
        aaguid, cred_id, cred_public_key, extensions)`. AAGUID as a UUID; cred key as a COSE_Key.",
    keywords = "webauthn, fido2, ctap2, authenticatordata, authdata, aaguid, sign_count, flags, \
        credentialpublickey, rpidhash",
    examples = "[{\"description\":\"User-present flag and sign count of a minimal authData (no attested cred).\",\"sql\":\"SELECT (cbor.main.webauthn_authdata(from_hex('00000000000000000000000000000000000000000000000000000000000000000100000005'))).sign_count AS sc\"}]",
    build = build_authdata,
}
