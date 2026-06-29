//! CWT scalar: `cwt_claims`. Unwraps a tag-61 / COSE envelope and names the
//! registered claim keys. No signature verification.

use std::sync::Arc;

use arrow_array::{ArrayRef, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use cbor_core::security::cwt::{self, CwtClaims};

use crate::arrow_io;
use crate::blob_scalar;

/// The `cwt_claims` STRUCT return type.
pub fn cwt_type() -> DataType {
    DataType::Struct(Fields::from(vec![
        Field::new("iss", DataType::Utf8, true),
        Field::new("sub", DataType::Utf8, true),
        Field::new("aud", DataType::Utf8, true),
        Field::new("exp", arrow_io::ts_type(), true),
        Field::new("nbf", arrow_io::ts_type(), true),
        Field::new("iat", arrow_io::ts_type(), true),
        Field::new("cti", DataType::Binary, true),
        Field::new("extra", arrow_io::json_type(), true),
    ]))
}

fn build_cwt(rows: &[Option<&[u8]>]) -> vgi_rpc::Result<ArrayRef> {
    let claims: Vec<Option<CwtClaims>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| cwt::cwt_claims(bytes).ok()))
        .collect();

    let s = |f: fn(&CwtClaims) -> Option<String>| -> Vec<Option<String>> {
        claims.iter().map(|c| c.as_ref().and_then(f)).collect()
    };
    let t = |f: fn(&CwtClaims) -> Option<i64>| -> Vec<Option<i64>> {
        claims.iter().map(|c| c.as_ref().and_then(f)).collect()
    };

    let cti: Vec<Option<Vec<u8>>> = claims
        .iter()
        .map(|c| c.as_ref().and_then(|c| c.cti.clone()))
        .collect();
    let valid: Vec<bool> = claims.iter().map(|c| c.is_some()).collect();

    let DataType::Struct(fields) = cwt_type() else {
        unreachable!()
    };
    let arrays: Vec<ArrayRef> = vec![
        arrow_io::string_array(&s(|c| c.iss.clone())),
        arrow_io::string_array(&s(|c| c.sub.clone())),
        arrow_io::string_array(&s(|c| c.aud.clone())),
        arrow_io::ts_array(&t(|c| c.exp)),
        arrow_io::ts_array(&t(|c| c.nbf)),
        arrow_io::ts_array(&t(|c| c.iat)),
        arrow_io::binary_array(&cti),
        arrow_io::string_array(&s(|c| c.extra.clone())),
    ];
    Ok(Arc::new(StructArray::new(
        fields,
        arrays,
        Some(NullBuffer::from(valid)),
    )))
}

blob_scalar! {
    struct CwtClaimsFn,
    sql_name = "cwt_claims",
    ret = cwt_type(),
    arg_doc = "A CWT (RFC 8392) token BLOB, or a COSE message / tag-61 envelope wrapping one.",
    description = "Decode a CWT claim set: STRUCT(iss, sub, aud, exp, nbf, iat, cti, extra)",
    title = "CWT Token Claim Set",
    doc_llm = "Decode a CWT (RFC 8392) claim set into STRUCT(iss VARCHAR, sub VARCHAR, aud \
        VARCHAR, exp TIMESTAMPTZ, nbf TIMESTAMPTZ, iat TIMESTAMPTZ, cti BLOB, extra JSON). \
        Registered claim keys 1..7 are named; the NumericDate claims exp/nbf/iat become \
        TIMESTAMPTZ; private / unregistered claims collect into `extra` as JSON. Unwraps a tag-61 \
        or COSE (Sign1/Mac0/…) envelope automatically and parses the inner claims map. NO \
        signature verification. NULL if not a CWT / COSE message.",
    doc_md = "Decode a CWT → `STRUCT(iss, sub, aud, exp, nbf, iat, cti, extra)`. Unwraps tag-61 / \
        COSE envelopes; NumericDate → TIMESTAMPTZ. No crypto.",
    keywords = "cwt, rfc 8392, claims, iss, sub, aud, exp, iat, cti, token, cose, tag 61",
    examples = "[{\"description\":\"Issuer of a bare CWT claim set {1:'coap://as'}.\",\"sql\":\"SELECT (cbor.main.cwt_claims(from_hex('a10169636f61703a2f2f6173'))).iss AS iss\"}]",
    build = build_cwt,
}
