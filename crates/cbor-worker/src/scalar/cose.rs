//! COSE / COSE_Key scalars: `cose_decode`, `cose_payload`, `cose_headers`,
//! `cose_x5t`, `cose_x5chain`, `cose_key`. Structural decode only — no crypto.

use std::sync::Arc;

use arrow_array::{ArrayRef, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use cbor_core::security::cose::{self, CoseDecoded, CoseHeaders};
use cbor_core::security::cose_key;

use crate::arrow_io;

/// The `cose_decode` STRUCT return type.
pub fn cose_decode_type() -> DataType {
    DataType::Struct(Fields::from(vec![
        Field::new("tag", DataType::UInt64, true),
        Field::new("msg_type", DataType::Utf8, true),
        Field::new(
            "protected",
            DataType::Struct(arrow_io::header_fields()),
            true,
        ),
        Field::new(
            "unprotected",
            DataType::Struct(arrow_io::header_fields()),
            true,
        ),
        Field::new("payload", DataType::Binary, true),
        Field::new("signature", DataType::Binary, true),
        Field::new("recipients", arrow_io::json_type(), true),
    ]))
}

fn build_cose_decode(rows: &[Option<&[u8]>]) -> vgi_rpc::Result<ArrayRef> {
    let decoded: Vec<Option<CoseDecoded>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| cose::cose_decode(bytes).ok()))
        .collect();

    let tag: Vec<Option<u64>> = decoded
        .iter()
        .map(|d| d.as_ref().and_then(|d| d.tag))
        .collect();
    let msg_type: Vec<Option<String>> = decoded
        .iter()
        .map(|d| d.as_ref().map(|d| d.msg_type.clone()))
        .collect();
    let protected: Vec<Option<CoseHeaders>> = decoded
        .iter()
        .map(|d| d.as_ref().map(|d| d.protected.clone()))
        .collect();
    let unprotected: Vec<Option<CoseHeaders>> = decoded
        .iter()
        .map(|d| d.as_ref().map(|d| d.unprotected.clone()))
        .collect();
    let payload: Vec<Option<Vec<u8>>> = decoded
        .iter()
        .map(|d| d.as_ref().and_then(|d| d.payload.clone()))
        .collect();
    let signature: Vec<Option<Vec<u8>>> = decoded
        .iter()
        .map(|d| d.as_ref().and_then(|d| d.signature.clone()))
        .collect();
    let recipients: Vec<Option<String>> = decoded
        .iter()
        .map(|d| d.as_ref().and_then(|d| d.recipients.clone()))
        .collect();
    let valid: Vec<bool> = decoded.iter().map(|d| d.is_some()).collect();

    let DataType::Struct(fields) = cose_decode_type() else {
        unreachable!()
    };
    let arrays: Vec<ArrayRef> = vec![
        arrow_io::u64_opt_array(&tag),
        arrow_io::string_array(&msg_type),
        arrow_io::header_array_opt(&protected),
        arrow_io::header_array_opt(&unprotected),
        arrow_io::binary_array(&payload),
        arrow_io::binary_array(&signature),
        arrow_io::string_array(&recipients),
    ];
    Ok(Arc::new(StructArray::new(
        fields,
        arrays,
        Some(NullBuffer::from(valid)),
    )))
}

fn build_cose_payload(rows: &[Option<&[u8]>]) -> vgi_rpc::Result<ArrayRef> {
    let col: Vec<Option<Vec<u8>>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| cose::cose_payload(bytes).ok().flatten()))
        .collect();
    Ok(arrow_io::binary_array(&col))
}

fn build_cose_headers(rows: &[Option<&[u8]>]) -> vgi_rpc::Result<ArrayRef> {
    let col: Vec<Option<CoseHeaders>> = rows
        .iter()
        .map(|b| {
            b.and_then(|bytes| cose::cose_decode(bytes).ok())
                .map(|d| cose::merged_headers(&d))
        })
        .collect();
    Ok(arrow_io::header_array_opt(&col))
}

fn build_cose_x5t(rows: &[Option<&[u8]>]) -> vgi_rpc::Result<ArrayRef> {
    let col: Vec<Option<String>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| cose::cose_x5t(bytes).ok().flatten()))
        .collect();
    Ok(arrow_io::string_array(&col))
}

fn build_cose_x5chain(rows: &[Option<&[u8]>]) -> vgi_rpc::Result<ArrayRef> {
    let col: Vec<Option<Vec<Vec<u8>>>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| cose::cose_x5chain(bytes).ok().flatten()))
        .collect();
    Ok(arrow_io::list_binary_array(&col))
}

fn build_cose_key(rows: &[Option<&[u8]>]) -> vgi_rpc::Result<ArrayRef> {
    let col: Vec<Option<cose_key::CoseKeyInfo>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| cose_key::cose_key(bytes).ok()))
        .collect();
    Ok(arrow_io::cose_key_array(&col))
}

blob_scalar! {
    struct CoseDecodeFn,
    sql_name = "cose_decode",
    ret = cose_decode_type(),
    arg_doc = "A COSE (RFC 9052) message BLOB — tagged (18/98/16/96/17/97/61) or a bare array.",
    description = "Structurally decode a COSE message (no crypto): tag, type, headers, payload, sig",
    title = "COSE Message Decode",
    category = "cose",
    doc_llm = "Structurally decode a COSE (RFC 9052) message into `STRUCT(tag UBIGINT, msg_type \
        VARCHAR, protected STRUCT, unprotected STRUCT, payload BLOB, signature BLOB, recipients \
        JSON)`. Recognizes COSE_Sign1 (tag 18), COSE_Sign (98), COSE_Encrypt0 (16), COSE_Encrypt \
        (96), COSE_Mac0 (17), COSE_Mac (97), and CWT (61) envelopes. Header maps are decoded with \
        named labels (alg as its IANA name, kid, x5chain, x5t, …). This is structural unwrap only \
        — NO signature/MAC verification and no decryption. Re-feed `payload` to `decode` or \
        `cwt_claims`. NULL for input that is not a COSE message.",
    doc_md = "Decode a COSE message → `STRUCT(tag, msg_type, protected, unprotected, payload, \
        signature, recipients)`. Structural only (no crypto). Tags 18/98/16/96/17/97/61.",
    keywords = "cose, rfc 9052, sign1, encrypt0, mac0, decode, structural, payload, signature, header",
    examples = "[{\"description\":\"The message type of a COSE_Sign1 (tag 18) skeleton.\",\"sql\":\"SELECT (cbor.main.cose_decode(from_hex('d28443a10126a0405820deadbeef'))).msg_type AS t\"}]",
    build = build_cose_decode,
}

blob_scalar! {
    struct CosePayload,
    sql_name = "cose_payload",
    ret = DataType::Binary,
    arg_doc = "A COSE message BLOB.",
    description = "Return the raw inner payload bytes of a COSE message",
    title = "COSE Inner Payload",
    category = "cose",
    doc_llm = "Return the raw inner payload bytes of a COSE message (often itself CBOR / a CWT \
        claim set — re-feed to `decode` or `cwt_claims`). NULL if the message has no payload or \
        is not a COSE message.",
    doc_md = "The raw inner payload `BLOB` of a COSE message. Often nested CBOR — re-feed to \
        `decode`/`cwt_claims`.",
    keywords = "cose, payload, rfc 9052, inner, bytes, nested cbor",
    examples = "[{\"description\":\"Length of the recovered payload.\",\"sql\":\"SELECT octet_length(cbor.main.cose_payload(from_hex('d28443a10126a0445249534b5820deadbeef'))) AS n\"}]",
    build = build_cose_payload,
}

blob_scalar! {
    struct CoseHeadersFn,
    sql_name = "cose_headers",
    ret = DataType::Struct(arrow_io::header_fields()),
    arg_doc = "A COSE message BLOB.",
    description = "Return the merged (protected over unprotected) COSE header STRUCT",
    title = "COSE Header Map",
    category = "cose",
    doc_llm = "Return the COSE message headers as a `STRUCT(alg VARCHAR, crit JSON, content_type \
        VARCHAR, kid BLOB, iv BLOB, x5chain LIST<BLOB>, x5t STRUCT(hash_alg, thumbprint))`, merging \
        the protected header over the unprotected one. `alg` is rendered as its IANA name (e.g. \
        ES256, EdDSA, A256GCM). NULL if not a COSE message.",
    doc_md = "Merged COSE headers → `STRUCT(alg, crit, content_type, kid, iv, x5chain, x5t)`. \
        `alg` as its IANA name.",
    keywords = "cose, headers, alg, kid, x5chain, x5t, rfc 9052, iana, protected, unprotected",
    examples = "[{\"description\":\"The algorithm name from a COSE_Sign1 header.\",\"sql\":\"SELECT (cbor.main.cose_headers(from_hex('d28443a10126a0405820deadbeef'))).alg AS alg\"}]",
    build = build_cose_headers,
}

blob_scalar! {
    struct CoseX5t,
    sql_name = "cose_x5t",
    ret = DataType::Utf8,
    arg_doc = "A COSE message BLOB carrying an x5t (label 34) thumbprint.",
    description = "Return the COSE x5t certificate thumbprint as a hex string (the vgi-x509 join key)",
    title = "COSE x5t Thumbprint",
    category = "cose",
    doc_llm = "Return the COSE x5t certificate thumbprint (header label 34) as a lowercase hex \
        string — the join key to a `vgi-x509` cert table for trust-anchor / vendor checks. \
        Searches the protected then the unprotected header. NULL if absent.",
    doc_md = "COSE x5t thumbprint as lowercase hex — join key to `vgi-x509`. NULL if absent.",
    keywords = "cose, x5t, thumbprint, certificate, x509, join, hex, rfc 9052",
    examples = "[{\"description\":\"x5t thumbprint hex (NULL when the header has none).\",\"sql\":\"SELECT cbor.main.cose_x5t(from_hex('d28443a10126a0405820deadbeef')) AS x5t\"}]",
    build = build_cose_x5t,
}

blob_scalar! {
    struct CoseX5chain,
    sql_name = "cose_x5chain",
    ret = DataType::List(Arc::new(Field::new("item", DataType::Binary, true))),
    arg_doc = "A COSE message BLOB carrying an x5chain (label 33).",
    description = "Return the COSE x5chain DER certificate list (the vgi-x509 join key)",
    title = "COSE Certificate Chain",
    category = "cose",
    doc_llm = "Return the COSE x5chain (header label 33) as a `LIST<BLOB>` of DER certificates — the \
        join key to `vgi-x509` for chain validation. Searches the protected then the unprotected \
        header. NULL if absent.",
    doc_md = "COSE x5chain → `LIST<BLOB>` of DER certs. Join to `vgi-x509`.",
    keywords = "cose, x5chain, certificate, chain, der, x509, join, rfc 9052",
    examples = "[{\"description\":\"Number of certs in the x5chain.\",\"sql\":\"SELECT len(cbor.main.cose_x5chain(from_hex('d28443a10126a0405820deadbeef'))) AS n\"}]",
    build = build_cose_x5chain,
}

blob_scalar! {
    struct CoseKeyFn,
    sql_name = "cose_key",
    ret = DataType::Struct(arrow_io::cose_key_fields()),
    arg_doc = "A COSE_Key (RFC 9052 §7) BLOB — e.g. a WebAuthn credentialPublicKey.",
    description = "Decode a COSE_Key into STRUCT(kty, kid, alg, crv, x, y, n, e)",
    title = "COSE_Key Decode",
    category = "cose",
    doc_llm = "Decode a COSE_Key (RFC 9052 §7) into `STRUCT(kty VARCHAR, kid BLOB, alg VARCHAR, \
        crv VARCHAR, x BLOB, y BLOB, n BLOB, e BLOB)`. `kty` is OKP/EC2/RSA/Symmetric; EC2/OKP \
        carry `crv`/`x`/`y`, RSA carries `n`/`e`. This is exactly the credentialPublicKey embedded \
        in WebAuthn attested-credential data. NULL if not a COSE_Key map.",
    doc_md = "Decode a COSE_Key → `STRUCT(kty, kid, alg, crv, x, y, n, e)`. EC2/OKP → crv/x/y; \
        RSA → n/e.",
    keywords = "cose_key, rfc 9052, ec2, okp, rsa, crv, public key, webauthn, credentialpublickey",
    examples = "[{\"description\":\"Key type of an EC2 / ES256 / P-256 COSE_Key.\",\"sql\":\"SELECT (cbor.main.cose_key(from_hex('a3010203262001'))).kty AS kty\"}]",
    build = build_cose_key,
}
