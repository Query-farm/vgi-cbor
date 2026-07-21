//! MessagePack scalars: `msgpack_decode`, `msgpack_to_json`, `msgpack_to_cbor`,
//! `msgpack_encode`.

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use cbor_core::codec::{encode, msgpack};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams, ScalarFunction};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io;
use crate::value_in::value_at;

fn build_mp_to_json(rows: &[Option<&[u8]>]) -> Result<ArrayRef> {
    let col: Vec<Option<String>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| msgpack::to_json_string(bytes).ok()))
        .collect();
    Ok(arrow_io::string_array(&col))
}

fn build_mp_to_cbor(rows: &[Option<&[u8]>]) -> Result<ArrayRef> {
    let col: Vec<Option<Vec<u8>>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| msgpack::to_cbor(bytes).ok()))
        .collect();
    Ok(arrow_io::binary_array(&col))
}

blob_scalar! {
    struct MsgpackToJson,
    sql_name = "msgpack_to_json",
    ret = DataType::Utf8,
    arg_doc = "A MessagePack-encoded BLOB to render as JSON.",
    description = "Render a MessagePack blob as JSON (ext types as {ext_type,data}; ts ext → instant)",
    title = "MessagePack → JSON",
    category = "messagepack",
    doc_llm = "Decode a MessagePack blob and render it as JSON. Binary and non-UTF-8 string \
        payloads render as base64url; `ext` types surface as {\"ext_type\":N,\"data\":\"…\"}; \
        the reserved timestamp ext (type −1, 32/64/96-bit) decodes to an RFC 3339 instant. NULL \
        for a malformed blob.",
    doc_md = "Render a MessagePack blob as JSON. `ext` → `{ext_type,data}`; timestamp ext (−1) → \
        RFC 3339 instant.",
    keywords = "messagepack, msgpack, json, decode, ext, timestamp, base64url",
    examples = "[{\"description\":\"Decode the msgpack array [1,2,3] to JSON.\",\"sql\":\"SELECT cbor.main.msgpack_to_json(from_hex('93010203')) AS j\"}]",
    build = build_mp_to_json,
}

blob_scalar! {
    struct MsgpackDecode,
    sql_name = "msgpack_decode",
    ret = DataType::Utf8,
    arg_doc = "A MessagePack-encoded BLOB to decode.",
    description = "Decode a MessagePack blob to its richest form (JSON in v1)",
    title = "MessagePack Decode",
    category = "messagepack",
    doc_llm = "Decode a MessagePack blob to its richest self-describing form as JSON. Like \
        `decode` for CBOR, a DuckDB scalar fixes its output type at bind time with no data \
        sample, so the worker returns canonical JSON text. NULL for a malformed blob.",
    doc_md = "Decode a MessagePack blob to JSON (the stable lossless column).",
    keywords = "messagepack, msgpack, decode, json, deserialize",
    examples = "[{\"description\":\"Decode a msgpack map to JSON.\",\"sql\":\"SELECT cbor.main.msgpack_decode(from_hex('81a16101')) AS d\"}]",
    build = build_mp_to_json,
}

blob_scalar! {
    struct MsgpackToCbor,
    sql_name = "msgpack_to_cbor",
    ret = DataType::Binary,
    arg_doc = "A MessagePack-encoded BLOB to transcode to CBOR.",
    description = "Transcode a MessagePack blob to CBOR bytes (the cross-format op)",
    title = "MessagePack → CBOR",
    category = "messagepack",
    doc_llm = "Transcode a MessagePack blob to equivalent CBOR bytes — the one genuinely useful \
        cross-format operation. msgpack `ext` types become a {ext_type,data} CBOR map; the \
        timestamp ext (−1) becomes CBOR tag 1. Decode both with `to_json` and they compare \
        equal. NULL for a malformed blob.",
    doc_md = "Transcode MessagePack → CBOR bytes. `ext` → `{ext_type,data}` map; timestamp ext \
        (−1) → CBOR tag 1.",
    keywords = "messagepack, msgpack, cbor, transcode, convert, ext, timestamp",
    examples = "[{\"description\":\"Transcode msgpack [1,2,3] to CBOR and hex it.\",\"sql\":\"SELECT to_hex(cbor.main.msgpack_to_cbor(from_hex('93010203'))) AS h\"}]",
    build = build_mp_to_cbor,
}

/// `msgpack_encode(value) -> BLOB` — DuckDB value → MessagePack (via CBOR Value).
pub struct MsgpackEncode;

impl ScalarFunction for MsgpackEncode {
    fn name(&self) -> &str {
        "msgpack_encode"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "DuckDB Value → MessagePack",
            "Encode a DuckDB value as MessagePack. Numeric → shortest int/float; `TIMESTAMP` → the \
             reserved timestamp ext; `BLOB` → bin; `STRUCT` → map with string keys; `LIST` → \
             array; `MAP` → map. NULL if the value cannot be encoded.",
            "Encode a DuckDB value as MessagePack bytes.",
            "messagepack, msgpack, encode, serialize, struct, list, timestamp",
            "messagepack",
        );
        tags.push((
            "vgi.example_queries".into(),
            "[{\"description\":\"Encode a list to MessagePack.\",\"sql\":\"SELECT to_hex(cbor.main.msgpack_encode([1,2,3])) AS h\"}]".into(),
        ));
        FunctionMetadata {
            description: "Encode a DuckDB value as MessagePack".into(),
            return_type: Some(DataType::Binary),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "value",
            0,
            "The DuckDB value to encode as MessagePack.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Binary))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out: Vec<Option<Vec<u8>>> = Vec::with_capacity(rows);
        for i in 0..rows {
            if col.is_null(i) {
                out.push(None);
                continue;
            }
            // Reuse the CBOR Value path, then transcode CBOR → MessagePack.
            let value = value_at(col, i)?;
            let bytes = encode::encode_value(&value)
                .ok()
                .and_then(|cbor| cbor_to_msgpack(&cbor));
            out.push(bytes);
        }
        let arr = arrow_io::binary_array(&out);
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

/// Encode CBOR bytes as MessagePack by decoding to a CBOR `Value` and writing the
/// equivalent `rmpv::Value`.
fn cbor_to_msgpack(cbor: &[u8]) -> Option<Vec<u8>> {
    let value = cbor_core::value::parse(cbor).ok()?;
    let mp = cbor_to_rmpv(&value);
    let mut out = Vec::new();
    rmpv_encode(&mp, &mut out).ok()?;
    Some(out)
}

fn rmpv_encode(v: &rmpv::Value, out: &mut Vec<u8>) -> std::result::Result<(), String> {
    rmpv::encode::write_value(out, v).map_err(|e| e.to_string())
}

fn cbor_to_rmpv(v: &ciborium::value::Value) -> rmpv::Value {
    use ciborium::value::Value as C;
    use rmpv::Value as M;
    match v {
        C::Null => M::Nil,
        C::Bool(b) => M::Boolean(*b),
        C::Integer(i) => {
            let n = i128::from(*i);
            if let Ok(u) = u64::try_from(n) {
                M::Integer(u.into())
            } else if let Ok(s) = i64::try_from(n) {
                M::Integer(s.into())
            } else {
                M::F64(n as f64)
            }
        }
        C::Float(f) => M::F64(*f),
        C::Text(s) => M::String(s.clone().into()),
        C::Bytes(b) => M::Binary(b.clone()),
        C::Array(items) => M::Array(items.iter().map(cbor_to_rmpv).collect()),
        C::Map(entries) => M::Map(
            entries
                .iter()
                .map(|(k, val)| (cbor_to_rmpv(k), cbor_to_rmpv(val)))
                .collect(),
        ),
        C::Tag(_, inner) => cbor_to_rmpv(inner),
        _ => M::Nil,
    }
}
