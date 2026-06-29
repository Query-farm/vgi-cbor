//! JSON bridge: `to_json` (CBOR → JSON, always succeeds on well-formed input)
//! and `from_json` (JSON → core-deterministic CBOR).
//!
//! `to_json` targets a self-describing sink, so it renders every CBOR item; it is
//! necessarily lossy on the types JSON lacks (byte strings render as base64url,
//! non-text map keys are stringified, tags are transparent). `decode` is the
//! lossless typed path.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ciborium::value::Value;
use serde_json::{Map as JsonMap, Number, Value as Json};

use crate::value::{int_i128, parse_strict, DecodeError};

/// Base64url-encode (no padding) a byte string — how `to_json` renders `BLOB`.
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Render a decoded CBOR value as a `serde_json::Value`. Tags are transparent
/// (the inner value is rendered); byte strings become base64url strings;
/// non-text map keys are stringified into the JSON object key.
pub fn to_json_value(v: &Value) -> Json {
    match v {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Integer(i) => int_to_json(int_i128(i)),
        Value::Float(f) => float_to_json(*f),
        Value::Text(s) => Json::String(s.clone()),
        Value::Bytes(b) => Json::String(b64url(b)),
        Value::Array(items) => Json::Array(items.iter().map(to_json_value).collect()),
        Value::Map(entries) => {
            let mut obj = JsonMap::with_capacity(entries.len());
            for (k, val) in entries {
                obj.insert(json_key(k), to_json_value(val));
            }
            Json::Object(obj)
        }
        Value::Tag(_, inner) => to_json_value(inner),
        // ciborium's `Value` is non-exhaustive; render any future variant as null.
        _ => Json::Null,
    }
}

/// Decode `bytes` and render the canonical JSON string. Always succeeds for
/// well-formed CBOR.
pub fn to_json_string(bytes: &[u8]) -> Result<String, DecodeError> {
    let value = parse_strict(bytes)?;
    Ok(to_json_value(&value).to_string())
}

/// A JSON object key for a CBOR map key. Text keys pass through; everything else
/// is stringified (numbers as decimal, bytes as base64url, etc.).
fn json_key(k: &Value) -> String {
    match k {
        Value::Text(s) => s.clone(),
        Value::Integer(i) => int_i128(i).to_string(),
        Value::Bytes(b) => b64url(b),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Float(f) => f.to_string(),
        other => to_json_value(other).to_string(),
    }
}

fn int_to_json(v: i128) -> Json {
    if let Ok(u) = u64::try_from(v) {
        Json::Number(Number::from(u))
    } else if let Ok(i) = i64::try_from(v) {
        Json::Number(Number::from(i))
    } else {
        // Outside JSON's safe integer range — render as a decimal string so no
        // precision is lost.
        Json::String(v.to_string())
    }
}

fn float_to_json(f: f64) -> Json {
    Number::from_f64(f).map(Json::Number).unwrap_or(Json::Null)
}

/// Encode a JSON string as core-deterministic CBOR.
pub fn from_json_str(s: &str) -> Result<Vec<u8>, String> {
    let json: Json = serde_json::from_str(s).map_err(|e| format!("invalid JSON: {e}"))?;
    let value = json_to_cbor(&json);
    let value = crate::codec::encode::canonicalize(value, crate::codec::encode::Canon::Core);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).map_err(|e| format!("encode: {e}"))?;
    Ok(out)
}

/// Convert a JSON value into a CBOR `Value`.
pub fn json_to_cbor(json: &Json) -> Value {
    match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::Integer(u.into())
            } else if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        Json::String(s) => Value::Text(s.clone()),
        Json::Array(items) => Value::Array(items.iter().map(json_to_cbor).collect()),
        Json::Object(obj) => Value::Map(
            obj.iter()
                .map(|(k, v)| (Value::Text(k.clone()), json_to_cbor(v)))
                .collect(),
        ),
    }
}
