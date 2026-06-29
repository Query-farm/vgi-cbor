//! MessagePack mirror of the CBOR codec: decode to JSON, transcode to CBOR, and
//! encode. `ext` types surface as `{ext_type, data}`; the reserved timestamp ext
//! (type −1, 32/64/96-bit) decodes to an RFC 3339 instant.

use ciborium::value::Value as Cbor;
use rmpv::Value as Mp;
use serde_json::{Map as JsonMap, Number, Value as Json};

use crate::codec::json::b64url;

/// Decode MessagePack bytes into an `rmpv::Value`.
pub fn parse(bytes: &[u8]) -> Result<Mp, String> {
    let mut cur = bytes;
    let value = rmpv::decode::read_value(&mut cur).map_err(|e| format!("msgpack decode: {e}"))?;
    if !cur.is_empty() {
        return Err("trailing bytes after the top-level msgpack item".to_string());
    }
    Ok(value)
}

/// `cbor.msgpack_to_json(blob)` — decode and render as a JSON string.
pub fn to_json_string(bytes: &[u8]) -> Result<String, String> {
    Ok(mp_to_json(&parse(bytes)?).to_string())
}

/// `cbor.msgpack_to_cbor(blob)` — transcode MessagePack to CBOR bytes.
pub fn to_cbor(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = mp_to_cbor(&parse(bytes)?);
    crate::codec::encode::encode_value(&value)
}

/// Render an `rmpv::Value` as JSON.
pub fn mp_to_json(v: &Mp) -> Json {
    match v {
        Mp::Nil => Json::Null,
        Mp::Boolean(b) => Json::Bool(*b),
        Mp::Integer(i) => {
            if let Some(u) = i.as_u64() {
                Json::Number(Number::from(u))
            } else if let Some(s) = i.as_i64() {
                Json::Number(Number::from(s))
            } else {
                Json::Null
            }
        }
        Mp::F32(f) => Number::from_f64(*f as f64)
            .map(Json::Number)
            .unwrap_or(Json::Null),
        Mp::F64(f) => Number::from_f64(*f).map(Json::Number).unwrap_or(Json::Null),
        Mp::String(s) => match s.as_str() {
            Some(text) => Json::String(text.to_string()),
            None => Json::String(b64url(s.as_bytes())),
        },
        Mp::Binary(b) => Json::String(b64url(b)),
        Mp::Array(items) => Json::Array(items.iter().map(mp_to_json).collect()),
        Mp::Map(entries) => {
            let mut obj = JsonMap::with_capacity(entries.len());
            for (k, val) in entries {
                obj.insert(mp_key(k), mp_to_json(val));
            }
            Json::Object(obj)
        }
        Mp::Ext(ty, data) => ext_to_json(*ty, data),
    }
}

/// Convert an `rmpv::Value` into a CBOR `Value`.
pub fn mp_to_cbor(v: &Mp) -> Cbor {
    match v {
        Mp::Nil => Cbor::Null,
        Mp::Boolean(b) => Cbor::Bool(*b),
        Mp::Integer(i) => {
            if let Some(u) = i.as_u64() {
                Cbor::Integer(u.into())
            } else if let Some(s) = i.as_i64() {
                Cbor::Integer(s.into())
            } else {
                Cbor::Null
            }
        }
        Mp::F32(f) => Cbor::Float(*f as f64),
        Mp::F64(f) => Cbor::Float(*f),
        Mp::String(s) => match s.as_str() {
            Some(text) => Cbor::Text(text.to_string()),
            None => Cbor::Bytes(s.as_bytes().to_vec()),
        },
        Mp::Binary(b) => Cbor::Bytes(b.clone()),
        Mp::Array(items) => Cbor::Array(items.iter().map(mp_to_cbor).collect()),
        Mp::Map(entries) => Cbor::Map(
            entries
                .iter()
                .map(|(k, val)| (mp_to_cbor(k), mp_to_cbor(val)))
                .collect(),
        ),
        Mp::Ext(ty, data) => {
            if *ty == -1 {
                if let Some((secs, _nanos)) = decode_timestamp(data) {
                    // CBOR tag 1 = epoch-based date/time.
                    return Cbor::Tag(1, Box::new(Cbor::Integer(secs.into())));
                }
            }
            Cbor::Map(vec![
                (
                    Cbor::Text("ext_type".into()),
                    Cbor::Integer((*ty as i64).into()),
                ),
                (Cbor::Text("data".into()), Cbor::Bytes(data.clone())),
            ])
        }
    }
}

fn mp_key(k: &Mp) -> String {
    match k {
        Mp::String(s) => s
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| b64url(s.as_bytes())),
        Mp::Integer(i) => i
            .as_i64()
            .map(|v| v.to_string())
            .or_else(|| i.as_u64().map(|v| v.to_string()))
            .unwrap_or_default(),
        other => mp_to_json(other).to_string(),
    }
}

fn ext_to_json(ty: i8, data: &[u8]) -> Json {
    if ty == -1 {
        if let Some((secs, nanos)) = decode_timestamp(data) {
            let mut obj = JsonMap::new();
            obj.insert("timestamp".into(), Json::String(rfc3339(secs, nanos)));
            return Json::Object(obj);
        }
    }
    let mut obj = JsonMap::new();
    obj.insert("ext_type".into(), Json::Number(Number::from(ty as i64)));
    obj.insert("data".into(), Json::String(b64url(data)));
    Json::Object(obj)
}

/// Decode the reserved timestamp ext payload (32 / 64 / 96-bit) → (seconds, nanos).
pub fn decode_timestamp(data: &[u8]) -> Option<(i64, u32)> {
    match data.len() {
        4 => {
            let secs = u32::from_be_bytes(data.try_into().ok()?) as i64;
            Some((secs, 0))
        }
        8 => {
            let v = u64::from_be_bytes(data.try_into().ok()?);
            let nanos = (v >> 34) as u32;
            let secs = (v & 0x0003_ffff_ffff) as i64;
            Some((secs, nanos))
        }
        12 => {
            let nanos = u32::from_be_bytes(data[0..4].try_into().ok()?);
            let secs = i64::from_be_bytes(data[4..12].try_into().ok()?);
            Some((secs, nanos))
        }
        _ => None,
    }
}

/// Minimal RFC 3339 UTC rendering from epoch seconds (+ nanos) — used only for
/// the JSON view of msgpack timestamps. Avoids a chrono dependency.
fn rfc3339(secs: i64, nanos: u32) -> String {
    // Days since the Unix epoch, civil-from-days (Howard Hinnant's algorithm).
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    if nanos > 0 {
        format!("{year:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{nanos:09}Z")
    } else {
        format!("{year:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }
}
