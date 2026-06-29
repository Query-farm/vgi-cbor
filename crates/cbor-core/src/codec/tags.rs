//! Semantic-tag walk (RFC 8949 §3.4): every tag in document order with a
//! JSONPath-ish location, plus `untag` to pull the value(s) under a given tag.

use ciborium::value::Value;

use crate::codec::json::to_json_value;
use crate::value::{parse_strict, DecodeError};

/// One tag occurrence found while walking a CBOR item.
#[derive(Debug, Clone)]
pub struct TagHit {
    /// The tag number.
    pub tag: u64,
    /// JSONPath-ish location of the tag, e.g. `$`, `$.a`, `$[2]`.
    pub path: String,
    /// The tagged value, rendered as a JSON string.
    pub value_json: String,
}

/// Walk every semantic tag in `bytes`, in document order.
pub fn tags(bytes: &[u8]) -> Result<Vec<TagHit>, DecodeError> {
    let value = parse_strict(bytes)?;
    let mut out = Vec::new();
    walk(&value, "$".to_string(), &mut out);
    Ok(out)
}

fn walk(value: &Value, path: String, out: &mut Vec<TagHit>) {
    match value {
        Value::Tag(tag, inner) => {
            out.push(TagHit {
                tag: *tag,
                path: path.clone(),
                value_json: to_json_value(inner).to_string(),
            });
            // Descend into the tagged value without changing the path.
            walk(inner, path, out);
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(item, format!("{path}[{i}]"), out);
            }
        }
        Value::Map(entries) => {
            for (k, v) in entries {
                let seg = match k {
                    Value::Text(s) => format!("{path}.{s}"),
                    _ => format!("{path}[{}]", crate::codec::diagnostic_key(k)),
                };
                walk(v, seg, out);
            }
        }
        _ => {}
    }
}

/// `cbor.untag(blob, tag)` — JSON array of every value carried under `tag`,
/// in document order (empty array if the tag is absent).
pub fn untag(bytes: &[u8], tag: u64) -> Result<String, DecodeError> {
    let value = parse_strict(bytes)?;
    let mut hits: Vec<serde_json::Value> = Vec::new();
    collect_tag(&value, tag, &mut hits);
    Ok(serde_json::Value::Array(hits).to_string())
}

fn collect_tag(value: &Value, want: u64, out: &mut Vec<serde_json::Value>) {
    match value {
        Value::Tag(tag, inner) => {
            if *tag == want {
                out.push(to_json_value(inner));
            }
            collect_tag(inner, want, out);
        }
        Value::Array(items) => items.iter().for_each(|v| collect_tag(v, want, out)),
        Value::Map(entries) => entries.iter().for_each(|(_, v)| collect_tag(v, want, out)),
        _ => {}
    }
}
