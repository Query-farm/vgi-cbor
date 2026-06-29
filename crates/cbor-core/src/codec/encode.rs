//! Deterministic CBOR encoding: shortest-form (ciborium's default) plus the two
//! canonical orderings the spec requires — RFC 8949 §4.2.1 **core** (map keys
//! sorted by encoded-byte order) and **CTAP2** (keys sorted length-first then
//! bytewise, required to recompute WebAuthn signatures).

use ciborium::value::Value;

use crate::value::{parse_strict, DecodeError};

/// Which canonical map-key ordering to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canon {
    /// RFC 8949 §4.2.1: keys sorted by their full encoded-byte sequence.
    Core,
    /// CTAP2 canonical CBOR: keys sorted by encoded length first, then bytewise.
    Ctap2,
}

impl Canon {
    /// Parse the `mode` string accepted by `cbor.canonical`.
    pub fn parse(s: &str) -> Result<Canon, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "core" => Ok(Canon::Core),
            "ctap2" => Ok(Canon::Ctap2),
            other => Err(format!(
                "unknown canonical mode '{other}' (expected core | ctap2)"
            )),
        }
    }
}

/// Encode a single CBOR value to bytes (ciborium emits shortest-form integers).
pub fn encode_value(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|e| format!("encode: {e}"))?;
    Ok(out)
}

/// Encode the just-encoded bytes of a key, for canonical ordering comparisons.
fn key_bytes(value: &Value) -> Vec<u8> {
    encode_value(value).unwrap_or_default()
}

/// Recursively re-order every map in `value` per `mode`, returning a new value.
pub fn canonicalize(value: Value, mode: Canon) -> Value {
    match value {
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|v| canonicalize(v, mode)).collect())
        }
        Value::Map(entries) => {
            let mut canon: Vec<(Value, Value)> = entries
                .into_iter()
                .map(|(k, v)| (canonicalize(k, mode), canonicalize(v, mode)))
                .collect();
            canon.sort_by(|(ka, _), (kb, _)| {
                let a = key_bytes(ka);
                let b = key_bytes(kb);
                match mode {
                    Canon::Core => a.cmp(&b),
                    Canon::Ctap2 => a.len().cmp(&b.len()).then_with(|| a.cmp(&b)),
                }
            });
            Value::Map(canon)
        }
        Value::Tag(tag, inner) => Value::Tag(tag, Box::new(canonicalize(*inner, mode))),
        other => other,
    }
}

/// `cbor.canonical(blob, mode)` — decode, canonicalize, and re-encode. Idempotent
/// and round-trips through `decode`.
pub fn canonical(bytes: &[u8], mode: Canon) -> Result<Vec<u8>, DecodeError> {
    let value = parse_strict(bytes)?;
    let canon = canonicalize(value, mode);
    encode_value(&canon).map_err(DecodeError::Structural)
}
