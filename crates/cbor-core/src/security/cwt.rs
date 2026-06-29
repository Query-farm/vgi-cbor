//! CWT (RFC 8392) claim-set decode. Unwraps a `tag 61` / COSE envelope
//! automatically, then maps the registered claim keys 1..7 to named fields;
//! NumericDate claims (`exp`/`nbf`/`iat`) become epoch seconds. **No** signature
//! verification.

use ciborium::value::Value;

use crate::value::{int_i128, parse, strip_transparent, DecodeError};

/// A decoded CWT claim set.
#[derive(Debug, Clone, Default)]
pub struct CwtClaims {
    /// Claim 1 — issuer.
    pub iss: Option<String>,
    /// Claim 2 — subject.
    pub sub: Option<String>,
    /// Claim 3 — audience.
    pub aud: Option<String>,
    /// Claim 4 — expiration (epoch seconds).
    pub exp: Option<i64>,
    /// Claim 5 — not-before (epoch seconds).
    pub nbf: Option<i64>,
    /// Claim 6 — issued-at (epoch seconds).
    pub iat: Option<i64>,
    /// Claim 7 — CWT ID.
    pub cti: Option<Vec<u8>>,
    /// All other (private / unregistered) claims, rendered as a JSON object.
    pub extra: Option<String>,
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s.clone()),
        Value::Bytes(b) => Some(crate::codec::json::b64url(b)),
        Value::Integer(i) => Some(int_i128(i).to_string()),
        _ => None,
    }
}

fn as_seconds(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i64::try_from(int_i128(i)).ok(),
        Value::Float(f) => Some(*f as i64),
        Value::Tag(_, inner) => as_seconds(inner),
        _ => None,
    }
}

fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i64::try_from(int_i128(i)).ok(),
        _ => None,
    }
}

/// Locate the CWT claims map inside `bytes`, unwrapping any COSE / tag-61
/// envelope. Returns the claims as a CBOR map value.
fn claims_value(bytes: &[u8]) -> Result<Value, DecodeError> {
    let value = parse(bytes)?;
    extract_claims(&value)
}

fn extract_claims(value: &Value) -> Result<Value, DecodeError> {
    let value = strip_transparent(value);
    match value {
        Value::Map(_) => Ok(value.clone()),
        Value::Tag(61, inner) => extract_claims(inner),
        // A COSE message: decode it and parse its payload as the claim set.
        Value::Tag(_, _) | Value::Array(_) => {
            let decoded = crate::security::cose::decode_value(value, None)?;
            let payload = decoded
                .payload
                .ok_or_else(|| DecodeError::Structural("COSE message has no payload".into()))?;
            let inner = parse(&payload)?;
            extract_claims(&inner)
        }
        _ => Err(DecodeError::Structural(
            "input is not a CWT claim set or COSE message".into(),
        )),
    }
}

/// `cbor.cwt_claims(blob)` — decode the claim set.
pub fn cwt_claims(bytes: &[u8]) -> Result<CwtClaims, DecodeError> {
    let Value::Map(entries) = claims_value(bytes)? else {
        return Err(DecodeError::Structural("CWT claims are not a map".into()));
    };
    let mut claims = CwtClaims::default();
    let mut extra = serde_json::Map::new();
    for (k, v) in &entries {
        match as_int(k) {
            Some(1) => claims.iss = as_text(v),
            Some(2) => claims.sub = as_text(v),
            Some(3) => claims.aud = as_text(v),
            Some(4) => claims.exp = as_seconds(v),
            Some(5) => claims.nbf = as_seconds(v),
            Some(6) => claims.iat = as_seconds(v),
            Some(7) => {
                claims.cti = match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                }
            }
            _ => {
                let key = match k {
                    Value::Text(s) => s.clone(),
                    Value::Integer(i) => int_i128(i).to_string(),
                    other => crate::codec::diagnostic_key(other),
                };
                extra.insert(key, crate::codec::json::to_json_value(v));
            }
        }
    }
    if !extra.is_empty() {
        claims.extra = Some(serde_json::Value::Object(extra).to_string());
    }
    Ok(claims)
}
