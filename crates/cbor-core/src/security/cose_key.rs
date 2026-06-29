//! COSE_Key (RFC 9052 §7) decode — the structure embedded as the WebAuthn
//! `credentialPublicKey`. Maps `kty`/`alg`/`crv` to their names and surfaces the
//! key-material parameters per key type.

use ciborium::value::Value;

use crate::security::registry::{alg_name, crv_name, kty_name};
use crate::value::{int_i128, parse, DecodeError};

/// A decoded COSE_Key.
#[derive(Debug, Clone, Default)]
pub struct CoseKeyInfo {
    /// Key type name (`OKP`/`EC2`/`RSA`/`Symmetric`).
    pub kty: Option<String>,
    /// Key identifier bytes.
    pub kid: Option<Vec<u8>>,
    /// Algorithm name.
    pub alg: Option<String>,
    /// Curve name (EC2 / OKP).
    pub crv: Option<String>,
    /// EC2/OKP public x-coordinate.
    pub x: Option<Vec<u8>>,
    /// EC2 public y-coordinate.
    pub y: Option<Vec<u8>>,
    /// RSA modulus.
    pub n: Option<Vec<u8>>,
    /// RSA public exponent.
    pub e: Option<Vec<u8>>,
}

fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i64::try_from(int_i128(i)).ok(),
        _ => None,
    }
}

fn as_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

/// Decode a COSE_Key from an already-parsed CBOR map value.
pub fn decode_value(value: &Value) -> Result<CoseKeyInfo, DecodeError> {
    let Value::Map(entries) = value else {
        return Err(DecodeError::Structural("COSE_Key is not a map".into()));
    };
    let mut key = CoseKeyInfo::default();
    let mut kty_id: Option<i64> = None;
    for (k, v) in entries {
        match as_int(k) {
            Some(1) => {
                kty_id = as_int(v);
                key.kty = kty_id.map(kty_name);
            }
            Some(2) => key.kid = as_bytes(v),
            Some(3) => key.alg = as_int(v).map(alg_name),
            Some(-1) => {
                // For EC2/OKP this is `crv`; for RSA it is the modulus `n`.
                if kty_id == Some(3) {
                    key.n = as_bytes(v);
                } else {
                    key.crv = as_int(v).map(crv_name);
                }
            }
            Some(-2) => {
                if kty_id == Some(3) {
                    key.e = as_bytes(v);
                } else {
                    key.x = as_bytes(v);
                }
            }
            Some(-3) => {
                if kty_id != Some(3) {
                    key.y = as_bytes(v);
                }
            }
            _ => {}
        }
    }
    // RSA fields may appear before `kty` in encoding order; re-scan if needed.
    if kty_id == Some(3) && key.n.is_none() {
        for (k, v) in entries {
            match as_int(k) {
                Some(-1) => key.n = as_bytes(v),
                Some(-2) => key.e = as_bytes(v),
                _ => {}
            }
        }
    }
    Ok(key)
}

/// `cbor.cose_key(blob)` — decode a COSE_Key blob.
pub fn cose_key(bytes: &[u8]) -> Result<CoseKeyInfo, DecodeError> {
    let value = parse(bytes)?;
    decode_value(&value)
}
