//! COSE (RFC 9052) structural decode — **no** cryptographic verification. Unwraps
//! the tagged/untagged COSE array shapes, decodes the protected & unprotected
//! header maps with named common labels, and exposes the x5t / x5chain join keys.

use ciborium::value::Value;

use crate::security::registry::alg_name;
use crate::value::{int_i128, parse, strip_transparent, DecodeError};

/// Named COSE header parameters (the common labels from RFC 9052 §3.1).
#[derive(Debug, Clone, Default)]
pub struct CoseHeaders {
    /// Label 1 — signature/encryption algorithm, as its IANA name.
    pub alg: Option<String>,
    /// Label 2 — `crit` critical-headers list, rendered as JSON.
    pub crit: Option<String>,
    /// Label 3 — content type (media type string or integer).
    pub content_type: Option<String>,
    /// Label 4 — key identifier bytes.
    pub kid: Option<Vec<u8>>,
    /// Label 5 — initialization vector bytes.
    pub iv: Option<Vec<u8>>,
    /// Label 33 — `x5chain` DER certificate chain.
    pub x5chain: Option<Vec<Vec<u8>>>,
    /// Label 34 — `x5t` certificate thumbprint `(hash_alg, thumbprint)`.
    pub x5t: Option<(String, Vec<u8>)>,
}

/// A structurally-decoded COSE message.
#[derive(Debug, Clone)]
pub struct CoseDecoded {
    /// The recognized CBOR tag (18/98/16/96/17/97/61), if the message was tagged.
    pub tag: Option<u64>,
    /// The message type name, e.g. `COSE_Sign1`.
    pub msg_type: String,
    /// Decoded protected header.
    pub protected: CoseHeaders,
    /// Decoded unprotected header.
    pub unprotected: CoseHeaders,
    /// The payload / ciphertext bytes (nil → `None`).
    pub payload: Option<Vec<u8>>,
    /// The signature / MAC-tag bytes for the single-recipient shapes.
    pub signature: Option<Vec<u8>>,
    /// The recipients / signers array, rendered as JSON (multi-recipient shapes).
    pub recipients: Option<String>,
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
        Value::Null => None,
        _ => None,
    }
}

/// Decode a COSE header map `Value` (already a CBOR map) into [`CoseHeaders`].
pub fn decode_header_map(map: &Value) -> CoseHeaders {
    let mut h = CoseHeaders::default();
    let Value::Map(entries) = map else {
        return h;
    };
    for (k, v) in entries {
        match as_int(k) {
            Some(1) => h.alg = as_int(v).map(alg_name).or_else(|| text_of(v)),
            Some(2) => h.crit = Some(crate::codec::json::to_json_value(v).to_string()),
            Some(3) => {
                h.content_type = as_int(v).map(|i| i.to_string()).or_else(|| text_of(v));
            }
            Some(4) => h.kid = as_bytes(v),
            Some(5) => h.iv = as_bytes(v),
            Some(33) => h.x5chain = decode_x5chain(v),
            Some(34) => h.x5t = decode_x5t(v),
            _ => {}
        }
    }
    h
}

/// Decode a protected header bstr (which wraps a CBOR map) into [`CoseHeaders`].
fn decode_protected(v: &Value) -> CoseHeaders {
    match v {
        Value::Bytes(b) if b.is_empty() => CoseHeaders::default(),
        Value::Bytes(b) => match parse(b) {
            Ok(inner) => decode_header_map(&inner),
            Err(_) => CoseHeaders::default(),
        },
        // Some encoders leave the protected header as a bare map.
        Value::Map(_) => decode_header_map(v),
        _ => CoseHeaders::default(),
    }
}

fn text_of(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn decode_x5chain(v: &Value) -> Option<Vec<Vec<u8>>> {
    match v {
        // A single cert is allowed to appear as a bare bstr.
        Value::Bytes(b) => Some(vec![b.clone()]),
        Value::Array(items) => {
            let certs: Vec<Vec<u8>> = items.iter().filter_map(as_bytes).collect();
            if certs.is_empty() {
                None
            } else {
                Some(certs)
            }
        }
        _ => None,
    }
}

fn decode_x5t(v: &Value) -> Option<(String, Vec<u8>)> {
    if let Value::Array(items) = v {
        if items.len() == 2 {
            let hash = as_int(&items[0]).map(alg_name).unwrap_or_default();
            let thumb = as_bytes(&items[1])?;
            return Some((hash, thumb));
        }
    }
    None
}

/// Identify the COSE message type for a tag.
fn type_for_tag(tag: u64) -> &'static str {
    match tag {
        18 => "COSE_Sign1",
        98 => "COSE_Sign",
        16 => "COSE_Encrypt0",
        96 => "COSE_Encrypt",
        17 => "COSE_Mac0",
        97 => "COSE_Mac",
        61 => "CWT",
        _ => "COSE_unknown",
    }
}

/// Structurally decode a COSE message from raw bytes.
pub fn cose_decode(bytes: &[u8]) -> Result<CoseDecoded, DecodeError> {
    let value = parse(bytes)?;
    decode_value(&value, None)
}

/// Decode an already-parsed COSE value, optionally carrying the outer tag.
pub fn decode_value(value: &Value, outer_tag: Option<u64>) -> Result<CoseDecoded, DecodeError> {
    let value = strip_transparent(value);
    // Unwrap a CWT (tag 61) envelope around an inner COSE message.
    if let Value::Tag(61, inner) = value {
        let mut decoded = decode_value(inner, Some(61))?;
        if decoded.tag.is_none() || outer_tag == Some(61) {
            decoded.tag = Some(61);
        }
        return Ok(decoded);
    }
    if let Value::Tag(tag, inner) = value {
        return decode_array(inner, Some(*tag));
    }
    decode_array(value, outer_tag)
}

fn decode_array(value: &Value, tag: Option<u64>) -> Result<CoseDecoded, DecodeError> {
    let Value::Array(items) = value else {
        return Err(DecodeError::Structural(
            "COSE message is not a CBOR array".into(),
        ));
    };
    if items.len() < 3 {
        return Err(DecodeError::Structural(format!(
            "COSE array has {} elements (expected 3 or 4)",
            items.len()
        )));
    }
    let protected = decode_protected(&items[0]);
    let unprotected = decode_header_map(&items[1]);

    let msg_type = match tag {
        Some(t) => type_for_tag(t).to_string(),
        None => {
            if items.len() == 3 {
                "COSE_Encrypt0".to_string()
            } else {
                "COSE_Sign1".to_string()
            }
        }
    };

    let payload = as_bytes(&items[2]);
    let (signature, recipients) = if items.len() >= 4 {
        match &items[3] {
            Value::Array(_) => (
                None,
                Some(crate::codec::json::to_json_value(&items[3]).to_string()),
            ),
            other => (as_bytes(other), None),
        }
    } else {
        (None, None)
    };

    Ok(CoseDecoded {
        tag,
        msg_type,
        protected,
        unprotected,
        payload,
        signature,
        recipients,
    })
}

/// Merge protected over unprotected headers (protected wins) — the view returned
/// by `cose_headers`.
pub fn merged_headers(d: &CoseDecoded) -> CoseHeaders {
    let mut h = d.unprotected.clone();
    let p = &d.protected;
    if p.alg.is_some() {
        h.alg = p.alg.clone();
    }
    if p.crit.is_some() {
        h.crit = p.crit.clone();
    }
    if p.content_type.is_some() {
        h.content_type = p.content_type.clone();
    }
    if p.kid.is_some() {
        h.kid = p.kid.clone();
    }
    if p.iv.is_some() {
        h.iv = p.iv.clone();
    }
    if p.x5chain.is_some() {
        h.x5chain = p.x5chain.clone();
    }
    if p.x5t.is_some() {
        h.x5t = p.x5t.clone();
    }
    h
}

/// `cbor.cose_payload(blob)` — the raw inner payload bytes.
pub fn cose_payload(bytes: &[u8]) -> Result<Option<Vec<u8>>, DecodeError> {
    Ok(cose_decode(bytes)?.payload)
}

/// `cbor.cose_x5t(blob)` — the x5t thumbprint as a lowercase hex string (the join
/// key to `vgi-x509`), searching protected then unprotected headers.
pub fn cose_x5t(bytes: &[u8]) -> Result<Option<String>, DecodeError> {
    let d = cose_decode(bytes)?;
    let h = merged_headers(&d);
    Ok(h.x5t.map(|(_, thumb)| hex::encode(thumb)))
}

/// `cbor.cose_x5chain(blob)` — the DER certificate chain.
pub fn cose_x5chain(bytes: &[u8]) -> Result<Option<Vec<Vec<u8>>>, DecodeError> {
    let d = cose_decode(bytes)?;
    Ok(merged_headers(&d).x5chain)
}
