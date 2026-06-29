//! WebAuthn / FIDO2 / CTAP2 decode: the fixed `authenticatorData` byte layout and
//! the attestation **object** with per-format `attStmt` shred. Structural only —
//! no signature verification.

use std::io::Cursor;

use ciborium::value::Value;
use uuid::Uuid;

use crate::security::cose_key::{self, CoseKeyInfo};
use crate::security::registry::alg_name;
use crate::value::{int_i128, parse, DecodeError, MAX_NESTING};

/// Parsed `authenticatorData`.
#[derive(Debug, Clone)]
pub struct AuthData {
    /// SHA-256 of the RP ID (32 bytes).
    pub rp_id_hash: Vec<u8>,
    /// User-present flag (bit 0).
    pub up: bool,
    /// User-verified flag (bit 2).
    pub uv: bool,
    /// Backup-eligible flag (bit 3).
    pub be: bool,
    /// Backup-state flag (bit 4).
    pub bs: bool,
    /// Attested-credential-data-present flag (bit 6).
    pub at: bool,
    /// Extension-data-present flag (bit 7).
    pub ed: bool,
    /// Signature counter.
    pub sign_count: u32,
    /// Authenticator AAGUID, rendered as a canonical UUID (present when `at`).
    pub aaguid: Option<String>,
    /// Credential ID bytes (present when `at`).
    pub cred_id: Option<Vec<u8>>,
    /// The attested credential public key (present when `at`).
    pub cred_public_key: Option<CoseKeyInfo>,
    /// Extension map rendered as JSON (present when `ed`).
    pub extensions: Option<String>,
}

/// `cbor.webauthn_authdata(blob)` — parse the authenticatorData byte layout.
pub fn webauthn_authdata(bytes: &[u8]) -> Result<AuthData, DecodeError> {
    if bytes.len() < 37 {
        return Err(DecodeError::Structural(format!(
            "authenticatorData is {} bytes (need at least 37)",
            bytes.len()
        )));
    }
    let rp_id_hash = bytes[0..32].to_vec();
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

    let up = flags & 0x01 != 0;
    let uv = flags & 0x04 != 0;
    let be = flags & 0x08 != 0;
    let bs = flags & 0x10 != 0;
    let at = flags & 0x40 != 0;
    let ed = flags & 0x80 != 0;

    let mut idx = 37usize;
    let mut aaguid = None;
    let mut cred_id = None;
    let mut cred_public_key = None;

    if at {
        if bytes.len() < idx + 18 {
            return Err(DecodeError::Structural(
                "attested credential data truncated (aaguid/credIdLen)".into(),
            ));
        }
        let aaguid_bytes: [u8; 16] = bytes[idx..idx + 16]
            .try_into()
            .map_err(|_| DecodeError::Structural("bad aaguid".into()))?;
        aaguid = Some(Uuid::from_bytes(aaguid_bytes).hyphenated().to_string());
        idx += 16;
        let cred_id_len = u16::from_be_bytes([bytes[idx], bytes[idx + 1]]) as usize;
        idx += 2;
        if bytes.len() < idx + cred_id_len {
            return Err(DecodeError::Structural(
                "attested credential data truncated (credentialId)".into(),
            ));
        }
        cred_id = Some(bytes[idx..idx + cred_id_len].to_vec());
        idx += cred_id_len;

        // The credential public key is a CBOR map; parse it and advance by the
        // exact number of bytes it consumed.
        let mut cur = Cursor::new(&bytes[idx..]);
        let key_val: Value = ciborium::de::from_reader_with_recursion_limit(&mut cur, MAX_NESTING)
            .map_err(|_| DecodeError::Structural("bad credentialPublicKey CBOR".into()))?;
        idx += cur.position() as usize;
        cred_public_key = Some(cose_key::decode_value(&key_val)?);
    }

    let mut extensions = None;
    if ed && idx < bytes.len() {
        if let Ok(ext) = parse(&bytes[idx..]) {
            extensions = Some(crate::codec::json::to_json_value(&ext).to_string());
        }
    }

    Ok(AuthData {
        rp_id_hash,
        up,
        uv,
        be,
        bs,
        at,
        ed,
        sign_count,
        aaguid,
        cred_id,
        cred_public_key,
        extensions,
    })
}

/// One row produced by `cbor.webauthn_attestation`.
#[derive(Debug, Clone)]
pub struct AttestationRow {
    /// Attestation statement format (`packed`, `fido-u2f`, `tpm`, `apple`, …).
    pub fmt: String,
    /// AAGUID from the embedded authenticatorData.
    pub aaguid: Option<String>,
    /// Signature counter.
    pub sign_count: u32,
    /// RP ID hash.
    pub rp_id_hash: Vec<u8>,
    /// User-present flag.
    pub up: bool,
    /// User-verified flag.
    pub uv: bool,
    /// Credential ID.
    pub cred_id: Option<Vec<u8>>,
    /// Signature algorithm name from the attestation statement.
    pub alg: Option<String>,
    /// Attestation signature bytes.
    pub sig: Option<Vec<u8>>,
    /// Attestation certificate chain (the `vgi-x509` join key).
    pub x5c: Vec<Vec<u8>>,
    /// The full attestation statement rendered as JSON.
    pub att_stmt: String,
}

fn as_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(s) if s == key => Some(v),
        _ => None,
    })
}

fn decode_x5c(v: &Value) -> Vec<Vec<u8>> {
    match v {
        Value::Array(items) => items.iter().filter_map(as_bytes).collect(),
        Value::Bytes(b) => vec![b.clone()],
        _ => Vec::new(),
    }
}

/// `cbor.webauthn_attestation(blob)` — decode the attestation object and shred its
/// format-specific statement into one typed row.
pub fn webauthn_attestation(bytes: &[u8]) -> Result<AttestationRow, DecodeError> {
    let value = parse(bytes)?;
    let Value::Map(entries) = &value else {
        return Err(DecodeError::Structural(
            "attestation object is not a CBOR map".into(),
        ));
    };

    let fmt = match map_get(entries, "fmt") {
        Some(Value::Text(s)) => s.clone(),
        _ => {
            return Err(DecodeError::Structural(
                "attestation object missing fmt".into(),
            ))
        }
    };
    let auth_data_bytes = match map_get(entries, "authData") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => {
            return Err(DecodeError::Structural(
                "attestation object missing authData".into(),
            ))
        }
    };
    let auth = webauthn_authdata(&auth_data_bytes)?;

    let att_stmt = map_get(entries, "attStmt");
    let att_stmt_json = att_stmt
        .map(|v| crate::codec::json::to_json_value(v).to_string())
        .unwrap_or_else(|| "{}".to_string());

    let mut alg = None;
    let mut sig = None;
    let mut x5c = Vec::new();
    if let Some(Value::Map(st)) = att_stmt {
        if let Some(Value::Integer(i)) = map_get(st, "alg") {
            alg = i64::try_from(int_i128(i)).ok().map(alg_name);
        }
        if let Some(s) = map_get(st, "sig") {
            sig = as_bytes(s);
        }
        if let Some(c) = map_get(st, "x5c") {
            x5c = decode_x5c(c);
        }
    }

    Ok(AttestationRow {
        fmt,
        aaguid: auth.aaguid,
        sign_count: auth.sign_count,
        rp_id_hash: auth.rp_id_hash,
        up: auth.up,
        uv: auth.uv,
        cred_id: auth.cred_id,
        alg,
        sig,
        x5c,
        att_stmt: att_stmt_json,
    })
}
