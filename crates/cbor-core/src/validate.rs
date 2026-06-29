//! Well-formedness checks. Both `is_valid` and `well_formed` are total: malformed
//! input is reported, never panicked on.

use crate::value::{has_duplicate_keys, parse_strict, DecodeError};

/// The structured result of `cbor.well_formed`.
#[derive(Debug, Clone)]
pub struct WellFormed {
    /// Whether the blob is a single well-formed CBOR item with no trailing bytes
    /// and no duplicate map keys.
    pub ok: bool,
    /// A human-readable error message (empty when `ok`).
    pub error: Option<String>,
    /// The error taxonomy label (see [`DecodeError::kind`]); `None` when `ok`.
    pub kind: Option<String>,
}

/// `cbor.is_valid(blob)` — true iff the blob is exactly one well-formed CBOR item.
/// Duplicate keys are tolerated here (they are well-formed per RFC 8949 §1.2);
/// use `well_formed` for the stricter validity-plus-duplicates check.
pub fn is_valid(bytes: &[u8]) -> bool {
    parse_strict(bytes).is_ok()
}

/// `cbor.well_formed(blob)` — full diagnosis. Never errors.
pub fn well_formed(bytes: &[u8]) -> WellFormed {
    match parse_strict(bytes) {
        Ok(value) => {
            if has_duplicate_keys(&value) {
                let e = DecodeError::DuplicateKey;
                WellFormed {
                    ok: false,
                    error: Some(e.to_string()),
                    kind: Some(e.kind().to_string()),
                }
            } else {
                WellFormed {
                    ok: true,
                    error: None,
                    kind: None,
                }
            }
        }
        Err(e) => WellFormed {
            ok: false,
            error: Some(e.to_string()),
            kind: Some(e.kind().to_string()),
        },
    }
}
