//! Shared CBOR parsing helpers over [`ciborium::value::Value`].
//!
//! Every public decoder funnels through [`parse`] / [`parse_strict`], which apply
//! the worker's untrusted-input discipline: a bounded recursion limit (so a
//! hostile deeply-nested blob cannot stack-overflow the worker) and explicit
//! trailing-byte detection. Nothing here panics on malformed input — errors are
//! returned as [`DecodeError`] and surfaced per-row by the worker.

use std::io::Cursor;

use ciborium::value::Value;

/// Maximum CBOR nesting depth accepted by the decoders. A blob deeper than this
/// is rejected with [`DecodeError::NestingLimit`] rather than recursing into a
/// stack overflow.
///
/// Kept conservative (well below the spec's nominal 256) so the bounded recursion
/// stays within a small (2 MiB) worker-/test-thread stack: `ciborium`'s serde
/// `Value` deserialization uses a heavy per-level stack frame (especially in
/// unoptimized debug builds), so the safe depth is lower than the theoretical
/// limit. 64 levels is still far deeper than any real COSE / CWT / WebAuthn /
/// telemetry document, and a deeper blob is cleanly rejected as `nesting-limit`.
pub const MAX_NESTING: usize = 64;

/// A classified decode failure. The `kind()` string lines up with the
/// `well_formed` `kind` taxonomy in the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended mid-item.
    Truncated,
    /// Bytes remain after a complete top-level item.
    TrailingBytes,
    /// A reserved / ill-formed major-type or argument encoding.
    InvalidMajor(String),
    /// A text string contained invalid UTF-8.
    BadUtf8,
    /// A map contained the same key twice.
    DuplicateKey,
    /// Nesting exceeded [`MAX_NESTING`].
    NestingLimit,
    /// A reserved simple value (24..=31) was used.
    ReservedSimple,
    /// Anything structural the higher-level decoders reject (e.g. a COSE array
    /// of the wrong shape). Not a well-formedness failure of the CBOR itself.
    Structural(String),
}

impl DecodeError {
    /// The `well_formed.kind` label for this error.
    pub fn kind(&self) -> &'static str {
        match self {
            DecodeError::Truncated => "truncated",
            DecodeError::TrailingBytes => "trailing-bytes",
            DecodeError::InvalidMajor(_) => "invalid-major",
            DecodeError::BadUtf8 => "bad-utf8",
            DecodeError::DuplicateKey => "duplicate-key",
            DecodeError::NestingLimit => "nesting-limit",
            DecodeError::ReservedSimple => "reserved-simple",
            DecodeError::Structural(_) => "structural",
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "input ended before the item was complete"),
            DecodeError::TrailingBytes => write!(f, "trailing bytes after the top-level item"),
            DecodeError::InvalidMajor(m) => write!(f, "ill-formed CBOR: {m}"),
            DecodeError::BadUtf8 => write!(f, "text string is not valid UTF-8"),
            DecodeError::DuplicateKey => write!(f, "map contains a duplicate key"),
            DecodeError::NestingLimit => write!(f, "nesting exceeds the {MAX_NESTING}-level limit"),
            DecodeError::ReservedSimple => write!(f, "reserved simple value"),
            DecodeError::Structural(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Map a ciborium deserialization error onto a [`DecodeError`] kind.
fn classify(err: &ciborium::de::Error<std::io::Error>) -> DecodeError {
    use ciborium::de::Error;
    match err {
        Error::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => DecodeError::Truncated,
        Error::Io(io) => DecodeError::InvalidMajor(io.to_string()),
        Error::Syntax(_) => DecodeError::InvalidMajor("invalid initial byte / argument".into()),
        Error::Semantic(_, msg) => {
            let lower = msg.to_ascii_lowercase();
            if lower.contains("utf") {
                DecodeError::BadUtf8
            } else if lower.contains("simple") {
                DecodeError::ReservedSimple
            } else {
                DecodeError::InvalidMajor(msg.clone())
            }
        }
        Error::RecursionLimitExceeded => DecodeError::NestingLimit,
    }
}

/// Decode exactly one CBOR item, allowing trailing bytes (used by COSE / msgpack
/// callers that have already validated framing). Bounded recursion.
pub fn parse(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut cur = Cursor::new(bytes);
    ciborium::de::from_reader_with_recursion_limit(&mut cur, MAX_NESTING).map_err(|e| classify(&e))
}

/// Decode exactly one well-formed CBOR item and require that the whole input is
/// consumed (no trailing bytes). This is the strict entry the validators use.
pub fn parse_strict(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut cur = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader_with_recursion_limit(&mut cur, MAX_NESTING)
        .map_err(|e| classify(&e))?;
    if (cur.position() as usize) != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(value)
}

/// Recursively scan a decoded value for duplicate map keys (ciborium keeps both,
/// last-wins). Returns `true` if any map has two equal keys.
pub fn has_duplicate_keys(value: &Value) -> bool {
    match value {
        Value::Map(entries) => {
            for i in 0..entries.len() {
                for j in (i + 1)..entries.len() {
                    if values_equal(&entries[i].0, &entries[j].0) {
                        return true;
                    }
                }
            }
            entries
                .iter()
                .any(|(k, v)| has_duplicate_keys(k) || has_duplicate_keys(v))
        }
        Value::Array(items) => items.iter().any(has_duplicate_keys),
        Value::Tag(_, inner) => has_duplicate_keys(inner),
        _ => false,
    }
}

/// Structural equality for map-key comparison (ciborium's `Value` is not `Eq`
/// because of `f64`, so compare by hand).
pub fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => x == y,
        (Value::Bytes(x), Value::Bytes(y)) => x == y,
        (Value::Float(x), Value::Float(y)) => x == y || (x.is_nan() && y.is_nan()),
        (Value::Text(x), Value::Text(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Null, Value::Null) => true,
        (Value::Tag(tx, vx), Value::Tag(ty, vy)) => tx == ty && values_equal(vx, vy),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| values_equal(p, q))
        }
        (Value::Map(x), Value::Map(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|((kx, vx), (ky, vy))| values_equal(kx, ky) && values_equal(vx, vy))
        }
        _ => false,
    }
}

/// Strip transparent self-describe tags (55799) and embedded-CBOR tags (24),
/// returning the innermost meaningful value. Used before structural decode.
pub fn strip_transparent(value: &Value) -> &Value {
    let mut v = value;
    while let Value::Tag(tag, inner) = v {
        if *tag == 55799 {
            v = inner;
        } else {
            break;
        }
    }
    v
}

/// Read an [`i128`] out of a ciborium `Integer`.
pub fn int_i128(i: &ciborium::value::Integer) -> i128 {
    i128::from(*i)
}
