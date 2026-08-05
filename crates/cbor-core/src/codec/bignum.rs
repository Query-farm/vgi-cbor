//! CBOR arbitrary-precision integers (RFC 8949 §3.4.3) and the integer half of
//! decimal fractions (§3.4.4).
//!
//! CBOR's native integers span `-2^64 ..= 2^64 - 1`. Anything wider rides as a
//! *bignum*: tag 2 for a non-negative value and tag 3 for a negative one, each
//! wrapping a big-endian byte string. A tag-3 payload `n` denotes `-1 - n`, so
//! the representation is symmetric without a sign bit.
//!
//! `DECIMAL(38, s)` needs this: its unscaled mantissa reaches 10^38, an order of
//! magnitude past what a native CBOR integer can hold.

use ciborium::value::{Integer, Value};

/// Encode an `i128` as the narrowest CBOR integer that holds it — a native
/// integer where one fits, otherwise a tag-2 / tag-3 bignum.
pub fn to_value(n: i128) -> Value {
    match Integer::try_from(n) {
        Ok(i) => Value::Integer(i),
        Err(_) => {
            // Outside the native range: emit a bignum. Tag 3 stores `-1 - n`.
            let (tag, magnitude) = if n >= 0 {
                (2u64, n as u128)
            } else {
                (3u64, (-1 - n) as u128)
            };
            Value::Tag(tag, Box::new(Value::Bytes(trim_be(magnitude))))
        }
    }
}

/// Decode a CBOR integer or bignum back to `i128`. Returns `None` for anything
/// that is not an integer, or for a bignum too wide to fit.
pub fn from_value(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(i) => Some(i128::from(*i)),
        Value::Tag(2, inner) => match inner.as_ref() {
            Value::Bytes(b) => be_to_u128(b).and_then(|m| i128::try_from(m).ok()),
            _ => None,
        },
        Value::Tag(3, inner) => match inner.as_ref() {
            // Tag 3 encodes `-1 - n`, so the magnitude may be one past i128::MAX.
            Value::Bytes(b) => be_to_u128(b)
                .and_then(|m| i128::try_from(m).ok().and_then(|m| (-1i128).checked_sub(m))),
            _ => None,
        },
        _ => None,
    }
}

/// Big-endian bytes of `n`, with leading zero bytes removed (CBOR bignums are
/// minimally encoded). Zero encodes as a single `0x00`.
fn trim_be(n: u128) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[first..].to_vec()
}

/// Big-endian byte string → `u128`. `None` when wider than 16 bytes.
fn be_to_u128(bytes: &[u8]) -> Option<u128> {
    // Leading zeros are permitted by the spec even though we never emit them.
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let significant = &bytes[start..];
    if significant.len() > 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    buf[16 - significant.len()..].copy_from_slice(significant);
    Some(u128::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(n: i128) {
        let encoded = to_value(n);
        assert_eq!(from_value(&encoded), Some(n), "round-trip failed for {n}");
    }

    #[test]
    fn native_range_stays_native() {
        for n in [
            0i128,
            1,
            -1,
            23,
            24,
            -24,
            i64::MAX as i128,
            i64::MIN as i128,
        ] {
            assert!(
                matches!(to_value(n), Value::Integer(_)),
                "{n} should be native"
            );
            roundtrip(n);
        }
    }

    #[test]
    fn wide_values_use_bignums() {
        // 10^38 - 1: the largest DECIMAL(38, s) mantissa.
        let big = 99_999_999_999_999_999_999_999_999_999_999_999_999i128;
        assert!(matches!(to_value(big), Value::Tag(2, _)));
        assert!(matches!(to_value(-big), Value::Tag(3, _)));
        roundtrip(big);
        roundtrip(-big);
        roundtrip(i128::MAX);
        roundtrip(i128::MIN);
    }

    #[test]
    fn bignums_are_minimally_encoded() {
        // 2^64 is the first value past the native range; its magnitude needs
        // exactly 9 bytes with no leading zero padding.
        let Value::Tag(2, inner) = to_value(1i128 << 64) else {
            panic!("expected a tag-2 bignum");
        };
        let Value::Bytes(bytes) = *inner else {
            panic!("expected a byte string");
        };
        assert_eq!(bytes, vec![1, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn leading_zeros_are_accepted_on_input() {
        let padded = Value::Tag(2, Box::new(Value::Bytes(vec![0, 0, 1])));
        assert_eq!(from_value(&padded), Some(1));
    }

    #[test]
    fn oversized_bignums_are_rejected_not_truncated() {
        let too_wide = Value::Tag(2, Box::new(Value::Bytes(vec![0xFF; 17])));
        assert_eq!(from_value(&too_wide), None);
    }

    #[test]
    fn non_integers_are_rejected() {
        assert_eq!(from_value(&Value::Text("1".into())), None);
        assert_eq!(
            from_value(&Value::Tag(2, Box::new(Value::Text("x".into())))),
            None
        );
    }
}
