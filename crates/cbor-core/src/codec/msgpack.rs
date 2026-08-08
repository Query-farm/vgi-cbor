//! MessagePack mirror of the CBOR codec: decode to JSON, transcode to CBOR, and
//! encode. `ext` types surface as `{ext_type, data}`; the reserved timestamp ext
//! (type −1, 32/64/96-bit) decodes to an RFC 3339 instant.
//!
//! Instants cross the formats as that reserved ext in both directions — CBOR
//! tag 1 ⇄ msgpack ext −1 — so a timestamp stays a *timestamp* to any msgpack
//! reader instead of decaying to a bare number, and its nanoseconds survive.

use ciborium::value::Value as Cbor;
use rmpv::Value as Mp;
use serde_json::{Map as JsonMap, Number, Value as Json};

use crate::codec::json::b64url;

/// MessagePack's reserved extension type for an instant.
const TIMESTAMP_EXT: i8 = -1;

/// CBOR tag 2 — a non-negative arbitrary-precision integer (RFC 8949 §3.4.3).
/// Mirrored as the MessagePack `ext` code of the same number.
const BIGNUM_POS: u64 = 2;
/// CBOR tag 3 — a negative arbitrary-precision integer, wrapping `-1 - n`.
const BIGNUM_NEG: u64 = 3;

/// Decode MessagePack bytes into an `rmpv::Value`.
pub fn parse(bytes: &[u8]) -> Result<Mp, String> {
    let mut cur = bytes;
    let value = rmpv::decode::read_value(&mut cur).map_err(|e| format!("msgpack decode: {e}"))?;
    if !cur.is_empty() {
        return Err("trailing bytes after the top-level msgpack item".to_string());
    }
    Ok(value)
}

/// The outcome of parsing a concatenated MessagePack stream.
#[derive(Debug, Clone, Default)]
pub struct StreamParse {
    /// The items decoded before the stream ended or went bad.
    pub items: Vec<Mp>,
    /// Set when decoding stopped early: the failure that ended the stream.
    /// `None` means every byte was consumed by a complete item.
    pub error: Option<String>,
}

/// Decode a concatenation of zero or more top-level MessagePack items — the
/// msgpack analogue of a CBOR Sequence (RFC 8742), and the on-disk shape the
/// `msgpack` COPY format uses (one item per row). Stops at the first item that
/// fails to decode, returning everything parsed so far plus the error that ended
/// it.
pub fn parse_stream(bytes: &[u8]) -> StreamParse {
    let mut cur = bytes;
    let mut items = Vec::new();
    while !cur.is_empty() {
        let before = cur.len();
        match rmpv::decode::read_value(&mut cur) {
            Ok(value) => {
                items.push(value);
                // Guard against a zero-advance loop on a pathological reader.
                if cur.len() == before {
                    return StreamParse {
                        items,
                        error: Some("stream reader made no progress".to_string()),
                    };
                }
            }
            Err(e) => {
                let error = Some(format!("item {}: {e}", items.len()));
                return StreamParse { items, error };
            }
        }
    }
    StreamParse { items, error: None }
}

/// Pull one item at a time from a concatenated MessagePack stream — the msgpack
/// counterpart of [`crate::seq::SeqReader`], and the same `BufRead` contract:
/// end-of-stream is checked before each decode so a truncated final item is
/// reported rather than mistaken for a clean end.
pub struct StreamReader<R: std::io::BufRead> {
    reader: R,
    done: bool,
    index: usize,
}

impl<R: std::io::BufRead> StreamReader<R> {
    /// Wrap a reader positioned at the start of a MessagePack stream.
    pub fn new(reader: R) -> Self {
        StreamReader {
            reader,
            done: false,
            index: 0,
        }
    }

    /// The next item, as a CBOR [`Cbor`] value (the shared value model).
    pub fn next_item(&mut self) -> Option<Result<Cbor, String>> {
        if self.done {
            return None;
        }
        match self.reader.fill_buf() {
            Ok([]) => {
                self.done = true;
                return None;
            }
            Ok(_) => {}
            Err(e) => {
                self.done = true;
                return Some(Err(format!("item {}: {e}", self.index)));
            }
        }
        match rmpv::decode::read_value(&mut self.reader) {
            Ok(value) => {
                self.index += 1;
                Some(Ok(mp_to_cbor(&value)))
            }
            Err(e) => {
                self.done = true;
                Some(Err(format!("item {}: {e}", self.index)))
            }
        }
    }
}

/// Encode an `rmpv::Value` to MessagePack bytes.
pub fn encode_value(v: &Mp) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, v).map_err(|e| format!("msgpack encode: {e}"))?;
    Ok(out)
}

/// Convert a CBOR `Value` into an `rmpv::Value` — the inverse of [`mp_to_cbor`],
/// used by the `msgpack_encode` scalar and the `msgpack` COPY-TO writer.
///
/// MessagePack has no tag concept, so a tagged value is replaced by its content.
/// The bignum tags (2 and 3) are the exception: they survive as an `ext` under
/// the same code, because their payloads are identical and only the tag carries
/// the sign. Integers too wide for `u64`/`i64` degrade to a float.
pub fn cbor_to_mp(v: &Cbor) -> Mp {
    match v {
        Cbor::Null => Mp::Nil,
        Cbor::Bool(b) => Mp::Boolean(*b),
        Cbor::Integer(i) => {
            let n = i128::from(*i);
            if let Ok(u) = u64::try_from(n) {
                Mp::Integer(u.into())
            } else if let Ok(s) = i64::try_from(n) {
                Mp::Integer(s.into())
            } else {
                Mp::F64(n as f64)
            }
        }
        Cbor::Float(f) => Mp::F64(*f),
        Cbor::Text(s) => Mp::String(s.clone().into()),
        Cbor::Bytes(b) => Mp::Binary(b.clone()),
        Cbor::Array(items) => Mp::Array(items.iter().map(cbor_to_mp).collect()),
        Cbor::Map(entries) => Mp::Map(
            entries
                .iter()
                .map(|(k, val)| (cbor_to_mp(k), cbor_to_mp(val)))
                .collect(),
        ),
        // Tag 1 (epoch instant) becomes MessagePack's own reserved timestamp
        // ext, so the value stays a *timestamp* to any msgpack reader rather
        // than decaying to a bare number. Nanoseconds survive: the 64/96-bit
        // forms carry them, which the previous tag-dropping path could not.
        Cbor::Tag(1, inner) => match instant_parts(inner) {
            Some((secs, nanos)) => Mp::Ext(TIMESTAMP_EXT, encode_timestamp(secs, nanos)),
            None => cbor_to_mp(inner),
        },
        // Bignums (tags 2/3) keep their identity as a MessagePack `ext` under the
        // same code. Dropping to the bare byte string like every other tag would
        // erase the sign — tag 2 and tag 3 wrap identical payloads and differ
        // only in the tag — which silently corrupts a wide DECIMAL.
        Cbor::Tag(tag @ (BIGNUM_POS | BIGNUM_NEG), inner) => match inner.as_ref() {
            Cbor::Bytes(b) => Mp::Ext(*tag as i8, b.clone()),
            other => cbor_to_mp(other),
        },
        Cbor::Tag(_, inner) => cbor_to_mp(inner),
        _ => Mp::Nil,
    }
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
            if *ty == TIMESTAMP_EXT {
                if let Some((secs, nanos)) = decode_timestamp(data) {
                    // CBOR tag 1 = epoch-based date/time. A whole second stays a
                    // compact integer; a sub-second instant rides as a tag-4
                    // decimal fraction so the nanoseconds survive exactly — the
                    // old code discarded them.
                    let inner = if nanos == 0 {
                        Cbor::Integer(secs.into())
                    } else {
                        let total = secs as i128 * 1_000_000_000 + nanos as i128;
                        Cbor::Tag(
                            4,
                            Box::new(Cbor::Array(vec![
                                Cbor::Integer((-9i64).into()),
                                crate::codec::bignum::to_value(total),
                            ])),
                        )
                    };
                    return Cbor::Tag(1, Box::new(inner));
                }
            }
            // The inverse of the bignum mapping in `cbor_to_mp`.
            if *ty == BIGNUM_POS as i8 || *ty == BIGNUM_NEG as i8 {
                return Cbor::Tag(*ty as u64, Box::new(Cbor::Bytes(data.clone())));
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

/// Encode an instant as the reserved timestamp ext payload, in the narrowest of
/// the three spec formats that holds it — the inverse of [`decode_timestamp`].
///
/// * 32-bit (4 bytes) — whole seconds inside `u32`.
/// * 64-bit (8 bytes) — `nanos << 34 | secs`, for seconds inside 34 bits.
/// * 96-bit (12 bytes) — `u32` nanos then `i64` seconds; covers everything else,
///   including pre-epoch instants, which the shorter forms cannot represent.
pub fn encode_timestamp(secs: i64, nanos: u32) -> Vec<u8> {
    if nanos == 0 && (0..=u32::MAX as i64).contains(&secs) {
        return (secs as u32).to_be_bytes().to_vec();
    }
    if (0..(1i64 << 34)).contains(&secs) {
        let packed = ((nanos as u64) << 34) | (secs as u64);
        return packed.to_be_bytes().to_vec();
    }
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&nanos.to_be_bytes());
    out.extend_from_slice(&secs.to_be_bytes());
    out
}

/// Split a CBOR tag-1 payload into `(seconds, nanos)`.
///
/// Accepts every form the encoder emits: an integer count of seconds, a tag-4
/// decimal fraction (the exact sub-second form), and a float (whatever a lossy
/// producer sent). `None` if the content is not numeric.
fn instant_parts(inner: &Cbor) -> Option<(i64, u32)> {
    const NANOS_PER_SEC: i128 = 1_000_000_000;
    // Exact: a decimal fraction, scaled to whole nanoseconds.
    if let Some((mantissa, exponent)) = decimal_parts(inner) {
        let shift = exponent + 9;
        let total = if shift >= 0 {
            mantissa.checked_mul(10i128.checked_pow(shift as u32)?)?
        } else {
            mantissa / 10i128.checked_pow((-shift) as u32)?
        };
        let secs = i64::try_from(total.div_euclid(NANOS_PER_SEC)).ok()?;
        return Some((secs, total.rem_euclid(NANOS_PER_SEC) as u32));
    }
    match inner {
        Cbor::Integer(i) => Some((i64::try_from(i128::from(*i)).ok()?, 0)),
        Cbor::Float(f) if f.is_finite() => {
            let secs = f.floor();
            let nanos = ((f - secs) * 1e9).round().clamp(0.0, 999_999_999.0) as u32;
            Some((secs as i64, nanos))
        }
        _ => None,
    }
}

/// The `(mantissa, exponent)` of a CBOR tag-4 decimal fraction, or the bare
/// `[exponent, mantissa]` array a tagless format degrades it to.
fn decimal_parts(v: &Cbor) -> Option<(i128, i32)> {
    let parts = match v {
        Cbor::Tag(4, inner) => match inner.as_ref() {
            Cbor::Array(parts) => parts,
            _ => return None,
        },
        Cbor::Array(parts) => parts,
        _ => return None,
    };
    if parts.len() != 2 {
        return None;
    }
    let exponent = i32::try_from(crate::codec::bignum::from_value(&parts[0])?).ok()?;
    Some((crate::codec::bignum::from_value(&parts[1])?, exponent))
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

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    /// CBOR tag 1 → msgpack ext → CBOR tag 1, comparing the instant itself
    /// rather than the encoding (whole seconds ride as an integer, sub-second
    /// as a decimal fraction).
    fn roundtrip(secs: i64, nanos: u32) {
        let encoded = Mp::Ext(TIMESTAMP_EXT, encode_timestamp(secs, nanos));
        let back = mp_to_cbor(&encoded);
        let Cbor::Tag(1, inner) = &back else {
            panic!("expected a tag-1 instant, got {back:?}");
        };
        assert_eq!(
            instant_parts(inner),
            Some((secs, nanos)),
            "instant {secs}.{nanos:09} did not survive the ext round-trip"
        );
    }

    #[test]
    fn whole_seconds_use_the_compact_32_bit_form() {
        assert_eq!(encode_timestamp(1_363_896_240, 0).len(), 4);
        roundtrip(1_363_896_240, 0);
        roundtrip(0, 0);
    }

    #[test]
    fn sub_second_instants_keep_their_nanoseconds() {
        // The bug this replaced: nanos were decoded and then thrown away.
        roundtrip(1_363_896_240, 123_456_789);
        roundtrip(0, 1);
        roundtrip(1, 999_999_999);
    }

    #[test]
    fn pre_epoch_instants_use_the_96_bit_form() {
        // Negative seconds do not fit the 32- or 64-bit layouts.
        assert_eq!(encode_timestamp(-1, 0).len(), 12);
        roundtrip(-1, 0);
        roundtrip(-2_208_988_800, 500_000_000); // 1900-01-01 with a half second
    }

    #[test]
    fn a_tag_1_instant_becomes_a_timestamp_ext_not_a_bare_number() {
        // What the `msgpack_encode` docs always promised.
        let cbor = Cbor::Tag(1, Box::new(Cbor::Integer(1_363_896_240i64.into())));
        match cbor_to_mp(&cbor) {
            Mp::Ext(TIMESTAMP_EXT, payload) => assert_eq!(payload.len(), 4),
            other => panic!("expected a timestamp ext, got {other:?}"),
        }
    }

    #[test]
    fn a_sub_second_decimal_fraction_survives_the_whole_way() {
        // The COPY writer's form: tag 1 wrapping a tag-4 decimal fraction.
        let cbor = Cbor::Tag(
            1,
            Box::new(Cbor::Tag(
                4,
                Box::new(Cbor::Array(vec![
                    Cbor::Integer((-6i64).into()),
                    Cbor::Integer(1_363_896_240_123_456i64.into()),
                ])),
            )),
        );
        let Mp::Ext(TIMESTAMP_EXT, payload) = cbor_to_mp(&cbor) else {
            panic!("expected a timestamp ext");
        };
        let back = mp_to_cbor(&Mp::Ext(TIMESTAMP_EXT, payload));
        let Cbor::Tag(1, inner) = &back else {
            panic!("expected a tag-1 instant");
        };
        assert_eq!(instant_parts(inner), Some((1_363_896_240, 123_456_000)));
    }

    #[test]
    fn an_unencodable_tag_1_payload_falls_back_to_its_content() {
        let cbor = Cbor::Tag(1, Box::new(Cbor::Text("not an instant".into())));
        assert_eq!(cbor_to_mp(&cbor), Mp::String("not an instant".into()));
    }
}
