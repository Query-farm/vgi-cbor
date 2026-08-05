//! Convert an Arrow input cell into a CBOR [`Value`] for the `encode` /
//! `msgpack_encode` and COPY-TO paths. STRUCT → string-keyed map, LIST → array,
//! BLOB → byte string, integers → shortest-lossless form.
//!
//! The temporal and decimal encodings are chosen for *exactness*, not brevity:
//! TIMESTAMP → tag 1 (an integer of seconds, or a tag-4 decimal fraction when
//! sub-second), DATE → tag 100 epoch days (RFC 8943), TIME → microseconds since
//! midnight, DECIMAL → a tag-4 decimal fraction carrying the unscaled integer.
//! Routing any of these through an f64 would silently drift.

use arrow_array::cast::AsArray;
use arrow_array::types::{
    Date32Type, Date64Type, Decimal128Type, Float32Type, Float64Type, Int16Type, Int32Type,
    Int64Type, Int8Type, Time32MillisecondType, Time32SecondType, Time64MicrosecondType,
    Time64NanosecondType, TimestampMicrosecondType, TimestampMillisecondType,
    TimestampNanosecondType, TimestampSecondType, UInt16Type, UInt32Type, UInt64Type, UInt8Type,
};
use arrow_array::{Array, ArrayRef};
use arrow_schema::{DataType, TimeUnit};
use cbor_core::codec::bignum;
use ciborium::value::Value;
use vgi_rpc::{Result, RpcError};

/// Milliseconds per day — the `Date64` (ms since epoch) → epoch-days conversion.
const MILLIS_PER_DAY: i64 = 86_400_000;

fn rt(e: impl std::fmt::Display) -> RpcError {
    RpcError::runtime_error(e.to_string())
}

/// Read element `row` of `array` as a CBOR [`Value`].
pub fn value_at(array: &ArrayRef, row: usize) -> Result<Value> {
    if array.is_null(row) {
        return Ok(Value::Null);
    }
    Ok(match array.data_type() {
        DataType::Null => Value::Null,
        DataType::Boolean => Value::Bool(array.as_boolean().value(row)),
        DataType::Int8 => {
            Value::Integer((array.as_primitive::<Int8Type>().value(row) as i64).into())
        }
        DataType::Int16 => {
            Value::Integer((array.as_primitive::<Int16Type>().value(row) as i64).into())
        }
        DataType::Int32 => {
            Value::Integer((array.as_primitive::<Int32Type>().value(row) as i64).into())
        }
        DataType::Int64 => Value::Integer(array.as_primitive::<Int64Type>().value(row).into()),
        DataType::UInt8 => {
            Value::Integer((array.as_primitive::<UInt8Type>().value(row) as u64).into())
        }
        DataType::UInt16 => {
            Value::Integer((array.as_primitive::<UInt16Type>().value(row) as u64).into())
        }
        DataType::UInt32 => {
            Value::Integer((array.as_primitive::<UInt32Type>().value(row) as u64).into())
        }
        DataType::UInt64 => Value::Integer(array.as_primitive::<UInt64Type>().value(row).into()),
        DataType::Float32 => Value::Float(array.as_primitive::<Float32Type>().value(row) as f64),
        DataType::Float64 => Value::Float(array.as_primitive::<Float64Type>().value(row)),
        // Tag 4 = decimal fraction (RFC 8949 §3.4.4): `[exponent, mantissa]`
        // denoting mantissa × 10^exponent. This keeps the unscaled integer
        // exactly — routing a DECIMAL through an f64 would silently round
        // anything past ~15 significant digits. A `DECIMAL(38, s)` mantissa
        // exceeds CBOR's native integer range, so it rides as a bignum.
        DataType::Decimal128(_, scale) => {
            let raw = array.as_primitive::<Decimal128Type>().value(row);
            Value::Tag(
                4,
                Box::new(Value::Array(vec![
                    Value::Integer((-(*scale as i64)).into()),
                    bignum::to_value(raw),
                ])),
            )
        }
        DataType::Utf8 => Value::Text(array.as_string::<i32>().value(row).to_string()),
        DataType::LargeUtf8 => Value::Text(array.as_string::<i64>().value(row).to_string()),
        DataType::Binary => Value::Bytes(array.as_binary::<i32>().value(row).to_vec()),
        DataType::LargeBinary => Value::Bytes(array.as_binary::<i64>().value(row).to_vec()),
        // Under `SET arrow_lossless_conversion = true` DuckDB hands the types
        // with no canonical Arrow match (HUGEINT, UUID, TIMETZ, …) across as
        // fixed-width binary carrying a `duckdb.type_name` extension, so
        // carrying the bytes through verbatim is what makes them round-trip.
        DataType::FixedSizeBinary(_) => {
            Value::Bytes(array.as_fixed_size_binary().value(row).to_vec())
        }
        // Tag 1 = epoch-based date/time (RFC 8949 §3.4.2), whose content is a
        // numerical value. A whole-second instant is a plain integer — compact,
        // and what every CBOR reader expects. A sub-second one is a tag-4 decimal
        // fraction (§3.4.4), which is also a numerical value and, unlike a float,
        // represents the epoch count *exactly*: `1e-6` has no finite binary
        // expansion, so float seconds silently drift once the instant needs more
        // than f64's 53 significant bits — from ~104 days past the epoch for a
        // nanosecond column.
        DataType::Timestamp(unit, _) => {
            let (raw, exponent) = timestamp_raw(array, row, *unit);
            let per_sec = 10i64.pow((-exponent) as u32);
            let inner = if raw % per_sec == 0 {
                Value::Integer((raw / per_sec).into())
            } else {
                Value::Tag(
                    4,
                    Box::new(Value::Array(vec![
                        Value::Integer((exponent as i64).into()),
                        bignum::to_value(raw as i128),
                    ])),
                )
            };
            Value::Tag(1, Box::new(inner))
        }
        // Tag 100 = days since the epoch (RFC 8943), the date-only counterpart to
        // tag 1 — a DATE carries no time, so encoding it as an instant would
        // invent a midnight that is not in the data.
        DataType::Date32 => Value::Tag(
            100,
            Box::new(Value::Integer(
                (array.as_primitive::<Date32Type>().value(row) as i64).into(),
            )),
        ),
        DataType::Date64 => Value::Tag(
            100,
            Box::new(Value::Integer(
                (array.as_primitive::<Date64Type>().value(row) / MILLIS_PER_DAY).into(),
            )),
        ),
        // Time-of-day has no registered CBOR tag, so it rides as a plain count of
        // microseconds since midnight; the reader is driven by the target column
        // type and converts back to the column's own unit.
        DataType::Time32(unit) => Value::Integer(
            match unit {
                TimeUnit::Second => {
                    array.as_primitive::<Time32SecondType>().value(row) as i64 * 1_000_000
                }
                _ => array.as_primitive::<Time32MillisecondType>().value(row) as i64 * 1_000,
            }
            .into(),
        ),
        DataType::Time64(unit) => Value::Integer(
            match unit {
                TimeUnit::Nanosecond => {
                    array.as_primitive::<Time64NanosecondType>().value(row) / 1_000
                }
                _ => array.as_primitive::<Time64MicrosecondType>().value(row),
            }
            .into(),
        ),
        DataType::List(_) => {
            let list = array.as_list::<i32>();
            let items = list.value(row);
            let mut out = Vec::with_capacity(items.len());
            for i in 0..items.len() {
                out.push(value_at(&items, i)?);
            }
            Value::Array(out)
        }
        DataType::LargeList(_) => {
            let list = array.as_list::<i64>();
            let items = list.value(row);
            let mut out = Vec::with_capacity(items.len());
            for i in 0..items.len() {
                out.push(value_at(&items, i)?);
            }
            Value::Array(out)
        }
        // DuckDB `ARRAY` (a fixed-length list, e.g. `INTEGER[3]`) encodes as an
        // ordinary CBOR array — the length is carried by the target column type,
        // so it needs no separate representation on the wire.
        DataType::FixedSizeList(_, _) => {
            let list = array.as_fixed_size_list();
            let items = list.value(row);
            let mut out = Vec::with_capacity(items.len());
            for i in 0..items.len() {
                out.push(value_at(&items, i)?);
            }
            Value::Array(out)
        }
        DataType::Struct(fields) => {
            let sa = array.as_struct();
            let mut pairs = Vec::with_capacity(fields.len());
            for (i, f) in fields.iter().enumerate() {
                pairs.push((
                    Value::Text(f.name().to_string()),
                    value_at(sa.column(i), row)?,
                ));
            }
            Value::Map(pairs)
        }
        DataType::Map(_, _) => {
            let ma = array.as_map();
            let entries = ma.value(row);
            let keys = entries.column(0);
            let vals = entries.column(1);
            let mut pairs = Vec::with_capacity(entries.len());
            for i in 0..entries.len() {
                pairs.push((value_at(keys, i)?, value_at(vals, i)?));
            }
            Value::Map(pairs)
        }
        other => return Err(rt(format!("encode: unsupported input type {other:?}"))),
    })
}

/// A timestamp cell as its raw count plus the base-10 exponent that turns that
/// count into seconds (e.g. microseconds → `-6`). Keeping the integer count and
/// its exponent — rather than a computed seconds value — is what lets the
/// encoder stay exact.
fn timestamp_raw(array: &ArrayRef, row: usize, unit: TimeUnit) -> (i64, i32) {
    match unit {
        TimeUnit::Second => (array.as_primitive::<TimestampSecondType>().value(row), 0),
        TimeUnit::Millisecond => (
            array.as_primitive::<TimestampMillisecondType>().value(row),
            -3,
        ),
        TimeUnit::Microsecond => (
            array.as_primitive::<TimestampMicrosecondType>().value(row),
            -6,
        ),
        TimeUnit::Nanosecond => (
            array.as_primitive::<TimestampNanosecondType>().value(row),
            -9,
        ),
    }
}
