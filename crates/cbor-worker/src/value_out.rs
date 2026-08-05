//! Convert decoded CBOR [`Value`]s into a typed Arrow column — the inverse of
//! [`crate::value_in`], and the half of the COPY-FROM path that lands parsed
//! rows on the target table's exact schema.
//!
//! DuckDB inserts no cast between a COPY-FROM scan and the target table, so the
//! emitted batch must match the target column types precisely. Every conversion
//! is therefore driven by the *target* [`DataType`], not by the shape of the
//! incoming value: numeric targets accept CBOR integers and floats, `VARCHAR`
//! accepts any value (non-text renders as JSON), `BLOB` accepts byte strings,
//! `TIMESTAMP` accepts an epoch instant (tag 1 wrapping an integer count of
//! seconds or a tag-4 decimal fraction), `DECIMAL` a tag-4 decimal fraction,
//! `DATE` a day count (tag 100, RFC 8943), `TIME` a microsecond count since
//! midnight, and the nested `LIST` / `STRUCT` / `MAP` targets recurse.
//!
//! The decimal-fraction forms are what keep `DECIMAL` and sub-second timestamps
//! *exact*: a float cannot represent either without drift.
//!
//! CBOR `null` — and, for `STRUCT`, an absent key — becomes SQL `NULL`. Semantic
//! tags are transparent for scalar targets: the tagged content is converted, so a
//! `TIMESTAMP` written as tag 1 by `encode` reads back unchanged.

use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, BooleanBuilder, Decimal128Builder, FixedSizeBinaryBuilder, LargeBinaryBuilder,
    LargeStringBuilder, PrimitiveBuilder, StringBuilder,
};
use arrow_array::types::{
    Date32Type, Float32Type, Float64Type, Int16Type, Int32Type, Int64Type, Int8Type,
    Time32MillisecondType, Time32SecondType, Time64MicrosecondType, Time64NanosecondType,
    TimestampMicrosecondType, TimestampMillisecondType, TimestampNanosecondType,
    TimestampSecondType, UInt16Type, UInt32Type, UInt64Type, UInt8Type,
};
use arrow_array::{ArrayRef, ArrowPrimitiveType, ListArray, MapArray, NullArray, StructArray};
use arrow_buffer::{NullBuffer, OffsetBuffer};
use arrow_schema::{DataType, Field, TimeUnit};
use cbor_core::codec::bignum;
use ciborium::value::Value;
use vgi_rpc::{Result, RpcError};

/// Seconds per day — the `DATE` (days since epoch) ⇄ epoch-seconds conversion.
const SECS_PER_DAY: i64 = 86_400;

fn err(path: &str, msg: impl std::fmt::Display) -> RpcError {
    RpcError::value_error(format!("column {path}: {msg}"))
}

/// The DuckDB name for a target column type, so a COPY error names the type the
/// user actually wrote in `CREATE TABLE` rather than its Arrow spelling.
fn sql_type(dt: &DataType) -> String {
    match dt {
        DataType::Boolean => "BOOLEAN".into(),
        DataType::Int8 => "TINYINT".into(),
        DataType::Int16 => "SMALLINT".into(),
        DataType::Int32 => "INTEGER".into(),
        DataType::Int64 => "BIGINT".into(),
        DataType::UInt8 => "UTINYINT".into(),
        DataType::UInt16 => "USMALLINT".into(),
        DataType::UInt32 => "UINTEGER".into(),
        DataType::UInt64 => "UBIGINT".into(),
        DataType::Float32 => "FLOAT".into(),
        DataType::Float64 => "DOUBLE".into(),
        DataType::Utf8 | DataType::LargeUtf8 => "VARCHAR".into(),
        DataType::Binary | DataType::LargeBinary => "BLOB".into(),
        DataType::FixedSizeBinary(n) => format!("a {n}-byte fixed-width value"),
        DataType::Date32 | DataType::Date64 => "DATE".into(),
        DataType::Time32(_) | DataType::Time64(_) => "TIME".into(),
        DataType::Timestamp(_, Some(_)) => "TIMESTAMPTZ".into(),
        DataType::Timestamp(_, None) => "TIMESTAMP".into(),
        DataType::Decimal128(p, s) => format!("DECIMAL({p},{s})"),
        DataType::List(_) | DataType::LargeList(_) => "LIST".into(),
        DataType::Struct(_) => "STRUCT".into(),
        DataType::Map(_, _) => "MAP".into(),
        DataType::Null => "NULL".into(),
        other => other.to_string(),
    }
}

/// A short, non-exploding label for a value, for type-mismatch messages.
fn describe(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Integer(_) => "an integer",
        Value::Float(_) => "a float",
        Value::Text(_) => "a text string",
        Value::Bytes(_) => "a byte string",
        Value::Array(_) => "an array",
        Value::Map(_) => "a map",
        Value::Tag(_, _) => "a tagged value",
        _ => "an unsupported value",
    }
}

/// Strip semantic tags down to the tagged content. Scalar targets treat tags as
/// transparent, so a tag-1 instant or a tagged bignum converts like its content.
fn untag(v: &Value) -> &Value {
    let mut cur = v;
    while let Value::Tag(_, inner) = cur {
        cur = inner;
    }
    cur
}

/// True when the value means SQL `NULL` (CBOR `null` or `undefined`).
fn is_null(v: &Value) -> bool {
    matches!(untag(v), Value::Null) || matches!(v, Value::Null)
}

fn as_i128(v: &Value) -> Option<i128> {
    match untag(v) {
        Value::Integer(i) => Some(i128::from(*i)),
        // An integral float (e.g. a JSON-sourced 3.0) is accepted for an integer
        // target; a fractional one is not, so precision is never silently lost.
        Value::Float(f) if f.fract() == 0.0 && f.is_finite() => Some(*f as i128),
        _ => None,
    }
}

/// The `(mantissa, exponent)` of a decimal fraction — CBOR tag 4 (RFC 8949
/// §3.4.4) or, since MessagePack has no tags, the bare `[exponent, mantissa]`
/// array it degrades to. `None` for anything else.
fn decimal_parts(v: &Value) -> Option<(i128, i32)> {
    let parts = match v {
        Value::Tag(4, inner) => match inner.as_ref() {
            Value::Array(parts) => parts,
            _ => return None,
        },
        Value::Array(parts) => parts,
        _ => return None,
    };
    if parts.len() != 2 {
        return None;
    }
    let exponent = i32::try_from(bignum::from_value(&parts[0])?).ok()?;
    Some((bignum::from_value(&parts[1])?, exponent))
}

fn as_f64(v: &Value) -> Option<f64> {
    // A decimal fraction is a number too: a DECIMAL column exported here and
    // loaded into a DOUBLE one must still land, just with float precision.
    if let Some((mantissa, exponent)) = decimal_parts(v) {
        return Some(mantissa as f64 * 10f64.powi(exponent));
    }
    match untag(v) {
        Value::Float(f) => Some(*f),
        Value::Integer(i) => Some(i128::from(*i) as f64),
        _ => None,
    }
}

/// Build a nullable primitive column from a per-row integer extractor.
fn build_int<T, F>(path: &str, values: &[Value], to_native: F) -> Result<ArrayRef>
where
    T: ArrowPrimitiveType,
    F: Fn(i128) -> Option<T::Native>,
{
    let mut b = PrimitiveBuilder::<T>::with_capacity(values.len());
    for v in values {
        if is_null(v) {
            b.append_null();
            continue;
        }
        let raw = as_i128(v).ok_or_else(|| {
            err(
                path,
                format!(
                    "expected an integer for {}, got {}",
                    sql_type(&T::DATA_TYPE),
                    describe(v)
                ),
            )
        })?;
        let native = to_native(raw).ok_or_else(|| {
            err(
                path,
                format!("{raw} is out of range for {}", sql_type(&T::DATA_TYPE)),
            )
        })?;
        b.append_value(native);
    }
    Ok(Arc::new(b.finish()))
}

/// Build a nullable primitive column from a per-row float extractor.
fn build_float<T, F>(path: &str, values: &[Value], to_native: F) -> Result<ArrayRef>
where
    T: ArrowPrimitiveType,
    F: Fn(f64) -> T::Native,
{
    let mut b = PrimitiveBuilder::<T>::with_capacity(values.len());
    for v in values {
        if is_null(v) {
            b.append_null();
            continue;
        }
        let raw = as_f64(v).ok_or_else(|| {
            err(
                path,
                format!(
                    "expected a number for {}, got {}",
                    sql_type(&T::DATA_TYPE),
                    describe(v)
                ),
            )
        })?;
        b.append_value(to_native(raw));
    }
    Ok(Arc::new(b.finish()))
}

/// Rescale `mantissa × 10^exponent` to the target's fixed `scale`, i.e. to the
/// unscaled integer Arrow stores. Rejects a value that would lose digits rather
/// than rounding it away.
fn rescale(path: &str, mantissa: i128, exponent: i32, scale: i8, dt: &DataType) -> Result<i128> {
    let shift = exponent + scale as i32;
    if shift >= 0 {
        // Scaling up: exact as long as it does not overflow.
        let factor = 10i128.checked_pow(shift as u32).ok_or_else(|| {
            err(
                path,
                format!("exponent {exponent} is out of range for {}", sql_type(dt)),
            )
        })?;
        mantissa.checked_mul(factor).ok_or_else(|| {
            err(
                path,
                format!("{mantissa}e{exponent} overflows {}", sql_type(dt)),
            )
        })
    } else {
        // Scaling down: only exact when the dropped digits are all zero.
        let factor = 10i128.checked_pow((-shift) as u32).ok_or_else(|| {
            err(
                path,
                format!("exponent {exponent} is out of range for {}", sql_type(dt)),
            )
        })?;
        if mantissa % factor != 0 {
            return Err(err(
                path,
                format!(
                    "{mantissa}e{exponent} needs more than {scale} fractional digits for {}",
                    sql_type(dt)
                ),
            ));
        }
        Ok(mantissa / factor)
    }
}

/// Read one cell as the unscaled integer of a `DECIMAL(_, scale)` column.
///
/// The exact forms are a CBOR tag-4 decimal fraction and — because MessagePack
/// has no tags — the bare `[exponent, mantissa]` array it degrades to. A plain
/// integer is taken at face value. A float is accepted last, for values that
/// arrived from JSON or another lossy producer; it is the only inexact path.
fn decimal_at(path: &str, v: &Value, scale: i8, dt: &DataType) -> Result<i128> {
    if let Some((mantissa, exponent)) = decimal_parts(v) {
        return rescale(path, mantissa, exponent, scale, dt);
    }

    // A bare integer (possibly a bignum) is an exact whole number.
    if let Some(n) = bignum::from_value(v) {
        return rescale(path, n, 0, scale, dt);
    }

    // Last resort: a float. Inherently inexact past ~15 significant digits.
    let raw = as_f64(v).ok_or_else(|| {
        err(
            path,
            format!(
                "expected a decimal fraction, integer, or number for {}, got {}",
                sql_type(dt),
                describe(v)
            ),
        )
    })?;
    let scaled = (raw * 10f64.powi(scale as i32)).round();
    if !scaled.is_finite() || scaled.abs() >= 1.7014118346046923e38 {
        return Err(err(
            path,
            format!("{raw} is out of range for {}", sql_type(dt)),
        ));
    }
    Ok(scaled as i128)
}

/// Build a `TIME` column from per-row microseconds-since-midnight, rescaled to
/// the target's unit by `to_native`.
fn build_time<T, F>(path: &str, values: &[Value], to_native: F) -> Result<ArrayRef>
where
    T: ArrowPrimitiveType,
    F: Fn(i128) -> Option<T::Native>,
{
    let mut b = PrimitiveBuilder::<T>::with_capacity(values.len());
    for v in values {
        if is_null(v) {
            b.append_null();
            continue;
        }
        let us = as_i128(v).ok_or_else(|| {
            err(
                path,
                format!(
                    "expected microseconds since midnight for TIME, got {}",
                    describe(v)
                ),
            )
        })?;
        let native =
            to_native(us).ok_or_else(|| err(path, format!("{us} is out of range for TIME")))?;
        b.append_value(native);
    }
    Ok(Arc::new(b.finish()))
}

/// Convert one epoch instant to a count in `unit`.
///
/// Accepts the exact forms the encoder emits — a tag-1 integer number of
/// seconds, and a tag-1 decimal fraction (or, since MessagePack drops tags, the
/// bare `[exponent, mantissa]` array) — plus a plain float for instants that
/// came from JSON or another lossy producer.
fn timestamp_at(path: &str, v: &Value, unit: TimeUnit, dt: &DataType) -> Result<i64> {
    // How many of `unit` make a second, as a base-10 exponent.
    let unit_exp: i8 = match unit {
        TimeUnit::Second => 0,
        TimeUnit::Millisecond => 3,
        TimeUnit::Microsecond => 6,
        TimeUnit::Nanosecond => 9,
    };

    // Strip the tag-1 wrapper, if present, to reach the numeric content.
    let inner = match v {
        Value::Tag(1, boxed) => boxed.as_ref(),
        other => other,
    };

    // Exact paths: a decimal fraction, or a whole number of seconds.
    if let Some((mantissa, exponent)) = decimal_parts(inner) {
        let scaled = rescale(path, mantissa, exponent, unit_exp, dt)?;
        return i64::try_from(scaled).map_err(|_| {
            err(
                path,
                format!("epoch instant is out of range for {}", sql_type(dt)),
            )
        });
    }
    if let Some(secs) = bignum::from_value(inner) {
        let scaled = rescale(path, secs, 0, unit_exp, dt)?;
        return i64::try_from(scaled).map_err(|_| {
            err(
                path,
                format!("epoch instant {secs}s is out of range for {}", sql_type(dt)),
            )
        });
    }

    // Inexact fallback: a float number of seconds.
    let secs = as_f64(inner).ok_or_else(|| {
        err(
            path,
            format!(
                "expected an epoch instant (CBOR tag 1, a decimal fraction, or a number of \
                 seconds) for {}, got {}",
                sql_type(dt),
                describe(v)
            ),
        )
    })?;
    let scale = 10f64.powi(unit_exp as i32);
    let scaled = (secs * scale).round();
    // `i64::MAX as f64` rounds *up* to exactly 2^63, so comparing against it
    // lets 2^63 through and `as i64` then saturates — silently turning an
    // out-of-range instant into i64::MAX, which DuckDB renders as `infinity`.
    // Bound against 2^63 itself (exact in f64) so the overflow is refused.
    const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
    if !scaled.is_finite() || !(-TWO_POW_63..TWO_POW_63).contains(&scaled) {
        return Err(err(
            path,
            format!("epoch instant {secs} is out of range for {}", sql_type(dt)),
        ));
    }
    Ok(scaled as i64)
}

/// Build the Arrow column of type `field.data_type()` holding one element per
/// entry of `values`. Fails with a column-qualified message when a value cannot
/// be represented in the target type.
pub fn build_column(path: &str, field: &Field, values: &[Value]) -> Result<ArrayRef> {
    let dt = field.data_type();
    Ok(match dt {
        DataType::Null => Arc::new(NullArray::new(values.len())),

        DataType::Boolean => {
            let mut b = BooleanBuilder::with_capacity(values.len());
            for v in values {
                if is_null(v) {
                    b.append_null();
                } else if let Value::Bool(x) = untag(v) {
                    b.append_value(*x);
                } else {
                    return Err(err(
                        path,
                        format!("expected a boolean for BOOLEAN, got {}", describe(v)),
                    ));
                }
            }
            Arc::new(b.finish())
        }

        DataType::Int8 => build_int::<Int8Type, _>(path, values, |n| i8::try_from(n).ok())?,
        DataType::Int16 => build_int::<Int16Type, _>(path, values, |n| i16::try_from(n).ok())?,
        DataType::Int32 => build_int::<Int32Type, _>(path, values, |n| i32::try_from(n).ok())?,
        DataType::Int64 => build_int::<Int64Type, _>(path, values, |n| i64::try_from(n).ok())?,
        DataType::UInt8 => build_int::<UInt8Type, _>(path, values, |n| u8::try_from(n).ok())?,
        DataType::UInt16 => build_int::<UInt16Type, _>(path, values, |n| u16::try_from(n).ok())?,
        DataType::UInt32 => build_int::<UInt32Type, _>(path, values, |n| u32::try_from(n).ok())?,
        DataType::UInt64 => build_int::<UInt64Type, _>(path, values, |n| u64::try_from(n).ok())?,

        DataType::Float32 => build_float::<Float32Type, _>(path, values, |f| f as f32)?,
        DataType::Float64 => build_float::<Float64Type, _>(path, values, |f| f)?,

        // `DATE` is days since the epoch. `encode` never emits a DATE (there is
        // no CBOR date type in the value model), so accept both the RFC 8943
        // tag-1004/100 "days" convention (a bare integer after untagging) and a
        // tag-1 epoch-seconds instant, which is what a TIMESTAMP round-trip
        // would produce if the target column is a DATE.
        DataType::Date32 => {
            let mut b = PrimitiveBuilder::<Date32Type>::with_capacity(values.len());
            for v in values {
                if is_null(v) {
                    b.append_null();
                    continue;
                }
                let days = match v {
                    Value::Tag(1, _) => {
                        timestamp_at(path, v, TimeUnit::Second, dt)?.div_euclid(SECS_PER_DAY)
                    }
                    _ => as_i128(v).ok_or_else(|| {
                        err(
                            path,
                            format!(
                                "expected a day count or epoch instant for DATE, got {}",
                                describe(v)
                            ),
                        )
                    })? as i64,
                };
                let days = i32::try_from(days)
                    .map_err(|_| err(path, format!("{days} is out of range for DATE")))?;
                b.append_value(days);
            }
            Arc::new(b.finish())
        }

        // Time-of-day rides as a count of microseconds since midnight (see
        // `value_in`), rescaled here into the target column's own unit.
        DataType::Time32(TimeUnit::Second) => {
            build_time::<Time32SecondType, _>(path, values, |us| {
                i32::try_from(us / 1_000_000).ok()
            })?
        }
        DataType::Time32(_) => build_time::<Time32MillisecondType, _>(path, values, |us| {
            i32::try_from(us / 1_000).ok()
        })?,
        DataType::Time64(TimeUnit::Nanosecond) => {
            build_time::<Time64NanosecondType, _>(path, values, |us| {
                i64::try_from(us).ok()?.checked_mul(1_000)
            })?
        }
        DataType::Time64(_) => {
            build_time::<Time64MicrosecondType, _>(path, values, |us| i64::try_from(us).ok())?
        }

        DataType::Timestamp(unit, tz) => {
            macro_rules! ts {
                ($t:ty) => {{
                    let mut b = PrimitiveBuilder::<$t>::with_capacity(values.len());
                    for v in values {
                        if is_null(v) {
                            b.append_null();
                        } else {
                            b.append_value(timestamp_at(path, v, *unit, dt)?);
                        }
                    }
                    Arc::new(b.finish().with_timezone_opt(tz.clone())) as ArrayRef
                }};
            }
            match unit {
                TimeUnit::Second => ts!(TimestampSecondType),
                TimeUnit::Millisecond => ts!(TimestampMillisecondType),
                TimeUnit::Microsecond => ts!(TimestampMicrosecondType),
                TimeUnit::Nanosecond => ts!(TimestampNanosecondType),
            }
        }

        DataType::Decimal128(precision, scale) => {
            let mut b = Decimal128Builder::with_capacity(values.len());
            for v in values {
                if is_null(v) {
                    b.append_null();
                    continue;
                }
                b.append_value(decimal_at(path, v, *scale, dt)?);
            }
            Arc::new(
                b.finish()
                    .with_precision_and_scale(*precision, *scale)
                    .map_err(|e| err(path, e))?,
            )
        }

        // VARCHAR takes text verbatim; anything else renders as its canonical
        // JSON, so a nested value still lands losslessly in a text column.
        DataType::Utf8 => {
            let mut b = StringBuilder::new();
            for v in values {
                match text_of(v) {
                    Some(s) => b.append_value(s),
                    None => b.append_null(),
                }
            }
            Arc::new(b.finish())
        }
        DataType::LargeUtf8 => {
            let mut b = LargeStringBuilder::new();
            for v in values {
                match text_of(v) {
                    Some(s) => b.append_value(s),
                    None => b.append_null(),
                }
            }
            Arc::new(b.finish())
        }

        // BLOB takes a CBOR byte string; a text string is accepted as its UTF-8
        // bytes so a VARCHAR-sourced column still round-trips into a BLOB.
        DataType::Binary => {
            let mut b = BinaryBuilder::new();
            for v in values {
                match bytes_of(path, v)? {
                    Some(bytes) => b.append_value(bytes),
                    None => b.append_null(),
                }
            }
            Arc::new(b.finish())
        }
        DataType::LargeBinary => {
            let mut b = LargeBinaryBuilder::new();
            for v in values {
                match bytes_of(path, v)? {
                    Some(bytes) => b.append_value(bytes),
                    None => b.append_null(),
                }
            }
            Arc::new(b.finish())
        }

        // The fixed-width binary DuckDB uses for HUGEINT / UUID / TIMETZ / … under
        // `SET arrow_lossless_conversion = true`. The width is part of the target
        // type, so a payload of the wrong length is a data error, not a cast.
        DataType::FixedSizeBinary(width) => {
            let n = *width as usize;
            let mut b = FixedSizeBinaryBuilder::with_capacity(values.len(), *width);
            for v in values {
                match bytes_of(path, v)? {
                    None => b.append_null(),
                    Some(bytes) if bytes.len() == n => {
                        b.append_value(bytes).map_err(|e| err(path, e))?
                    }
                    Some(bytes) => {
                        return Err(err(
                            path,
                            format!(
                                "expected exactly {n} bytes for {}, got {}",
                                sql_type(dt),
                                bytes.len()
                            ),
                        ))
                    }
                }
            }
            Arc::new(b.finish())
        }

        // DuckDB `ARRAY` — a list whose length is fixed by the column type. Every
        // row must carry exactly `size` elements (a null row contributes `size`
        // null children, which is how Arrow lays a null fixed-size list out).
        DataType::FixedSizeList(child, size) => {
            let n = *size as usize;
            let mut flat: Vec<Value> = Vec::with_capacity(values.len() * n);
            for v in values {
                if is_null(v) {
                    flat.extend(std::iter::repeat_n(Value::Null, n));
                    continue;
                }
                match untag(v) {
                    Value::Array(items) if items.len() == n => flat.extend(items.iter().cloned()),
                    Value::Array(items) => {
                        return Err(err(
                            path,
                            format!(
                                "expected exactly {n} elements for {}, got {}",
                                sql_type(dt),
                                items.len()
                            ),
                        ))
                    }
                    other => {
                        return Err(err(
                            path,
                            format!(
                                "expected an array for {}, got {}",
                                sql_type(dt),
                                describe(other)
                            ),
                        ))
                    }
                }
            }
            let child_array = build_column(&format!("{path}[]"), child, &flat)?;
            Arc::new(
                arrow_array::FixedSizeListArray::try_new(
                    child.clone(),
                    *size,
                    child_array,
                    null_buffer(values),
                )
                .map_err(|e| err(path, e))?,
            )
        }

        DataType::List(child) => {
            let (offsets, nulls, flat) = flatten_lists(path, values)?;
            let child_path = format!("{path}[]");
            let child_array = build_column(&child_path, child, &flat)?;
            Arc::new(
                ListArray::try_new(child.clone(), offsets, child_array, nulls)
                    .map_err(|e| err(path, e))?,
            )
        }

        DataType::Struct(fields) => {
            let mut columns: Vec<ArrayRef> = Vec::with_capacity(fields.len());
            for f in fields {
                // Pull this field's value out of every row's map; an absent key
                // (or a null / non-map row) contributes NULL.
                let per_row: Vec<Value> = values
                    .iter()
                    .map(|v| match untag(v) {
                        Value::Map(entries) => entries
                            .iter()
                            .find(|(k, _)| matches!(untag(k), Value::Text(t) if t == f.name()))
                            .map(|(_, val)| val.clone())
                            .unwrap_or(Value::Null),
                        _ => Value::Null,
                    })
                    .collect();
                let child_path = format!("{path}.{}", f.name());
                columns.push(build_column(&child_path, f, &per_row)?);
            }
            // Reject a present-but-wrong-shaped row rather than silently
            // all-NULLing it; a genuinely null row is fine.
            for v in values {
                if !is_null(v) && !matches!(untag(v), Value::Map(_)) {
                    return Err(err(
                        path,
                        format!("expected a map for STRUCT, got {}", describe(v)),
                    ));
                }
            }
            let nulls = null_buffer(values);
            Arc::new(
                StructArray::try_new(fields.clone(), columns, nulls).map_err(|e| err(path, e))?,
            )
        }

        DataType::Map(entry_field, sorted) => {
            let DataType::Struct(entry_fields) = entry_field.data_type() else {
                return Err(err(path, "MAP entries are not a struct"));
            };
            let mut offsets: Vec<i32> = Vec::with_capacity(values.len() + 1);
            offsets.push(0);
            let mut keys: Vec<Value> = Vec::new();
            let mut vals: Vec<Value> = Vec::new();
            for v in values {
                if !is_null(v) {
                    match untag(v) {
                        Value::Map(entries) => {
                            for (k, val) in entries {
                                keys.push(k.clone());
                                vals.push(val.clone());
                            }
                        }
                        other => {
                            return Err(err(
                                path,
                                format!("expected a map for MAP, got {}", describe(other)),
                            ))
                        }
                    }
                }
                offsets.push(keys.len() as i32);
            }
            let key_field = &entry_fields[0];
            let val_field = &entry_fields[1];
            let key_array = build_column(&format!("{path}.key"), key_field, &keys)?;
            let val_array = build_column(&format!("{path}.value"), val_field, &vals)?;
            let entries =
                StructArray::try_new(entry_fields.clone(), vec![key_array, val_array], None)
                    .map_err(|e| err(path, e))?;
            Arc::new(
                MapArray::try_new(
                    entry_field.clone(),
                    OffsetBuffer::new(offsets.into()),
                    entries,
                    null_buffer(values),
                    *sorted,
                )
                .map_err(|e| err(path, e))?,
            )
        }

        other => {
            return Err(err(
                path,
                format!(
                    "unsupported target column type {} for COPY FROM",
                    sql_type(other)
                ),
            ))
        }
    })
}

/// The text form of a value for a `VARCHAR` target: text verbatim, anything else
/// as canonical JSON. `None` for SQL `NULL`.
fn text_of(v: &Value) -> Option<String> {
    if is_null(v) {
        return None;
    }
    match untag(v) {
        Value::Text(s) => Some(s.clone()),
        other => Some(cbor_core::codec::json::to_json_value(other).to_string()),
    }
}

/// The bytes for a `BLOB` target: a byte string verbatim, a text string as its
/// UTF-8 bytes. `None` for SQL `NULL`.
fn bytes_of<'a>(path: &str, v: &'a Value) -> Result<Option<&'a [u8]>> {
    if is_null(v) {
        return Ok(None);
    }
    match untag(v) {
        Value::Bytes(b) => Ok(Some(b.as_slice())),
        Value::Text(s) => Ok(Some(s.as_bytes())),
        other => Err(err(
            path,
            format!("expected a byte string for BLOB, got {}", describe(other)),
        )),
    }
}

/// The validity mask for a column: a row is null when its value is CBOR null.
/// `None` when every row is valid (Arrow's cheaper representation).
fn null_buffer(values: &[Value]) -> Option<NullBuffer> {
    if values.iter().any(is_null) {
        Some(NullBuffer::from_iter(values.iter().map(|v| !is_null(v))))
    } else {
        None
    }
}

/// Flatten per-row arrays into (offsets, validity, concatenated elements).
type Flattened = (OffsetBuffer<i32>, Option<NullBuffer>, Vec<Value>);
fn flatten_lists(path: &str, values: &[Value]) -> Result<Flattened> {
    let mut offsets: Vec<i32> = Vec::with_capacity(values.len() + 1);
    offsets.push(0);
    let mut flat: Vec<Value> = Vec::new();
    for v in values {
        if !is_null(v) {
            match untag(v) {
                Value::Array(items) => flat.extend(items.iter().cloned()),
                other => {
                    return Err(err(
                        path,
                        format!("expected an array for LIST, got {}", describe(other)),
                    ))
                }
            }
        }
        offsets.push(flat.len() as i32);
    }
    Ok((OffsetBuffer::new(offsets.into()), null_buffer(values), flat))
}
