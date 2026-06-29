//! Convert an Arrow input cell into a CBOR [`Value`] for the `encode` /
//! `msgpack_encode` paths. STRUCT → string-keyed map, LIST → array, TIMESTAMP →
//! tag 1 (epoch), BLOB → byte string, numeric → shortest-lossless integer/float.

use arrow_array::cast::AsArray;
use arrow_array::types::{
    Decimal128Type, Float32Type, Float64Type, Int16Type, Int32Type, Int64Type, Int8Type,
    TimestampMicrosecondType, TimestampMillisecondType, TimestampNanosecondType,
    TimestampSecondType, UInt16Type, UInt32Type, UInt64Type, UInt8Type,
};
use arrow_array::{Array, ArrayRef};
use arrow_schema::{DataType, TimeUnit};
use ciborium::value::Value;
use vgi_rpc::{Result, RpcError};

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
        DataType::Decimal128(_, scale) => {
            let raw = array.as_primitive::<Decimal128Type>().value(row);
            Value::Float(raw as f64 / 10f64.powi(*scale as i32))
        }
        DataType::Utf8 => Value::Text(array.as_string::<i32>().value(row).to_string()),
        DataType::LargeUtf8 => Value::Text(array.as_string::<i64>().value(row).to_string()),
        DataType::Binary => Value::Bytes(array.as_binary::<i32>().value(row).to_vec()),
        DataType::LargeBinary => Value::Bytes(array.as_binary::<i64>().value(row).to_vec()),
        DataType::Timestamp(unit, _) => {
            let secs = timestamp_seconds(array, row, *unit);
            Value::Tag(1, Box::new(Value::Integer(secs.into())))
        }
        DataType::List(_) => {
            let list = array.as_list::<i32>();
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

fn timestamp_seconds(array: &ArrayRef, row: usize, unit: TimeUnit) -> i64 {
    match unit {
        TimeUnit::Second => array.as_primitive::<TimestampSecondType>().value(row),
        TimeUnit::Millisecond => {
            array.as_primitive::<TimestampMillisecondType>().value(row) / 1_000
        }
        TimeUnit::Microsecond => {
            array.as_primitive::<TimestampMicrosecondType>().value(row) / 1_000_000
        }
        TimeUnit::Nanosecond => {
            array.as_primitive::<TimestampNanosecondType>().value(row) / 1_000_000_000
        }
    }
}
