//! Arrow input/output helpers shared across the scalar and table functions:
//! reading a BLOB/VARCHAR input cell, the shared STRUCT schemas (COSE header,
//! COSE_Key), and small column builders.

use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, BooleanBuilder, StringBuilder, TimestampMicrosecondBuilder, UInt64Builder,
};
use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef, ListArray, StructArray};
use arrow_buffer::{NullBuffer, OffsetBuffer, ScalarBuffer};
use arrow_schema::{DataType, Field, Fields, TimeUnit};
use cbor_core::security::cose::CoseHeaders;
use cbor_core::security::cose_key::CoseKeyInfo;
use vgi_rpc::{Result, RpcError};

/// The Arrow type used for DuckDB `JSON` columns — we publish JSON as VARCHAR
/// carrying canonical JSON text (DuckDB casts it to JSON on demand).
pub fn json_type() -> DataType {
    DataType::Utf8
}

/// `TIMESTAMPTZ` — microsecond UTC timestamp.
pub fn ts_type() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
}

/// Borrow the raw bytes of a BLOB/VARCHAR input cell at `row`, or `None` if null.
pub fn blob_bytes(col: &ArrayRef, row: usize) -> Result<Option<&[u8]>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Binary => col.as_binary::<i32>().value(row),
        DataType::LargeBinary => col.as_binary::<i64>().value(row),
        DataType::Utf8 => col.as_string::<i32>().value(row).as_bytes(),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row).as_bytes(),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a BLOB or VARCHAR argument, got {other:?}"
            )))
        }
    }))
}

/// Build a nullable VARCHAR column from per-row optional strings.
pub fn string_array(col: &[Option<String>]) -> ArrayRef {
    let mut b = StringBuilder::new();
    for v in col {
        match v {
            Some(s) => b.append_value(s),
            None => b.append_null(),
        }
    }
    Arc::new(b.finish())
}

/// Build a nullable BLOB column from per-row optional byte vectors.
pub fn binary_array(col: &[Option<Vec<u8>>]) -> ArrayRef {
    let mut b = BinaryBuilder::new();
    for v in col {
        match v {
            Some(bytes) => b.append_value(bytes),
            None => b.append_null(),
        }
    }
    Arc::new(b.finish())
}

/// Build a nullable BOOLEAN column.
pub fn bool_opt_array(col: &[Option<bool>]) -> ArrayRef {
    let mut b = BooleanBuilder::new();
    for v in col {
        match v {
            Some(x) => b.append_value(*x),
            None => b.append_null(),
        }
    }
    Arc::new(b.finish())
}

/// Build a nullable `TIMESTAMPTZ` column from per-row epoch seconds.
pub fn ts_array(col: &[Option<i64>]) -> ArrayRef {
    let mut b = TimestampMicrosecondBuilder::new();
    for v in col {
        match v {
            Some(secs) => b.append_value(secs.saturating_mul(1_000_000)),
            None => b.append_null(),
        }
    }
    Arc::new(b.finish().with_timezone("UTC"))
}

/// Build a nullable UBIGINT column.
pub fn u64_opt_array(col: &[Option<u64>]) -> ArrayRef {
    let mut b = UInt64Builder::new();
    for v in col {
        match v {
            Some(x) => b.append_value(*x),
            None => b.append_null(),
        }
    }
    Arc::new(b.finish())
}

/// Build a nullable UINTEGER column.
pub fn u32_opt_array(col: &[Option<u32>]) -> ArrayRef {
    let mut b = arrow_array::builder::UInt32Builder::new();
    for v in col {
        match v {
            Some(x) => b.append_value(*x),
            None => b.append_null(),
        }
    }
    Arc::new(b.finish())
}

/// Build a nullable `LIST<BLOB>` column from per-row optional lists of byte
/// vectors. A `None` row is a NULL list; a `Some(empty)` row is an empty list.
pub fn list_binary_array(col: &[Option<Vec<Vec<u8>>>]) -> ArrayRef {
    let item = Arc::new(Field::new("item", DataType::Binary, true));
    let mut flat: Vec<Option<Vec<u8>>> = Vec::new();
    let mut offsets: Vec<i32> = vec![0];
    let mut valid: Vec<bool> = Vec::with_capacity(col.len());
    let mut total = 0i32;
    for v in col {
        match v {
            Some(items) => {
                for it in items {
                    flat.push(Some(it.clone()));
                }
                total += items.len() as i32;
                valid.push(true);
            }
            None => valid.push(false),
        }
        offsets.push(total);
    }
    let child = binary_array(&flat);
    Arc::new(ListArray::new(
        item,
        OffsetBuffer::new(ScalarBuffer::from(offsets)),
        child,
        Some(NullBuffer::from(valid)),
    ))
}

/// The COSE header STRUCT fields (used by `cose_decode` and `cose_headers`).
pub fn header_fields() -> Fields {
    Fields::from(vec![
        Field::new("alg", DataType::Utf8, true),
        Field::new("crit", json_type(), true),
        Field::new("content_type", DataType::Utf8, true),
        Field::new("kid", DataType::Binary, true),
        Field::new("iv", DataType::Binary, true),
        Field::new(
            "x5chain",
            DataType::List(Arc::new(Field::new("item", DataType::Binary, true))),
            true,
        ),
        Field::new(
            "x5t",
            DataType::Struct(Fields::from(vec![
                Field::new("hash_alg", DataType::Utf8, true),
                Field::new("thumbprint", DataType::Binary, true),
            ])),
            true,
        ),
    ])
}

/// Build a non-null STRUCT array of COSE headers, one element per row.
pub fn header_array(col: &[CoseHeaders]) -> ArrayRef {
    let alg: Vec<Option<String>> = col.iter().map(|h| h.alg.clone()).collect();
    let crit: Vec<Option<String>> = col.iter().map(|h| h.crit.clone()).collect();
    let ct: Vec<Option<String>> = col.iter().map(|h| h.content_type.clone()).collect();
    let kid: Vec<Option<Vec<u8>>> = col.iter().map(|h| h.kid.clone()).collect();
    let iv: Vec<Option<Vec<u8>>> = col.iter().map(|h| h.iv.clone()).collect();
    let x5chain: Vec<Option<Vec<Vec<u8>>>> = col.iter().map(|h| h.x5chain.clone()).collect();

    let x5t_hash: Vec<Option<String>> = col
        .iter()
        .map(|h| h.x5t.as_ref().map(|(a, _)| a.clone()))
        .collect();
    let x5t_thumb: Vec<Option<Vec<u8>>> = col
        .iter()
        .map(|h| h.x5t.as_ref().map(|(_, t)| t.clone()))
        .collect();
    let x5t_valid: Vec<bool> = col.iter().map(|h| h.x5t.is_some()).collect();
    let x5t_fields = Fields::from(vec![
        Field::new("hash_alg", DataType::Utf8, true),
        Field::new("thumbprint", DataType::Binary, true),
    ]);
    let x5t = StructArray::new(
        x5t_fields,
        vec![string_array(&x5t_hash), binary_array(&x5t_thumb)],
        Some(NullBuffer::from(x5t_valid)),
    );

    let arrays: Vec<ArrayRef> = vec![
        string_array(&alg),
        string_array(&crit),
        string_array(&ct),
        binary_array(&kid),
        binary_array(&iv),
        list_binary_array(&x5chain),
        Arc::new(x5t),
    ];
    Arc::new(StructArray::new(header_fields(), arrays, None))
}

/// Build a STRUCT array of COSE headers with per-row nullability (`None` → NULL).
pub fn header_array_opt(col: &[Option<CoseHeaders>]) -> ArrayRef {
    let defaults: Vec<CoseHeaders> = col.iter().map(|h| h.clone().unwrap_or_default()).collect();
    let inner = header_array(&defaults);
    let struct_arr = inner.as_any().downcast_ref::<StructArray>().unwrap();
    let valid: Vec<bool> = col.iter().map(|h| h.is_some()).collect();
    let (fields, arrays, _) = struct_arr.clone().into_parts();
    Arc::new(StructArray::new(
        fields,
        arrays,
        Some(NullBuffer::from(valid)),
    ))
}

/// The COSE_Key STRUCT fields (used by `cose_key` and the WebAuthn decoders).
pub fn cose_key_fields() -> Fields {
    Fields::from(vec![
        Field::new("kty", DataType::Utf8, true),
        Field::new("kid", DataType::Binary, true),
        Field::new("alg", DataType::Utf8, true),
        Field::new("crv", DataType::Utf8, true),
        Field::new("x", DataType::Binary, true),
        Field::new("y", DataType::Binary, true),
        Field::new("n", DataType::Binary, true),
        Field::new("e", DataType::Binary, true),
    ])
}

/// Build a STRUCT array of COSE_Key info, one element per row. `None` → NULL row.
pub fn cose_key_array(col: &[Option<CoseKeyInfo>]) -> ArrayRef {
    let g = |f: fn(&CoseKeyInfo) -> Option<String>| -> Vec<Option<String>> {
        col.iter().map(|k| k.as_ref().and_then(f)).collect()
    };
    let gb = |f: fn(&CoseKeyInfo) -> Option<Vec<u8>>| -> Vec<Option<Vec<u8>>> {
        col.iter().map(|k| k.as_ref().and_then(f)).collect()
    };
    let arrays: Vec<ArrayRef> = vec![
        string_array(&g(|k| k.kty.clone())),
        binary_array(&gb(|k| k.kid.clone())),
        string_array(&g(|k| k.alg.clone())),
        string_array(&g(|k| k.crv.clone())),
        binary_array(&gb(|k| k.x.clone())),
        binary_array(&gb(|k| k.y.clone())),
        binary_array(&gb(|k| k.n.clone())),
        binary_array(&gb(|k| k.e.clone())),
    ];
    let valid: Vec<bool> = col.iter().map(|k| k.is_some()).collect();
    Arc::new(StructArray::new(
        cose_key_fields(),
        arrays,
        Some(NullBuffer::from(valid)),
    ))
}
