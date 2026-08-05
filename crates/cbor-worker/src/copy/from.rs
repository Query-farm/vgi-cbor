//! `COPY … FROM` readers for the `cbor` and `msgpack` formats.
//!
//! The source file is a bare concatenation of top-level items, one per row (a
//! CBOR Sequence / a MessagePack stream). Each item is projected onto the COPY
//! target's columns — by name for `row_format 'map'`, positionally for
//! `row_format 'array'` — and converted to the target's exact Arrow types by
//! [`crate::value_out`], because DuckDB inserts no cast between the scan and the
//! target table.

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::SchemaRef;
use ciborium::value::Value;
use vgi::copy_from::{CopyFromFunction, CopyFromReadContext};
use vgi::function::{ArgSpec, BindParams, FunctionMetadata};
use vgi::secrets::SecretLookup;
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::cloud::{self, Location};
use crate::copy::common::{format_metadata, row_format_arg, RowShape, Wire, READ_BATCH_ROWS};
use crate::copy::location;
use crate::value_out::build_column;

/// A `COPY … FROM` reader for one wire format.
pub struct CborCopyFrom {
    wire: Wire,
}

impl CborCopyFrom {
    /// The `cbor` reader.
    pub fn cbor() -> Self {
        CborCopyFrom { wire: Wire::Cbor }
    }

    /// The `msgpack` reader.
    pub fn msgpack() -> Self {
        CborCopyFrom {
            wire: Wire::Msgpack,
        }
    }
}

impl CopyFromFunction for CborCopyFrom {
    fn format(&self) -> &str {
        self.wire.format()
    }

    // Shared with the writer for the same format — see `Wire::handler`.
    fn handler_name(&self) -> &str {
        self.wire.handler()
    }

    fn comment(&self) -> Option<String> {
        Some(format!(
            "Load a {} row file ({}) into the COPY target table",
            self.wire.label(),
            self.wire.framing()
        ))
    }

    fn metadata(&self) -> FunctionMetadata {
        // Shared with the writer: one format, one catalog object, one set of docs.
        format_metadata(self.wire)
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            row_format_arg(),
            ArgSpec::column(
                "ignore_errors",
                -1,
                "boolean",
                "Skip rows that cannot be projected onto the target columns, and accept a \
                 truncated trailing item, instead of failing the COPY (default false).",
            ),
        ]
    }

    fn secret_lookups(&self, params: &BindParams) -> Vec<SecretLookup> {
        // Ask for the DuckDB secret matching the COPY source, scoped to its URL,
        // when the source is a cloud path that needs credentials (s3://). The
        // two-phase secret bind resolves it into `ctx.params.secrets`.
        params
            .copy_from
            .as_ref()
            .and_then(|cf| cloud::secret_lookup(&cf.file_path))
            .into_iter()
            .collect()
    }

    fn read(
        &self,
        ctx: &CopyFromReadContext,
        out: &mut OutputCollector,
    ) -> Result<Vec<RecordBatch>> {
        let format = self.wire.format();
        let shape = RowShape::parse(format, ctx.options.named_str("row_format"))?;
        let ignore_errors = ctx.options.named_bool("ignore_errors").unwrap_or(false);

        // A remote source is read through the object store, so it works the same
        // wherever the worker runs; a local one is subject to the worker's own
        // filesystem, which is what the path diagnostics are about.
        let bytes = match cloud::classify(ctx.path)? {
            Location::Remote(url) => cloud::read_object(&url, &ctx.params.secrets, &[])?,
            Location::Local(path) => {
                if let Some(warning) = location::misleading_path_warning(format, &path) {
                    out.client_log(vgi_rpc::LogLevel::Warn, warning);
                }
                std::fs::read(&path).map_err(|e| location::path_error(format, "read", &path, &e))?
            }
        };

        let (items, tail_error) = self.wire.parse_rows(&bytes);
        if let Some(e) = tail_error {
            if !ignore_errors {
                return Err(RpcError::value_error(format!(
                    "{format}: {} decode failed at {e} (set ignore_errors true to load the \
                     {} row(s) before it)",
                    self.wire.label(),
                    items.len()
                )));
            }
        }

        let schema = ctx.expected_schema.clone();
        let mut batches = Vec::new();

        for chunk in items.chunks(READ_BATCH_ROWS) {
            // Project each row item onto the target columns first, so a row that
            // does not fit the declared shape can be dropped under ignore_errors
            // before any type conversion runs.
            let mut rows: Vec<&Value> = Vec::with_capacity(chunk.len());
            for item in chunk {
                let usable = match shape {
                    RowShape::Map => matches!(item, Value::Map(_)),
                    RowShape::Array => matches!(item, Value::Array(_)),
                };
                if usable {
                    rows.push(item);
                } else if !ignore_errors {
                    return Err(RpcError::value_error(format!(
                        "{format}: row_format '{}' expects every item to be {}, found one that \
                         is not (set ignore_errors true to skip it)",
                        match shape {
                            RowShape::Map => "map",
                            RowShape::Array => "array",
                        },
                        match shape {
                            RowShape::Map => "a map",
                            RowShape::Array => "an array",
                        }
                    )));
                }
            }

            // Convert the whole chunk at once — the fast path. Under
            // ignore_errors, a chunk that fails is retried a row at a time so
            // only the rows that genuinely cannot be represented are dropped
            // (one bad cell would otherwise fail its column, and with it every
            // other row in the chunk).
            let batch = match build_batch(&schema, shape, &rows) {
                Ok(batch) => batch,
                Err(_) if ignore_errors => {
                    let kept: Vec<&Value> = rows
                        .iter()
                        .copied()
                        .filter(|row| build_batch(&schema, shape, &[row]).is_ok())
                        .collect();
                    build_batch(&schema, shape, &kept)?
                }
                Err(e) => return Err(e),
            };
            batches.push(batch);
        }

        Ok(batches)
    }
}

/// Project `rows` onto `schema` and build one `RecordBatch`. Every row must
/// already match `shape`; a value that cannot be represented in its target
/// column is an error naming that column.
fn build_batch(schema: &SchemaRef, shape: RowShape, rows: &[&Value]) -> Result<RecordBatch> {
    let fields = schema.fields();
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(fields.len());
    for (idx, field) in fields.iter().enumerate() {
        let per_row: Vec<Value> = rows
            .iter()
            .map(|row| match (shape, *row) {
                (RowShape::Map, Value::Map(entries)) => entries
                    .iter()
                    .find(|(k, _)| matches!(k, Value::Text(t) if t == field.name()))
                    .map(|(_, v)| v.clone())
                    .unwrap_or(Value::Null),
                (RowShape::Array, Value::Array(items)) => {
                    items.get(idx).cloned().unwrap_or(Value::Null)
                }
                _ => Value::Null,
            })
            .collect();
        columns.push(build_column(field.name(), field, &per_row)?);
    }
    RecordBatch::try_new(Arc::clone(schema), columns)
        .map_err(|e| RpcError::runtime_error(format!("build batch: {e}")))
}
