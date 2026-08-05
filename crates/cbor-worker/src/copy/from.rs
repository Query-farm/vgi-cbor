//! `COPY … FROM` readers for the `cbor` and `msgpack` formats.
//!
//! The source file is a bare concatenation of top-level items, one per row (a
//! CBOR Sequence / a MessagePack stream). Each item is projected onto the COPY
//! target's columns — by name for `row_format 'map'`, positionally for
//! `row_format 'array'` — and converted to the target's exact Arrow types by
//! [`crate::value_out`], because DuckDB inserts no cast between the scan and the
//! target table.

use std::io::{BufRead, BufReader};
use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::SchemaRef;
use ciborium::value::Value;
use vgi::copy_from::{CopyFromFunction, CopyFromReadContext};
use vgi::function::{ArgSpec, BindParams, FunctionMetadata};
use vgi::secrets::SecretLookup;
use vgi::table_function::TableProducer;
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::cloud::{self, Location};
use crate::copy::common::{
    format_metadata, row_format_arg, ItemReader, RowShape, Wire, READ_BATCH_ROWS,
};
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
        // The buffered contract, expressed through the streaming one so there is
        // a single decode path. Only reached if `read_stream` returned None,
        // which it never does here — kept correct rather than `unreachable!`.
        let mut producer = self.open(ctx, out)?;
        let mut batches = Vec::new();
        while let Some(batch) = producer.next_batch(out)? {
            batches.push(batch);
        }
        Ok(batches)
    }

    fn read_stream(&self, ctx: &CopyFromReadContext) -> Result<Option<Box<dyn TableProducer>>> {
        // Streaming is always the right shape here: both decoders consume one
        // item per call, so a row file of any size costs one batch of memory.
        // `out` is only needed for the container-path warning, which `open`
        // takes separately.
        let mut sink = None;
        Ok(Some(self.open_boxed(ctx, &mut sink)?))
    }
}

impl CborCopyFrom {
    /// Build the streaming producer for this call.
    fn open(
        &self,
        ctx: &CopyFromReadContext,
        out: &mut OutputCollector,
    ) -> Result<Box<dyn TableProducer>> {
        let mut warning = None;
        let producer = self.open_boxed(ctx, &mut warning)?;
        if let Some(w) = warning {
            out.client_log(vgi_rpc::LogLevel::Warn, w);
        }
        Ok(producer)
    }

    /// Open the source and wrap it in a [`RowProducer`].
    ///
    /// Any client-facing warning is handed back through `warning` rather than
    /// logged here, because `read_stream` has no `OutputCollector` — the
    /// producer is built before the stream exists.
    fn open_boxed(
        &self,
        ctx: &CopyFromReadContext,
        warning: &mut Option<String>,
    ) -> Result<Box<dyn TableProducer>> {
        let format = self.wire.format();
        let shape = RowShape::parse(format, ctx.options.named_str("row_format"))?;
        let ignore_errors = ctx.options.named_bool("ignore_errors").unwrap_or(false);

        // A remote source streams through the object store, so it works the same
        // wherever the worker runs; a local one is subject to the worker's own
        // filesystem, which is what the path diagnostics are about.
        let reader: Box<dyn BufRead + Send> = match cloud::classify(ctx.path)? {
            Location::Remote(url) => Box::new(BufReader::new(cloud::open_reader(
                &url,
                &ctx.params.secrets,
                &[],
            )?)),
            Location::Local(path) => {
                *warning = location::misleading_path_warning(format, &path);
                let file = std::fs::File::open(&path)
                    .map_err(|e| location::path_error(format, "read", &path, &e))?;
                Box::new(BufReader::new(file))
            }
        };

        Ok(Box::new(RowProducer {
            items: self.wire.item_reader(reader),
            schema: ctx.expected_schema.clone(),
            wire: self.wire,
            shape,
            ignore_errors,
            done: false,
        }))
    }
}

/// Decodes the source one item at a time, emitting a batch every
/// [`READ_BATCH_ROWS`] rows.
///
/// This is the whole point of the streaming path: peak memory is one batch plus
/// one 8 MiB range chunk, whatever the size of the row file.
struct RowProducer {
    items: ItemReader,
    schema: SchemaRef,
    wire: Wire,
    shape: RowShape,
    ignore_errors: bool,
    done: bool,
}

impl TableProducer for RowProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        let format = self.wire.format();
        let mut rows: Vec<Value> = Vec::with_capacity(READ_BATCH_ROWS);

        while rows.len() < READ_BATCH_ROWS {
            let Some(next) = self.items.next_item() else {
                self.done = true;
                break;
            };
            let item = match next {
                Ok(item) => item,
                Err(e) => {
                    self.done = true;
                    if self.ignore_errors {
                        break;
                    }
                    return Err(RpcError::value_error(format!(
                        "{format}: {} decode failed at {e} (set ignore_errors true to load the \
                         rows before it)",
                        self.wire.label()
                    )));
                }
            };
            // Drop a row that does not fit the declared shape before any type
            // conversion runs.
            let usable = match self.shape {
                RowShape::Map => matches!(item, Value::Map(_)),
                RowShape::Array => matches!(item, Value::Array(_)),
            };
            if usable {
                rows.push(item);
            } else if !self.ignore_errors {
                return Err(RpcError::value_error(format!(
                    "{format}: row_format '{}' expects every item to be {}, found one that is \
                     not (set ignore_errors true to skip it)",
                    match self.shape {
                        RowShape::Map => "map",
                        RowShape::Array => "array",
                    },
                    match self.shape {
                        RowShape::Map => "a map",
                        RowShape::Array => "an array",
                    }
                )));
            }
        }

        if rows.is_empty() {
            return Ok(None);
        }
        let refs: Vec<&Value> = rows.iter().collect();
        // Convert the batch at once — the fast path. Under ignore_errors a
        // failing batch is retried a row at a time so only genuinely bad rows
        // are dropped (one bad cell would otherwise fail its whole column).
        match build_batch(&self.schema, self.shape, &refs) {
            Ok(batch) => Ok(Some(batch)),
            Err(_) if self.ignore_errors => {
                let kept: Vec<&Value> = refs
                    .iter()
                    .copied()
                    .filter(|row| build_batch(&self.schema, self.shape, &[row]).is_ok())
                    .collect();
                Ok(Some(build_batch(&self.schema, self.shape, &kept)?))
            }
            Err(e) => Err(e),
        }
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
