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
                "Skip incompatible rows with warnings. On a decode error, discard that file's \
                 unreadable remainder and continue with the next source (default false). \
                 Source-open failures still fail the COPY.",
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
        let mut producer = self.open(ctx)?;
        let mut batches = Vec::new();
        while let Some(batch) = producer.next_batch(out)? {
            batches.push(batch);
        }
        Ok(batches)
    }

    fn read_stream(&self, ctx: &CopyFromReadContext) -> Result<Option<Box<dyn TableProducer>>> {
        // Streaming is always the right shape here: both decoders consume one
        // item per call, so a row file of any size costs one batch of memory.
        Ok(Some(self.open(ctx)?))
    }
}

impl CborCopyFrom {
    /// Build the producer; client warnings are emitted once its stream exists.
    fn open(&self, ctx: &CopyFromReadContext) -> Result<Box<dyn TableProducer>> {
        let format = self.wire.format();
        let shape = RowShape::parse(format, ctx.options.named_str("row_format"))?;
        let ignore_errors = ctx.options.named_bool("ignore_errors").unwrap_or(false);

        // A glob expands to every file it matches, in sorted order, so a COPY
        // over `data/*.cbor` reads them as one concatenated row stream. A
        // literal path yields exactly itself.
        let mut sources = cloud::resolve_locations(ctx.path, &ctx.params.secrets, &[])?;
        if sources.is_empty() {
            return Err(RpcError::value_error(format!(
                "{format}: '{}' matched no files",
                ctx.path
            )));
        }
        // The container-path warning is about the worker's filesystem, so it
        // applies to the local sources only; one is enough to make the point.
        let warning = match sources.first() {
            Some(Location::Local(first)) => location::misleading_path_warning(format, first),
            _ => None,
        };
        sources.reverse(); // pop() walks them in sorted order

        Ok(Box::new(RowProducer {
            pending: sources,
            items: None,
            source: String::new(),
            warning,
            secrets: ctx.params.secrets.clone(),
            schema: ctx.expected_schema.clone(),
            wire: self.wire,
            shape,
            ignore_errors,
        }))
    }
}

/// Decodes the source one item at a time, emitting a batch every
/// [`READ_BATCH_ROWS`] rows.
///
/// This is the whole point of the streaming path: peak memory is one batch plus
/// one 8 MiB range chunk, whatever the size of the row file.
struct RowProducer {
    /// Sources still to read, in reverse sorted order so `pop()` yields them in
    /// order. Opened one at a time — a 10,000-file glob costs one open handle.
    pending: Vec<Location>,
    /// The source currently being decoded, or `None` before the first open and
    /// between sources.
    items: Option<ItemReader>,
    source: String,
    warning: Option<String>,
    secrets: vgi::secrets::Secrets,
    schema: SchemaRef,
    wire: Wire,
    shape: RowShape,
    ignore_errors: bool,
}

impl RowProducer {
    /// Open the next source, or return `false` when they are all consumed.
    fn advance(&mut self) -> Result<bool> {
        let format = self.wire.format();
        let Some(next) = self.pending.pop() else {
            return Ok(false);
        };
        self.source = match &next {
            Location::Remote(url) => url.to_string(),
            Location::Local(path) => path.clone(),
        };
        let reader: Box<dyn BufRead + Send> = match next {
            Location::Remote(url) => Box::new(BufReader::new(cloud::open_reader(
                &url,
                &self.secrets,
                &[],
            )?)),
            Location::Local(path) => {
                let file = std::fs::File::open(&path)
                    .map_err(|e| location::path_error(format, "read", &path, &e))?;
                Box::new(BufReader::new(file))
            }
        };
        self.items = Some(self.wire.item_reader(reader));
        Ok(true)
    }

    /// The next row item across the whole source list, rolling on to the next
    /// file when one runs out.
    fn next_row(&mut self, warn: &mut impl FnMut(String)) -> Option<Result<Value>> {
        loop {
            if self.items.is_none() {
                match self.advance() {
                    Ok(true) => {}
                    Ok(false) => return None,
                    Err(e) => return Some(Err(e)),
                }
            }
            match self.items.as_mut().and_then(|r| r.next_item()) {
                Some(Ok(item)) => return Some(Ok(item)),
                Some(Err(e)) => {
                    self.items = None;
                    if self.ignore_errors {
                        warn(format!(
                            "{}: skipping the unreadable remainder of '{}': {e}; \
                             continuing with the next source",
                            self.wire.format(),
                            self.source
                        ));
                        continue;
                    }
                    return Some(Err(RpcError::value_error(format!(
                        "{}: {} decode failed in '{}' at {e} (set ignore_errors true to load \
                         the preceding rows and continue with the next source)",
                        self.wire.format(),
                        self.wire.label(),
                        self.source
                    ))));
                }
                None => self.items = None, // this source is done; try the next
            }
        }
    }
}

impl TableProducer for RowProducer {
    fn next_batch(&mut self, out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        let format = self.wire.format();
        if let Some(warning) = self.warning.take() {
            out.client_log(vgi_rpc::LogLevel::Warn, warning);
        }
        let mut rows: Vec<Value> = Vec::with_capacity(READ_BATCH_ROWS);
        let mut skipped_shapes = 0;

        while rows.len() < READ_BATCH_ROWS {
            let Some(next) =
                self.next_row(&mut |message| out.client_log(vgi_rpc::LogLevel::Warn, message))
            else {
                break;
            };
            // Opening a source (including credentials/network setup) must still
            // fail the COPY. Only decoded row errors are recoverable.
            let item = next?;
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
            } else {
                skipped_shapes += 1;
            }
        }

        if skipped_shapes > 0 {
            out.client_log(
                vgi_rpc::LogLevel::Warn,
                format!("{format}: skipped {skipped_shapes} rows with the wrong row_format"),
            );
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
                out.client_log(
                    vgi_rpc::LogLevel::Warn,
                    format!(
                        "{format}: skipped {} rows incompatible with the target column types",
                        refs.len() - kept.len()
                    ),
                );
                Ok(Some(build_batch(&self.schema, self.shape, &kept)?))
            }
            Err(e) => Err(e),
        }
    }

    fn resume_supported(&self) -> bool {
        // Not resumable: the position is an open decoder part-way through a
        // (possibly remote) byte stream, not a value that can travel. The SDK
        // COPY FROM wrapper (`vgi::copy_from`) declares `false` around this
        // producer anyway, so a resume cursor here would never be consulted.
        false
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn fixture_reader(wire: Wire, ignore_errors: bool) -> RowProducer {
        let ext = if wire == Wire::Cbor { "cbor" } else { "mp" };
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/data/copy-recovery");
        RowProducer {
            pending: (1..=3)
                .rev()
                .map(|i| {
                    Location::Local(root.join(format!("{i:02}.{ext}")).to_str().unwrap().into())
                })
                .collect(),
            items: None,
            source: String::new(),
            warning: None,
            secrets: Default::default(),
            schema: Arc::new(arrow_schema::Schema::empty()),
            wire,
            shape: RowShape::Map,
            ignore_errors,
        }
    }

    #[test]
    fn decode_recovery_keeps_later_files_and_reports_each_damaged_source() {
        for wire in [Wire::Cbor, Wire::Msgpack] {
            let mut reader = fixture_reader(wire, true);
            let mut warnings = Vec::new();
            let mut rows = Vec::new();
            while let Some(row) = reader.next_row(&mut |w| warnings.push(w)) {
                rows.push(row.unwrap());
            }
            let expected: Vec<_> = [1, 3]
                .into_iter()
                .map(|id| Value::Map(vec![(Value::Text("id".into()), Value::Integer(id.into()))]))
                .collect();
            assert_eq!(rows, expected);
            assert_eq!(warnings.len(), 2);
            assert!(warnings[0].contains("01."));
            assert!(warnings[1].contains("02."));
        }
    }

    #[test]
    fn strict_decode_reports_the_file_and_ignore_errors_still_rejects_missing_sources() {
        for wire in [Wire::Cbor, Wire::Msgpack] {
            let mut reader = fixture_reader(wire, false);
            let mut warnings = Vec::new();
            assert!(reader.next_row(&mut |w| warnings.push(w)).unwrap().is_ok());
            let error = reader
                .next_row(&mut |w| warnings.push(w))
                .unwrap()
                .unwrap_err();
            assert!(error.to_string().contains("01."));
            assert!(warnings.is_empty());

            let dir = tempfile::tempdir().unwrap();
            let mut reader = fixture_reader(wire, true);
            reader.pending.push(Location::Local(
                dir.path().join("missing.cbor").to_str().unwrap().into(),
            ));
            assert!(reader.next_row(&mut |w| warnings.push(w)).unwrap().is_err());
            assert!(warnings.is_empty());
        }
    }
}
