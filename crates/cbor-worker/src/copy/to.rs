//! `COPY … TO` writers for the `cbor` and `msgpack` formats.
//!
//! The destination is a bare concatenation of top-level items, one per row (a
//! CBOR Sequence / a MessagePack stream) — the exact shape the matching reader
//! consumes, so `COPY … TO` then `COPY … FROM` round-trips.
//!
//! Both writers declare [`CopyToFunction::ordered`] = `true`, so DuckDB installs
//! a single-thread sink and one worker sees every batch in source order: a row
//! file's order is part of its content, and `COPY (SELECT … ORDER BY …) TO` must
//! preserve it. `write()` still persists each batch to `execution_id`-scoped
//! storage rather than buffering on `self`, because the sink and the terminal
//! `close()` may land on different worker processes.

use std::io::Write;

use arrow_array::RecordBatch;
use cbor_core::codec::encode;
use ciborium::value::Value;
use vgi::copy_to::{CopyToCloseContext, CopyToFunction, CopyToWriteContext};
use vgi::function::{ArgSpec, BindParams, FunctionMetadata};
use vgi::ipc;
use vgi::secrets::SecretLookup;
use vgi_rpc::{Result, RpcError};

use crate::cloud::{self, Location};
use crate::copy::common::{format_metadata, parse_canonical, row_format_arg, RowShape, Wire};
use crate::copy::location;
use crate::value_in::value_at;

/// Append-only shard namespace (execution-scoped). Each `write()` appends one
/// IPC-serialized input batch; `close()` reads them back in append order.
const SHARD_NS: &[u8] = b"cbor_copy_to_shard";

/// A `COPY … TO` writer for one wire format.
pub struct CborCopyTo {
    wire: Wire,
}

impl CborCopyTo {
    /// The `cbor` writer.
    pub fn cbor() -> Self {
        CborCopyTo { wire: Wire::Cbor }
    }

    /// The `msgpack` writer.
    pub fn msgpack() -> Self {
        CborCopyTo {
            wire: Wire::Msgpack,
        }
    }

    /// Resolve and validate the COPY options up front, so a bad option fails on
    /// the first sink batch rather than at the terminal write.
    fn parse_options(&self, options: &vgi::arguments::Arguments) -> Result<Options> {
        let shape = RowShape::parse(self.wire.format(), options.named_str("row_format"))?;
        let canonical = match self.wire {
            Wire::Cbor => parse_canonical(options.named_str("canonical"))?,
            Wire::Msgpack => None,
        };
        Ok(Options { shape, canonical })
    }
}

/// Resolved + validated COPY options.
struct Options {
    shape: RowShape,
    canonical: Option<encode::Canon>,
}

impl CopyToFunction for CborCopyTo {
    fn format(&self) -> &str {
        self.wire.format()
    }

    // Shares the reader's handler name: a format registered for both directions
    // advertises one handler, which the extension hands to the reader (table)
    // and writer (buffering) registries alike.
    fn handler_name(&self) -> &str {
        self.wire.handler()
    }

    fn comment(&self) -> Option<String> {
        Some(format!(
            "Write the COPY source rows to a {} row file ({})",
            self.wire.label(),
            self.wire.framing()
        ))
    }

    fn metadata(&self) -> FunctionMetadata {
        // Shared with the reader: one format, one catalog object, one set of docs.
        format_metadata(self.wire)
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![row_format_arg()];
        if self.wire == Wire::Cbor {
            specs.push(ArgSpec::column(
                "canonical",
                -1,
                "varchar",
                "Deterministic map-key ordering to apply: 'core' (RFC 8949 §4.2.1) or 'ctap2'. \
                 Unset keeps ciborium's shortest-form output with keys in column order.",
            ));
        }
        specs
    }

    fn secret_lookups(&self, params: &BindParams) -> Vec<SecretLookup> {
        // Same as the reader, scoped to the COPY destination.
        params
            .copy_to
            .as_ref()
            .and_then(|ct| cloud::secret_lookup(&ct.file_path))
            .into_iter()
            .collect()
    }

    fn ordered(&self) -> bool {
        // A row file's order is part of its content: keep the source order so
        // `COPY (SELECT … ORDER BY …) TO` writes what the user asked for.
        true
    }

    fn write(&self, ctx: &CopyToWriteContext, batch: &RecordBatch) -> Result<()> {
        // Validate eagerly so a bad option surfaces on the first batch.
        self.parse_options(ctx.options)?;
        // Buffer the batch as an IPC blob in execution-scoped storage; `append`
        // is atomic and preserves order, and survives worker-pool rotation.
        let blob = ipc::write_batch(batch)?;
        ctx.storage.append(ctx.execution_id, SHARD_NS, b"", blob);
        Ok(())
    }

    fn close(&self, ctx: &CopyToCloseContext) -> Result<i64> {
        let format = self.wire.format();
        let opts = self.parse_options(ctx.options)?;

        // A pattern names a set, and a write needs exactly one file. Without
        // this the `*` becomes a literal filename character and the COPY
        // "succeeds" into a file nobody will look for.
        if cloud::is_glob(ctx.path) {
            return Err(RpcError::value_error(format!(
                "{format}: '{}' looks like a glob, but COPY … TO writes a single file — \
                 give one destination path",
                ctx.path
            )));
        }
        let destination = cloud::classify(ctx.path)?;
        let mut sink = match &destination {
            Location::Remote(url) => {
                Sink::Remote(cloud::open_writer(url, &ctx.params.secrets, &[])?)
            }
            Location::Local(path) => {
                // Warn before writing: a relative destination inside a container
                // lands in the image's ephemeral filesystem, so the COPY
                // "succeeds" and the file is nowhere the caller can reach.
                if let Some(warning) = location::misleading_path_warning(format, path) {
                    ctx.params.log(warning);
                }
                local_sink(path).map_err(|e| location::path_error(format, "create", path, &e))?
            }
        };

        let mut rows_written: i64 = 0;
        let mut after_id = -1;
        // One staged batch at a time, including for SQLite-backed storage.
        // Scanning the whole log would materialize the input in memory even
        // when the destination itself is streamed.
        while let Some((id, blob)) = ctx
            .storage
            .scan(ctx.execution_id, SHARD_NS, b"", after_id, 1)
            .pop()
        {
            after_id = id;
            let batch = ipc::read_batch(&blob)?;
            let names: Vec<String> = batch
                .schema()
                .fields()
                .iter()
                .map(|f| f.name().clone())
                .collect();
            for row in 0..batch.num_rows() {
                let mut cells = Vec::with_capacity(batch.num_columns());
                for col in batch.columns() {
                    cells.push(value_at(col, row)?);
                }
                let value = match opts.shape {
                    RowShape::Array => Value::Array(cells),
                    RowShape::Map => {
                        Value::Map(names.iter().cloned().map(Value::Text).zip(cells).collect())
                    }
                };
                let value = match opts.canonical {
                    Some(mode) => encode::canonicalize(value, mode),
                    None => value,
                };
                let bytes = self
                    .wire
                    .encode_row(&value)
                    .map_err(|e| RpcError::runtime_error(format!("{format}: {e}")))?;
                sink.write_all(&bytes)
                    .map_err(|e| write_err(format, ctx.path, e))?;
                rows_written += 1;
            }
        }

        // A zero-row COPY still produces the destination: an empty file is a
        // valid empty sequence/stream, which the reader loads as zero rows.
        sink.finish(ctx.path)
            .map_err(|e| write_err(format, ctx.path, e))?;
        Ok(rows_written)
    }
}

/// Neither destination is published until every row has been encoded. Drop
/// cleans up the temporary file or aborts an unfinished multipart upload.
enum Sink {
    #[cfg(not(target_arch = "wasm32"))]
    File(std::io::BufWriter<tempfile::NamedTempFile>),
    Remote(cloud::ObjectWriter),
}

impl Sink {
    fn finish(self, _path: &str) -> std::io::Result<()> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Sink::File(mut writer) => {
                writer.flush()?;
                let file = writer.into_inner().map_err(|e| e.into_error())?;
                file.persist(_path).map_err(|e| e.error)?;
                Ok(())
            }
            Sink::Remote(writer) => writer.finish(),
        }
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Sink::File(w) => w.write(buf),
            Sink::Remote(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Sink::File(w) => w.flush(),
            Sink::Remote(w) => w.flush(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn local_sink(path: &str) -> std::io::Result<Sink> {
    let parent = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    // A sibling keeps the final rename on the same filesystem. NamedTempFile
    // removes the unpublished file on all ordinary error paths.
    let file = tempfile::Builder::new()
        .prefix(".vgi-cbor-")
        .tempfile_in(parent)?;
    Ok(Sink::File(std::io::BufWriter::new(file)))
}

#[cfg(target_arch = "wasm32")]
fn local_sink(_path: &str) -> std::io::Result<Sink> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "local COPY destinations are unavailable in the browser; use s3://",
    ))
}

fn write_err(format: &str, path: &str, e: std::io::Error) -> RpcError {
    RpcError::runtime_error(format!("{format}: write to {path} failed: {e}"))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use arrow_array::{ArrayRef, Int64Array, IntervalMonthDayNanoArray};
    use arrow_schema::{Field, Schema};
    use std::sync::{Arc, Mutex};
    use vgi::buffering::BufferingParams;
    use vgi::storage::MemoryStorage;

    fn export_batches(wire: Wire, path: &str, batches: Vec<RecordBatch>) -> Result<i64> {
        let writer = CborCopyTo { wire };
        let params = BufferingParams {
            execution_id: b"test-export".to_vec(),
            storage: Arc::new(MemoryStorage::new()),
            output_schema: Arc::new(Schema::empty()),
            arguments: Default::default(),
            settings: Default::default(),
            secrets: Default::default(),
            attach_opaque_data: None,
            batch_index: None,
            copy_to: None,
            input_schema: None,
            logs: Arc::new(Mutex::new(Vec::new())),
        };
        for batch in batches {
            writer.write(
                &CopyToWriteContext {
                    path,
                    options: &params.arguments,
                    storage: &params.storage,
                    execution_id: &params.execution_id,
                    params: &params,
                },
                &batch,
            )?;
        }
        writer.close(&CopyToCloseContext {
            path,
            options: &params.arguments,
            storage: &params.storage,
            execution_id: &params.execution_id,
            params: &params,
            input_schema: None,
        })
    }

    fn single_column(values: ArrayRef) -> RecordBatch {
        let schema = Schema::new(vec![Field::new("id", values.data_type().clone(), true)]);
        RecordBatch::try_new(Arc::new(schema), vec![values]).unwrap()
    }

    #[test]
    fn staged_exports_preserve_all_batches_in_order_in_both_formats() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rows");
        for wire in [Wire::Cbor, Wire::Msgpack] {
            let batches = (0..20)
                .map(|i| single_column(Arc::new(Int64Array::from(vec![i * 2, i * 2 + 1]))))
                .collect();
            assert_eq!(
                export_batches(wire, path.to_str().unwrap(), batches).unwrap(),
                40
            );
            let file = std::fs::File::open(&path).unwrap();
            let mut reader = wire.item_reader(Box::new(std::io::BufReader::new(file)));
            for id in 0..40 {
                assert_eq!(
                    reader.next_item().unwrap().unwrap(),
                    Value::Map(vec![(Value::Text("id".into()), Value::Integer(id.into()))])
                );
            }
            assert!(reader.next_item().is_none());
            assert_eq!(
                export_batches(wire, path.to_str().unwrap(), vec![]).unwrap(),
                0
            );
            assert!(std::fs::read(&path).unwrap().is_empty());
        }
    }

    #[test]
    fn encoding_failure_after_a_row_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rows");
        for wire in [Wire::Cbor, Wire::Msgpack] {
            std::fs::write(&path, b"original").unwrap();
            let values = IntervalMonthDayNanoArray::from(vec![
                None,
                Some(arrow_buffer::IntervalMonthDayNano::new(0, 1, 0)),
            ]);
            let error = export_batches(
                wire,
                path.to_str().unwrap(),
                vec![single_column(Arc::new(values))],
            )
            .unwrap_err();
            assert!(error
                .to_string()
                .contains("unsupported input type Interval"));
            assert_eq!(std::fs::read(&path).unwrap(), b"original");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn local_export_publishes_only_at_finish() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rows.cbor");
        std::fs::write(&path, b"original").unwrap();
        let mut sink = local_sink(path.to_str().unwrap()).unwrap();
        sink.write_all(b"replacement").unwrap();
        sink.flush().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        sink.finish(path.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn abandoned_local_export_preserves_destination_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rows.cbor");
        for existing in [false, true] {
            if existing {
                std::fs::write(&path, b"original").unwrap();
            }
            let mut sink = local_sink(path.to_str().unwrap()).unwrap();
            sink.write_all(b"partial output").unwrap();
            sink.flush().unwrap();
            drop(sink);
            assert_eq!(path.exists(), existing);
            assert_eq!(
                std::fs::read_dir(dir.path()).unwrap().count(),
                usize::from(existing)
            );
            if existing {
                assert_eq!(std::fs::read(&path).unwrap(), b"original");
            }
        }
    }

    #[test]
    fn failed_local_publish_cleans_up_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("directory");
        std::fs::create_dir(&destination).unwrap();
        let mut sink = local_sink(destination.to_str().unwrap()).unwrap();
        sink.write_all(b"rows").unwrap();
        assert!(sink.finish(destination.to_str().unwrap()).is_err());
        assert!(destination.is_dir());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
