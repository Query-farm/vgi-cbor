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

        let shards = ctx
            .storage
            .scan(ctx.execution_id, SHARD_NS, b"", -1, usize::MAX);

        // Classify first: a remote destination is PUT as one object (object
        // stores have no append), so its rows are encoded into a buffer; a local
        // one streams straight through a BufWriter and never holds the file in
        // memory.
        let destination = cloud::classify(ctx.path)?;
        let mut sink = match &destination {
            Location::Remote(_) => Sink::Buffer(Vec::new()),
            Location::Local(path) => {
                // Warn before writing: a relative destination inside a container
                // lands in the image's ephemeral filesystem, so the COPY
                // "succeeds" and the file is nowhere the caller can reach.
                if let Some(warning) = location::misleading_path_warning(format, path) {
                    ctx.params.log(warning);
                }
                let file = std::fs::File::create(path)
                    .map_err(|e| location::path_error(format, "create", path, &e))?;
                Sink::File(std::io::BufWriter::new(file))
            }
        };

        let mut rows_written: i64 = 0;
        for (_id, blob) in &shards {
            let batch = ipc::read_batch(blob)?;
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
        sink.flush().map_err(|e| write_err(format, ctx.path, e))?;

        if let Location::Remote(url) = &destination {
            // Object stores have no append: the whole file goes up as one PUT.
            cloud::write_object(url, &ctx.params.secrets, &[], sink.buffer())?;
        }
        Ok(rows_written)
    }
}

/// Where `close()` streams the encoded rows.
///
/// A local destination is written straight through, so an arbitrarily large
/// export never has to fit in memory. A remote one is buffered because object
/// stores take a whole object per PUT — the row file is materialized once and
/// uploaded.
enum Sink {
    File(std::io::BufWriter<std::fs::File>),
    Buffer(Vec<u8>),
}

impl Sink {
    /// The encoded bytes, for the remote path. Empty for a local sink, which has
    /// already written them out.
    fn buffer(&self) -> &[u8] {
        match self {
            Sink::Buffer(b) => b,
            Sink::File(_) => &[],
        }
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Sink::File(w) => w.write(buf),
            Sink::Buffer(b) => b.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Sink::File(w) => w.flush(),
            Sink::Buffer(b) => b.flush(),
        }
    }
}

fn write_err(format: &str, path: &str, e: std::io::Error) -> RpcError {
    RpcError::runtime_error(format!("{format}: write to {path} failed: {e}"))
}
