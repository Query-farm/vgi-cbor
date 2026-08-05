//! Shared plumbing for the `cbor` / `msgpack` COPY formats: the wire selector,
//! the row-shape option, and the canonical-ordering option.

use cbor_core::codec::{encode, msgpack};
use ciborium::value::Value;
use vgi::function::{ArgSpec, FunctionMetadata};
use vgi_rpc::{Result, RpcError};

use crate::meta;

/// How many rows one emitted `RecordBatch` carries on the COPY-FROM path. Large
/// enough to amortize per-batch overhead, small enough that a huge source file
/// does not materialize as a single allocation.
pub const READ_BATCH_ROWS: usize = 8192;

/// Which binary encoding a COPY format speaks. Both are self-describing,
/// schema-less, and framed as a bare concatenation of top-level items — one item
/// per row — so they stream without a container header or footer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// CBOR (RFC 8949), framed as a CBOR Sequence (RFC 8742).
    Cbor,
    /// MessagePack, framed as concatenated top-level items.
    Msgpack,
}

impl Wire {
    /// The SQL `FORMAT` identifier.
    pub fn format(self) -> &'static str {
        match self {
            Wire::Cbor => "cbor",
            Wire::Msgpack => "msgpack",
        }
    }

    /// Registered name of the worker function backing this format. The reader
    /// and writer share it: a format serving both COPY directions advertises a
    /// single handler, which the extension wires to the read (table) and write
    /// (buffering) paths alike.
    pub fn handler(self) -> &'static str {
        match self {
            Wire::Cbor => "cbor_copy",
            Wire::Msgpack => "msgpack_copy",
        }
    }

    /// Human-readable name for docs and error messages.
    pub fn label(self) -> &'static str {
        match self {
            Wire::Cbor => "CBOR",
            Wire::Msgpack => "MessagePack",
        }
    }

    /// The framing's spec name, for docs.
    pub fn framing(self) -> &'static str {
        match self {
            Wire::Cbor => "CBOR Sequence (RFC 8742)",
            Wire::Msgpack => "concatenated MessagePack items",
        }
    }

    /// An incremental item reader over this wire format, so a COPY FROM can
    /// decode a row at a time instead of buffering the whole source.
    pub fn item_reader(self, reader: Box<dyn std::io::BufRead + Send>) -> ItemReader {
        match self {
            Wire::Cbor => ItemReader::Cbor(cbor_core::seq::SeqReader::new(reader)),
            Wire::Msgpack => ItemReader::Msgpack(msgpack::StreamReader::new(reader)),
        }
    }

    /// Encode one row value to its wire bytes.
    pub fn encode_row(self, value: &Value) -> std::result::Result<Vec<u8>, String> {
        match self {
            Wire::Cbor => encode::encode_value(value),
            Wire::Msgpack => msgpack::encode_value(&msgpack::cbor_to_mp(value)),
        }
    }
}

/// One item at a time from either wire format, yielding the shared CBOR value
/// model. Both underlying readers stop at the first bad item.
pub enum ItemReader {
    Cbor(cbor_core::seq::SeqReader<Box<dyn std::io::BufRead + Send>>),
    Msgpack(msgpack::StreamReader<Box<dyn std::io::BufRead + Send>>),
}

impl ItemReader {
    /// The next row item: `None` at a clean end of input.
    pub fn next_item(&mut self) -> Option<std::result::Result<Value, String>> {
        match self {
            ItemReader::Cbor(r) => r.next_item(),
            ItemReader::Msgpack(r) => r.next_item(),
        }
    }
}

/// How a single row is represented as one wire item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowShape {
    /// A map keyed by column name — self-describing, and tolerant of a source
    /// whose columns are ordered differently or carry extras.
    Map,
    /// An array of values in column order — compact, but positional.
    Array,
}

impl RowShape {
    /// Parse the `row_format` COPY option (default [`RowShape::Map`]).
    pub fn parse(format: &str, raw: Option<String>) -> Result<RowShape> {
        match raw
            .as_deref()
            .map(str::trim)
            .unwrap_or("map")
            .to_ascii_lowercase()
            .as_str()
        {
            "map" => Ok(RowShape::Map),
            "array" => Ok(RowShape::Array),
            other => Err(RpcError::value_error(format!(
                "{format}: 'row_format' must be one of ['map', 'array'], got {other:?}"
            ))),
        }
    }
}

/// The `row_format` option spec, shared by every reader and writer.
pub fn row_format_arg() -> ArgSpec {
    ArgSpec::column(
        "row_format",
        -1,
        "varchar",
        "How each row is framed as one item: 'map' (default) keys it by column name; \
         'array' writes the values positionally in column order.",
    )
}

/// The shared discovery metadata for a format. Reader and writer are one
/// catalog object (one format name, one handler, `direction="both"`), so both
/// sides return this — the docs describe the format, not a single direction.
pub fn format_metadata(wire: Wire) -> FunctionMetadata {
    let label = wire.label();
    let framing = wire.framing();
    let format = wire.format();
    let scalar = match wire {
        Wire::Cbor => "decode",
        Wire::Msgpack => "msgpack_decode",
    };
    let canonical_doc = match wire {
        Wire::Cbor => {
            " On write, `canonical 'core'` (RFC 8949 §4.2.1) or `canonical 'ctap2'` orders map \
             keys deterministically, so the same rows always produce byte-identical output."
        }
        Wire::Msgpack => "",
    };

    let mut tags = meta::object_tags(
        &format!("{label} Row Files (COPY FROM / TO)"),
        &format!(
            "Bulk-move whole tables in and out of {label} data files — the row-file counterpart \
             to the per-blob `{scalar}` scalar. The file is a {framing}: one top-level item per \
             row, with no container header or footer, so it appends and streams. The same format \
             name serves both directions, and a file written by one round-trips through the \
             other. The `FORMAT` identifier is scoped by the ATTACH alias, so it reads \
             `<alias>.{format}`:\n\n\
             ```sql\n\
             COPY (<query>) TO '<path>' (FORMAT '<alias>.{format}');\n\
             COPY <table> FROM '<path>' (FORMAT '<alias>.{format}');\n\
             ```\n\n\
             With the default `row_format 'map'` each item is a map keyed by column name: \
             self-describing, so on read the columns may appear in any order, a key absent from \
             an item reads as NULL, and extra keys are ignored. `row_format 'array'` frames each \
             row as an array of values in column order — more compact, but positional. Column \
             values encode exactly as the `encode` scalar does (shortest-lossless integers and \
             floats, `BLOB` as a byte string, `TIMESTAMP` as an epoch instant, `LIST` / `STRUCT` \
             / `MAP` as arrays and maps) and decode back onto the COPY target's exact column \
             types. A value that cannot be represented in its target column fails the COPY with \
             a column-qualified message; `ignore_errors true` instead skips unusable rows and \
             tolerates a truncated trailing item. Rows are written in source order, so an \
             ordered source query keeps its ordering in the file.{canonical_doc}\n\n\
             **Paths resolve on the worker.** The file is opened by the worker process, so the \
             path is interpreted against its filesystem and working directory — not the SQL \
             client's. That is invisible when DuckDB spawns the worker locally, but a worker in \
             a container or on another host cannot see the caller's paths: use a location both \
             sides agree on (a mounted volume), and prefer absolute paths. A path the worker \
             cannot open is reported with the directory it actually looked in."
        ),
        &format!(
            "Bulk import and export of {label} row files. The file is a {framing} — one item per \
             row, no container header — so it appends, streams, and round-trips between the two \
             directions. The `FORMAT` identifier is scoped by the ATTACH alias:\n\n\
             ```sql\n\
             COPY (<query>) TO '<path>' (FORMAT '<alias>.{format}');\n\
             COPY <table> FROM '<path>' (FORMAT '<alias>.{format}');\n\
             ```\n\n\
             `row_format 'map'` (the default) keys each row by column name; `row_format 'array'` \
             is positional. On read, `ignore_errors true` skips unusable rows and tolerates a \
             truncated tail. Writes preserve source order.{canonical_doc}\n\n\
             Paths are opened by the **worker** process, so they resolve against its filesystem \
             and working directory rather than the client's — a containerized or remote worker \
             needs a shared location, and absolute paths."
        ),
        &format!(
            "{format}, copy, copy from, copy to, import, export, load, dump, bulk, ingest, \
             {}, row file, sequence, stream, encode, decode, serialize, deserialize",
            label.to_ascii_lowercase()
        ),
        "copy",
    );

    // The read path's result columns are the COPY target table's columns, fixed
    // by the COPY statement rather than by an argument, so the schema is
    // described rather than enumerated (VGI307).
    tags.push((
        "vgi.result_dynamic_columns_md".into(),
        format!(
            "### Read direction — columns mirror the COPY target\n\n\
             The scan emits exactly the COPY target table's columns, in its declared order and \
             types: DuckDB fixes them from the target and the reader projects each {label} item \
             onto them, inserting no cast. There is no independent result schema, so the shape \
             below is one worked variant — a target declared \
             `(id INTEGER, name VARCHAR, seen TIMESTAMP)`.\n\n\
             | Name | Type | Description |\n|---|---|---|\n\
             | id | INTEGER | The item's value for the `id` column — by key name under \
             `row_format 'map'`, by position under `row_format 'array'`. |\n\
             | name | VARCHAR | The item's value for the `name` column. A nested value lands as \
             its JSON text. |\n\
             | seen | TIMESTAMP | The item's value for the `seen` column, read from an epoch \
             instant. A key absent from the item reads as `NULL`. |"
        ),
    ));

    // Each example runs standalone in a bare session: the write direction needs
    // no fixture, and the discovery query names the handler so a caller can read
    // this format's option set straight out of the catalog. The read direction
    // needs a source file on disk, so it is shown as the fenced template above
    // and exercised by the repo's SQLLogic round-trip test rather than here.
    tags.push((
        "vgi.example_queries".into(),
        format!(
            "[{{\"description\":\"Export query results to a {label} row file, one item per row.\",\
               \"sql\":\"COPY (SELECT 1 AS id, 'alpha' AS name) TO 'events.{format}' (FORMAT 'cbor.{format}')\"}},\
              {{\"description\":\"Export positionally (each row an array in column order) for a more compact file.\",\
               \"sql\":\"COPY (SELECT 1 AS id, 'alpha' AS name) TO 'events_array.{format}' (FORMAT 'cbor.{format}', row_format 'array')\"}},\
              {{\"description\":\"List the COPY options this format accepts, and the directions it serves.\",\
               \"sql\":\"SELECT format_name, direction, option_name FROM vgi_copy_formats() WHERE handler = '{handler}' ORDER BY option_name\"}}]",
            handler = wire.handler()
        ),
    ));

    FunctionMetadata {
        description: format!(
            "Bulk import and export of {label} row files ({framing}), one item per row"
        ),
        tags,
        ..Default::default()
    }
}

/// Parse the CBOR-only `canonical` option: unset/empty keeps ciborium's
/// shortest-form output, `core` / `ctap2` select a deterministic key ordering.
pub fn parse_canonical(raw: Option<String>) -> Result<Option<encode::Canon>> {
    match raw.as_deref().map(str::trim).unwrap_or("") {
        "" => Ok(None),
        mode => encode::Canon::parse(mode)
            .map(Some)
            .map_err(|e| RpcError::value_error(format!("cbor: 'canonical' {e}"))),
    }
}
