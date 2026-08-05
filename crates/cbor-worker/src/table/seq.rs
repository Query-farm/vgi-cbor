//! `seq_decode(blob)` — fan a CBOR Sequence (RFC 8742) into one row per
//! top-level item.
//!
//! Registered as a *blended* table-in-out function: its positional argument is
//! a real per-row input column, so one registration serves the literal call
//! (`FROM seq_decode(from_hex('010203'))`), the column call
//! (`FROM t, seq_decode(t.blob)`), and correlated `LATERAL`. Because a row can
//! fan out to any number of items, each emitted batch carries `parent_rows`
//! provenance so the extension's batched-LATERAL operator can stamp the
//! correlated columns back onto every output row.

use std::sync::Arc;

use arrow_array::builder::{Int64Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use cbor_core::seq;
use vgi::table_in_out::{EmitOptions, TableInOutFunction, TableInOutOutput};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io;

pub struct SeqDecode;

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("idx", DataType::Int64, false),
        Field::new("value", arrow_io::json_type(), true),
    ]))
}

impl TableInOutFunction for SeqDecode {
    fn name(&self) -> &str {
        "seq_decode"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "CBOR Sequence Decode",
            "Decode a CBOR Sequence (RFC 8742 — a concatenation of zero or more CBOR items) into \
             one row per item, with columns `idx` (`BIGINT`, zero-based position) and `value` \
             (JSON). A truncated trailing item stops the sequence cleanly, returning the items \
             parsed so far (never panics). The blob argument is a per-row input column, so the \
             function works equally on a literal, on a whole column, and under a correlated \
             LATERAL join — fanning each row's sequence out beside that row's other columns. A \
             NULL or undecodable blob contributes no rows. To load a whole *file* of CBOR rows \
             into a table, use the `cbor` bulk-copy format instead.",
            "Fan a CBOR Sequence (RFC 8742) into rows of `(idx BIGINT, value JSON)` — per literal, \
             per column, or under a correlated LATERAL join.",
            "cbor, sequence, rfc 8742, seq_decode, fan-out, lateral, stream, items",
            "sequence",
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            r#"[{"name":"idx","type":"BIGINT","description":"Zero-based position of the item within the CBOR sequence."},{"name":"value","type":"VARCHAR","description":"The decoded item rendered as JSON text."}]"#
                .into(),
        ));
        tags.push((
            "vgi.example_queries".into(),
            "[{\"description\":\"Decode the 3-item CBOR sequence 01 02 03 into rows.\",\"sql\":\"SELECT idx, value FROM cbor.main.seq_decode(from_hex('010203')) ORDER BY idx\"},\
              {\"description\":\"Fan every row's sequence out beside its own id, as a correlated join.\",\"sql\":\"SELECT t.id, s.idx, s.value FROM (SELECT 1 AS id, from_hex('010203') AS b) t, cbor.main.seq_decode(t.b) s ORDER BY t.id, s.idx\"}]".into(),
        ));
        FunctionMetadata {
            description: "Decode a CBOR Sequence (RFC 8742) into one row per item".into(),
            // Blended: the positional arg IS the per-row input column, so there
            // is no synthetic TABLE placeholder and the literal / column /
            // LATERAL call forms all bind to this one registration.
            input_from_args: true,
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column(
            "blob",
            0,
            "blob",
            "A CBOR Sequence (RFC 8742) — zero or more concatenated CBOR items.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: schema(),
            opaque_data: Vec::new(),
        })
    }

    fn process_out(
        &self,
        params: &ProcessParams,
        batch: &RecordBatch,
        out: &mut TableInOutOutput,
    ) -> Result<()> {
        let col = batch.column(0);
        let mut idx = Int64Builder::new();
        let mut value = StringBuilder::new();
        // One entry per emitted row, naming the input row it came from — the
        // row count changes here, so this provenance is required (an identity
        // 1→1 map is the only case the extension may assume).
        let mut parent_rows: Vec<i32> = Vec::new();

        for row in 0..batch.num_rows() {
            let Some(bytes) = arrow_io::blob_bytes(col, row)? else {
                continue; // NULL input contributes no rows
            };
            for item in seq::seq_decode(bytes) {
                idx.append_value(item.idx);
                value.append_value(&item.value_json);
                parent_rows.push(row as i32);
            }
        }

        let columns: Vec<ArrayRef> = vec![Arc::new(idx.finish()), Arc::new(value.finish())];
        let out_batch = RecordBatch::try_new(params.output_schema.clone(), columns)
            .map_err(|e| RpcError::runtime_error(e.to_string()))?;
        out.emit_with(
            out_batch,
            EmitOptions {
                parent_rows: Some(parent_rows),
                ..Default::default()
            },
        )
    }
}
