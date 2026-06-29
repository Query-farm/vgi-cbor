//! `seq_decode(blob)` — LATERAL table function over a CBOR Sequence (RFC 8742):
//! fans one blob into one row per top-level item.

use std::sync::Arc;

use arrow_array::builder::{Int64Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use cbor_core::seq;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io;

pub struct SeqDecode;

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("idx", DataType::Int64, false),
        Field::new("value", arrow_io::json_type(), true),
    ]))
}

impl TableFunction for SeqDecode {
    fn name(&self) -> &str {
        "seq_decode"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "CBOR Sequence Decode",
            "Decode a CBOR Sequence (RFC 8742 — a concatenation of zero or more CBOR items) into \
             one row per item: STRUCT columns idx (BIGINT, zero-based position) and value (JSON). \
             A truncated trailing item stops the sequence cleanly, returning the items parsed so \
             far (never panics). Use as a LATERAL table function over a column of CBOR-sequence \
             blobs.",
            "LATERAL: fan a CBOR Sequence (RFC 8742) into rows of `(idx BIGINT, value JSON)`.",
            "cbor, sequence, rfc 8742, seq_decode, fan-out, lateral, stream, items",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "One row per top-level item in the CBOR sequence:\n\n\
             | column | type | description |\n\
             |---|---|---|\n\
             | `idx` | BIGINT | Zero-based position in the sequence. |\n\
             | `value` | JSON | The item rendered as JSON. |"
                .into(),
        ));
        tags.push((
            "vgi.example_queries".into(),
            "[{\"description\":\"Decode the 3-item CBOR sequence 01 02 03 into rows.\",\"sql\":\"SELECT idx, value FROM cbor.main.seq_decode(from_hex('010203')) ORDER BY idx\"}]".into(),
        ));
        FunctionMetadata {
            description: "Decode a CBOR Sequence (RFC 8742) into one row per item (LATERAL)".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::const_arg(
            "blob",
            0,
            "blob",
            "A CBOR Sequence (RFC 8742) BLOB — zero or more concatenated CBOR items.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let items = params
            .arguments
            .const_bytes(0)
            .map(|b| seq::seq_decode(&b))
            .unwrap_or_default();
        Ok(Box::new(SeqProducer {
            schema: params.output_schema.clone(),
            items: Some(items),
        }))
    }
}

struct SeqProducer {
    schema: SchemaRef,
    items: Option<Vec<seq::SeqItem>>,
}

impl TableProducer for SeqProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        let Some(items) = self.items.take() else {
            return Ok(None);
        };
        let mut idx = Int64Builder::new();
        let mut value = StringBuilder::new();
        for it in &items {
            idx.append_value(it.idx);
            value.append_value(&it.value_json);
        }
        let columns: Vec<ArrayRef> = vec![Arc::new(idx.finish()), Arc::new(value.finish())];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), columns)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
