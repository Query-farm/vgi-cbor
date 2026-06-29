//! Shared scaffolding for the single-BLOB-input scalar functions. The
//! `blob_scalar!` macro generates a `ScalarFunction` whose body is a column
//! builder over the decoded input bytes, with the metadata the `vgi-lint` strict
//! profile expects (title / doc_llm / doc_md / keywords / per-arg docs /
//! example_queries). Decoders capture errors per row (a malformed blob yields a
//! NULL output, never a panic that crashes the scan).

/// Generate a `ScalarFunction` taking one BLOB/VARCHAR column and producing one
/// output column of a fixed type.
///
/// `$build` is a free function `fn(&[Option<&[u8]>]) -> vgi_rpc::Result<ArrayRef>`.
#[macro_export]
macro_rules! blob_scalar {
    (
        struct $ty:ident,
        sql_name = $name:literal,
        ret = $ret:expr,
        arg_doc = $argdoc:literal,
        description = $desc:literal,
        title = $title:literal,
        doc_llm = $llm:literal,
        doc_md = $md:literal,
        keywords = $kw:literal,
        examples = $examples:literal,
        build = $build:path $(,)?
    ) => {
        pub struct $ty;

        impl vgi::ScalarFunction for $ty {
            fn name(&self) -> &str {
                $name
            }

            fn metadata(&self) -> vgi::FunctionMetadata {
                let mut tags = $crate::meta::object_tags($title, $llm, $md, $kw);
                tags.push(("vgi.example_queries".into(), $examples.into()));
                vgi::FunctionMetadata {
                    description: $desc.into(),
                    tags,
                    ..Default::default()
                }
            }

            fn argument_specs(&self) -> Vec<vgi::ArgSpec> {
                vec![vgi::ArgSpec::any_column("blob", 0, $argdoc)]
            }

            fn on_bind(&self, _params: &vgi::BindParams) -> vgi_rpc::Result<vgi::BindResponse> {
                Ok(vgi::BindResponse::result($ret))
            }

            fn process(
                &self,
                params: &vgi::ProcessParams,
                batch: &arrow_array::RecordBatch,
            ) -> vgi_rpc::Result<arrow_array::RecordBatch> {
                let col = batch.column(0);
                let rows = batch.num_rows();
                let mut input: Vec<Option<&[u8]>> = Vec::with_capacity(rows);
                for i in 0..rows {
                    input.push($crate::arrow_io::blob_bytes(col, i)?);
                }
                let out: arrow_array::ArrayRef = $build(&input)?;
                arrow_array::RecordBatch::try_new(params.output_schema.clone(), vec![out])
                    .map_err(|e| vgi_rpc::RpcError::runtime_error(e.to_string()))
            }
        }
    };
}
