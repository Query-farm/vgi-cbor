//! Core CBOR codec scalars: `to_json`, `diagnostic`, `decode`, `from_json`,
//! `encode`, `canonical`, `is_valid`, `well_formed`, `tags`, `untag`.

use std::sync::Arc;

use arrow_array::builder::{StringBuilder, UInt64Builder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::{NullBuffer, OffsetBuffer, ScalarBuffer};
use arrow_schema::{DataType, Field, Fields};
use cbor_core::codec::{diagnostic, encode, json, tags};
use cbor_core::validate;
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams, ScalarFunction};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{self, blob_bytes};
use crate::value_in::value_at;

// --- closed argument value sets ------------------------------------------
//
// Single source of truth for each `mode` argument's closed value set. These
// drive BOTH the runtime validator and the machine-readable `choices`
// constraint surfaced via `vgi_function_arguments()` (VGI317), so metadata and
// behaviour cannot drift.

/// Allowed `mode` values for `decode` (all currently render JSON text — see the
/// function note).
const DECODE_MODES: [&str; 4] = ["auto", "struct", "map", "json"];
/// Allowed `mode` values for `encode`.
const ENCODE_MODES: [&str; 3] = ["shortest", "canonical_core", "canonical_ctap2"];
/// Allowed `mode` values for `canonical`.
const CANONICAL_MODES: [&str; 2] = ["core", "ctap2"];

// --- builders used by the macro-generated scalars -------------------------

fn build_to_json(rows: &[Option<&[u8]>]) -> Result<ArrayRef> {
    let col: Vec<Option<String>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| json::to_json_string(bytes).ok()))
        .collect();
    Ok(arrow_io::string_array(&col))
}

fn build_diagnostic(rows: &[Option<&[u8]>]) -> Result<ArrayRef> {
    let col: Vec<Option<String>> = rows
        .iter()
        .map(|b| b.and_then(|bytes| diagnostic::diagnostic(bytes).ok()))
        .collect();
    Ok(arrow_io::string_array(&col))
}

fn build_is_valid(rows: &[Option<&[u8]>]) -> Result<ArrayRef> {
    let col: Vec<Option<bool>> = rows.iter().map(|b| b.map(validate::is_valid)).collect();
    Ok(arrow_io::bool_opt_array(&col))
}

/// The `well_formed` STRUCT type.
pub fn well_formed_type() -> DataType {
    DataType::Struct(Fields::from(vec![
        Field::new("ok", DataType::Boolean, true),
        Field::new("error", DataType::Utf8, true),
        Field::new("kind", DataType::Utf8, true),
    ]))
}

fn build_well_formed(rows: &[Option<&[u8]>]) -> Result<ArrayRef> {
    let mut ok: Vec<Option<bool>> = Vec::with_capacity(rows.len());
    let mut error: Vec<Option<String>> = Vec::with_capacity(rows.len());
    let mut kind: Vec<Option<String>> = Vec::with_capacity(rows.len());
    let mut valid: Vec<bool> = Vec::with_capacity(rows.len());
    for b in rows {
        match b {
            None => {
                ok.push(None);
                error.push(None);
                kind.push(None);
                valid.push(false);
            }
            Some(bytes) => {
                let wf = validate::well_formed(bytes);
                ok.push(Some(wf.ok));
                error.push(wf.error);
                kind.push(wf.kind);
                valid.push(true);
            }
        }
    }
    let DataType::Struct(fields) = well_formed_type() else {
        unreachable!()
    };
    let arrays = vec![
        arrow_io::bool_opt_array(&ok),
        arrow_io::string_array(&error),
        arrow_io::string_array(&kind),
    ];
    Ok(Arc::new(StructArray::new(
        fields,
        arrays,
        Some(NullBuffer::from(valid)),
    )))
}

/// The `tags` LIST<STRUCT(tag, path, value)> element fields.
fn tag_item_fields() -> Fields {
    Fields::from(vec![
        Field::new("tag", DataType::UInt64, false),
        Field::new("path", DataType::Utf8, false),
        Field::new("value", DataType::Utf8, true),
    ])
}

/// The `tags` return type.
pub fn tags_type() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(tag_item_fields()),
        true,
    )))
}

fn build_tags(rows: &[Option<&[u8]>]) -> Result<ArrayRef> {
    let mut tag_b = UInt64Builder::new();
    let mut path_b = StringBuilder::new();
    let mut val_b = StringBuilder::new();
    let mut offsets: Vec<i32> = vec![0];
    let mut valid: Vec<bool> = Vec::with_capacity(rows.len());
    let mut total = 0i32;
    for b in rows {
        match b.and_then(|bytes| tags::tags(bytes).ok()) {
            Some(hits) => {
                for h in &hits {
                    tag_b.append_value(h.tag);
                    path_b.append_value(&h.path);
                    val_b.append_value(&h.value_json);
                }
                total += hits.len() as i32;
                valid.push(true);
            }
            None => valid.push(false),
        }
        offsets.push(total);
    }
    let item_struct = StructArray::new(
        tag_item_fields(),
        vec![
            Arc::new(tag_b.finish()),
            Arc::new(path_b.finish()),
            Arc::new(val_b.finish()),
        ],
        None,
    );
    let item_field = Arc::new(Field::new(
        "item",
        DataType::Struct(tag_item_fields()),
        true,
    ));
    Ok(Arc::new(arrow_array::ListArray::new(
        item_field,
        OffsetBuffer::new(ScalarBuffer::from(offsets)),
        Arc::new(item_struct),
        Some(NullBuffer::from(valid)),
    )))
}

// --- macro-generated scalars ----------------------------------------------

blob_scalar! {
    struct ToJson,
    sql_name = "to_json",
    ret = DataType::Utf8,
    arg_doc = "The CBOR-encoded bytes to render as JSON.",
    description = "Render a CBOR blob as canonical JSON text (byte strings as base64url)",
    title = "CBOR → JSON",
    category = "codec",
    doc_llm = "Decode a CBOR (RFC 8949) blob and render it as a canonical JSON string. Always \
        succeeds on well-formed input; it is necessarily lossy on the types JSON lacks — byte \
        strings render as base64url, non-text map keys are stringified, and semantic tags are \
        transparent (the inner value is shown). For the lossless typed path use `decode`; for a \
        tag- and byte-preserving human view use `diagnostic`. Returns NULL for a malformed blob.",
    doc_md = "Render a CBOR blob as JSON text. Lossy on `BLOB`/non-string keys (base64url), tags \
        transparent. `decode` is the lossless path, `diagnostic` the debug path.",
    keywords = "cbor, json, to_json, decode, convert, rfc 8949, deserialize, base64url",
    examples = "[{\"description\":\"Decode the CBOR array [1,2,3] to JSON.\",\"sql\":\"SELECT cbor.main.to_json(from_hex('83010203')) AS j\"}]",
    build = build_to_json,
}

blob_scalar! {
    struct Diagnostic,
    sql_name = "diagnostic",
    ret = DataType::Utf8,
    arg_doc = "A CBOR-encoded BLOB to render in diagnostic notation.",
    description = "Render a CBOR blob in RFC 8949 Extended Diagnostic Notation (EDN)",
    title = "CBOR Diagnostic Notation",
    category = "validation",
    doc_llm = "Render a CBOR blob in RFC 8949 §8 Extended Diagnostic Notation (EDN) — the \
        human-debug surface. Unlike `to_json` it preserves semantic tags (e.g. `1(1719600000)`), \
        byte strings (`h'0102'`), float precision, and the null/undefined distinction. Returns \
        NULL for a malformed blob.",
    doc_md = "Render a CBOR blob in EDN, e.g. `[1, 2, {\"a\": h'0102'}, 1(1719600000)]`. \
        Preserves tags, byte strings, and floats — the debug view.",
    keywords = "cbor, diagnostic, edn, rfc 8949, debug, notation, tags, hex",
    examples = "[{\"description\":\"Diagnostic notation for [1,2,3].\",\"sql\":\"SELECT cbor.main.diagnostic(from_hex('83010203')) AS edn\"}]",
    build = build_diagnostic,
}

blob_scalar! {
    struct IsValid,
    sql_name = "is_valid",
    ret = DataType::Boolean,
    arg_doc = "A BLOB to test for CBOR well-formedness.",
    description = "Return true iff the blob is exactly one well-formed CBOR item (RFC 8949 §1.2)",
    title = "CBOR Is-Valid",
    category = "validation",
    doc_llm = "Return TRUE iff the blob is exactly one well-formed CBOR item per RFC 8949 §1.2 \
        (no trailing bytes, bounded nesting). Duplicate map keys are tolerated here (they are \
        well-formed); use `well_formed` for the stricter check plus the failure reason. Never \
        errors — a malformed blob simply returns FALSE; a NULL input returns NULL.",
    doc_md = "TRUE iff the blob is one well-formed CBOR item. Total (never throws). See \
        `well_formed` for the reason on failure.",
    keywords = "cbor, valid, is_valid, well-formed, validate, rfc 8949, check",
    examples = "[{\"description\":\"A valid item vs trailing garbage.\",\"sql\":\"SELECT cbor.main.is_valid(from_hex('01')) AS ok, cbor.main.is_valid(from_hex('01ff')) AS bad\"}]",
    build = build_is_valid,
}

blob_scalar! {
    struct WellFormed,
    sql_name = "well_formed",
    ret = well_formed_type(),
    arg_doc = "A BLOB to diagnose for CBOR well-formedness.",
    description = "Diagnose CBOR well-formedness: STRUCT(ok BOOL, error VARCHAR, kind VARCHAR)",
    title = "CBOR Well-Formed Diagnosis",
    category = "validation",
    doc_llm = "Diagnose a CBOR blob and return STRUCT(ok BOOL, error VARCHAR, kind VARCHAR). \
        `kind` is one of truncated, trailing-bytes, invalid-major, bad-utf8, duplicate-key, \
        nesting-limit, reserved-simple (NULL when ok). Stricter than `is_valid`: it also flags \
        duplicate map keys. Never errors or panics on hostile input — malformed bytes return \
        ok=false with the classified reason, so a bad row never crashes the scan.",
    doc_md = "Diagnose well-formedness → `STRUCT(ok, error, kind)`. `kind` ∈ {truncated, \
        trailing-bytes, invalid-major, bad-utf8, duplicate-key, nesting-limit, reserved-simple}.",
    keywords = "cbor, well_formed, validate, error, kind, truncated, duplicate-key, robustness",
    examples = "[{\"description\":\"Diagnose a truncated blob.\",\"sql\":\"SELECT (cbor.main.well_formed(from_hex('83010203'))).ok AS ok\"}]",
    build = build_well_formed,
}

blob_scalar! {
    struct Tags,
    sql_name = "tags",
    ret = tags_type(),
    arg_doc = "A CBOR-encoded BLOB to walk for semantic tags.",
    description = "List every CBOR semantic tag with its path and value (RFC 8949 §3.4)",
    title = "CBOR Tag Walk",
    category = "tags",
    doc_llm = "Walk a CBOR blob and return a LIST of STRUCT(tag UBIGINT, path VARCHAR, value \
        JSON) — one entry per semantic tag (RFC 8949 §3.4) in document order. `path` is a \
        JSONPath-ish location like `$`, `$.a`, or `$[2]`; `value` is the tagged value as JSON. \
        Use it to find tag 0/1 timestamps, tag 2/3 bignums, tag 32 URIs, or any application tag. \
        See `untag` to pull the value(s) under a specific tag. NULL for a malformed blob.",
    doc_md = "List every semantic tag → `LIST<STRUCT(tag UBIGINT, path VARCHAR, value JSON)>` in \
        document order. Pair with `untag(blob, tag)`.",
    keywords = "cbor, tags, semantic tag, rfc 8949, tag 0, tag 1, bignum, uri, walk, path",
    examples = "[{\"description\":\"The single tag-1 epoch timestamp in 1(1363896240).\",\"sql\":\"SELECT (cbor.main.tags(from_hex('c11a514b67b0'))[1]).tag AS tag\"}]",
    build = build_tags,
}

// --- explicit scalars (extra args / non-BLOB input) -----------------------

fn ve(e: impl std::fmt::Display) -> RpcError {
    RpcError::value_error(e.to_string())
}

/// `decode(blob, mode := 'auto')` — decode to JSON. The `mode` argument is
/// validated; STRUCT/MAP typed inference is documented as falling back to JSON in
/// v1 (a DuckDB scalar's output type is fixed at bind, with no data sample).
pub struct Decode {
    /// Whether this overload accepts the optional positional `mode` argument.
    pub with_mode: bool,
}

impl ScalarFunction for Decode {
    fn name(&self) -> &str {
        "decode"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "CBOR Decode",
            "Decode a CBOR (RFC 8949) blob to its richest self-describing form as JSON. The \
             optional `mode` argument is one of 'auto' (default), 'struct', 'map', or 'json'. \
             NOTE: a DuckDB scalar function fixes its output column type at bind time with no \
             data sample available, so this worker returns canonical JSON text for every mode \
             (the lossless, stable column type). For typed STRUCT projection of a known shape, \
             cast the JSON or use the structural decoders (cose_decode / cwt_claims / cose_key / \
             webauthn_authdata). Returns NULL for a malformed blob.",
            "Decode a CBOR blob to JSON (the stable lossless column). `mode` ∈ {auto, struct, \
             map, json} is accepted; all currently return JSON text.",
            "cbor, decode, json, struct, map, rfc 8949, deserialize",
            "codec",
        );
        let example = if self.with_mode {
            "[{\"description\":\"Decode the CBOR map {\\\"a\\\":1} forcing JSON mode.\",\"sql\":\"SELECT cbor.main.decode(from_hex('a1616101'), 'json') AS d\"}]"
        } else {
            "[{\"description\":\"Decode the CBOR map {\\\"a\\\":1} to JSON.\",\"sql\":\"SELECT cbor.main.decode(from_hex('a1616101')) AS d\"}]"
        };
        tags.push(("vgi.example_queries".into(), example.into()));
        FunctionMetadata {
            description: if self.with_mode {
                "Decode a CBOR blob to its richest form (JSON in v1), with an explicit mode argument"
            } else {
                "Decode a CBOR blob to its richest form (JSON in v1)"
            }
            .into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::any_column(
            "blob",
            0,
            "A CBOR-encoded BLOB to decode.",
        )];
        if self.with_mode {
            specs.push(
                ArgSpec::const_arg(
                    "mode",
                    1,
                    "varchar",
                    "Decode mode. All currently produce JSON text (see the function note).",
                )
                .with_choices(DECODE_MODES)
                .with_default("auto"),
            );
        }
        specs
    }

    fn on_bind(&self, params: &BindParams) -> Result<BindResponse> {
        if let Some(mode) = params.arguments.const_str(1) {
            validate_mode(&mode)?;
        }
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out: Vec<Option<String>> = Vec::with_capacity(rows);
        for i in 0..rows {
            out.push(blob_bytes(col, i)?.and_then(|b| json::to_json_string(b).ok()));
        }
        let arr = arrow_io::string_array(&out);
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

fn validate_mode(mode: &str) -> Result<()> {
    let normalized = mode.trim().to_ascii_lowercase();
    match normalized.as_str() {
        m if DECODE_MODES.contains(&m) => Ok(()),
        other => Err(ve(format!(
            "decode: unknown mode '{other}' (expected {})",
            DECODE_MODES.join(" | ")
        ))),
    }
}

/// `from_json(json) -> BLOB` — encode JSON text as core-deterministic CBOR.
pub struct FromJson;

impl ScalarFunction for FromJson {
    fn name(&self) -> &str {
        "from_json"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "JSON → CBOR",
            "Encode a JSON string as core-deterministic CBOR (RFC 8949 §4.2.1: shortest integers, \
             map keys sorted by encoded-byte order). The inverse of `to_json` for JSON-expressible \
             values. Returns NULL on invalid JSON.",
            "Encode JSON text as deterministic CBOR bytes. Inverse of `to_json`.",
            "cbor, from_json, encode, json, deterministic, rfc 8949, serialize",
            "codec",
        );
        tags.push((
            "vgi.example_queries".into(),
            "[{\"description\":\"Encode a JSON array to CBOR and hex it.\",\"sql\":\"SELECT to_hex(cbor.main.from_json('[1,2,3]')) AS h\"}]".into(),
        ));
        FunctionMetadata {
            description: "Encode a JSON string as core-deterministic CBOR".into(),
            return_type: Some(DataType::Binary),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "json",
            0,
            "The JSON text to encode as CBOR.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Binary))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out: Vec<Option<Vec<u8>>> = Vec::with_capacity(rows);
        for i in 0..rows {
            let s = blob_bytes(col, i)?
                .and_then(|b| std::str::from_utf8(b).ok())
                .and_then(|s| json::from_json_str(s).ok());
            out.push(s);
        }
        let arr = arrow_io::binary_array(&out);
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

/// `untag(blob, tag) -> JSON` — value(s) carried under `tag`, as a JSON array.
pub struct Untag;

impl ScalarFunction for Untag {
    fn name(&self) -> &str {
        "untag"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "CBOR Untag",
            "Return a JSON array of every value carried under semantic `tag` in the CBOR blob, in \
             document order (an empty array if the tag is absent). Complements `tags`, which lists \
             all tags; `untag` projects one. Returns NULL for a malformed blob.",
            "Pull the value(s) under a given CBOR tag → JSON array. Complements `tags`.",
            "cbor, untag, tag, rfc 8949, extract, json",
            "tags",
        );
        tags.push((
            "vgi.example_queries".into(),
            "[{\"description\":\"Pull the value under tag 1 (epoch time).\",\"sql\":\"SELECT cbor.main.untag(from_hex('c11a514b67b0'), 1) AS v\"}]".into(),
        ));
        FunctionMetadata {
            description: "Return the value(s) under a CBOR semantic tag as a JSON array".into(),
            return_type: Some(DataType::Utf8),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::any_column("blob", 0, "A CBOR-encoded BLOB to search for `tag`."),
            ArgSpec::const_arg(
                "tag",
                1,
                "uint64",
                "The semantic tag number to extract (e.g. 0, 1, 2, 32).",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let tag = params
            .arguments
            .const_i64(1)
            .ok_or_else(|| ve("untag: a constant tag number is required"))?
            as u64;
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out: Vec<Option<String>> = Vec::with_capacity(rows);
        for i in 0..rows {
            out.push(blob_bytes(col, i)?.and_then(|b| tags::untag(b, tag).ok()));
        }
        let arr = arrow_io::string_array(&out);
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

/// `encode(value, mode := 'shortest') -> BLOB` — DuckDB value → CBOR.
pub struct Encode {
    /// Whether this overload accepts the optional positional `mode` argument.
    pub with_mode: bool,
}

impl ScalarFunction for Encode {
    fn name(&self) -> &str {
        "encode"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "CBOR Encode",
            "Encode a DuckDB value as CBOR (RFC 8949). Numeric → shortest-lossless major type; \
             TIMESTAMP/TIMESTAMPTZ → tag 1 (epoch); BLOB → byte string; STRUCT → string-keyed \
             map; LIST → array; MAP → map. The optional `mode` is 'shortest' (default), \
             'canonical_core' (RFC 8949 §4.2.1 ordering), or 'canonical_ctap2' (CTAP2 ordering). \
             Returns NULL if the value cannot be encoded.",
            "Encode a DuckDB value as CBOR. `mode` ∈ {shortest, canonical_core, canonical_ctap2}.",
            "cbor, encode, serialize, struct, list, timestamp, canonical, ctap2, rfc 8949",
            "codec",
        );
        let example = if self.with_mode {
            "[{\"description\":\"Encode a struct to canonical-core CBOR.\",\"sql\":\"SELECT to_hex(cbor.main.encode({'a': 1, 'b': 2}, 'canonical_core')) AS h\"}]"
        } else {
            "[{\"description\":\"Encode a struct to CBOR.\",\"sql\":\"SELECT to_hex(cbor.main.encode({'a': 1, 'b': 2})) AS h\"}]"
        };
        tags.push(("vgi.example_queries".into(), example.into()));
        FunctionMetadata {
            description: if self.with_mode {
                "Encode a DuckDB value as CBOR with an explicit mode (shortest / canonical_core / canonical_ctap2)"
            } else {
                "Encode a DuckDB value as CBOR (shortest form)"
            }
            .into(),
            return_type: Some(DataType::Binary),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::any_column(
            "value",
            0,
            "The DuckDB value to encode as CBOR.",
        )];
        if self.with_mode {
            specs.push(
                ArgSpec::const_arg(
                    "mode",
                    1,
                    "varchar",
                    "How to encode: plain shortest-form, or a deterministic canonical ordering.",
                )
                .with_choices(ENCODE_MODES)
                .with_default("shortest"),
            );
        }
        specs
    }

    fn on_bind(&self, params: &BindParams) -> Result<BindResponse> {
        if let Some(mode) = params.arguments.const_str(1) {
            parse_encode_mode(&mode)?;
        }
        Ok(BindResponse::result(DataType::Binary))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let mode = params
            .arguments
            .const_str(1)
            .map(|m| parse_encode_mode(&m))
            .transpose()?
            .unwrap_or(EncodeMode::Shortest);
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out: Vec<Option<Vec<u8>>> = Vec::with_capacity(rows);
        for i in 0..rows {
            if col.is_null(i) {
                out.push(None);
                continue;
            }
            let value = value_at(col, i)?;
            let value = match mode {
                EncodeMode::Shortest => value,
                EncodeMode::Core => encode::canonicalize(value, encode::Canon::Core),
                EncodeMode::Ctap2 => encode::canonicalize(value, encode::Canon::Ctap2),
            };
            out.push(encode::encode_value(&value).ok());
        }
        let arr = arrow_io::binary_array(&out);
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[derive(Clone, Copy)]
enum EncodeMode {
    Shortest,
    Core,
    Ctap2,
}

fn parse_encode_mode(mode: &str) -> Result<EncodeMode> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "shortest" => Ok(EncodeMode::Shortest),
        "canonical_core" | "core" => Ok(EncodeMode::Core),
        "canonical_ctap2" | "ctap2" => Ok(EncodeMode::Ctap2),
        other => Err(ve(format!(
            "encode: unknown mode '{other}' (expected shortest | canonical_core | canonical_ctap2)"
        ))),
    }
}

/// `canonical(blob, mode := 'core') -> BLOB` — re-encode deterministically.
pub struct Canonical {
    /// Whether this overload accepts the optional positional `mode` argument.
    pub with_mode: bool,
}

impl ScalarFunction for Canonical {
    fn name(&self) -> &str {
        "canonical"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "CBOR Canonicalize",
            "Re-encode a CBOR blob into a deterministic form. `mode` is 'core' (default, RFC 8949 \
             §4.2.1: shortest integers, map keys sorted by encoded-byte order) or 'ctap2' (CTAP2 \
             canonical CBOR: keys sorted length-first then bytewise — required to recompute \
             WebAuthn signatures). Idempotent and round-trips through `decode`. NULL on malformed \
             input.",
            "Deterministically re-encode CBOR. `mode` ∈ {core, ctap2}. Idempotent.",
            "cbor, canonical, deterministic, ctap2, rfc 8949, re-encode, sort keys, webauthn",
            "codec",
        );
        let example = if self.with_mode {
            "[{\"description\":\"Canonicalize a map with CTAP2 ordering.\",\"sql\":\"SELECT to_hex(cbor.main.canonical(from_hex('a2616201616101'), 'ctap2')) AS h\"}]"
        } else {
            "[{\"description\":\"Canonicalize a map's key order (core).\",\"sql\":\"SELECT to_hex(cbor.main.canonical(from_hex('a2616201616101'))) AS h\"}]"
        };
        tags.push(("vgi.example_queries".into(), example.into()));
        FunctionMetadata {
            description: if self.with_mode {
                "Re-encode CBOR into a deterministic form with an explicit mode (core / ctap2)"
            } else {
                "Re-encode CBOR into a deterministic core form (RFC 8949 §4.2.1)"
            }
            .into(),
            return_type: Some(DataType::Binary),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::any_column(
            "blob",
            0,
            "A CBOR-encoded BLOB to canonicalize.",
        )];
        if self.with_mode {
            specs.push(
                ArgSpec::const_arg(
                    "mode",
                    1,
                    "varchar",
                    "Which deterministic key ordering to apply: RFC 8949 §4.2.1 core, or CTAP2.",
                )
                .with_choices(CANONICAL_MODES)
                .with_default("core"),
            );
        }
        specs
    }

    fn on_bind(&self, params: &BindParams) -> Result<BindResponse> {
        if let Some(mode) = params.arguments.const_str(1) {
            encode::Canon::parse(&mode).map_err(ve)?;
        }
        Ok(BindResponse::result(DataType::Binary))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let mode = params
            .arguments
            .const_str(1)
            .map(|m| encode::Canon::parse(&m).map_err(ve))
            .transpose()?
            .unwrap_or(encode::Canon::Core);
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out: Vec<Option<Vec<u8>>> = Vec::with_capacity(rows);
        for i in 0..rows {
            out.push(blob_bytes(col, i)?.and_then(|b| encode::canonical(b, mode).ok()));
        }
        let arr = arrow_io::binary_array(&out);
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
