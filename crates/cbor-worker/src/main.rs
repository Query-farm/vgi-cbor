//! The `cbor` VGI worker.
//!
//! A standalone binary DuckDB launches and talks to over Apache Arrow IPC. It
//! brings CBOR (RFC 8949) / MessagePack decode & encode, plus tag-aware COSE
//! (RFC 9052) / CWT (RFC 8392) / WebAuthn structural decode, to SQL under the
//! catalog `cbor`, schema `main`.

mod arrow_io;
mod meta;
mod scalar;
mod table;
mod value_in;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Catalog + schema metadata surfaced to DuckDB and the `vgi-lint` metadata
/// linter. The function objects themselves are served from the registered
/// scalars / table functions.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "CBOR (RFC 8949) / MessagePack decode & encode plus tag-aware COSE / CWT / WebAuthn \
             structural decode for SQL."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "CBOR / MessagePack / COSE / CWT / WebAuthn Codec".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                meta::keywords_json(
                    "cbor, rfc 8949, messagepack, msgpack, cose, rfc 9052, cwt, rfc 8392, \
                     webauthn, fido2, ctap2, attestation, aaguid, cose_key, decode, encode, \
                     diagnostic, edn, canonical, ctap2 canonical, tags, x5chain, x5t, x509, \
                     iot, telemetry, binary, serialization",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Read, write, and reshape CBOR (RFC 8949) and MessagePack binary payloads from \
                 SQL, and structurally explode the security tokens that ride on CBOR — COSE \
                 (RFC 9052) signed/encrypted objects, CWT (RFC 8392) tokens, COSE keys, and \
                 WebAuthn / FIDO2 / CTAP2 attestation — into typed, queryable columns. The \
                 commodity byte codec (render to JSON or diagnostic notation, parse back, \
                 canonicalize, walk semantic tags, and check untrusted-input well-formedness) is \
                 the entry point; the real value is turning opaque credential and IoT-telemetry \
                 blobs into relational data at fleet scale — for example lifting an embedded \
                 certificate chain or thumbprint out of a COSE header to join against an X.509 \
                 worker. Everything is pure in-engine compute over a BLOB column: no network, no \
                 persisted state, and — importantly — structural decode ONLY, with no \
                 cryptographic signature/MAC verification and no decryption. Reach for this \
                 worker whenever a column holds CBOR, MessagePack, COSE, CWT, or WebAuthn bytes \
                 and you need to inspect, validate, flatten, or re-encode them. List the \
                 schema to discover the individual functions."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# cbor\n\nDecode and encode **CBOR** (RFC 8949) and **MessagePack** in SQL, plus \
                 tag-aware structural decoders for **COSE** (RFC 9052), **CWT** (RFC 8392), \
                 **COSE_Key**, and **WebAuthn / FIDO2 / CTAP2** attestation. The byte codec is \
                 commodity; the value is the in-engine security-payload decode and the bulk SQL \
                 join surface (COSE `x5t`/`x5chain` and WebAuthn `x5c` join to `vgi-x509`). Pure \
                 scalar / table compute over a `BLOB` column — no network, no state, zero \
                 egress.\n\n**Structural decode only:** no signature/MAC verification and no \
                 decryption (a downstream verifier consumes `cose_payload` + `cose_key`)."
                    .to_string(),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-cbor/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-cbor/blob/main/README.md".to_string(),
            ),
            // Fixed agent-suitability suite (VGI152 / VGI920). Prompts are
            // natural-language and deliberately do NOT name a function, so the
            // suite measures how discoverable the worker is; the grader-only
            // reference_sql is deterministic (pure in-engine transforms over
            // fixed hex fixtures) and column-name/row-order tolerant.
            (
                "vgi.agent_test_tasks".to_string(),
                r#"[{"name":"cbor_to_json","prompt":"I have a CBOR-encoded value stored as the hex string '83010203'. Convert the raw CBOR bytes into their JSON text representation.","reference_sql":"SELECT cbor.main.to_json(from_hex('83010203')) AS json","ignore_column_names":true},{"name":"json_to_cbor_hex","prompt":"Encode the JSON array [1,2,3] as CBOR bytes and return the result as a lowercase hex string.","reference_sql":"SELECT to_hex(cbor.main.from_json('[1,2,3]')) AS hex","ignore_column_names":true},{"name":"cwt_issuer_claim","prompt":"The hex string 'a10169636f61703a2f2f6173' is a CBOR Web Token (CWT) claim set. Extract its issuer (iss) claim as text.","reference_sql":"SELECT (cbor.main.cwt_claims(from_hex('a10169636f61703a2f2f6173'))).iss AS iss","ignore_column_names":true},{"name":"cbor_well_formed","prompt":"Determine whether the CBOR blob with hex '83010203' is well-formed. Return a single boolean.","reference_sql":"SELECT (cbor.main.well_formed(from_hex('83010203'))).ok AS ok","ignore_column_names":true},{"name":"cbor_sequence_expand","prompt":"The hex string '010203' is a CBOR Sequence containing three separate top-level items. Return one row per item, giving each item's zero-based position and its decoded value.","reference_sql":"SELECT idx, value FROM cbor.main.seq_decode(from_hex('010203')) ORDER BY idx","ignore_column_names":true,"unordered":true},{"name":"cbor_diagnostic","prompt":"Render the CBOR blob with hex 'c11a514b67b0' in human-readable CBOR diagnostic notation (EDN).","reference_sql":"SELECT cbor.main.diagnostic(from_hex('c11a514b67b0')) AS edn","ignore_column_names":true}]"#
                    .to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-cbor".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "CBOR / MessagePack / COSE / CWT / WebAuthn decode & encode functions.".to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "CBOR — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    meta::keywords_json(
                        "cbor, messagepack, cose, cwt, webauthn, decode, encode, to_json, \
                         diagnostic, canonical, tags, cose_decode, cwt_claims, cose_key, \
                         webauthn_attestation, seq_decode, x5chain, x5t",
                    ),
                ),
                ("domain".to_string(), "security".to_string()),
                ("category".to_string(), "parsing-and-serialization".to_string()),
                ("topic".to_string(), "cbor-cose-webauthn".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "The single schema for the `cbor` worker; qualify calls as \
                     `cbor.main.<fn>(...)`. It groups a commodity binary codec — CBOR and \
                     MessagePack rendered to and parsed from JSON, diagnostic (EDN) notation, \
                     canonical / core-deterministic re-encoding, semantic-tag inspection, and \
                     untrusted-input well-formedness checks that never crash the scan — with \
                     tag-aware structural decoders for the CBOR-based security payloads (COSE \
                     messages, CWT tokens, COSE keys, and WebAuthn authenticator data), plus \
                     LATERAL table functions that fan a CBOR Sequence or a WebAuthn attestation \
                     object into one row per item. All decode is structural only, with no \
                     cryptographic verification. List the schema to discover the individual \
                     functions and their signatures."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "## CBOR / MessagePack / security codec\n\n\
                     The single schema for the `cbor` worker. The catalog name matches the \
                     `ATTACH` name, so qualify calls as `cbor.main.<fn>(...)` (or \
                     `SET search_path='cbor.main'`).\n\n\
                     **Binary codec.** Render CBOR and MessagePack blobs to JSON or diagnostic \
                     (EDN) notation, parse them back, re-encode into canonical / \
                     core-deterministic forms, walk semantic tags, and run untrusted-input \
                     well-formedness checks that never crash a scan.\n\n\
                     **Security payloads.** Tag-aware structural decoders explode the CBOR-based \
                     credential formats — COSE messages, CWT tokens, COSE keys, and WebAuthn \
                     authenticator data — into typed columns, and LATERAL table functions fan a \
                     CBOR Sequence or a WebAuthn attestation object into one row per item.\n\n\
                     All decode is *structural only*: no signature/MAC verification and no \
                     decryption. List the schema to discover the individual functions and their \
                     signatures."
                        .to_string(),
                ),
                (
                    "vgi.categories".to_string(),
                    r#"[{"name":"codec","title":"Codec","description":"Encode and decode CBOR between binary blobs and SQL/JSON values (render to JSON, parse back, canonical/core-deterministic re-encoding)."},{"name":"validation","title":"Validation & diagnostics","description":"Human-readable diagnostic (EDN) rendering and untrusted-input well-formedness checks that never crash the scan."},{"name":"tags","title":"Semantic tags","description":"Inspect and strip CBOR semantic tags."},{"name":"messagepack","title":"MessagePack","description":"Decode, encode, and transcode the sibling MessagePack binary format."},{"name":"cose","title":"COSE / CWT security","description":"Structurally decode COSE (RFC 9052) messages, CWT (RFC 8392) tokens, and COSE keys into typed columns."},{"name":"webauthn","title":"WebAuthn / FIDO2","description":"Decode WebAuthn / FIDO2 / CTAP2 authenticator data and attestation objects."},{"name":"sequence","title":"CBOR sequences","description":"Fan a CBOR Sequence (RFC 8742) into one row per item."},{"name":"introspection","title":"Introspection","description":"Worker build and version metadata."}]"#
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    "SELECT cbor.main.to_json(from_hex('83010203'));\n\
                     SELECT cbor.main.diagnostic(from_hex('c11a514b67b0'));\n\
                     SELECT to_hex(cbor.main.from_json('[1,2,3]'));\n\
                     SELECT (cbor.main.well_formed(from_hex('83010203'))).ok;\n\
                     SELECT (cbor.main.cwt_claims(from_hex('a10169636f61703a2f2f6173'))).iss;\n\
                     SELECT idx, value FROM cbor.main.seq_decode(from_hex('010203'));"
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "cbor");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "cbor".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
