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
                "Decode and encode CBOR (RFC 8949) and MessagePack binary blobs in SQL, with \
                 first-class STRUCT decoders for the security payloads that ride on CBOR: COSE \
                 (RFC 9052) signed/encrypted objects, CWT (RFC 8392) tokens, COSE_Key, and \
                 WebAuthn / FIDO2 / CTAP2 attestation. `to_json` / `diagnostic` render any blob; \
                 `decode` returns the richest form; `encode` / `from_json` / `canonical` go the \
                 other way (shortest, RFC 8949 core, or CTAP2 canonical). `tags` / `untag` walk \
                 semantic tags. `is_valid` / `well_formed` give untrusted-input-safe \
                 well-formedness checks that never crash the scan. The MessagePack mirror \
                 (`msgpack_to_json`, `msgpack_decode`, `msgpack_encode`, `msgpack_to_cbor`) \
                 transcodes the sibling format. The security decoders — `cose_decode`, \
                 `cose_payload`, `cose_headers`, `cose_x5t`, `cose_x5chain`, `cose_key`, \
                 `cwt_claims`, `webauthn_authdata`, and the `webauthn_attestation` LATERAL table \
                 function — explode tokens into typed columns you can join to `vgi-x509` cert \
                 tables at fleet scale. `seq_decode` fans a CBOR Sequence (RFC 8742) into rows. \
                 Structural decode only — NO cryptographic verification or decryption. Pure \
                 in-engine compute over a BLOB column: no network, no state, zero egress."
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
                    "Functions for CBOR / MessagePack / COSE / CWT / WebAuthn. Codec: `to_json`, \
                     `decode`, `diagnostic`, `from_json`, `encode`, `canonical`, `tags`, `untag`, \
                     `is_valid`, `well_formed`. MessagePack: `msgpack_to_json`, `msgpack_decode`, \
                     `msgpack_encode`, `msgpack_to_cbor`. Security: `cose_decode`, `cose_payload`, \
                     `cose_headers`, `cose_x5t`, `cose_x5chain`, `cose_key`, `cwt_claims`, \
                     `webauthn_authdata`. Table functions: `webauthn_attestation` (LATERAL \
                     fan-out) and `seq_decode` (CBOR Sequence). Structural decode only — no crypto."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "The single schema for the `cbor` worker — the catalog name matches the \
                     `ATTACH` name, so qualify calls as `cbor.main.<fn>(...)`. Holds the CBOR / \
                     MessagePack codec scalars, the COSE / CWT / COSE_Key / WebAuthn structural \
                     decoders, and the `webauthn_attestation` / `seq_decode` LATERAL table \
                     functions."
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
