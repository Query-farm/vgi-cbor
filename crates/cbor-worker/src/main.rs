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

use vgi::catalog::{CatSchema, CatView, CatalogModel};
use vgi::Worker;

/// The browsable `cose_registry` view: the worker's built-in IANA COSE registry
/// (algorithms, key types, curves) exposed as a plain, credential-free relation.
///
/// A worker whose surface is entirely LATERAL table functions gives an agent
/// nothing to *browse* — it must already know a function's arguments before it
/// can see any data (VGI146). This view is the cheap discovery entry point: it
/// is the exact `(id → name)` mapping the COSE decoders (`cose_headers.alg`,
/// `cose_key.kty` / `.crv`) emit, sourced from the same
/// `cbor_core::security::registry` tables so the SQL a caller can browse and the
/// names the decoders produce cannot drift apart. It is defined over a literal
/// `VALUES` list, so it scans in-engine with no worker round-trip.
fn cose_registry_view() -> CatView {
    use cbor_core::security::registry::{ALG_TABLE, CRV_TABLE, KTY_TABLE};

    let mut rows: Vec<String> = Vec::new();
    for (kind, table) in [("alg", ALG_TABLE), ("kty", KTY_TABLE), ("crv", CRV_TABLE)] {
        for (id, name) in table {
            // Registry names carry no single quotes today; escape defensively so
            // the generated view definition can never be malformed.
            let escaped = name.replace('\'', "''");
            rows.push(format!("('{kind}',{id},'{escaped}')"));
        }
    }
    let definition = format!(
        "SELECT registry, id, name FROM (VALUES {}) AS t(registry, id, name)",
        rows.join(", ")
    );

    CatView {
        name: "cose_registry".to_string(),
        definition,
        comment: Some(
            "IANA COSE registry (algorithms, key types, and curves) as a browsable lookup table: \
             the numeric-label → name mapping the COSE / COSE_Key decoders apply."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "IANA COSE Registry (alg / kty / crv)".to_string(),
            ),
            // Classifying tag (VGI123) reusing the schema's `domain` vocabulary,
            // and the navigation category (VGI411) — the view belongs with the
            // COSE / CWT security surface it documents.
            ("domain".to_string(), "security".to_string()),
            ("vgi.category".to_string(), "cose".to_string()),
            (
                "vgi.doc_llm".to_string(),
                "A browsable lookup table of the IANA COSE registries this worker knows: the \
                 signature/encryption/MAC/KDF algorithms (RFC 9053, e.g. -7 → ES256, -8 → EdDSA, \
                 5 → 'HMAC 256/256'), the key types (`kty`, e.g. 1 → OKP, 2 → EC2, 3 → RSA), and \
                 the elliptic curves (`crv`, e.g. 1 → P-256, 6 → Ed25519, 8 → secp256k1). Columns \
                 are `registry` ('alg' | 'kty' | 'crv'), the signed numeric `id`, and the standard \
                 `name`. It is exactly the mapping the `cose_headers`, `cose_decode`, and \
                 `cose_key` decoders apply when they turn the raw numeric COSE labels into names, \
                 so you can join a decoded id back to its name, discover which algorithms are \
                 recognized, or reverse a name to its numeric label — no CBOR blob required to get \
                 started."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "## cose_registry\n\nThe IANA COSE registries the worker recognizes, as a plain \
                 browsable table.\n\n| column | type | description |\n|---|---|---|\n| `registry` \
                 | VARCHAR | Which registry: `alg`, `kty`, or `crv`. |\n| `id` | BIGINT | The \
                 signed numeric COSE label (algorithm ids are typically negative). |\n| `name` | \
                 VARCHAR | The standard IANA name (e.g. `ES256`, `EdDSA`, `EC2`, `P-256`). |\n\n\
                 This is the same numeric-label → name mapping the `cose_headers` / `cose_decode` \
                 / `cose_key` decoders apply, so a decoded `alg` id or `kty` joins straight back \
                 to its name here."
                    .to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                meta::keywords_json(
                    "cose, iana, registry, algorithm, alg, kty, key type, crv, curve, es256, \
                     eddsa, ec2, okp, p-256, ed25519, rfc 9053, lookup, reference",
                ),
            ),
            (
                "vgi.example_queries".to_string(),
                "[{\"description\":\"The COSE signature algorithms this worker recognizes, by id.\",\
                  \"sql\":\"SELECT id, name FROM cbor.main.cose_registry WHERE registry = 'alg' ORDER BY id\"},\
                  {\"description\":\"Reverse a COSE algorithm name to its numeric label.\",\
                  \"sql\":\"SELECT id FROM cbor.main.cose_registry WHERE registry = 'alg' AND name = 'ES256'\"}]"
                    .to_string(),
            ),
        ],
        column_comments: vec![
            (
                "registry".to_string(),
                "Which IANA COSE registry the row belongs to: 'alg', 'kty', or 'crv'.".to_string(),
            ),
            (
                "id".to_string(),
                "The signed numeric COSE label (algorithm ids are typically negative, e.g. -7 for \
                 ES256)."
                    .to_string(),
            ),
            (
                "name".to_string(),
                "The standard IANA name for the label (e.g. ES256, EdDSA, EC2, P-256).".to_string(),
            ),
        ],
    }
}

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
                r#"[{"name": "cbor_to_json", "prompt": "I have a CBOR-encoded value stored as the hex string '83010203'. Convert the raw CBOR bytes into their JSON text representation.", "reference_sql": "SELECT cbor.main.to_json(from_hex('83010203')) AS json", "ignore_column_names": true}, {"name": "json_to_cbor", "prompt": "Encode the JSON array [1,2,3] as CBOR bytes and return the result as an uppercase hex string.", "reference_sql": "SELECT to_hex(cbor.main.from_json('[1,2,3]')) AS hex", "ignore_column_names": true}, {"name": "cbor_decode_map", "prompt": "This hex string is a CBOR-encoded map: 'a1616101'. Decode it to its JSON representation.", "reference_sql": "SELECT cbor.main.decode(from_hex('a1616101'), 'json') AS d", "ignore_column_names": true}, {"name": "cbor_diagnostic", "prompt": "Render the CBOR blob with hex 'c11a514b67b0' in human-readable CBOR diagnostic notation (EDN).", "reference_sql": "SELECT cbor.main.diagnostic(from_hex('c11a514b67b0')) AS edn", "ignore_column_names": true}, {"name": "cbor_encode_roundtrip", "prompt": "Take the structured value {'a': 1, 'b': 2}, serialize it to CBOR bytes, and then render those bytes back to JSON to confirm the round-trip.", "reference_sql": "SELECT cbor.main.to_json(cbor.main.encode({'a': 1, 'b': 2})) AS j", "ignore_column_names": true}, {"name": "cbor_canonical", "prompt": "This CBOR map has its keys out of deterministic order: 'a2616201616101'. Re-encode it into RFC 8949 canonical (deterministic) form and return the resulting bytes as an uppercase hex string.", "reference_sql": "SELECT to_hex(cbor.main.canonical(from_hex('a2616201616101'))) AS h", "ignore_column_names": true}, {"name": "cbor_is_valid", "prompt": "Is the CBOR blob with hex '01ff' a single, valid CBOR item with no trailing bytes? Return a single boolean.", "reference_sql": "SELECT cbor.main.is_valid(from_hex('01ff')) AS ok", "ignore_column_names": true}, {"name": "cbor_well_formed", "prompt": "Determine whether the CBOR blob with hex '83010203' is well-formed. Return a single boolean.", "reference_sql": "SELECT (cbor.main.well_formed(from_hex('83010203'))).ok AS ok", "ignore_column_names": true}, {"name": "cbor_tag_number", "prompt": "What CBOR semantic tag number wraps the top-level value in the blob with hex 'c11a514b67b0'?", "reference_sql": "SELECT (cbor.main.tags(from_hex('c11a514b67b0'))[1]).tag AS tag", "ignore_column_names": true}, {"name": "cbor_untag", "prompt": "The CBOR blob 'c11a514b67b0' carries a value under semantic tag 1. Extract the value(s) carried under tag 1 as a JSON array.", "reference_sql": "SELECT cbor.main.untag(from_hex('c11a514b67b0'), 1) AS v", "ignore_column_names": true}, {"name": "cbor_sequence_expand", "prompt": "The hex string '010203' is a CBOR Sequence containing three separate top-level items. Return one row per item, giving each item's zero-based position and its decoded value.", "reference_sql": "SELECT idx, value FROM cbor.main.seq_decode(from_hex('010203')) ORDER BY idx", "ignore_column_names": true, "unordered": true}, {"name": "msgpack_to_json", "prompt": "This is a MessagePack-encoded value stored as hex '93010203'. Render it as JSON text.", "reference_sql": "SELECT cbor.main.msgpack_to_json(from_hex('93010203')) AS j", "ignore_column_names": true}, {"name": "msgpack_decode_map", "prompt": "Decode the MessagePack map with hex '81a16101' into its JSON representation.", "reference_sql": "SELECT cbor.main.msgpack_decode(from_hex('81a16101')) AS d", "ignore_column_names": true}, {"name": "msgpack_encode", "prompt": "Encode the array [1,2,3] as MessagePack bytes and return the result as an uppercase hex string.", "reference_sql": "SELECT to_hex(cbor.main.msgpack_encode([1,2,3])) AS h", "ignore_column_names": true}, {"name": "msgpack_to_cbor", "prompt": "Transcode the MessagePack blob with hex '93010203' into the equivalent CBOR bytes and return them as an uppercase hex string.", "reference_sql": "SELECT to_hex(cbor.main.msgpack_to_cbor(from_hex('93010203'))) AS h", "ignore_column_names": true}, {"name": "cose_message_type", "prompt": "What kind of COSE message is the CBOR blob with hex 'd28443a10126a2182142aabb1822822642ccdd445249534b43010203'? Return the COSE message type name.", "reference_sql": "SELECT (cbor.main.cose_decode(from_hex('d28443a10126a2182142aabb1822822642ccdd445249534b43010203'))).msg_type AS mt", "ignore_column_names": true}, {"name": "cose_algorithm", "prompt": "Extract the signature algorithm named in the COSE header of the message with hex 'd28443a10126a2182142aabb1822822642ccdd445249534b43010203'. Return the algorithm name.", "reference_sql": "SELECT (cbor.main.cose_headers(from_hex('d28443a10126a2182142aabb1822822642ccdd445249534b43010203'))).alg AS alg", "ignore_column_names": true}, {"name": "cose_payload_length", "prompt": "Recover the payload carried by the COSE_Sign1 message with hex 'd28443a10126a2182142aabb1822822642ccdd445249534b43010203' and return its length in bytes.", "reference_sql": "SELECT octet_length(cbor.main.cose_payload(from_hex('d28443a10126a2182142aabb1822822642ccdd445249534b43010203'))) AS n", "ignore_column_names": true}, {"name": "cose_x5t_thumbprint", "prompt": "The COSE message with hex 'd28443a10126a2182142aabb1822822642ccdd445249534b43010203' carries an x5t certificate thumbprint in its header. Return that thumbprint as a hex string.", "reference_sql": "SELECT cbor.main.cose_x5t(from_hex('d28443a10126a2182142aabb1822822642ccdd445249534b43010203')) AS x5t", "ignore_column_names": true}, {"name": "cose_x5chain_count", "prompt": "How many certificates are in the x5chain embedded in the header of the COSE message with hex 'd28443a10126a2182142aabb1822822642ccdd445249534b43010203'?", "reference_sql": "SELECT len(cbor.main.cose_x5chain(from_hex('d28443a10126a2182142aabb1822822642ccdd445249534b43010203'))) AS n", "ignore_column_names": true}, {"name": "cose_key_type", "prompt": "The CBOR blob with hex 'a3010203262001' is a COSE_Key. What is its key type (kty)? Return the key type name.", "reference_sql": "SELECT (cbor.main.cose_key(from_hex('a3010203262001'))).kty AS kty", "ignore_column_names": true}, {"name": "cwt_issuer_claim", "prompt": "The hex string 'a10169636f61703a2f2f6173' is a CBOR Web Token (CWT) claim set. Extract its issuer (iss) claim as text.", "reference_sql": "SELECT (cbor.main.cwt_claims(from_hex('a10169636f61703a2f2f6173'))).iss AS iss", "ignore_column_names": true}, {"name": "webauthn_authdata_signcount", "prompt": "This is WebAuthn authenticator data stored as hex '00000000000000000000000000000000000000000000000000000000000000000100000005'. What is its signature counter value?", "reference_sql": "SELECT (cbor.main.webauthn_authdata(from_hex('00000000000000000000000000000000000000000000000000000000000000000100000005'))).sign_count AS sc", "ignore_column_names": true}, {"name": "webauthn_attestation_fmt", "prompt": "The hex string 'a363666d74667061636b65646761747453746d74a363616c67266373696742dead637835638143300100686175746844617461588700000000000000000000000000000000000000000000000000000000000000004100000007111111111111111111111111111111110003cafe01a5010203262001215820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa225820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' is a WebAuthn attestation object. Return its attestation statement format and the authenticator AAGUID.", "reference_sql": "SELECT fmt, aaguid FROM cbor.main.webauthn_attestation(from_hex('a363666d74667061636b65646761747453746d74a363616c67266373696742dead637835638143300100686175746844617461588700000000000000000000000000000000000000000000000000000000000000004100000007111111111111111111111111111111110003cafe01a5010203262001215820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa225820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'))", "ignore_column_names": true}, {"name": "cose_registry_lookup", "prompt": "According to this worker's built-in COSE registry, what is the standard name of the signature algorithm whose numeric COSE label is -7?", "reference_sql": "SELECT name FROM cbor.main.cose_registry WHERE registry = 'alg' AND id = -7", "ignore_column_names": true}, {"name": "worker_version_present", "prompt": "This worker can report its own build/version identifier. Return TRUE if that reported version string is non-empty.", "reference_sql": "SELECT length(cbor.main.cbor_version()) > 0 AS ok", "ignore_column_names": true}]"#
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
            views: vec![cose_registry_view()],
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
