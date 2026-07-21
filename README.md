# vgi-cbor

Decode and encode **CBOR** (RFC 8949) and **MessagePack** binary blobs in DuckDB
with SQL — and, the part DuckDB can't do natively, **tag-aware structural
decoders** for the security payloads that ride on CBOR: **COSE** (RFC 9052)
signed/encrypted objects, **CWT** (RFC 8392) tokens, **COSE_Key**, and
**WebAuthn / FIDO2 / CTAP2** attestation. Explode tokens into typed columns and
join COSE `x5t`/`x5chain` and WebAuthn `x5c` against your cert tables
(`vgi-x509`) — across millions of rows, at scan time.

It runs as a [VGI worker](https://query.farm): a small standalone binary that
DuckDB launches and talks to over Apache Arrow. You `ATTACH` it and call its
functions like any other. Pure in-engine scalar/table compute over a `BLOB`
column — **no network, no state, zero egress** (safe for air-gapped / regulated
data).

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'cbor' (TYPE vgi, LOCATION './target/release/cbor-worker');
SET search_path = 'cbor.main';

SELECT to_json(from_hex('83010203'));        -- [1,2,3]
SELECT diagnostic(from_hex('c11a514b67b0')); -- 1(1363896240)
```

> **Structural decode only.** This worker performs **no cryptographic
> verification** of COSE/CWT signatures or MACs and **no decryption** — by
> design, so it ships no key management and no egress. A downstream verifier (or
> a future `vgi-cose-verify`) consumes `cose_payload` + `cose_key`.

---

## Quick start

**1. Get the worker binary.** Download a prebuilt archive from the
[Releases page](https://github.com/Query-farm/vgi-cbor/releases) for your
platform (`vgi-cbor-<version>-<platform>.tar.gz`, where `<platform>` is one of
`linux_amd64`, `linux_arm64`, `osx_amd64`, `osx_arm64`, `windows_amd64`) and
unpack the `cbor-worker` executable…

```sh
tar -xzf vgi-cbor-<version>-osx_arm64.tar.gz   # → cbor-worker
```

…or build it from source (needs Rust 1.90+):

```sh
cargo build --release          # produces target/release/cbor-worker
```

**2. Attach it in DuckDB** (the `vgi` community extension provides `TYPE vgi`):

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'cbor' (TYPE vgi, LOCATION '/path/to/cbor-worker');
SET search_path = 'cbor.main';   -- so you can call functions unqualified
```

The catalog name you `ATTACH` as (`cbor` here) is what you qualify calls with:
`cbor.main.<fn>(...)`.

---

## What you can do

### 1. Decode a CBOR blob to JSON / diagnostic notation

```sql
SELECT cbor.decode(payload)      AS as_struct,   -- richest typed form (JSON in v1, see notes)
       cbor.to_json(payload)     AS as_json,     -- canonical JSON
       cbor.diagnostic(payload)  AS edn          -- RFC 8949 diagnostic notation
FROM read_blob('s3://iot/telemetry/*.cbor');
```

### 2. MessagePack round-trip + encode a struct back to CBOR

```sql
SELECT cbor.msgpack_to_json(frame)                     AS decoded,
       cbor.encode({temp: 21.5, unit: 'C', ts: now()}) AS cbor_bytes
FROM device_frames;
```

### 3. Explode a WebAuthn attestation object and join to a cert table

```sql
SELECT w.fmt, w.aaguid, w.sign_count, w.rp_id_hash, x.subject_cn
FROM webauthn_enrollments e,
     LATERAL cbor.webauthn_attestation(e.att_obj) w
LEFT JOIN x509_certs x ON x.fingerprint = cbor.cose_x5t(w.att_stmt);
```

### 4. Verify-free COSE / CWT inspection (structural unwrap, not crypto)

```sql
SELECT cbor.cose_decode(token) AS cose, cbor.cwt_claims(token) AS claims
FROM cwt_tokens;
```

---

## Function reference

All functions live in catalog `cbor`, schema `main`.

| Area | Functions |
| --- | --- |
| **CBOR decode** | `decode(blob[,mode])` → JSON · `to_json(blob)` → JSON · `diagnostic(blob)` → VARCHAR (EDN) |
| **CBOR encode** | `encode(value[,mode])` → BLOB · `canonical(blob[,mode])` → BLOB · `from_json(json)` → BLOB |
| **MessagePack** | `msgpack_decode(blob)` → JSON · `msgpack_to_json(blob)` → JSON · `msgpack_encode(value)` → BLOB · `msgpack_to_cbor(blob)` → BLOB |
| **Tags** | `tags(blob)` → `LIST<STRUCT(tag UBIGINT, path VARCHAR, value JSON)>` · `untag(blob, tag)` → JSON |
| **Validate** | `is_valid(blob)` → BOOLEAN · `well_formed(blob)` → `STRUCT(ok, error, kind)` |
| **COSE** | `cose_decode(blob)` → STRUCT · `cose_payload(blob)` → BLOB · `cose_headers(blob)` → STRUCT · `cose_x5t(blob)` → VARCHAR · `cose_x5chain(blob)` → `LIST<BLOB>` |
| **CWT** | `cwt_claims(blob)` → `STRUCT(iss, sub, aud, exp, nbf, iat, cti, extra)` |
| **COSE_Key** | `cose_key(blob)` → `STRUCT(kty, kid, alg, crv, x, y, n, e)` |
| **WebAuthn** | `webauthn_authdata(blob)` → STRUCT · `webauthn_attestation(blob)` → TABLE (LATERAL) |
| **Sequences** | `seq_decode(blob)` → TABLE `(idx BIGINT, value JSON)` (RFC 8742, LATERAL) |

The worker's own build version is published as the catalog's
`implementation_version` (read it from `vgi_catalogs()` / `duckdb_databases()`),
not as a scalar function.

`mode` arguments: `decode` ∈ {auto, struct, map, json}; `encode` ∈ {shortest,
canonical_core, canonical_ctap2}; `canonical` ∈ {core, ctap2}. Each
optional-`mode` function ships a 1-argument and a 2-argument overload.

### COSE message shapes

`cose_decode` recognizes the tagged (and untagged) COSE arrays and names the
common header labels (`alg` as its IANA name — `ES256`, `EdDSA`, `A256GCM`, …):

| Tag | Type | Array shape |
| --- | --- | --- |
| 18 | COSE_Sign1 | `[protected, unprotected, payload, signature]` |
| 98 | COSE_Sign | `[protected, unprotected, payload, [signatures]]` |
| 16 | COSE_Encrypt0 | `[protected, unprotected, ciphertext]` |
| 96 | COSE_Encrypt | `[…, [recipients]]` |
| 17 | COSE_Mac0 | `[protected, unprotected, payload, tag]` |
| 97 | COSE_Mac | `[…, [recipients]]` |
| 61 | CWT | tagged COSE message wrapping a claim set |

---

## Notes & limitations

- **`decode` returns JSON in v1.** A DuckDB scalar function fixes its output
  column type at *bind* time, with no data sample available, so the spec's
  per-scan STRUCT/MAP inference cannot be realized for a runtime `BLOB` column.
  `decode` therefore returns canonical JSON text (the stable, lossless column
  type) for every `mode`. For typed projection of a *known* shape, use the
  structural decoders (`cose_decode` / `cwt_claims` / `cose_key` /
  `webauthn_authdata`), whose schemas are fixed and fully typed.
- **JSON columns** are published as `VARCHAR` carrying canonical JSON text
  (DuckDB casts to `JSON` on demand). Byte strings render as base64url; `decode`
  is the lossless path.
- **Untrusted-input hardening.** Every decoder captures errors per row — a
  malformed or hostile blob yields a NULL (or `well_formed(ok=false, kind=…)`),
  never a panic that crashes the scan. Recursion is bounded (`nesting-limit`) so
  a deeply-nested blob can't stack-overflow the worker. A `cargo test` proptest
  gate fuzzes every decoder on arbitrary and truncated bytes with a **zero-panic**
  assertion.
- **No crypto, no network, no state.** Signature/MAC verification, COSE_Encrypt
  decryption, and CDDL validation are explicit non-goals (see the build spec).

---

## Development

```sh
cargo build --release          # build the worker
cargo test                     # unit (RFC fixtures) + proptest fuzz
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
./run_tests.sh                 # haybarn SQLLogic E2E (needs the vgi community ext)
```

The repo is a Cargo workspace: `crates/cbor-core` is the pure-compute codec /
security library (no Arrow / VGI deps, independently testable), and
`crates/cbor-worker` maps it onto DuckDB's Arrow type system and serves the VGI
protocol.

Built on the published VGI Rust SDK (`vgi = "0.9.5"`, arrow 59). The CBOR codec
is [`ciborium`](https://crates.io/crates/ciborium) and MessagePack is
[`rmpv`](https://crates.io/crates/rmpv) — all permissive (Apache-2.0 / MIT), no
copyleft.

## License

MIT — see [LICENSE](LICENSE). Copyright 2026 Query Farm LLC.

CBOR / COSE / CWT / WebAuthn / CTAP2 are open IETF / W3C / FIDO standards.
