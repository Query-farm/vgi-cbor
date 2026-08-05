# vgi-cbor

Read, write, and explode **CBOR** (RFC 8949) and **MessagePack** in DuckDB with
SQL — and, the part DuckDB can't do natively, **tag-aware structural decoders**
for the security payloads that ride on CBOR: **COSE** (RFC 9052)
signed/encrypted objects, **CWT** (RFC 8392) tokens, **COSE_Key**, and
**WebAuthn / FIDO2 / CTAP2** attestation. Explode tokens into typed columns and
join COSE `x5t`/`x5chain` and WebAuthn `x5c` against your cert tables
(`vgi-x509`) — across millions of rows, at scan time.

It runs as a [VGI worker](https://query.farm): a small standalone binary that
DuckDB launches and talks to over Apache Arrow. You `ATTACH` it and call its
functions like any other. Pure in-engine compute — **no network, no state, zero
egress** (safe for air-gapped / regulated data).

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'cbor' (TYPE vgi, LOCATION './target/release/cbor-worker');
SET search_path = 'memory.main,cbor.main';

SELECT to_json(from_hex('83010203'));        -- [1,2,3]
SELECT diagnostic(from_hex('c11a514b67b0')); -- 1(1363896240)
```

> **Structural decode only.** This worker performs **no cryptographic
> verification** of COSE/CWT signatures or MACs and **no decryption** — by
> design, so it ships no key management and no egress. A downstream verifier (or
> a future `vgi-cose-verify`) consumes `cose_payload` + `cose_key`.

---

## Two ways to use it

The worker exposes the same codec through two surfaces. Which one you want
depends on where the bytes live.

**1. Functions — for CBOR that lives *inside* a column.** Your table already has
a `BLOB` (or `VARCHAR`) column holding CBOR, MessagePack, a COSE token, or a
WebAuthn attestation object, and you want to look inside it:

```sql
SELECT to_json(payload) FROM telemetry;
```

**2. COPY formats — for CBOR that *is* the file.** You want to bulk-load a
CBOR/MessagePack data file into a table, or dump a query out to one:

```sql
COPY events FROM 'events.cbor' (FORMAT 'cbor.cbor');
COPY (SELECT * FROM events) TO 'events.cbor' (FORMAT 'cbor.cbor');
```

These do not overlap: the functions never touch the filesystem, and COPY never
looks inside a column. Both are covered in full below.

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

…or build it from source (needs Rust 1.97+):

```sh
cargo build --release          # produces target/release/cbor-worker
```

**2. Attach it in DuckDB** (the `vgi` community extension provides `TYPE vgi`):

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'cbor' (TYPE vgi, LOCATION '/path/to/cbor-worker');
```

The catalog name you `ATTACH` as (`cbor` here) is what you qualify calls with:
`cbor.main.<fn>(...)`. It also scopes the COPY format names — `'cbor.cbor'` and
`'cbor.msgpack'`. Attach it as something else and those names follow.

To drop the qualification, put the worker's schema on the search path — but keep
your own database *first*, because the leading entry is also where `CREATE TABLE`
lands, and the worker's catalog is read-only:

```sql
SET search_path = 'memory.main,cbor.main';   -- your DB first, then the worker
SELECT to_json(payload) FROM telemetry;      -- now unqualified
```

---

## What you can do

### 1. Decode a CBOR blob to JSON / diagnostic notation

```sql
SELECT decode(payload)     AS as_struct,   -- richest typed form (JSON in v1, see notes)
       to_json(payload)    AS as_json,     -- canonical JSON
       diagnostic(payload) AS edn          -- RFC 8949 diagnostic notation
FROM read_blob('s3://iot/telemetry/*.cbor');
```

### 2. Screen untrusted blobs without crashing the scan

```sql
SELECT id, (well_formed(payload)).kind AS problem
FROM inbound
WHERE NOT is_valid(payload);          -- 'truncated', 'trailing-bytes', 'nesting-limit', …
```

### 3. MessagePack round-trip + encode a struct back to CBOR

```sql
SELECT msgpack_to_json(frame)                          AS decoded,
       encode({'temp': 21.5, 'unit': 'C', 'ts': now()}) AS cbor_bytes
FROM device_frames;
```

### 4. Explode a WebAuthn attestation object and join to a cert table

`webauthn_attestation` shreds each enrollment into typed columns — including the
attestation statement's certificate chain — under a correlated `LATERAL` join,
so the leaf certificate joins straight to your cert table:

```sql
SELECT e.id, w.fmt, w.aaguid, w.sign_count, w.alg, x.subject_cn
FROM webauthn_enrollments e,
     LATERAL webauthn_attestation(e.att_obj) w
LEFT JOIN x509_certs x ON x.der = w.x5c[1];   -- x5c is BLOB[], leaf first
```

A row whose blob is NULL or isn't a valid attestation object simply contributes
no rows.

For COSE messages the same join runs off the scalars — `cose_x5chain` returns
`BLOB[]`, so `unnest` fans the chain out per certificate:

```sql
SELECT m.id, (cose_headers(m.token)).alg, x.subject_cn
FROM cose_msgs m, unnest(cose_x5chain(m.token)) AS u(cert)
LEFT JOIN x509_certs x ON x.der = u.cert;
```

### 5. Verify-free COSE / CWT inspection (structural unwrap, not crypto)

```sql
SELECT cose_decode(token)         AS cose,
       cwt_claims(token)          AS claims,
       (cose_headers(token)).alg  AS algorithm
FROM cwt_tokens;
```

`webauthn_authdata` is the scalar counterpart for bare authenticator data:

```sql
SELECT (webauthn_authdata(auth_data)).sign_count AS counter,
       (webauthn_authdata(auth_data)).uv         AS user_verified
FROM webauthn_enrollments;
```

### 6. Bulk-load a CBOR row file into a table

```sql
CREATE TABLE events (id INTEGER, name VARCHAR, ts TIMESTAMP);
COPY events FROM 'events.cbor' (FORMAT 'cbor.cbor');
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
| **Reference** | `cose_registry` — a browsable view of the IANA COSE `alg` / `kty` / `crv` registries |
| **Bulk COPY** | `FORMAT 'cbor.cbor'` · `FORMAT 'cbor.msgpack'` — see [Bulk COPY formats](#bulk-copy-formats) |

The two table functions take their blob as a **per-row input column**, so one
call form covers everything: a literal
(`FROM seq_decode(from_hex('010203'))`), a whole column
(`FROM t, seq_decode(t.blob)`), or a correlated `LATERAL` join, which fans each
row's items out beside that row's own columns. A NULL or undecodable blob
contributes no rows rather than failing the scan. To load a whole *file* of CBOR
rows into a table, use the [COPY formats](#bulk-copy-formats) instead.

The worker's own build version is published as the catalog's
`implementation_version` (read it from `vgi_catalogs()` / `duckdb_databases()`),
not as a scalar function.

`mode` arguments: `decode` ∈ {auto, struct, map, json}; `encode` ∈ {shortest,
canonical_core, canonical_ctap2}; `canonical` ∈ {core, ctap2}. Each
optional-`mode` function ships a 1-argument and a 2-argument overload.

### COSE message shapes

`cose_decode` recognizes the tagged (and untagged) COSE arrays and names the
common header labels (`alg` as its IANA name — `ES256`, `EdDSA`, `A256GCM`, …).
`cose_registry` is the same mapping as a browsable table.

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

## Bulk COPY formats

Where the functions work one blob at a time, the COPY formats move whole tables.
Both `cbor` and `msgpack` serve **both directions under one format name**, so a
file written by `COPY … TO` loads back with `COPY … FROM`:

```sql
COPY (SELECT * FROM events ORDER BY ts) TO 'events.cbor' (FORMAT 'cbor.cbor');
COPY events FROM 'events.cbor' (FORMAT 'cbor.cbor');

COPY (SELECT * FROM events) TO 'events.mp' (FORMAT 'cbor.msgpack');
COPY events FROM 'events.mp' (FORMAT 'cbor.msgpack');
```

### File layout

A file is a bare concatenation of top-level items — **one item per row**, with no
container header or footer. That is a CBOR Sequence (RFC 8742) for `cbor` and a
MessagePack stream for `msgpack`, so files append and stream, and any conforming
reader can consume them. Rows are written in source order, so
`COPY (SELECT … ORDER BY …) TO` preserves it.

### Options

| Option | Direction | Values | Meaning |
| --- | --- | --- | --- |
| `row_format` | both | `map` (default), `array` | `map` frames each row as a map keyed by column name (self-describing); `array` frames it as an array of values in column order (compact, positional). |
| `ignore_errors` | FROM | BOOLEAN (default false) | Skip rows that can't be projected onto the target columns, and accept a truncated trailing item, instead of failing the COPY. |
| `canonical` | TO (`cbor` only) | `core`, `ctap2` | Emit deterministically ordered map keys (RFC 8949 §4.2.1 / CTAP2), so the same rows always produce byte-identical output. |

Under the default `map` framing the source columns may appear in any order, a key
absent from an item reads as `NULL`, and extra keys are ignored — so a file
survives the target table gaining or reordering columns. A value that can't be
represented in its target column fails the COPY with a message naming that
column.

### Type support

Values are encoded for **exactness**, not brevity: `DECIMAL` and sub-second
timestamps ride as CBOR decimal fractions (RFC 8949 §3.4.4) rather than doubles,
because a float cannot represent either without drift. Verified against DuckDB's
own `test_all_types()` fixture at each type's minimum, maximum, and `NULL` — see
`test/sql/copy_types.test`.

| | |
| --- | --- |
| **Numeric** | every signed and unsigned integer width, `FLOAT`, `DOUBLE` (including the non-finite values), `BIGNUM`, and `DECIMAL` at every width — including `DECIMAL(38,10)`, whose mantissa travels as a CBOR bignum |
| **Temporal** | `DATE` (tag 100, RFC 8943 epoch days), `TIME`, `TIME_NS`, and every `TIMESTAMP` unit including `TIMESTAMPTZ` — across DuckDB's full range |
| **Bytes & text** | `VARCHAR` (any UTF-8), `BLOB`, `GEOMETRY` |
| **Nested** | `LIST` and nested lists, `STRUCT`, `MAP`, fixed-length `ARRAY` (`INTEGER[3]`), and their combinations |

`HUGEINT`, `UHUGEINT`, `UUID`, `BIT`, and `TIMETZ` round-trip exactly too, but
only with DuckDB's lossless Arrow export enabled. Without it these types reach
the worker as a different Arrow type than DuckDB will accept back, and
`COPY … FROM` inserts no cast, so the read is refused at bind. If your tables use
them, set this once per session:

```sql
SET arrow_lossless_conversion = true;
```

`INTERVAL`, `ENUM`, and `UNION` have no representation in the value model and are
refused on write with a typed error — they fail loudly rather than round-tripping
wrong.

---

## Notes & limitations

- **`decode` returns JSON in v1.** A DuckDB scalar function fixes its output
  column type at *bind* time, with no data sample available, so the spec's
  per-scan STRUCT/MAP inference cannot be realized for a runtime `BLOB` column.
  `decode` therefore returns canonical JSON text (the stable, lossless column
  type) for every `mode`. For typed projection of a *known* shape, use the
  structural decoders (`cose_decode` / `cwt_claims` / `cose_key` /
  `webauthn_authdata`), whose schemas are fixed and fully typed — or, for a whole
  file of uniform rows, the COPY formats, which land on the target table's exact
  column types.
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

Built on the published VGI Rust SDK (`vgi = "0.27"`, arrow 59). The CBOR codec is
[`ciborium`](https://crates.io/crates/ciborium) and MessagePack is
[`rmpv`](https://crates.io/crates/rmpv) — all permissive (Apache-2.0 / MIT), no
copyleft.

## License

MIT — see [LICENSE](LICENSE). Copyright 2026 Query Farm LLC.

CBOR / COSE / CWT / WebAuthn / CTAP2 are open IETF / W3C / FIDO standards.
