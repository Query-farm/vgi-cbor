# CLAUDE.md

Guidance for working in this repository.

## What this is

`vgi-cbor` is a **VGI worker** (a standalone binary DuckDB launches and talks to
over Apache Arrow IPC, `ATTACH 'cbor' (TYPE vgi, LOCATION '…')`) that brings
**CBOR** (RFC 8949) / **MessagePack** decode & encode, plus tag-aware **COSE**
(RFC 9052) / **CWT** (RFC 8392) / **COSE_Key** / **WebAuthn / FIDO2 / CTAP2**
structural decode, to SQL. Functions live under catalog `cbor`, schema `main`.

Built on the published VGI Rust SDK (`vgi = "0.9.5"` from crates.io), arrow 59.
Modeled on `../vgi-fixedformat`. The repo builds standalone — no local SDK
checkout, no `path` dependency on the SDK.

The real value is the **security-payload structural decode** (COSE/CWT/WebAuthn)
and the bulk SQL join surface (`cose_x5t` / `cose_x5chain` / WebAuthn `x5c` join
to `vgi-x509`). The raw CBOR/msgpack codec is commodity.

## Layout

```
crates/cbor-core/      # pure compute, NO arrow/vgi deps — independently testable
  src/value.rs         #   bounded parse (MAX_NESTING), DecodeError taxonomy, dup-key scan
  src/codec/           #   json (to_json/from_json), diagnostic (EDN), encode (+ canonical), msgpack, tags
  src/security/        #   cose, cwt, cose_key, webauthn, registry (IANA alg/kty/crv)
  src/validate.rs      #   is_valid / well_formed (kind taxonomy)
  src/seq.rs           #   RFC 8742 CBOR Sequence
  tests/vectors.rs     #   RFC 8949 App. A + COSE/CWT/WebAuthn golden fixtures
  tests/fuzz.rs        #   proptest zero-panic gate (big-stack threads, see below)
crates/cbor-worker/    # arrow + vgi: maps core results onto DuckDB types, serves VGI
  src/main.rs          #   bootstrap + catalog/schema metadata (source_url + tags)
  src/arrow_io.rs      #   input blob reading + shared STRUCT schemas (COSE header, COSE_Key) + builders
  src/value_in.rs      #   Arrow cell -> ciborium Value (encode paths)
  src/value_out.rs     #   ciborium Value -> typed Arrow column (COPY FROM; inverse of value_in)
  src/scalar/          #   scalar fns (common.rs = blob_scalar! macro; codec, msgpack, cose, cwt, webauthn, version)
  src/table/           #   blended table-in-out fns (LATERAL): webauthn_attestation, seq_decode
  src/copy/            #   COPY FROM/TO row-file formats (common.rs = Wire/RowShape + shared metadata)
test/sql/basic.test    # haybarn SQLLogic E2E over committed hex fixtures
test/sql/copy.test     # COPY FROM/TO round-trip, options, ordering, error paths, scale
test/sql/copy_types.test # COPY type fidelity, driven by DuckDB's test_all_types()
```

## SQL surface

See README for the full table. Catalog `cbor`, schema `main`; qualify as
`cbor.main.<fn>(...)` or `SET search_path='cbor.main'`.

- Codec scalars: `to_json`, `decode`, `diagnostic`, `from_json`, `encode`,
  `canonical`, `tags`, `untag`, `is_valid`, `well_formed`.
- MessagePack: `msgpack_to_json`, `msgpack_decode`, `msgpack_encode`,
  `msgpack_to_cbor`.
- Security: `cose_decode`, `cose_payload`, `cose_headers`, `cose_x5t`,
  `cose_x5chain`, `cose_key`, `cwt_claims`, `webauthn_authdata`.
- Table (LATERAL): `webauthn_attestation`, `seq_decode`.
- COPY formats: `FORMAT 'cbor.cbor'` / `FORMAT 'cbor.msgpack'`, each serving
  **both** directions under one name. Options: `row_format` ('map' default |
  'array'), `ignore_errors` (FROM), `canonical` (TO, cbor only).

The worker's build version is published as the catalog's
`implementation_version` (read via `vgi_catalogs()` / `duckdb_databases()`), not
as a scalar — a parameterless `*_version()` function is a vgi-lint VGI328 error.

## Conventions & gotchas

- **Optional `mode` args are arity overloads.** DuckDB binds a const arg as
  required, so `decode` / `encode` / `canonical` each register a 1-arg and a
  2-arg form (`with_mode: bool`). Give each overload a distinct `description` and
  example (VGI120).
- **`blob_scalar!` macro** (`scalar/common.rs`) generates the many
  single-BLOB-input scalars: pass a `build: fn(&[Option<&[u8]>]) -> Result<ArrayRef>`
  plus metadata. Functions with extra/non-blob args are written out by hand.
- **JSON = `Utf8`.** There is no DuckDB-JSON Arrow extension type here; JSON
  columns are VARCHAR carrying canonical JSON text. `TIMESTAMPTZ` =
  `Timestamp(Microsecond, "UTC")`; `UBIGINT` = `UInt64`; `UINTEGER` = `UInt32`.
- **`decode` returns JSON, not a dynamic STRUCT.** A scalar's output type is
  fixed at bind with no data sample, so per-scan STRUCT inference isn't possible;
  the typed value lives in the fixed-schema structural decoders. Documented in
  README and the function's own doc.
- **Untrusted-input discipline.** All decode funnels through
  `value::parse`/`parse_strict` with bounded recursion (`MAX_NESTING`). Per-row
  decoders return `None`/`ok=false` on error — never panic. Keep it that way; the
  `tests/fuzz.rs` zero-panic proptest gates it.
- **`MAX_NESTING` is 64, not 256.** `ciborium`'s serde `Value` deserialization
  uses a large per-level stack frame (huge in debug builds), so the bounded
  recursion is kept well under the spec's nominal 256 to stay within a small
  worker-/test-thread stack. 64 is far deeper than any real document; deeper
  blobs are cleanly rejected as `nesting-limit`. The fuzz tests run on explicit
  64 MB-stack threads so debug frames don't mask the assertions.
- **A COPY format serves both directions under one name.** The DuckDB extension
  registers one `CopyFunction` per `alias.format_name` and keeps the first
  registration, so a reader and a writer advertising the same format name would
  silently drop one direction. The SDK pairs them into a single
  `direction="both"` entry instead — which requires the `CopyFromFunction` and
  `CopyToFunction` for a format to return the **same `handler_name`** (the wire
  carries one handler per format). Hence `Wire::handler()`, shared by
  `copy/from.rs` and `copy/to.rs`, and the single shared `format_metadata()`:
  reader and writer are one catalog object, so they must not disagree about it.
  Requires vgi ≥ 0.27.
- **`s3://` / `http(s)://` COPY paths go through `cloud.rs`** (ported from
  `../vgi-fixedformat`), not the filesystem — which is what makes COPY usable
  from a container, a remote worker, or the browser. `cloud::classify` splits
  local from remote; `cloud::secret_lookup` feeds the COPY traits'
  `secret_lookups` hook so DuckDB's `TYPE s3` secret is resolved and scoped to
  the URL. A remote destination is buffered and PUT as one object (object stores
  have no append); a local one still streams. Ported deliberately *without*
  fixedformat's `RangeReader` and `list_glob`: one COPY statement names one
  path, and the reader parses a whole row file at once. `http(s)://` reads are
  SSRF-guarded (`VGI_CBOR_ALLOW_INTERNAL_HOSTS=1` overrides).
- **The wasm build needs `src/wasm/{http,crypto}.rs`.** `object_store`'s native
  transport (reqwest/rustls) and crypto (aws-lc-rs) do not build for wasm, so
  the wasm target takes the `aws-base`/`http-base` features and supplies a
  sync-XHR `HttpService` and a sha2/hmac `CryptoProvider`. The XHR side needs
  `wasm/vgi_http_lib.js` passed to emcc as a `--js-library` — if s3 silently
  fails in the browser, check that link flag first.
- **COPY does its *local* file I/O in the worker.** A COPY path is resolved against the
  *worker's* filesystem and cwd, not the SQL client's, so the COPY tests require
  a co-located worker. `test/sql/copy*.test` gate on `require-env
  VGI_CBOR_COLOCATED`, which `run_tests.sh` and `ci/run-integration.sh` set only
  when they launch the worker themselves; the docker image_test runs the suite
  against a *container*, where those paths do not exist, and the two files
  self-skip. Any new test that moves real files needs the same gate.
- **COPY-TO writers are `ordered = true`.** A row file's order is part of its
  content, so `COPY (SELECT … ORDER BY …) TO` must preserve it; that costs the
  parallel sink (DuckDB installs a single-thread one). `write()` still shards
  through `ctx.storage` scoped by `execution_id` — never buffer on `self`, since
  the sink and the terminal `close()` can land on different worker processes.
- **COPY FROM streams; it does not buffer the source.** `read_stream` (vgi 0.28)
  hands back a `RowProducer` that decodes one item at a time and emits a batch
  every `READ_BATCH_ROWS`, so peak memory is flat in the source size: measured
  on a 376 MB row file, buffered peaked at 415-429 MB against 67-73 MB
  streaming. `SeqReader` / `StreamReader` take **`BufRead`, not `Read`** — that
  is load-bearing, because ciborium reports both "end of sequence" and "final
  item truncated" as `UnexpectedEof`, and `fill_buf` is what tells them apart
  without consuming. Get that wrong and a truncated file loads silently.
  `read()` is kept only as the trait's buffered contract and just drains the
  producer, so there is one decode path.
- **`ignore_errors` retries a failing chunk row-by-row.** COPY FROM converts a
  whole chunk at once; one unconvertible cell fails its column and would take
  every other row in the chunk with it. Under `ignore_errors` the chunk is
  rebuilt one row at a time so only genuinely bad rows are dropped. Keep the
  bulk path as the default — the row-at-a-time path is the error path only.
- **`test_all_types()` is the type-fidelity fixture.** `test/sql/copy_types.test`
  round-trips DuckDB's own all-types table (every type at min / max / NULL)
  through both formats, so a type DuckDB adds later shows up as a test change
  rather than a silent gap. Each known gap is pinned to its exact failure mode —
  refused-on-write (`INTERVAL` / `ENUM` / `UNION`) and refused-at-bind unless
  `SET arrow_lossless_conversion = true` (`HUGEINT` / `UHUGEINT` / `UUID` /
  `BIT` / `TIMETZ`, which otherwise reach the worker as an Arrow type that does
  not map back to the same DuckDB type). With that setting on, only the three
  write-unsupported families remain. When closing a gap, delete its pin — do not
  leave both.
- **Exactness beats brevity in the value encodings.** `DECIMAL` is a CBOR tag-4
  decimal fraction carrying the unscaled integer (a `DECIMAL(38,s)` mantissa
  overflows CBOR's native integer range, so it rides as a tag-2/3 bignum — see
  `cbor_core::codec::bignum`), and a sub-second `TIMESTAMP` is a tag-4 fraction
  inside tag 1. Neither may be routed through an `f64`: `1e-6` has no finite
  binary expansion, so float seconds drift past ~104 days from the epoch for a
  nanosecond column, and a float `DECIMAL` loses everything past ~15 digits.
  MessagePack has no tags, so `cbor_to_mp` maps the bignum tags to an `ext` of
  the same code — dropping to a bare byte string would erase the sign.
- **`value_in` and `value_out` must stay symmetric.** Every branch added to one
  needs its inverse in the other, or COPY silently half-works: a type that
  encodes but has no read branch fails at bind, and vice versa. The temporal
  encodings are load-bearing — `DATE` is tag 100 (epoch *days*, not a midnight
  instant), `TIME` is a bare microsecond count since midnight, and `TIMESTAMP`
  is tag 1 wrapping an integer of seconds, or a tag-4 decimal fraction when
  sub-second.
- **Never let a range check saturate.** `timestamp_at` bounds against `2^63`
  rather than `i64::MAX as f64`, because the latter rounds *up* to `2^63` and
  lets the overflow through, after which `as i64` saturates and DuckDB renders
  the result as `infinity` — silent corruption. Prefer a loud error.
- **vgi-lint VGI504 is waived for the two COPY handlers** (`vgi-lint.toml`,
  `per_object`). They are registered as worker functions, so the linter lints
  them as table functions, but SQL invokes a COPY format by `FORMAT` identifier
  and never by handler name — no correct example can call `cbor_copy` by name.
  It is the repo's only waiver; everything else stays clean at 100/100 with
  `ignore = []`.
- **No crypto / no network / no state.** Verification, decryption, and CDDL are
  non-goals. Don't add a key-management or egress surface here — that belongs in
  a separate `vgi-cose-verify`.

## Build / test / gates

```sh
cargo build --release                                  # → target/release/cbor-worker
cargo test --workspace --all-features                  # RFC fixtures + proptest fuzz
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
./run_tests.sh                                         # haybarn SQLLogic E2E
# vgi-lint metadata gate (must be clean at fail-on=info):
uvx --from vgi-lint-check vgi-lint lint \
    "$PWD/target/release/cbor-worker" --catalog cbor --fail-on info
```

CI (`.github/workflows/ci.yml`) runs fmt/clippy/test/doc, the haybarn E2E, the
vgi-lint metadata gate, `cargo audit`, and an MSRV (1.90) check. Releases go
through the shared `Query-farm/vgi-actions` reusable workflow on a `vX.Y.Z` tag
(bump `[workspace.package] version` first; `ci/check-version.sh` enforces the
match).

## Metadata (vgi-lint)

Every function carries `vgi.title` / `vgi.doc_llm` / `vgi.doc_md` /
`vgi.keywords` / `vgi.example_queries` (each a described `[{description,sql}]`
JSON list — VGI515) plus per-arg docs on every argument; the catalog carries
`source_url`, `implementation_version`, classifying tags, and the
`vgi.executable_examples` (VGI509) verified examples. Keep the gate at **100/100,
no findings** — titles must not merely restate the machine name (VGI125),
overloads must have distinct descriptions (VGI120), and DuckDB type names in
prose must be code-formatted (VGI182).
