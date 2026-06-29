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
  src/scalar/          #   scalar fns (common.rs = blob_scalar! macro; codec, msgpack, cose, cwt, webauthn, version)
  src/table/           #   LATERAL table fns: webauthn_attestation, seq_decode
test/sql/basic.test    # haybarn SQLLogic E2E over committed hex fixtures
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
- `cbor_version`.

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
`vgi.keywords` / `vgi.example_queries` (per-arg docs on every argument), the
catalog carries `source_url` + classifying tags, and `cbor_version` carries the
`vgi.executable_examples` (VGI509) verified examples. Keep the gate at **100/100,
no findings** — titles must not merely restate the machine name (VGI125), and
overloads must have distinct descriptions (VGI120).
