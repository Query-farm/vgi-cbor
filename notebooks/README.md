# CBOR structural-decoding notebooks

[01 · Inspect expiry dates inside COSE envelopes](01_expiry_dates_inside_cose_envelopes.ipynb)
constructs synthetic CWT claim sets inside COSE_Sign1 envelopes, decodes typed
fields with the released worker, and inventories claimed expiration dates using
visible SQL. Two charts show input dispositions and the dated subset. A focused
experiment expands the review window without changing any input bytes.

**No cryptographic verification is performed.** Every constructed envelope has
a 64-byte zero placeholder signature. These are deliberately untrusted teaching
examples, not credentials or authentication decisions.

## Run from this directory

Install [uv](https://docs.astral.sh/uv/), then:

```sh
cd notebooks
uv sync --locked
uv run --locked python execute.py
```

In a notebook editor select this directory's `.venv/bin/python` kernel and run
all cells. The full directory also works outside the worker checkout. Python
3.13–3.14 is supported; `uv` can provision the interpreter. No Rust compiler,
local worker build, keys, account access or root virtual environment is needed.

The connection remains visible and literal:

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'cbor' (TYPE vgi,
  LOCATION 'github-auto://Query-farm/vgi-cbor@v0.7.1');
```

VGI downloads the native platform archive, verifies its SHA256 sidecar and caches
it. The notebook environment locks Haybarn 2.0.0rc11 and its Python dependencies.
Initial installation requires network access; all codec calls operate on local
synthetic bytes in memory. Change the visible release tag and rerun the default
and experiment before adopting another worker release.

Parameters, connection SQL, analytical SQL and useful outputs stay expanded.
Imports, styling, plotting, prose-generation source and cleanup are folded.

## One-parameter experiment

```sh
uv run --locked python execute.py --parameters '{"HORIZON_DAYS":30}' \
  --output-dir validation/horizon-30
```

The parameter accepts whole days from 1 through 90; default 7, experiment 30.
The audit time is fixed at **2026-11-14 00:00:00 UTC**. Expiry at or before that
instant is elapsed. The future review window is open at the audit time and closed
at its deadline: `audit < expiry <= audit + HORIZON_DAYS`.

Changing the horizon changes classifications and the deadline line, preserving
the envelopes, decoded timestamps, point positions and elapsed/undated counts.
Reset to 7 after comparing outputs.

The runner uses fresh kernels, requires a separate destination for overrides,
rejects unknown parameter names and source-directory overwrites, and replaces
saved notebooks only after success. Copies include branding, helpers, the locked
environment and this guide. Logs, extracted charts and experiment copies under
`validation/` are ignored. The main notebook keeps successful outputs and charts.

## Provenance and interpretation

All inputs are constructed in visible SQL. Eight subjects have expiry offsets
of -4, 0, 2, 7, 8, 21, 45 and 90 days; a ninth omits expiration. Three additional
controls are a truncated envelope, the well-formed CBOR integer zero and NULL.
Issuer `https://issuer.example` and all subject labels are fictional. No external
tokens or secrets are read or stored.

The construction uses integer CWT labels 1 (issuer), 2 (subject) and 4 (expiry).
Small framing literals form the map and COSE_Sign1 envelope; the real worker's
`encode` function encodes each string, integer and byte-string value. Expiry
integers are exact epoch seconds. The ES256 header is only a claimed algorithm
label; it does not mean any signing operation occurred.

`well_formed` checks the outer CBOR representation, including duplicate map keys
and trailing bytes. It does not recursively validate CBOR hidden inside byte
strings or enforce a CWT claim schema. `cose_decode` exposes envelope fields and
`cwt_claims` extracts claim values. The notebook checks exact subject/issuer and
expiry round trips against the constructed seed, plus unchanged placeholder
signatures. The registry is left-joined so missing metadata retains its input row.

Missing input, malformed CBOR, absence of decoded claims and a missing expiry
remain separate inventory categories. None is converted to an epoch-zero date.
A genuine zero-day offset appears at the audit instant and is classified elapsed.
All displayed timestamps explicitly use UTC.

Structural decode does not authenticate issuer/subject, validate signatures,
check audience or required-claim policy, or determine whether a token should be
accepted. A downstream verifier must address those application-specific checks.
This notebook is an inspection and accounting example only.

The unchanged official Strata Sun and VGI media-kit assets are bundled locally.
Linked Strata Sun branding appears at both the top and final end of the notebook.

References: [worker documentation](https://github.com/Query-farm/vgi-cbor),
[pinned release](https://github.com/Query-farm/vgi-cbor/releases/tag/v0.7.1),
[CWT decoder](https://github.com/Query-farm/vgi-cbor/blob/v0.7.1/crates/cbor-core/src/security/cwt.rs).
