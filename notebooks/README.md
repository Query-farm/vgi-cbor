# CBOR: claimed dates and representation identity

| Notebook | Question | Run |
|---|---|---|
| [01 · Expiry dates inside COSE envelopes](01_expiry_dates_inside_cose_envelopes.ipynb) | Which unverified claimed dates fall inside a review window, while missing and malformed inputs stay visible? | [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-cbor/blob/main/notebooks/01_expiry_dates_inside_cose_envelopes.ipynb) |
| [02 · JSON equality is not CBOR identity](02_json_equality_is_not_cbor_identity.ipynb) | Which type distinctions disappear when CBOR is projected through JSON and reconstructed? | [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-cbor/blob/main/notebooks/02_json_equality_is_not_cbor_identity.ipynb) |

Both stories use the native [vgi-cbor v0.7.1 release](https://github.com/Query-farm/vgi-cbor/releases/tag/v0.7.1)
and authored synthetic bytes constructed in visible SQL. No credentials, real
tokens, file/cloud exports or external data feeds are used. Initial installation
requires network access; the worker then computes on in-memory inputs.

In Colab choose **Runtime → Run all**. The visible bootstrap installs the base
shared package, then retrieves the immutable SHA256-verified presentation helper.
Compatible kernel and plotting libraries remain installed. No worker checkout or
Rust build is needed. The locked local environment includes the `[runner]` extra:

```sh
uv sync --locked
uv run --locked vgi-notebooks
uv run --locked vgi-notebooks 01_expiry_dates_inside_cose_envelopes.ipynb --parameters '{"HORIZON_DAYS":30}' --output-dir artifacts/horizon-30
uv run --locked vgi-notebooks 02_json_equality_is_not_cbor_identity.ipynb --parameters '{"REBUILD_FROM_JSON":true}' --output-dir artifacts/json-rebuild
```

For local interactive Jupyter select `notebooks/.venv/bin/python`; the shared
runner provisions its own temporary kernel. Overrides require a separate output
directory, and failed runs preserve saved defaults. If an earlier bootstrap
replaced kernel libraries, save your work, disconnect/delete that runtime, and
open the current notebook in a fresh runtime.

The connection is visible and literal in both notebooks:

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'cbor' (TYPE vgi,
  LOCATION 'github-auto://Query-farm/vgi-cbor@v0.7.1');
```

VGI downloads the platform archive, checks its SHA256 sidecar and caches it.
Haybarn 2.0.0rc11 and the Python environment are locked. Shared
[v0.3.7](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.7/docs/standard.md)
provides canonical branding, isolated SQL secrets, SVG rendering and execution
protections. `cbor_example.py` validates parameters and presents returned results;
worker calls and analytical transformations stay visible. Keep committed `charts/`
SVGs with saved notebooks for GitHub rendering. Colab/Jupyter reruns emit native
SVG; PNG review exports remain ignored under `artifacts/review/`.

The two stories cover **14 of 27 public named SQL surfaces**, meeting the required
14 for a catalog larger than ten. Complete released/current runtime exports,
full view columns, successful execution receipts and reviewed mappings are bound
by `coverage.json`. Overloads count once. Both catalog snapshots contain 26
function names and the `cose_registry` view; current main changes composed example
metadata but has the same signatures. Notebooks execute v0.7.1; current-interface
compatibility is not a claim of current-main notebook execution.

Thirteen surfaces remain explicitly uncovered: `cbor_copy`, `msgpack_copy`,
`msgpack_decode`, `msgpack_encode`, `msgpack_to_cbor`, `msgpack_to_json`,
`seq_decode`, `cose_payload`, `cose_key`, `cose_x5chain`, `cose_x5t`,
`webauthn_attestation`, and `webauthn_authdata`. COPY handlers count in the denominator
although SQL invokes them through FORMAT identifiers. Their local/cloud read and
write capabilities, including optional authentication, are not exercised here.

Notebook 01 constructs nine synthetic CWT claim sets inside COSE_Sign1 envelopes,
each with a **64-byte zero placeholder signature**. Eight have expiry offsets
-4, 0, 2, 7, 8, 21, 45 and 90 days; one omits expiry. A truncated envelope, integer
zero and NULL are separate controls. Issuer `https://issuer.example` and all
subjects are fictional. The real `encode` function encodes typed claim values and
the nested payload byte string. The ES256 header is a claimed label, not evidence
that signing occurred. Structural decode does not verify a signature, issuer,
audience, required claims or authorization.

The fixed audit instant is **2026-11-14 00:00:00 UTC**. Claimed expiry at or before
that instant is elapsed; the forward window is `audit < expiry <= deadline`.
Changing only `HORIZON_DAYS` from **7 to 30** changes classifications and the
inclusive deadline, preserving bytes, decoded timestamps and the elapsed/undated
counts. Missing input, malformed CBOR, absent decoded claims and missing expiry
remain distinct categories. The registry uses a left join to retain every input.
The construction follows the claim labels in [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html)
and envelope structure in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).

Notebook 02 compares eight explicit items in four pairs: byte string/text,
tag/bare integer, integer/text map keys, and map insertion order. Four separate
controls cover duplicate keys, truncation, trailing bytes and NULL. The diagnostic
view preserves distinctions hidden by JSON. Tag 1 denotes an epoch-based date/time
representation; the example uses the integer 1, not a real event timestamp.
`untag(...,1)` returns JSON values found under that tag; it does not rewrite CBOR.
These distinctions and JSON conversion limits are described in
[RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html).

`decode(...,'struct')` actually returns VARCHAR JSON in this release, identical to
`to_json` for these cases. A mode name or non-NULL result therefore does not prove
lossless typed decoding. `is_valid` accepts the duplicate-key control as one
parseable item, while `well_formed` rejects it. These worker checks are not a full
application schema or trust policy.

Changing only `REBUILD_FROM_JSON` from **False to True** selects JSON reconstruction
instead of core canonical bytes as a derived archive; originals stay retained.
The study starts with eight distinct encodings, core canonical encoding retains
seven, and the JSON view/reconstruction retains four. JSON reconstruction changes
five of eight core-normalized encodings. Byte counts can grow or shrink while
losing types, tags or key distinctions. Do not replace signed bytes with any
normalized encoding and assume an existing signature still applies.

An additional validation probe found a narrow combined-call limitation in the
pinned engine/worker path: selecting both `canonical(row,'core')` and
`canonical(row,'ctap2')` over the same row input returned the first mode for both.
Each mode in a separate query, and both modes over constant literals, returned
its expected distinct encoding. [Exact SQL/results](coverage/canonical-mode-probe.json)
retain that evidence without attributing the cause. Notebook 02 uses only the
default core overload, so its comparison does not depend on that combined call.

Default executions, one detached experiment per notebook, six runner guards and
preloaded Colab-compatible kernel libraries are validated. A Colab link is not a
claim of manually operating the hosted service. Source checks retain the repo's
existing contracts; source and root locks are unchanged.
