#!/usr/bin/env bash
# Build the cbor VGI worker and run the SQLLogic tests against it using the
# haybarn DuckDB distribution's unittest runner (which ships the `vgi` extension
# via the community repository).
#
# Requires Rust and uv. Resolve the current haybarn runner with uvx rather than
# picking up an older global install. VGI_UNITTEST may override the runner.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

if [[ -n "${VGI_UNITTEST:-}" ]]; then
    if [[ ! -x "$VGI_UNITTEST" ]]; then
        echo "ERROR: VGI_UNITTEST must name an executable: $VGI_UNITTEST" >&2
        exit 1
    fi
    UNITTEST=("$VGI_UNITTEST")
else
    UNITTEST=(uvx --refresh --isolated --prerelease allow --from 'haybarn-unittest>=2.0.0rc11,<2.1' haybarn-unittest)
fi

# Refresh the extension as well: a successful LOAD alone can hide a stale
# protocol version. Keep the worker SDK current when the extension advances.
echo "==> Updating vgi extension from community repository"
echo "FORCE INSTALL vgi FROM community;" | uvx --refresh --isolated --prerelease allow --from 'haybarn-cli>=2.0.0rc11,<2.1' haybarn-cli

echo "==> Building cbor-worker (release)"
cargo build --release --bin cbor-worker

# NOTE: this is a Catch2 test-name filter, not a shell glob. Catch2 only honors a
# trailing `*` wildcard, so use `test/sql/*` (not `test/sql/*.test`).
WORKER="$REPO_ROOT/target/release/cbor-worker"
TEST_GLOB="${1:-test/sql/*}"

echo "==> Running SQLLogic tests"
echo "    worker:   $WORKER"
echo "    unittest: ${UNITTEST[*]}"
echo "    tests:    $TEST_GLOB"

# --keep-home: haybarn-unittest 2.0 isolates $HOME, which would hide the vgi
# extension installed above.
# The worker runs here, so it shares this filesystem: the COPY tests, which move
# real files through the worker, can run (see ci/run-integration.sh).
VGI_CBOR_WORKER="$WORKER" \
VGI_CBOR_COLOCATED=1 \
VGI_WORKER_CATALOG_NAME="cbor" \
    "${UNITTEST[@]}" --keep-home --test-dir "$REPO_ROOT" "$TEST_GLOB"
