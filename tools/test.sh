#!/bin/sh
# test.sh — build and run the package's tests, debug then release. `kama` is taken from $KAMA or the PATH.
# Every case is hermetic (in-memory pipes and loopback), so this is the whole gate. The test PKI comes from
# tools/gen-certs.sh, into out/test-certs, which the tests find through KTLS_TEST_CERTS.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KAMA=${KAMA:-kama}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

"$KAMA" check "$ROOT/kama.json"
"$ROOT/tools/gen-certs.sh"
KTLS_TEST_CERTS="$ROOT/out/test-certs"; export KTLS_TEST_CERTS
"$KAMA" pkg install "$ROOT/tests/kama.json" >/dev/null
for mode in --debug --release; do
    "$KAMA" build "$ROOT/tests/kama.json" $mode -o "$tmp/tests$mode"
    "$tmp/tests$mode"
done
echo "test.sh: OK"
