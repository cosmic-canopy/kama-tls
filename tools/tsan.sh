#!/bin/sh
# tsan.sh — build the package's tests under ThreadSanitizer and run them once. `kama` is taken from $KAMA or the
# PATH, and must be 0.9.610 or later: that is the first release whose `select` values carry build flags. So the
# TSAN build type lives in a manifest written here, beside a copy of tests/src, and not in tests/kama.json, whose
# floor is the package's. TSan exits non-zero after a report, and so does this script. Not part of the gate.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KAMA=${KAMA:-kama}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

"$ROOT/tools/gen-certs.sh"
KTLS_TEST_CERTS="$ROOT/out/test-certs"; export KTLS_TEST_CERTS
cp -R "$ROOT/tests/src" "$tmp/src"
cat > "$tmp/kama.json" <<EOF
{
  "name": "tls_tests",
  "version": "0.1.0",
  "kind": "executable",
  "kama": ">=0.9.610",
  "entry": "src/main.kama",
  "dependencies": { "@kama/tls": { "path": "$ROOT" } },
  "modules": { ".": { "visibility": "internal" } },
  "select": { "BUILD_TYPE": {
      "TSAN": { "inherits": "DEBUG",
                "cflags":  ["-fsanitize=thread", "-fno-omit-frame-pointer"],
                "ldflags": ["-fsanitize=thread"] } } }
}
EOF
"$KAMA" pkg install "$tmp/kama.json" >/dev/null
"$KAMA" build "$tmp/kama.json" --select BUILD_TYPE=TSAN -o "$tmp/tests-tsan"
"$tmp/tests-tsan"
echo "tsan.sh: OK"
