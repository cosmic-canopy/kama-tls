#!/bin/sh
# tsan.sh — build the package's tests under ThreadSanitizer and run them once. `kama` is taken from $KAMA or the
# PATH, and must meet the tests' floor (tests/kama.json); `select` values carry build flags from 0.9.610 on. The
# TSAN build type lives in a manifest written here, beside a copy of tests/src and tests/csrc, rather than in
# tests/kama.json; its `csources` must stay the same as that file's. TSan exits non-zero after a report, and so does
# this script. Not part of the gate.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KAMA=${KAMA:-kama}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

"$ROOT/tools/gen-certs.sh"
KTLS_TEST_CERTS="$ROOT/out/test-certs"; export KTLS_TEST_CERTS
cp -R "$ROOT/tests/src" "$tmp/src"
cp -R "$ROOT/tests/csrc" "$tmp/csrc"
cat > "$tmp/kama.json" <<EOF
{
  "name": "tls_tests",
  "version": "0.1.0",
  "kind": "executable",
  "kama": ">=0.9.690",
  "entry": "src/main.kama",
  "dependencies": { "@kama/tls": { "path": "$ROOT" } },
  "csources": [{ "path": "csrc/windows_roots.c", "compileFor": ["OS_WINDOWS"] }, "csrc/raw_client.c"],
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
