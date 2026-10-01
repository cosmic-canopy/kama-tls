#!/bin/sh
# vendor-mbedtls.sh — pin one Mbed TLS release into third_party/mbedtls/ and regenerate the `csources` and
# `cincludes` lists in kama.json from what landed.
#
# Vendored on purpose. A consumer of @kama/tls gets a working build with nothing to install, on every target
# kama has. A package cannot add `-I/opt/homebrew/include` for a consumer, and wasm has no system libraries.
# A shipped binary links one known TLS stack rather than whichever one a machine had. Upgrading means
# running this script with a new VERSION and SHA256, reading the diff, and bumping this package's version.
#
# The release tarball, not GitHub's source snapshot. Only `mbedtls-X.Y.Z.tar.bz2` carries the bundled
# TF-PSA-Crypto and the generated sources (error.c, version_features.c, ssl_debug_helpers_generated.c,
# psa_crypto_driver_wrappers*, the config-check headers). So no Python or CMake generation step ever runs
# here. The script refuses a tarball that lacks them.
#
# What lands, each file byte-identical to the release:
#   third_party/mbedtls/LICENSE, include/, library/              Mbed TLS: TLS and X.509
#   third_party/mbedtls/tf-psa-crypto/LICENSE, include/, core/, dispatch/, drivers/builtin/, platform/,
#                                     utilities/, extras/       TF-PSA-Crypto: the PSA crypto core
# Only `.c` and `.h` files are copied from those directories (plus the two LICENSEs). The build machinery,
# tests, programs and docs are not.
#
# What does NOT land, and why. These are the three optional drivers, each off in this package's
# configuration. Every reference to them in the kept code is behind the config macro that enables it, and
# csrc/ktls_crypto_user_config.h refuses a build that turns one on.
#   drivers/everest   HACL* X25519 (MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED). The builtin X25519 is used.
#                     Its files are Apache-2.0 only, not the project's dual license.
#   drivers/p256-m    the minimal P-256 driver (MBEDTLS_PSA_P256M_DRIVER_ENABLED). The builtin ECC is used.
#   drivers/pqcp      ML-DSA post-quantum signatures (TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED). Not needed for TLS.
# So every vendored source file carries `SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later`, and this
# package takes it under Apache-2.0. The script checks that too.
#
# Every directory holding a `.c` file is put on every translation unit's include path by kama, the
# consumer's included. So the script FAILS if two headers on that path share a basename, because which one
# an `#include "x.h"` found would depend on order.
#
# The `csources` and `cincludes` arrays in kama.json are GENERATED here. Everything else in the manifest is
# hand-written and left alone. Needs python3 for that JSON edit.
set -eu

VERSION=4.1.1
SHA256=3359a349e23db3d5536fcee032ae7b2ecbfc08972fab643089b5cbf2a375c98c
URL="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${VERSION}/mbedtls-${VERSION}.tar.bz2"

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEST="$ROOT/third_party/mbedtls"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# A local tarball (checked against the same hash) skips the download.
tarball="${MBEDTLS_TARBALL:-}"
if [ -z "$tarball" ]; then
    tarball="$tmp/mbedtls.tar.bz2"
    echo "vendor-mbedtls: fetching $URL"
    curl -fsSL -o "$tarball" "$URL"
fi
got=$(shasum -a 256 "$tarball" | cut -d' ' -f1)
if [ "$got" != "$SHA256" ]; then
    echo "vendor-mbedtls: sha256 mismatch for mbedtls-$VERSION: got $got, want $SHA256" >&2
    exit 1
fi

tar -xjf "$tarball" -C "$tmp"
src="$tmp/mbedtls-$VERSION"
[ -d "$src/tf-psa-crypto/core" ] || { echo "vendor-mbedtls: unexpected tarball layout" >&2; exit 1; }

for f in library/error.c library/version_features.c library/ssl_debug_helpers_generated.c \
         library/mbedtls_config_check_before.h library/mbedtls_config_check_final.h \
         library/mbedtls_config_check_user.h \
         tf-psa-crypto/core/psa_crypto_driver_wrappers.h \
         tf-psa-crypto/core/psa_crypto_driver_wrappers_no_static.c \
         tf-psa-crypto/core/tf_psa_crypto_config_check_before.h \
         tf-psa-crypto/core/tf_psa_crypto_config_check_final.h \
         tf-psa-crypto/core/tf_psa_crypto_config_check_user.h; do
    [ -f "$src/$f" ] || { echo "vendor-mbedtls: the release lacks generated file $f" >&2; exit 1; }
done

KEEP="include library tf-psa-crypto/include tf-psa-crypto/core tf-psa-crypto/dispatch tf-psa-crypto/drivers/builtin
      tf-psa-crypto/platform tf-psa-crypto/utilities tf-psa-crypto/extras"

rm -rf "$DEST"
mkdir -p "$DEST/tf-psa-crypto"
cp "$src/LICENSE" "$DEST/LICENSE"
cp "$src/tf-psa-crypto/LICENSE" "$DEST/tf-psa-crypto/LICENSE"
(cd "$src" && find $KEEP -type f \( -name '*.c' -o -name '*.h' \)) | while read -r f; do
    mkdir -p "$DEST/$(dirname "$f")"
    cp "$src/$f" "$DEST/$f"
done

# Every vendored source carries the project's dual license, generated files included (they have no SPDX
# line of their own, and are produced by the project's scripts).
bad=$(cd "$DEST" && find . -type f \( -name '*.c' -o -name '*.h' \) | while read -r f; do
    if grep -q "SPDX-License-Identifier" "$f" && ! grep -q "SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later" "$f"; then
        echo "$f"
    fi
done)
if [ -n "$bad" ]; then
    echo "vendor-mbedtls: files under a license other than Apache-2.0 OR GPL-2.0-or-later:" >&2
    echo "$bad" >&2
    exit 1
fi

# Header basenames on the shared include path must be unique: every directory with a `.c` file, every
# cincludes root, and this package's csrc/.
dirs=$(cd "$ROOT" && { find third_party/mbedtls -name '*.c' -exec dirname {} \; ; echo csrc; } | LC_ALL=C sort -u)
cinc="third_party/mbedtls/include third_party/mbedtls/tf-psa-crypto/include
      third_party/mbedtls/tf-psa-crypto/drivers/builtin/include third_party/mbedtls/tf-psa-crypto/dispatch"
dups=$(cd "$ROOT" && for d in $dirs $cinc; do find "$d" -maxdepth 1 -name '*.h' -exec basename {} \; ; done | LC_ALL=C sort | uniq -d)
if [ -n "$dups" ]; then
    echo "vendor-mbedtls: header basenames shared by two include-path directories: $dups" >&2
    exit 1
fi

count=$(cd "$ROOT" && find third_party/mbedtls -name '*.c' | wc -l | tr -d ' ')
printf 'Mbed TLS %s (with its bundled TF-PSA-Crypto)\n%s\nsha256 %s\n\nKept, byte-identical to the release (.c and .h only, plus both LICENSE files):\n  %s\nNot vendored (optional drivers, off in this package'"'"'s configuration): drivers/everest, drivers/p256-m, drivers/pqcp\n' \
    "$VERSION" "$URL" "$SHA256" "$(echo $KEEP)" > "$DEST/VENDORED"

python3 - "$ROOT" <<'EOF'
import json, os, re, sys
root = sys.argv[1]
def rel(p): return os.path.relpath(p, root)
csources = sorted(rel(os.path.join(dp, f)) for base in ("csrc", "third_party/mbedtls")
                  for dp, _, fs in os.walk(os.path.join(root, base)) for f in fs if f.endswith(".c"))
cincludes = ["third_party/mbedtls/include", "third_party/mbedtls/tf-psa-crypto/include",
             "third_party/mbedtls/tf-psa-crypto/drivers/builtin/include",
             "third_party/mbedtls/tf-psa-crypto/dispatch"]
path = os.path.join(root, "kama.json")
text = open(path).read()
def block(key, items):
    body = ",\n".join('    "%s"' % i for i in items)
    return '"%s": [\n%s\n  ]' % (key, body)
for key, items in (("cincludes", cincludes), ("csources", csources)):
    pat = re.compile(r'"%s":\s*\[[^\]]*\]' % key)
    if pat.search(text):
        text = pat.sub(lambda m: block(key, items), text)
    else:  # first run: append before the closing brace
        text = re.sub(r'\n}\s*$', ',\n  %s\n}\n' % block(key, items), text)
json.loads(text)  # still valid JSON
open(path, "w").write(text)
EOF

echo "vendor-mbedtls: Mbed TLS $VERSION in third_party/mbedtls ($count C files); kama.json csources/cincludes regenerated"
