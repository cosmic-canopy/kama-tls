#!/bin/sh
# gen-certs.sh — the throwaway PKI the tests handshake with, generated into out/test-certs.
#
# Nothing here is ever tracked. out/ is gitignored, so no key can reach a commit or a published tarball
# (`kama publish` refuses secret-shaped names, and the registry refuses them again). The files are
# regenerated whenever the directory is missing; `--force` regenerates them anyway.
#
#   ca.crt                       the CA every good certificate chains to
#   other-ca.crt                 a CA nothing chains to: verification against it must fail
#   server.crt / server.key      RSA-2048, CN=localhost, SAN localhost / 127.0.0.1 / ::1
#   server-ec.crt / .key         ECDSA P-256, the same names
#   wronghost.crt / .key         RSA, CN and SAN wrong.example: a hostname check must fail
#   expired.crt / .key           RSA, localhost, valid 2020-01-01 to 2021-01-01: must fail as expired
#   client.crt / client.key      RSA, CN=tls-client, clientAuth: for servers that require a client cert
#
# Every leaf is signed with `openssl ca`, which takes explicit validity dates on both LibreSSL and OpenSSL
# (the newer `x509 -not_before` is OpenSSL 3.4+ only). OPENSSL picks the binary (default `openssl`).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIR="$ROOT/out/test-certs"
OPENSSL=${OPENSSL:-openssl}

if [ -f "$DIR/ca.crt" ] && [ "${1:-}" != "--force" ]; then
    exit 0
fi
rm -rf "$DIR"
mkdir -p "$DIR/work"
cd "$DIR/work"

ossl() { "$OPENSSL" "$@" >/dev/null 2>"err.txt" || { echo "gen-certs: $OPENSSL $1 failed:" >&2; cat err.txt >&2; exit 1; }; }

cat > ca.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = kama-tls test CA
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ca]
default_ca = test
[test]
dir = .
database = index.txt
serial = serial
new_certs_dir = .
certificate = ca.crt
private_key = ca.key
default_md = sha256
policy = anything
copy_extensions = none
unique_subject = no
[anything]
commonName = supplied
[server]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
[wronghost]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:wrong.example
[client]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
sed 's/kama-tls test CA/kama-tls UNTRUSTED CA/' ca.cnf > other-ca.cnf
touch index.txt
echo 1000 > serial

ossl req -new -x509 -days 3650 -nodes -newkey rsa:2048 -keyout ca.key -out ca.crt -config ca.cnf -extensions v3_ca
ossl req -new -x509 -days 3650 -nodes -newkey rsa:2048 -keyout other-ca.key -out other-ca.crt -config other-ca.cnf -extensions v3_ca

# leaf <name> <CN> <extensions section> <key: rsa|ec> [startdate enddate]
leaf() {
    if [ "$4" = ec ]; then ossl ecparam -name prime256v1 -genkey -noout -out "$1.key"
    else ossl genrsa -out "$1.key" 2048; fi
    printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = %s\n' "$2" > "$1.cnf"
    ossl req -new -key "$1.key" -out "$1.csr" -config "$1.cnf"
    if [ $# -ge 6 ]; then
        ossl ca -batch -config ca.cnf -extfile ca.cnf -extensions "$3" -startdate "$5" -enddate "$6" -in "$1.csr" -out "$1.crt"
    else
        ossl ca -batch -config ca.cnf -extfile ca.cnf -extensions "$3" -days 825 -in "$1.csr" -out "$1.crt"
    fi
    # `openssl ca` writes a text dump before the PEM block; keep only the certificate.
    sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$1.crt" > "../$1.crt"
    cp "$1.key" "../$1.key"
}

leaf server     localhost     server    rsa
leaf server-ec  localhost     server    ec
leaf wronghost  wrong.example wronghost rsa
leaf expired    localhost     server    rsa 20200101000000Z 20210101000000Z
leaf client     tls-client    client    rsa

cp ca.crt other-ca.crt ..
cd .. && rm -rf work
chmod 0644 ./*
echo "gen-certs: wrote $(ls | wc -l | tr -d ' ') files to out/test-certs"
