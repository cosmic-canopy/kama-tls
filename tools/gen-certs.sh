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
#   client-pkcs8.key             client.key encrypted as PKCS#8 (PBES2, AES-256-CBC, HMAC-SHA256)
#   client-trad.key              client.key encrypted as a traditional PEM (AES-256-CBC); both use KEY_PASSWORD
#   mismatch.key                 an RSA key that is NOT client.crt's: an identity check must fail
#   client.der / client-key.der  client.crt and client.key as DER (the key as PKCS#8)
#   server-sha224 / -sha384 / -sha1 .crt/.key   localhost leaves signed with that hash, each with a .endpoint file:
#                                the RFC 5929 tls-server-end-point hash in hex, computed by openssl from the DER
#   revoked.crt / revoked.key    a localhost leaf the CA has revoked
#   revoked.crl                  the CA's CRL, listing revoked.crt; crldir/<hash>.r0 is the same CRL, named as
#                                OpenSSL's hashed-directory lookup names it
#   empty.crl                    the CA's CRL before the revocation: lists nothing
#   other-ca.crl                 an empty CRL from the untrusted CA, so a CRL set can lack the trusted CA's
#
# Every leaf is signed with `openssl ca`, which takes explicit validity dates on both LibreSSL and OpenSSL
# (the newer `x509 -not_before` is OpenSSL 3.4+ only). OPENSSL picks the binary (default `openssl`).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIR="$ROOT/out/test-certs"
OPENSSL=${OPENSSL:-openssl}

# Bump GENERATION when the set of files changes, so an older out/test-certs is regenerated rather than used.
GENERATION=4
KEY_PASSWORD='kama-tls test key pw'
if [ "$(cat "$DIR/.generation" 2>/dev/null)" = "$GENERATION" ] && [ "${1:-}" != "--force" ]; then
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
        ossl ca -batch -config ca.cnf -extfile ca.cnf -extensions "$3" -days 825 -md "${MD:-sha256}" -in "$1.csr" -out "$1.crt"
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

# Leaves signed with other hashes, and the end-point hash RFC 5929 assigns each: SHA-1 (like MD5) becomes SHA-256,
# every other hash is used as it is.
# (MD is set and cleared around the call: an assignment in front of a shell function call outlives it in sh.)
for md in sha224 sha384 sha1; do
    MD=$md; leaf "server-$md" localhost server rsa; MD=
    case $md in sha1) dg=sha256 ;; *) dg=$md ;; esac
    "$OPENSSL" x509 -in "../server-$md.crt" -outform DER | "$OPENSSL" dgst "-$dg" -binary | od -An -v -tx1 | tr -d ' \n' > "../server-$md.endpoint"
done

# The client key, encrypted both ways Mbed TLS reads (it has no DES), and a key that pairs with nothing.
ossl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -in client.key -out ../client-pkcs8.key -passout "pass:$KEY_PASSWORD"
if ! "$OPENSSL" rsa -aes256 -traditional -in client.key -out ../client-trad.key -passout "pass:$KEY_PASSWORD" 2>/dev/null; then
    ossl rsa -aes256 -in client.key -out ../client-trad.key -passout "pass:$KEY_PASSWORD"   # LibreSSL: traditional already
fi
grep -q 'Proc-Type: 4,ENCRYPTED' ../client-trad.key || { echo "gen-certs: client-trad.key is not a traditional encrypted PEM" >&2; exit 1; }
ossl genrsa -out ../mismatch.key 2048
ossl x509 -in client.crt -outform DER -out ../client.der
ossl pkcs8 -topk8 -nocrypt -in client.key -outform DER -out ../client-key.der

# Revocation: an empty CRL first, then revoke a leaf and issue the CRL that lists it. The untrusted CA issues an
# empty CRL of its own.
ossl ca -batch -config ca.cnf -gencrl -crldays 3650 -out ../empty.crl
leaf revoked localhost server rsa
ossl ca -batch -config ca.cnf -revoke revoked.crt
ossl ca -batch -config ca.cnf -gencrl -crldays 3650 -out ../revoked.crl
mkdir -p ../crldir
cp ../revoked.crl "../crldir/$("$OPENSSL" crl -hash -noout -in ../revoked.crl).r0"
sed -e 's/^database = index.txt/database = other-index.txt/' -e 's/^certificate = ca.crt/certificate = other-ca.crt/' \
    -e 's/^private_key = ca.key/private_key = other-ca.key/' ca.cnf > other-ca-sign.cnf
touch other-index.txt
ossl ca -batch -config other-ca-sign.cnf -gencrl -crldays 3650 -out ../other-ca.crl

cp ca.crt other-ca.crt ..
cd .. && rm -rf work
chmod 0644 ./*.crt ./*.key ./*.der ./*.crl ./*.endpoint crldir/*
echo "$GENERATION" > .generation
echo "gen-certs: wrote $(ls | wc -l | tr -d ' ') entries to out/test-certs"
