# Roadmap

Where this is, 2026-10-03: `TlsConfig`, `TlsStream<S>` and `Certificate` are done and tested, debug and release, on
macOS arm64 and Linux aarch64, on kama 0.9.519. `@kama/postgres` phase 6 exercised everything against PostgreSQL 14–19
(its whole suite runs over TLS too), and asked for what it lacked, now added: failures in words (alerts by name, key
and PEM errors), the RFC 5929 SHA-224 fix, chain verification without SNI, certificate names from a session or a
file, CRLs with OpenSSL's every-certificate rule, whether the server asked for a client certificate, a step-wise
identity with a pair check, and key logging. Next: publish 0.1.0, on the maintainer's word, before `@kama/postgres`.

| # | phase | state |
|---|---|---|
| 0 | Scaffold | **done** |
| 1 | `tools/vendor-mbedtls.sh`: pin mbedtls-4.1.1 by SHA256, assert the generated sources are present, fail on a foreign license or colliding header names, regenerate `csources`/`cincludes`; config deltas in `csrc/`; `tls::ready()` and `tls::version()` = `4.1.1`, debug and release | **done** |
| 2 | `TlsStream<S: ReliableStream>` over a memory BIO: handshake step (WantRead / WantWrite), read, write, close_notify; `TlsConfig` (trust roots from a file / PEM bytes / the system bundle, identity, verify full / ca-only / none, SNI, ALPN, versions); peer certificate DER and the RFC 5929 end-point hash. Tests: TLS 1.2 and 1.3, every verify mode, wrong host, untrusted CA, expired, client certificate required, ALPN, a large transfer, close_notify against truncation — over an in-memory pipe, and once over loopback TCP | **done** |
| 3 | Exercised by `@kama/postgres` (sslmode matrix, SCRAM-SHA-256-PLUS, client certificates) against PostgreSQL 14–19 | **done** |
| — | Publish 0.1.0 — only on the maintainer's word, and before `@kama/postgres` | |

Windows is out of scope for 0.1.0: threading there needs `MBEDTLS_THREADING_ALT` with Windows mutexes, and it has never been built.

## Known differences from OpenSSL-based clients

- **An IP address given as the server name is also sent as SNI.** Mbed TLS sends whatever name it is given, and
  RFC 6066 says an IP literal should not be sent. Servers ignore it in practice (PostgreSQL does). A caller that
  must not send one passes "" under `Verify::Chain` and checks the names from `peerNames()` itself, as
  @kama/postgres does for libpq's rules.
- **As a TLS 1.3 server, Mbed TLS sends a client-authentication alert under its handshake keys** (it switches to
  the application keys only at wrap-up), so a client that has already switched cannot read it and reports a bad
  MAC instead of `certificate_required`. OpenSSL switches at its own Finished. This matters only when this package
  is the server; as a client it reads an OpenSSL server's alert. Under TLS 1.2, Mbed TLS sends no alert for a
  missing client certificate.
- **`mbedtls_pk_check_pair` is not used.** In TF-PSA-Crypto 1.2.0 it compares cached public halves, and a parsed
  RSA private key has none, so it refuses every RSA pair. ktls compares the public key it exports through PSA
  instead (`ktls_pair_matches`). Worth reporting upstream; drop the workaround when a release fixes it.
- **`trustSystem()` reads a CA bundle file**, not the Windows certificate store or the macOS keychain. On macOS
  that is `/etc/ssl/cert.pem`, which Apple maintains; `SSL_CERT_FILE` overrides it, as with OpenSSL.
