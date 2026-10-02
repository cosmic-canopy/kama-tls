# Roadmap

Where this is, 2026-10-02: `TlsConfig` and `TlsStream<S>` are done and tested, debug and release, on macOS
arm64 and Linux aarch64. The package is ported to kama 0.9.519, which has the new `IoError` and fixes for
every gap this package filed (KTLS-1 to KTLS-3), and it now needs that compiler. Next, `@kama/postgres` uses
it against PostgreSQL 14–19.

| # | phase | state |
|---|---|---|
| 0 | Scaffold | **done** |
| 1 | `tools/vendor-mbedtls.sh`: pin mbedtls-4.1.1 by SHA256, assert the generated sources are present, fail on a foreign license or colliding header names, regenerate `csources`/`cincludes`; config deltas in `csrc/`; `tls::ready()` and `tls::version()` = `4.1.1`, debug and release | **done** |
| 2 | `TlsStream<S: ReliableStream>` over a memory BIO: handshake step (WantRead / WantWrite), read, write, close_notify; `TlsConfig` (trust roots from a file / PEM bytes / the system bundle, identity, verify full / ca-only / none, SNI, ALPN, versions); peer certificate DER and the RFC 5929 end-point hash. Tests: TLS 1.2 and 1.3, every verify mode, wrong host, untrusted CA, expired, client certificate required, ALPN, a large transfer, close_notify against truncation — over an in-memory pipe, and once over loopback TCP | **done** |
| 3 | Exercised by `@kama/postgres` (sslmode matrix, SCRAM-SHA-256-PLUS, client certificates) against PostgreSQL 14–19 | next |
| — | Publish 0.1.0 — only on the maintainer's word, and before `@kama/postgres` | |

Windows is out of scope for 0.1.0: threading there needs `MBEDTLS_THREADING_ALT` with Windows mutexes, and it has never been built.

## Known differences from OpenSSL-based clients

- **An IP address given as the server name is also sent as SNI.** Mbed TLS sends whatever name it verifies
  against, and RFC 6066 says an IP literal should not be sent. Servers ignore it in practice (PostgreSQL does).
  Separating the two would mean verifying IP SANs by hand in a callback, which is not worth owning yet.
- **`trustSystem()` reads a CA bundle file**, not the Windows certificate store or the macOS keychain. On macOS
  that is `/etc/ssl/cert.pem`, which Apple maintains; `SSL_CERT_FILE` overrides it, as with OpenSSL.
