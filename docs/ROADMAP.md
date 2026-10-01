# Roadmap

Where this is, 2026-09-30: Mbed TLS 4.1.1 is vendored and builds debug and release on macOS arm64 and Linux
aarch64. `TlsStream` is next.

| # | phase | state |
|---|---|---|
| 0 | Scaffold | **done** |
| 1 | `tools/vendor-mbedtls.sh`: pin mbedtls-4.1.1 by SHA256, assert the generated sources are present, fail on a foreign license or colliding header names, regenerate `csources`/`cincludes`; config deltas in `csrc/`; `tls::ready()` and `tls::version()` = `4.1.1`, debug and release | **done** |
| 2 | `TlsStream<S: ReliableStream>` over a memory BIO: handshake step (WantRead / WantWrite), read, write, close_notify; `TlsConfig` (trust roots from a file / PEM bytes / the system bundle, identity, verify full / ca-only / none, SNI, ALPN, versions); peer certificate DER and the RFC 5929 end-point hash. Tests: TLS 1.2 and 1.3, every verify mode, wrong host, untrusted CA, expired, client certificate required, ALPN, a large transfer, close_notify against truncation — over an in-memory pipe, and once over loopback TCP | next |
| 3 | Exercised by `@kama/postgres` (sslmode matrix, SCRAM-SHA-256-PLUS, client certificates) against PostgreSQL 14–19 | |
| — | Publish 0.1.0 — only on the maintainer's word, and before `@kama/postgres` | |

Windows is out of scope for 0.1.0: threading there needs `MBEDTLS_THREADING_ALT` with Windows mutexes, and it has never been built.
