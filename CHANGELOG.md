# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/). In 0.x, a minor bump may break.

## [Unreleased]

Needs **kama ≥ 0.9.519**.

### Changed
- **Ported to kama 0.9.519**, where `std::io::IoError` is a kind plus the OS's code (`e.kind()`), not an enum.
  A read, write or flush that fails in the TLS engine answers `IoError.of(kind: IoErrorKind::Other)`, and the
  engine's code is no longer carried in the `IoError` (it was `IoError::Other(code)`). `TlsStream.tlsError()`
  reports it instead. A truncation is an `UnexpectedEof` `IoError`.
- The workarounds for kama gaps KTLS-1 to KTLS-3 are gone. All three were fixed in kama 0.9.488 to 0.9.490.
- **Licensed under MIT OR Apache-2.0**, at your option, like kama itself (`LICENSE-MIT`, `LICENSE-APACHE`).
  Copyright is Cosmic Canopy LLC and the kama contributors. Mbed TLS stays Apache-2.0 OR GPL-2.0-or-later.

### Added
- `TlsStream.tlsError()`: why the engine last failed, as a `TlsError`. A certificate rejected by a handshake that
  a read or write ran keeps its flags and reasons, which the old `Other(code)` dropped.
- `TlsError::Session(code, detail)`: the session failed after its handshake (an alert, a record that did not
  authenticate). Before, `close()` reported such a failure as `Handshake`.
- The package scaffold: manifest, agent files, the hermetic test program (`tools/test.sh`).
- Mbed TLS 4.1.1 (LTS) with TF-PSA-Crypto 1.2.0, vendored by `tools/vendor-mbedtls.sh` and compiled through
  `csources` (110 files). Configuration: upstream defaults plus the deltas in `csrc/ktls_*_user_config.h`
  (threading on; DTLS, renegotiation, socket I/O and persistent key storage off).
- `tls::ready()` (initialise the crypto core once, `Result<Unit, TlsError>`) and `tls::version()`.
- `TlsConfig`: client or server; trust roots from a file, PEM bytes or the system bundle; an identity from PEM
  files or bytes; `Verify::None` / `Chain` / `Full`; ALPN; protocol versions. Shared across sessions and
  isolates (atomic reference count), and frozen once a session uses it.
- `TlsStream<S: ReliableStream>`: a client or server session over any stream, itself a `ReliableStream`.
  The engine works on memory (csrc/ktls.c); kama moves every byte. A non-blocking `handshake()`
  (`Progress::Done` / `WantRead` / `WantWrite`); an orderly `close()`; `protocolVersion`, `cipherSuite`,
  `alpnProtocol`, `peerCertificate`, and `tlsServerEndPoint` (RFC 5929). A truncation reads as
  `IoError::UnexpectedEof`.
- Tests over an in-memory pipe and loopback TCP: every verify mode, wrong host, untrusted CA,
  expired, IP SAN, ECDSA, TLS 1.2 and 1.3, ALPN, required client certificates, 1 MiB both ways, close_notify
  against truncation, the end-point hash against an independently decoded DER, a frozen configuration, the
  system bundle, a session whose server runs in another isolate, and `tlsError()` for a rejected certificate
  and a corrupted record. Test PKI from `tools/gen-certs.sh`.
