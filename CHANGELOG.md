# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/). In 0.x, a minor bump may break.

## [Unreleased]

Needs **kama ≥ 0.9.519**.

### Fixed
- `tlsServerEndPoint()` follows RFC 5929 as PostgreSQL does: only an MD5 or SHA-1 signature hashes with SHA-256,
  and a SHA-224 signature hashes with SHA-224 (it used SHA-256, so SCRAM-SHA-256-PLUS failed against such a
  certificate). A signature hash outside MD5/SHA-1/SHA-2 gives no binding rather than a guess.
- The verify reasons in `TlsError::Certificate` are joined with "; " as documented (it was ";"), and each starts in
  lower case so the list reads inside a sentence.

### Changed
- **`Verify::Chain` takes an empty server name**: then no SNI is sent and no name is compared, and the chain still
  decides. Mbed TLS 4 allows this through an explicit `mbedtls_ssl_set_hostname(NULL)`. `Verify::Full` still
  needs a name. A caller that must not send an IP address as SNI (libpq) passes "" and checks names itself.
- **Ported to kama 0.9.519**, where `std::io::IoError` is a kind plus the OS's code (`e.kind()`), not an enum.
  A read, write or flush that fails in the TLS engine answers `IoError.of(kind: IoErrorKind::Other)`, and the
  engine's code is no longer carried in the `IoError` (it was `IoError::Other(code)`). `TlsStream.tlsError()`
  reports it instead. A truncation is an `UnexpectedEof` `IoError`.
- The workarounds for kama gaps KTLS-1 to KTLS-3 are gone. All three were fixed in kama 0.9.488 to 0.9.490.
- **Licensed under MIT OR Apache-2.0**, at your option, like kama itself (`LICENSE-MIT`, `LICENSE-APACHE`).
  Copyright is Cosmic Canopy LLC and the kama contributors. Mbed TLS stays Apache-2.0 OR GPL-2.0-or-later.

### Added
- `Certificate.parse(bytes)`: an X.509 certificate from PEM or DER, with no session, and its `der()`, `names()` and
  `tlsServerEndPoint()`.
- `CertificateNames` (`count()`, `kindAt(index:)`, `valueAt(index:)`) and `TlsStream.peerNames()`: the names a
  certificate carries, in the order a host-name check meets them (subjectAltName dNSName and iPAddress entries,
  then subject commonNames), each as its raw bytes. A caller that checks names by its own rules (libpq's) reads
  them here.
- `TlsError::Alert(description, name, established)`: the peer ended the session with a fatal alert, by its RFC
  number and name (48 `unknown_ca`, 70 `protocol_version`, 116 `certificate_required`, …), and whether the
  handshake had finished. Before, an alert was a `Handshake` or `Session` error saying only "A fatal alert message
  was received from our peer".
- `TlsError.reason()`: the failure in words that read after a frame such as libpq's `SSL error: `, with no module
  tag ("received fatal alert: unknown_ca", "certificate verify failed: the certificate validity has expired").
- Words for the key, PEM and PSA failures Mbed TLS 4 prints as "UNKNOWN ERROR CODE": "the private key is
  encrypted, and no password was given", "the password does not decrypt the private key", a PEM encrypted with a
  cipher this build lacks (DES), and the rest of `MBEDTLS_ERR_PK_*` / `PEM_*`.
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
