# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/). In 0.x, a minor bump may break.

## [Unreleased]

Version 0.1.1. Needs **kama ≥ 0.9.523**.

### Added
- What a registry shows and `kama pkg search` matches: a `description`, the `repository`
  (https://github.com/cosmic-canopy/kama-tls) and the keywords `ssl`, `mbedtls`, `x509`, `crypto` and `networking`.

### Changed
- The `kama` floor is 0.9.523, the release that introduced those manifest keys. The code is unchanged. Note: a
  registry index does not carry the floor yet, so a `^0.1.0` dependency resolves to 0.1.1 and an older compiler is
  told to update at install.

## [0.1.0] — 2026-10-02

The first published version. Needs **kama ≥ 0.9.519**; verified on kama 0.9.520 (the latest release), debug and
release, on macOS arm64 and Linux aarch64, and exercised by `@kama/postgres` against PostgreSQL 14–19. The
"Fixed" and "Changed" entries below record what changed while that work ran, before anything was published.

### Fixed
- An identity whose key does not belong to its certificate is refused when it is loaded. Before, nothing compared
  them, and the handshake failed later with a signature error. The comparison is ktls's own: TF-PSA-Crypto 1.2.0's
  `mbedtls_pk_check_pair` refuses every parsed RSA private key, because it leaves that key's cached public half
  empty.
- `identityPem` took a DER key with an extra NUL and could not parse it; DER is now passed at its exact length.
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
- Key logging for a debugger: `TlsStream.logKeys()` before the handshake, then `takeKeyLog()` gives the session's
  NSS key-log lines (SSLKEYLOGFILE's format: CLIENT_RANDOM for TLS 1.2, the four traffic secrets for TLS 1.3), wiped
  from the session as they are taken. Mbed TLS exports no TLS 1.3 EXPORTER_SECRET, which OpenSSL also logs.
- An identity in two steps, so a failure says which: `TlsConfig.certificateChain(bytes)` (PEM or DER; the first
  certificate is this side's), then `privateKey(bytes, password)` (PEM or DER at its exact length, decrypted when a
  password is given), which must pair with that certificate or fails with code -8, "the private key does not
  match the certificate". `identityFiles` and `identityPem` run both steps and check the pair too.
- `trustSystemWith(certFile:)`: `trustSystem()` with SSL_CERT_FILE's value supplied by the caller.
- `TlsStream.keyBits()`, and for a non-blocking caller `hasPendingOutput()` (ciphertext the transport has not
  taken: flush before waiting for an answer) and `hasBufferedInput()` (bytes a read answers without the transport:
  read them before waiting).
- `TlsStream.certificateRequested()`: a client learns whether the server asked for a certificate (libpq's
  `sslcertmode=require` needs it). The handshake now runs a step at a time in ktls, which samples Mbed TLS's
  private handshake state between steps.
- For a server: `TlsConfig.requestClientCertificate()` asks for a client certificate but completes the handshake
  whatever the client answers, and `TlsStream.requestedServerName()` is the SNI the client sent.
- Certificate revocation lists: `TlsConfig.revocationFile(path)`, `revocationPem(bytes)` (PEM or DER) and
  `revocationDir(path)` (the CRLs of an OpenSSL hashed directory, `<hash>.r<n>`). `revocation(mode:)` chooses
  `Revocation::Listed` (Mbed TLS's rule, the default: a certificate whose issuer has no CRL passes) or
  `Revocation::Complete` (OpenSSL's CRL_CHECK_ALL, which libpq sets: every certificate in the chain, the trust
  anchor too, needs its issuer's CRL, or fails with `BADCERT_NO_CRL`; with no CRL loaded at all, every chain fails,
  as OpenSSL's does).
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
