# @kama/tls

TLS for [kama](https://kama-lang.org): [Mbed TLS](https://www.trustedfirmware.org/projects/mbed-tls/) 4.1 LTS,
vendored and bound. It is a client **and** a server over any `ReliableStream` — a `TcpStream`, a `UnixStream`,
or an in-memory pipe — and it is itself a `ReliableStream`, so a protocol written against the contract runs
over TLS unchanged. The first consumer is [`@kama/postgres`](https://github.com/cosmic-canopy/kama-postgres).

> **Status: not yet published.** `TlsStream` and `TlsConfig` work and are tested on macOS and Linux;
> `@kama/postgres` exercising them is next (see [docs/ROADMAP.md](docs/ROADMAP.md)). Needs **kama ≥ 0.9.519**.

## Using it

```kama
import { std::net::TcpStream, std::io::IoError, std::io::writeAll,
         tls::TlsConfig, tls::TlsStream, tls::TlsError };

// Once per program: what to trust, and how much to check (Verify::Full — chain AND name — is the default).
Result<TlsConfig, TlsError> made = TlsConfig.client();
TlsConfig config = match (give made) { case Ok(value: c): give c; case Err(error: e): { … } };
Result<isize, TlsError> roots = config.trustSystem();      // or trustFile(path:) / trustPem(pem:)

// Per connection: wrap any ReliableStream. The handshake runs on first use (or call handshake()).
string host = "db.example.com";
Result<TcpStream, IoError> sock = TcpStream.connectHost(host: host, port: 443ui16);
…
Result<TlsStream<TcpStream>, TlsError> tls = TlsStream::<TcpStream>.client(inner: give s, config: config, serverName: host);
```

A `TlsStream` is a `ReliableStream`, so `writeAll`, `BufReader` and every protocol written against the contract
work over it. A server is the same with `TlsConfig.server()`, an identity (`identityFiles` / `identityPem`), and
`TlsStream.server(inner:, config:)`. One configuration serves every session, on any isolate (`share()` hands out
another handle). After the handshake: `protocolVersion()`, `cipherSuite()`, `alpnProtocol()`,
`peerCertificate()` (DER), and `tlsServerEndPoint()` — the RFC 5929 channel binding SCRAM-SHA-256-PLUS needs.

A failed handshake says why as data: `TlsError::Certificate(flags, reasons)` names every check the peer's
certificate failed ("The certificate validity has expired", "The certificate Common Name (CN) does not match…").
A read or write that fails in the TLS engine rather than the transport answers an `Other` `IoError`, and
`tlsError()` says why as a `TlsError`: a certificate rejected by a handshake that a read ran, an alert, or a
record that did not authenticate (`TlsError::Session`). A peer that vanishes without a close_notify reads as an
`UnexpectedEof` `IoError`, never as an orderly end.

## What is vendored, and why

Mbed TLS 4.1.1 (LTS until March 2029), with its bundled TF-PSA-Crypto, is compiled from source through
`csources`: 110 C files, about 5 seconds for a cold debug + release build on an M-series Mac, and cached
after that. Nothing is linked from the system. So a consumer needs nothing installed, a shipped binary
contains one known TLS stack rather than whichever one a machine has, and every kama target builds it the
same way.

`tools/vendor-mbedtls.sh` pins the release tarball by SHA256 and copies its library sources byte-for-byte.
It leaves out the three optional drivers this configuration does not use. It regenerates the source list
in `kama.json`, and `third_party/mbedtls/VENDORED` records exactly what was kept. The configuration is
upstream's default plus a short, commented list of deltas in `csrc/ktls_*_user_config.h`. Upgrading means
running the script with a new version and reading the diff.

## License

`@kama/tls` is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. The vendored Mbed TLS is Apache-2.0 OR GPL-2.0-or-later, taken here under Apache-2.0; its
license travels with it in `third_party/mbedtls/`, and every vendored file carries that dual license (the
vendor script checks). A program that ships a binary built with this package lists Mbed TLS (Apache-2.0) in
its third-party notices.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
`@kama/tls` by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
