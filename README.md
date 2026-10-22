# @kama/tls

TLS for [kama](https://kama-lang.org): [Mbed TLS](https://www.trustedfirmware.org/projects/mbed-tls/) 4.1 LTS,
vendored and bound. It is a client **and** a server over any `ReliableStream` — a `TcpStream`, a `UnixStream`,
or an in-memory pipe — and it is itself a `ReliableStream`, so a protocol written against the contract runs
over TLS unchanged.

```sh
kama pkg add kama.json @kama/tls --version ^0.1.0     # from the official registry, registry.kama-lang.org
```

Needs **kama ≥ 0.9.690** — declared as `"kama": ">=0.9.690"` in the manifest, so an older compiler is refused by
name. (0.1.0 needed 0.9.519; 0.1.1 raised the floor to 0.9.523 for the registry's metadata keys, and 0.1.7 to 0.9.690
for a library linked on Windows alone.) Tested, debug and release, on macOS arm64, Linux aarch64 and x86-64, and
Windows x86-64. WebAssembly, TLS 1.2 resumption and bare metal are next ([docs/ROADMAP.md](docs/ROADMAP.md)).

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

`trustSystem()` trusts what the operating system does: the bundle `SSL_CERT_FILE` names when it is set, else the
system's CA bundle on Linux and macOS. On Windows it imports the roots the certificate store allows for server
authentication, less any in its Disallowed store. Windows also trusts a root it downloads the first time it meets one,
which no import can see, so a server whose root that machine has never needed may be refused; `SSL_CERT_FILE` then
names a bundle instead.

A `TlsStream` is a `ReliableStream`, so `writeAll`, `BufReader` and every protocol written against the contract
work over it. A server is the same with `TlsConfig.server()`, an identity (`identityFiles` / `identityPem`; several,
and each handshake serves the one whose certificate names the host the client asked for by SNI), and
`TlsStream.server(inner:, config:)`. One configuration serves every session, on any isolate (`share()` hands out
another handle). After the handshake: `protocolVersion()`, `cipherSuite()`, `alpnProtocol()`,
`peerCertificate()` (DER), and the channel bindings a SCRAM-…-PLUS login folds in: `tlsServerEndPoint()` (RFC 5929,
TLS 1.2 and 1.3, the one PostgreSQL uses) and `tlsExporter()` (RFC 9266 tls-exporter, TLS 1.3 only).

A TLS 1.3 session can be resumed, which skips the certificate and its signature on the next connection. Both sides opt
in with `sessionTickets(lifetime:)`, from 1 second to 7 days. A resumed session does not check the certificate again,
so keep the lifetime short; two hours, OpenSSL's default, is a reasonable choice.

```kama
config.sessionTickets(lifetime: Duration.fromSecs(s: 7200i64));   // on the client's and the server's configuration
// The server's ticket arrives after the handshake, with a read.
Optional<TlsSession> kept = tls.takeSession();
// Later, a new stream through the same configuration, for the same server name, before its handshake:
next.resumeWith(session: give s);                                   // s from `kept`
bool fast = next.resumed();                                         // false when it fell back to a full handshake
```

A resumed session always runs a fresh (EC)DHE key exchange, and 0-RTT data is never sent or accepted. A `TlsSession`
lives in memory only and is used once. TLS 1.2 does not resume, and a server that asks for client certificates issues
no tickets, since a resumed session carries none.

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
