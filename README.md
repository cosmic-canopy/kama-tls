# @kama/tls

TLS for [kama](https://kama-lang.org): [Mbed TLS](https://www.trustedfirmware.org/projects/mbed-tls/) 4.1 LTS,
vendored and bound. It is a client **and** a server over any `ReliableStream` — a `TcpStream`, a `UnixStream`,
or an in-memory pipe — and it is itself a `ReliableStream`, so a protocol written against the contract runs
over TLS unchanged. The first consumer is [`@kama/postgres`](https://github.com/cosmic-canopy/kama-postgres).

> **Status: under construction, not yet published.** Mbed TLS is vendored and builds on macOS and Linux;
> the `TlsStream` API is next (see [docs/ROADMAP.md](docs/ROADMAP.md)). Needs **kama ≥ 0.9.486**.

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

This package's own code is MIT; see [LICENSE](LICENSE). Mbed TLS is Apache-2.0 OR GPL-2.0-or-later; this
package takes it under Apache-2.0, and its license travels with it in `third_party/mbedtls/`. Every vendored
file carries that dual license, which the vendor script checks. A program that ships a binary built with this
package should list Apache-2.0 (Mbed TLS) in its third-party notices.
