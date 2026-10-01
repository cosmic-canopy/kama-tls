# @kama/tls

TLS for [kama](https://kama-lang.org): [Mbed TLS](https://www.trustedfirmware.org/projects/mbed-tls/) 4.1 LTS,
vendored and bound. It is a client **and** a server over any `ReliableStream` — a `TcpStream`, a `UnixStream`,
or an in-memory pipe — and it is itself a `ReliableStream`, so a protocol written against the contract runs
over TLS unchanged. The first consumer is [`@kama/postgres`](https://github.com/cosmic-canopy/kama-postgres).

> **Status: under construction, not yet published.** The scaffold is in place; vendoring Mbed TLS is next
> (see [docs/ROADMAP.md](docs/ROADMAP.md)). Needs **kama ≥ 0.9.486**.

## What is vendored, and why

Mbed TLS 4.1.1 (LTS until March 2029), with its bundled TF-PSA-Crypto, is compiled from source through
`csources`. Nothing is linked from the system. So a consumer needs nothing installed, a shipped binary
contains one known TLS stack rather than whichever one a machine has, and every kama target builds it the
same way. `tools/vendor-mbedtls.sh` pins the release by SHA256 and regenerates the source list. Upgrading
means running it with a new version and reading the diff.

## License

This package is MIT; see [LICENSE](LICENSE). Mbed TLS is Apache-2.0 OR GPL-2.0-or-later, used here under
Apache-2.0, and its license travels with it in `third_party/mbedtls/`.
