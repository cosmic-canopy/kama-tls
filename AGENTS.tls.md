# @kama/tls — what is true in THIS repo

The two generated files carry the general rules: `AGENTS.md` is the language, `AGENTS.package.md` is the half
a publishable library needs. Both are written by `kama agents install` and are **not** hand-edited. This file
is the project-specific third, and it is the one to edit.

**Read [docs/ROADMAP.md](docs/ROADMAP.md) first.** The package needs **kama ≥ 0.9.519**, declared as `"kama"`
in every manifest here. Its first consumer is `@kama/postgres` (`../kama-postgres`), which exercised the whole API
before 0.1.0 was published. A registry version is permanent: a change ships as a new version, and only on the
maintainer's word.

- **Mbed TLS is vendored, never linked.** `tools/vendor-mbedtls.sh` pins one release, `mbedtls-4.1.1.tar.bz2`
  with its bundled TF-PSA-Crypto, by SHA256. It owns `third_party/mbedtls/` and the generated `csources`
  and `cincludes` blocks of `kama.json`, so do not hand-edit any of them. The release tarball carries the
  generated sources, so no Python/CMake step runs.
  - Only `.c`/`.h` files from the library directories are kept, byte-identical. The three optional
    drivers (everest, p256-m, pqcp) are left out.
  - The script fails on a license other than `Apache-2.0 OR GPL-2.0-or-later`, and on two include-path
    directories sharing a header name.
- **The configuration is upstream's default plus this package's deltas.** `cflags` set
  `MBEDTLS_USER_CONFIG_FILE` / `TF_PSA_CRYPTO_USER_CONFIG_FILE` to `csrc/ktls_mbedtls_user_config.h` and
  `csrc/ktls_crypto_user_config.h`. That works because kama 0.9.473 passes each flag as one argument. Each
  `#undef`/`#define` there carries its reason, and a change to the configuration is a change to those
  two files. Threading is on (isolates are OS threads); DTLS, renegotiation, socket I/O and persistent key
  storage are off.
- **The C this package writes is glue only** (`csrc/ktls.c`):
  - a once-guard over `psa_crypto_init`;
  - the memory-BIO session (phase 2);
  - error text into a caller buffer;
  - the RFC 5929 end-point hash;
  - a `_Static_assert` per size kama spells as a literal.

  Entropy is Mbed TLS's builtin source (getrandom / getentropy / BCryptGenRandom).

  Its C symbols are `ktls_…`, because `kama_…` is reserved.
- **Kama does the I/O.** Mbed TLS only ever sees memory buffers, and `TlsStream<S>` moves bytes over any
  `ReliableStream` S. So a handshake test needs no socket: `tests/` runs client and server over an in-memory
  pipe (`tests/src/pipe.kama`), plus one loopback-TCP case with the server in its own isolate.
- **`mbedtls_ssl_read` returns 0 for a transport that ended WITHOUT close_notify** (its documented contract)
  and `MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY` for an orderly end. `ktls_read` turns those into `KTLS_TRUNCATED`
  (→ an `UnexpectedEof` IoError) and `KTLS_CLOSED` (→ 0 bytes). Getting this backwards silently turns a
  truncation into a clean EOF; the truncation test guards it.
- **Mbed TLS 4 refuses a verifying client whose hostname was never set, but an explicit
  `mbedtls_ssl_set_hostname(NULL)` means "verify without a name".** So `Verify::Chain` (libpq's verify-ca) takes
  an empty server name: no SNI, no name compared. Given a name, it sends SNI, and a verify callback clears only
  the leaf's CN-mismatch flag. Mbed TLS sends whatever name it is given as SNI, an IP address too, so a caller
  that must not (libpq sends none for an IP) passes "" and checks names itself.
- **An engine failure in a read, write or flush is an `Other` IoError, and the stream keeps its code.** std's
  `IoError` is a kind plus an OS code, and only std can attach a code, so the engine's cannot ride in it.
  `TlsStream.tlsError()` rebuilds the `TlsError` from the kept code: `Certificate` or `Handshake` before the
  handshake finished, `Session` after. A transport failure stays the transport's own `IoError`.
- **Run the gate with the dev compiler by its full path:** `KAMA=$PWD/../cstar/out/Darwin-arm64/kama tools/test.sh`.
  The compiler finds std and its runtime headers relative to its own path, so run through `PATH` it fails with
  `cannot resolve module 'std::fs'`. The Linux aarch64 leg is the same script inside `localhost/kama-dev`
  (podman), with `../cstar/out/Linux-aarch64/kama` copied to `/k/out/L/kama` and `/k/lib` and `/k/include`
  linked to cstar's.
- **Test certificates are generated** into `out/test-certs` by `tools/gen-certs.sh` and never tracked.
  `kama publish` refuses a tracked `*.key` or `*.pem`, and so does the registry.
- **A gap goes in a `KAMA_GAPS.md` here the moment it is hit**, reduced to a repro and run on the named
  compiler. Postgres keeps its own file. When this one first appears, add it to `publish.exclude`, because
  an exclude entry that matches no tracked file is an error.
