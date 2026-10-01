# @kama/tls — what is true in THIS repo

The two generated files carry the general rules: `AGENTS.md` is the language, `AGENTS.package.md` is the half
a publishable library needs. Both are written by `kama agents install` and are **not** hand-edited. This file
is the project-specific third, and it is the one to edit.

**Read [docs/ROADMAP.md](docs/ROADMAP.md) first.** The package needs **kama ≥ 0.9.486**, declared as `"kama"`
in every manifest here. Its first consumer is `@kama/postgres` (`../kama-postgres`). This package is not
published until postgres has exercised its API, because a registry version is permanent.

- **Mbed TLS is vendored, never linked.** `tools/vendor-mbedtls.sh` pins one release, `mbedtls-4.1.1.tar.bz2`
  with its bundled TF-PSA-Crypto, by SHA256. It owns `third_party/mbedtls/` and the generated `csources`
  block of `kama.json`, so do not hand-edit either. The release tarball carries the generated sources, so no
  Python/CMake step runs. The configuration is selected the upstream way, with `MBEDTLS_CONFIG_FILE` and
  `TF_PSA_CRYPTO_CONFIG_FILE` in `cflags` pointing at this package's reviewed headers in `csrc/`. That has
  worked since kama 0.9.473 passes each flag as one argument, so `third_party/` stays byte-identical to the
  release.
- **The C this package writes is glue only** (`csrc/`):
  - the memory-BIO session;
  - the entropy callback (getentropy / BCryptGenRandom);
  - the threading callbacks;
  - error text into a caller buffer;
  - the RFC 5929 end-point hash;
  - a `_Static_assert` per size kama spells as a literal.

  Its C symbols are `ktls_…`, because `kama_…` is reserved.
- **Kama does the I/O.** Mbed TLS only ever sees memory buffers, and `TlsStream<S>` moves bytes over any
  `ReliableStream` S. So a handshake test needs no socket: `tests/` runs client and server over an in-memory
  pipe, plus one loopback-TCP case with the server in its own isolate.
- **Test certificates are generated** into `out/test-certs` by `tools/gen-certs.sh` and never tracked.
  `kama publish` refuses a tracked `*.key` or `*.pem`, and so does the registry.
- **A gap goes in a `KAMA_GAPS.md` here the moment it is hit**, reduced to a repro and run on the named
  compiler. Postgres keeps its own file. When this one first appears, add it to `publish.exclude`, because
  an exclude entry that matches no tracked file is an error.
