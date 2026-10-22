# @kama/tls — what is true in THIS repo

The two generated files carry the general rules: `AGENTS.md` is the language, `AGENTS.package.md` is the half
a publishable library needs. Both are written by `kama agents install` and are **not** hand-edited. This file
is the project-specific third, and it is the one to edit.

**Read [docs/ROADMAP.md](docs/ROADMAP.md) first.** The package and its tests need **kama ≥ 0.9.690** (`"kama"` in
`kama.json` and `tests/kama.json`). A registry version is permanent: a change ships as a new version, and only on the
maintainer's word.

- **Name no project this package does not depend on.** Code, comments, docs, the CHANGELOG and commit messages
  name its dependencies (kama and its std, Mbed TLS) and the standards and reference implementations a behavior
  is defined against (an RFC, OpenSSL, libpq's rules), never a package or program that uses this one, sibling
  `@kama/*` packages included. A request from a user becomes a general feature of this package, justified by the
  protocol or a general need rather than by who asked. Pushed commits and published versions stay as they are.

- **What the registry shows comes from `kama.json`:** `description`, `repository` and `keywords`, which `kama
  pkg search` and registry.kama-lang.org read. `kama publish` copies them into the version's index entry, and an
  entry is write-once, so a change reaches the registry only with a new version. The keys are new in kama
  0.9.523, and `kama publish` refuses them under a lower `"kama"` floor.
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
  two files. Threading is on for every target (isolates are OS threads: pthreads, and winpthreads on Windows);
  DTLS, renegotiation, socket I/O and persistent key storage are off.
- **The C this package writes is glue only** (`csrc/ktls.c`):
  - a once-guard over `psa_crypto_init`;
  - the memory-BIO session (phase 2);
  - error text into a caller buffer;
  - the RFC 5929 end-point hash and the RFC 9266 tls-exporter value;
  - the SNI callback that chooses among a server's identities (`ktls_sni_seen`);
  - the file loader behind every file-based setter (`ktls_load_file`), which opens a UTF-8 path as UTF-16 on Windows;
  - on Windows, the import of the certificate store's roots (`ktls_config_trust_windows`, `ktls_win_root_kept`);
  - a `_Static_assert` per size kama spells as a literal.

  Entropy is Mbed TLS's builtin source (`tf-psa-crypto/platform/platform_util.c`): the getrandom syscall on Linux
  with glibc, BCryptGenRandom on Windows, and `fopen("/dev/random")` on every other Unix-like system, macOS and
  emscripten among them.

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
  the leaf's CN-mismatch flag.
- **Mbed TLS sends whatever name it is given as SNI, an IP literal too, and RFC 6066 forbids one.** So a session
  whose server name is an IP literal gives Mbed TLS no name (`mbedtls_ssl_set_hostname(NULL)`), and a
  per-session verify callback (`mbedtls_ssl_set_verify`, which takes precedence over the configuration's)
  compares the address with the leaf's IP SANs under `Verify::Full` (`ktls_verify_ip_cb`). Only an IP SAN
  names an address, as in OpenSSL's `X509_check_ip` and Go.
- **A server's identities are chosen per handshake, in Mbed TLS's SNI callback.** `ktls_sni_seen` hands
  `mbedtls_ssl_set_hs_own_cert` every identity whose certificate covers the SNI name best, and Mbed TLS picks among
  them by the client's signature algorithms. The first identity is also the configuration's own certificate
  (`mbedtls_ssl_conf_own_cert`), which a handshake without SNI, or with a name none covers, falls back to. A
  configuration is frozen while sessions use it, so the callback reads the list without a lock.
- **A configuration's setters hold its lock.** `share()` puts one configuration in several isolates' hands. So these
  hold `ktls_config.lock`, an `mbedtls_mutex_*`:
  - every setter, through `ktls_change_begin` / `ktls_change_end`, which a new setter goes through too;
  - `ktls_config_trust_count`;
  - `ktls_session_new`, for its checks and the freeze.

  A frozen configuration never changes, so a session and its callbacks read it without the lock.
- **`tools/tsan.sh` runs the tests under ThreadSanitizer.** Run it after a change to anything isolates share. It
  needs kama ≥ 0.9.610, for build flags in a `select` value, so it writes its own manifest and is not part of the
  gate.
  - Loading a key takes Mbed TLS's PSA locks, which ThreadSanitizer counts as ordering both isolates. A test meant to
    catch a race keeps key loads out of the stretch where the two isolates overlap.
- **An engine failure in a read, write or flush is an `Other` IoError, and the stream keeps its code.** std's
  `IoError` is a kind plus an OS code, and only std can attach a code, so the engine's cannot ride in it.
  `TlsStream.tlsError()` rebuilds the `TlsError` from the kept code: `Certificate` or `Handshake` before the
  handshake finished, `Session` after. A transport failure stays the transport's own `IoError`.
- **Run the gate with the dev compiler by its full path:** `KAMA=$PWD/../cstar/out/Darwin-arm64/kama tools/test.sh`.
  The compiler finds std and its runtime headers relative to its own path, so run through `PATH` it fails with
  `cannot resolve module 'std::fs'`. The Linux aarch64 leg is the same script inside `localhost/kama-dev`
  (podman), with `../cstar/out/Linux-aarch64/kama` copied to `/k/out/L/kama` and `/k/lib` and `/k/include`
  linked to cstar's.
- **The Windows leg is the same script under Git Bash**, with msys2's UCRT64 clang first on the PATH:
  `PATH=/c/msys64/ucrt64/bin:$PATH KAMA=$PWD/../kama/out/UCRT64-x86_64/kama.exe tools/test.sh`.
  The compiler there is `../kama` built with `make` under msys2 UCRT64. A release works the same way, extracted
  anywhere. CI's Windows leg uses the release with zig bundled instead, so the compiler is part of the pin.
  - Git Bash and msys2's bash both rewrite a POSIX path in an environment variable for a Windows program, so
    `KTLS_TEST_CERTS` arrives as `C:/…` and `tools/test.sh` needs no Windows branch (checked 2026-10-22).
- **`trustSystem()` on Windows imports the certificate store; it never probes a bundle path.** There
  `/etc/ssl/cert.pem` is `C:\etc\ssl\cert.pem`, under a drive root where any user may make a directory, so probing
  it would let anyone on the machine plant a root. `systemRoots` in `src/config.kama` has a `@compileFor` twin per
  side.
  - The import's verdict per root is tested on stores made in memory (`tests/csrc/windows_roots.c`), never on the
    machine's own.
  - A machine's ROOT store holds only the roots Windows has needed so far: 21 load on a Windows 11 machine.
- **Code builds on every compiler from the floor to the dev one.** Newer compilers keep getting stricter:
  - no statement after a `while (true)` without `break`, or after a `panic`;
  - a test's "unwrap or stop" arm is `fail::<T>(msg:)` from `tests/src/main.kama`, because 0.9.690 wants a
    `return` after a `panic` in a value-producing arm, and later compilers refuse it as unreachable.
- **Test certificates are generated** into `out/test-certs` by `tools/gen-certs.sh` and never tracked.
  `kama publish` refuses a tracked `*.key` or `*.pem`, and so does the registry.
- **A gap goes in a `KAMA_GAPS.md` here the moment it is hit**, reduced to a repro and run on the named
  compiler. When this one first appears, add it to `publish.exclude`, because an exclude entry that matches no
  tracked file is an error.
