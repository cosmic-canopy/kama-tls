# Roadmap

Where this is, 2026-10-19: `TlsConfig`, `TlsStream<S>` and `Certificate` are done and tested, debug and release, on
macOS arm64 and Linux aarch64. Before 0.1.0 everything was exercised end to end against PostgreSQL 14–19, which added
failures in words (alerts by name, key and PEM errors), the RFC 5929 SHA-224 fix, chain verification without SNI,
certificate names from a session or a file, CRLs with OpenSSL's every-certificate rule, whether the server asked for a
client certificate, a step-wise identity with a pair check, and key logging.

Published on the official registry: 0.1.0 (2026-10-02); 0.1.1 (2026-10-03), what the registry shows and searches, so
it needs kama 0.9.523; 0.1.2 (2026-10-13), the RFC 9266 tls-exporter channel binding (phase 4); 0.1.3 (2026-10-18),
no IP literal as SNI, an IP matched against IP SANs alone, and `TlsError` `Sendable`; 0.1.4 (2026-10-18), a server
holds several identities and chooses one per handshake by SNI (phase 5); 0.1.5 (2026-10-19), a race on shared
configurations fixed (phase 6). 0.1.6 builds on kama 0.9.690 and on the 0.9.707 in development, and its tests need
0.9.690; the package's floor stays 0.9.523. It waits for the registry. Once the registry has published it, the
CHANGELOG heading takes the date, as `cac8a2e` did for 0.1.5.

**Next: every platform kama builds for** ([Platforms](#platforms)), starting with Windows (phase 7). Its section was
checked against cross builds on 2026-10-19 and has two questions for the maintainer. After the platforms comes
session resumption on TLS 1.3 and 1.2 ([Session resumption](#session-resumption)). The maintainer settled the scope
questions on 2026-10-18; the decisions are recorded in each section.

| # | phase | state |
|---|---|---|
| 0 | Scaffold | **done** |
| 1 | `tools/vendor-mbedtls.sh`: pin mbedtls-4.1.1 by SHA256, assert the generated sources are present, fail on a foreign license or colliding header names, regenerate `csources`/`cincludes`; config deltas in `csrc/`; `tls::ready()` and `tls::version()` = `4.1.1`, debug and release | **done** |
| 2 | `TlsStream<S: ReliableStream>` over a memory BIO: handshake step (WantRead / WantWrite), read, write, close_notify; `TlsConfig` (trust roots from a file / PEM bytes / the system bundle, identity, verify full / ca-only / none, SNI, ALPN, versions); peer certificate DER and the RFC 5929 end-point hash. Tests: TLS 1.2 and 1.3, every verify mode, wrong host, untrusted CA, expired, client certificate required, ALPN, a large transfer, close_notify against truncation — over an in-memory pipe, and once over loopback TCP | **done** |
| 3 | Exercised end to end against PostgreSQL 14–19 (the sslmode matrix, SCRAM-SHA-256-PLUS, client certificates) | **done** |
| — | Publish 0.1.0 | **done** (2026-10-02) |
| 4 | RFC 9266 tls-exporter channel binding as `TlsStream.tlsExporter()`, TLS 1.3 only ([issue #1](https://github.com/cosmic-canopy/kama-tls/issues/1)); see [Channel bindings](#channel-bindings) | **done** (0.1.2, 2026-10-13) |
| 5 | A server holds several identities and serves each handshake the ones whose certificate names the SNI host; see [Server identities](#server-identities) | **done** (0.1.4, 2026-10-18) |
| 6 | Setters on a shared configuration race each other and a session being made from it; see [Shared configurations](#shared-configurations) | **done** (0.1.5, unpublished) |
| 7 | Windows; see [Platforms](#platforms) | **next** |
| 8 | WebAssembly (`--target WASM`), the wasm leg `AGENTS.package.md` asks of a package that vendors C; see [Platforms](#platforms) | planned |
| 9 | Session resumption on TLS 1.3; see [Session resumption](#session-resumption) | planned |
| 10 | Session resumption on TLS 1.2; see [Session resumption](#session-resumption) | planned |
| 11 | Bare metal (`--target EMBEDDED`); see [Platforms](#platforms) | planned, questions first |

## Channel bindings

A channel binding is a value both ends of one TLS connection can compute and a man in the middle cannot, which a
login (SCRAM-…-PLUS) folds in to prove it ran over that connection. This package offers the TLS half only; SASL,
SCRAM and the XMPP extensions that negotiate a binding type (XEP-0440, XEP-0474, XEP-0515) belong in a SASL or
XMPP package built on it.

- **tls-server-end-point** (RFC 5929): `TlsStream.tlsServerEndPoint()`, TLS 1.2 and 1.3. The only type PostgreSQL
  supports. **Done.**
- **tls-exporter** (RFC 9266): phase 4, `TlsStream.tlsExporter()`. **Done** (0.1.2).
  - It is `mbedtls_ssl_export_keying_material` with the label `EXPORTER-Channel-Binding`, a zero-length context
    (`use_context` 0) and 32 bytes: `ktls_exporter`, beside `ktls_end_point` in `csrc/ktls.c`.
  - Mbed TLS's default config turns on `MBEDTLS_SSL_KEYING_MATERIAL_EXPORT` and our user configs leave it on.
    `ktls.c` has an `#error` if it is ever off, so a config change cannot silently remove the binding.
  - It is empty before the handshake is over and on a TLS 1.2 session. RFC 9266 allows TLS 1.2 only with
    extended master secret, and tls-server-end-point already covers 1.2.
  - The 32 bytes go out through the existing caller buffer, and the C side wipes its stack copy with
    `mbedtls_platform_zeroize`.
  - The kama side is one more `bytesFrom` case beside `tlsServerEndPoint()` in `src/stream.kama`.
  - Tests extend `channelBindingTests` in `tests/src/stream_test.kama`:
    - under TLS 1.3, client and server get the same 32 bytes;
    - a second session with the same configs gets none before its handshake, and different bytes after it;
    - a session pinned to TLS 1.2 gets none on either side.
  - Those tests cannot catch a wrong label, since both ends would share it. So it was checked once against OpenSSL
    3.6.4 (`openssl s_server -keymatexport EXPORTER-Channel-Binding -keymatexportlen 32` against a throwaway kama
    client that printed the value). Under TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_256_GCM_SHA384 the two printed
    the same 32 bytes, and the commit that added it records them. The gate stays hermetic, so that check is not in
    `tools/test.sh`.
  - The README has a line beside `tlsServerEndPoint()`. `kama.json` is 0.1.2, and the `"kama"` floor stays at
    0.9.523. The gate is green on macOS arm64 and Linux aarch64 (AGENTS.tls.md), and CI is green on kama 0.9.523.
    Published 2026-10-13.
- **tls-unique** (RFC 5929): **not offered.** It is defined only up to TLS 1.2, where the triple-handshake attack
  breaks it without extended master secret. RFC 9266 replaces it for 1.3, and Mbed TLS has no public API for the
  Finished message it is made from.

## Server identities

Phase 5, 0.1.4. A server can answer several host names from one listener, each with its own certificate.

- A server `TlsConfig` holds several identities, in the order they were loaded. Each is loaded as one always was:
  `identityFiles`, `identityPem`, or `certificateChain` then `privateKey`. A client holds one, and a second is
  refused (-5). A chain still waiting for its key refuses another identity (-5).
- Mbed TLS's SNI callback (`ktls_sni_seen`) scores each identity by how well its leaf's names cover the SNI name.
  - The names are the subjectAltName dNSNames, or the subject CNs when the certificate has none (RFC 6125 §6.4.4).
    So the server chooses by the same names a client then checks.
  - The comparison is ASCII case-insensitive, and one trailing dot on the SNI name is ignored.
  - An exact name scores 2. A `*.` wildcard scores 1, and covers exactly one whole left-most label (§6.4.3).
- Every identity at the best score goes to `mbedtls_ssl_set_hs_own_cert`, after the list is cleared, because a
  second ClientHello (after a HelloRetryRequest) chooses again. Mbed TLS then picks among them by the client's
  signature algorithms. Under TLS 1.3 it walks them in the client's order (`ssl_tls13_pick_key_cert`), so an RSA
  and an ECDSA certificate for one name both work.
- No SNI, or a name no identity covers, gets the first identity, which is also the configuration's own certificate
  (`mbedtls_ssl_conf_own_cert`).
  - It is not refused with `unrecognized_name`: the client decides whether that certificate will do, as Go and
    nginx leave it.
  - A strict mode waits until someone needs it.
- The names come from the certificates, so no second list can drift from them. A configuration is frozen while
  sessions use it, so the callback reads the identities without a lock, from any isolate.
- Tests: `tests/src/identities_test.kama`, against `sni-other`, `sni-wild`, `sni-exact` and `sni-cn` from
  `tools/gen-certs.sh` (generation 6). It was also checked once against OpenSSL 3.6.4's `s_client`, which the
  commit records.

## Shared configurations

Phase 6, **done** (0.1.5, unpublished). A data race found while building phase 5. No run had been seen to fail.

**The race.** `TlsConfig` is `Sendable`, and `share()` hands out another handle on the same C configuration.
- Every setter checked `frozen` and then changed the configuration, as two steps.
- `ktls_session_new` set `frozen` and then read the configuration (`mbedtls_ssl_setup`).

So with two handles on two isolates:
- two setters could change the configuration at once: the ALPN array, the trust chain, the CRLs, the identity list;
- a setter that had passed its check could still be changing the configuration while a session was set up from it.

Either one is a C data race, which is undefined behavior, not just a wrong answer. A program that finishes
configuring before it shares, the pattern the API documents, never hit it.

**The fix.**
- `ktls_config` has a mutex, Mbed TLS's `mbedtls_mutex_*`, so it follows `MBEDTLS_THREADING_*` to Windows in phase
  7. It sits under `#if defined(MBEDTLS_THREADING_C)`, as in Mbed TLS's own `ssl_cache.c`: a build without
  threading has one thread.
- Every setter takes it around its check and its change: `ktls_change_begin` and `ktls_change_end` around a
  `…_locked` body. So does `ktls_config_trust_count`, the one reader. `identityPem` holds it once across both of its
  steps.
- `ktls_session_new` takes it around its precondition checks and the store to `frozen`, now a plain field under the
  lock. It sets the session up after releasing it. A frozen configuration cannot change.
- The SNI and verify callbacks keep reading without a lock, because they run only after the freeze.
- The API doesn't change, so this is a patch release, 0.1.5.

**Rejected: freezing a configuration in `share()`.** It needs no lock, but a program that shares a configuration
and then sets something on it, on one isolate, would get `-4` where it gets Ok today. That breaks callers, so it
would have to be 0.2.0.

**The test.** `tests/src/shared_test.kama`.
- Two isolates each hold a handle on one server configuration.
  - One calls every kind of setter in a loop: an identity and an ALPN name in its first eight rounds, then the trust
    chain, the CRLs, the CRL rule, the verify mode and the versions in every round.
  - The other waits 50 ms, then makes eight sessions. Before each, it calls `versions(…)` and `trustCount()`.
- What must hold:
  - every handshake completes;
  - every setter answers Ok until the first session and `-4` after it, never Ok again;
  - the trust count holds still once the configuration is frozen.
- Why that shape. Loading a key takes Mbed TLS's PSA locks on both isolates, and ThreadSanitizer counts a lock as
  ordering everything before it. With an identity in every round and no head start, five runs before the fix each
  reported only one race: the two `versions(…)` calls meeting.

**ThreadSanitizer.** `tools/tsan.sh` builds the tests with `-fsanitize=thread` in a `select` entry and runs them.
- kama 0.9.523 refuses build flags in a `select` value; they arrived in 0.9.610. So the entry is not in
  `tests/kama.json`, whose floor is the package's. It is in a manifest the script writes into a temporary directory,
  beside a copy of `tests/src`.
- It ran on macOS arm64 with kama 0.9.671 and Apple clang 21.
- Before the fix, every one of six runs reported races. Among them:
  - `ktls_config_versions` on both isolates at once (two setters);
  - `ktls_config_trust_count` against `ktls_config_trust_file`, and against the CA chain growing in `x509_crt.c`
    (the reader);
  - `ktls_session_new` reading `verify` against `ktls_config_verify` (a session being made).
- After the fix: no report in seven runs, and every test passes.

## Session resumption

Phases 9 (TLS 1.3) and 10 (TLS 1.2). Neither side resumes a session today. Build each the way phases 4 and 5 were
built: a design in this section, tests in `tests/`, the gate on every platform the package then supports, and one
version per phase.

**Decided (the maintainer, 2026-10-18).**
- **Both versions, as production TLS stacks resume both** (OpenSSL, Go, rustls). TLS 1.3 comes first; TLS 1.2
  follows as its own phase. Neither has a security reason to leave out, given the two rules below.
- **TLS 1.3 resumes only with a fresh (EC)DHE** (psk_dhe_ke), so a resumed session keeps forward secrecy. Pure PSK
  (psk_ke) is never accepted or offered: `mbedtls_ssl_conf_tls13_key_exchange_modes` is set without
  `MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK`.
- **TLS 1.2 resumes only a session made with extended master secret** (RFC 7627), which shuts out the
  triple-handshake attack. Mbed TLS negotiates EMS by default (`MBEDTLS_SSL_EXTENDED_MASTER_SECRET`) but has no
  "required" switch, so ktls enforces it. It neither issues nor accepts a ticket, and caches no session ID, for a
  session without EMS.
  - A TLS 1.2 ticket carries the master secret encrypted under the ticket key, so a stolen ticket key decrypts every
    session resumed under it until the key rotates. The API comment says so.
  - Rotation is not optional.
  - Phase 10 covers both TLS 1.2 mechanisms: tickets (RFC 5077) and the server's session-ID cache (`ssl_cache.c`),
    for clients that send no ticket.
- **A client's `TlsSession` lives in memory only.** It is not saved to bytes, so the resumption secret never becomes
  data a caller stores.
- **Still open, for the phase 9 session to propose and the maintainer to confirm:** the default ticket lifetime and
  key rotation, and whether a caller can set them. Reference points: Go rotates its ticket keys daily and accepts a
  ticket for up to 7 days, and nginx's session timeout defaults to 5 minutes. Keep it short, because a resumed session
  is not re-verified.

**What the vendored Mbed TLS 4.1.1 has.** Our configuration keeps upstream's defaults for all of this:
- `MBEDTLS_SSL_SESSION_TICKETS`, `MBEDTLS_SSL_TICKET_C` and `MBEDTLS_SSL_CACHE_C` are on, and `ssl_ticket.c` and
  `ssl_cache.c` are compiled.
- All three TLS 1.3 key-exchange modes are on: ephemeral, psk and psk_ephemeral.
- `MBEDTLS_SSL_EARLY_DATA` is off.
- The server sets no ticket callbacks (`mbedtls_ssl_conf_session_tickets_cb`), so it issues no tickets.
- The TLS 1.3 client never enables `mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets`, so it discards the
  NewSessionTicket messages it receives.

**Proposed shape**
- **Server.** `TlsConfig.sessionTickets(…)` turns tickets on.
  - It owns an `mbedtls_ssl_ticket_context`, with random keys kept in memory only and rotated each lifetime, so a
    restart invalidates every ticket.
  - It sets `mbedtls_ssl_conf_session_tickets_cb`, and `mbedtls_ssl_conf_new_session_tickets` for how many a
    handshake sends.
  - `ssl_ticket.c` locks its own state under `MBEDTLS_THREADING_C`, so one configuration still serves sessions on
    any isolate.
- **Client.**
  - An opaque `TlsSession` resource (`Sendable`, so a pool on another isolate can hold it).
  - `TlsStream.session()` answers `Optional<TlsSession>` once a ticket has arrived, and a way to hand one to the
    next client session before its handshake (`mbedtls_ssl_set_session`).
  - Under TLS 1.3 the ticket arrives after the handshake. So the client enables the new-ticket signal, and
    `ktls_read` treats `MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET` as "keep reading" after keeping the session.
- **Both.** `TlsStream.resumed()`, so a caller (and the tests) can tell a resumed handshake from a full one.

**Security: each item is a guard or a test**
- **0-RTT stays off.** An `#error` fires if `MBEDTLS_SSL_EARLY_DATA` is ever on, because early data can be
  replayed.
- **A session is offered only to the name it was made for.** Check whether Mbed TLS 4.1.1 compares the ticket's
  hostname (it keeps `session->hostname`). If it does not, ktls compares before `mbedtls_ssl_set_session`.
- **A resumed session does not verify the certificate again,** so revocation is only as fresh as the ticket
  lifetime. Say so in the API comment, and keep the default lifetime short.
- **`TlsSession` holds the resumption secret.** Wipe it on drop (`mbedtls_ssl_session_free` zeroizes) and never log
  it.
- **Test the peer accessors on a resumed session:** `peerCertificate()`, `peerNames()` and `tlsServerEndPoint()`
  rely on `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` (on). Also test that `tlsExporter()` still differs from session to
  session.
- **A TLS 1.3 resumption that offers pure PSK is refused,** and a TLS 1.2 session without EMS is never resumed (see
  the decisions above). Each gets a test.

**Payoff.** A TLS 1.3 resumption skips the certificate and its signature, not a round trip; only 0-RTT saves a
round trip, and it stays off. So the gain is CPU on both sides, and the size of the server's certificate on the
wire.

## Platforms

**Decided (the maintainer, 2026-10-18): every platform kama builds for.** Tested today: macOS arm64 and Linux
aarch64 locally, Linux x86-64 and macOS arm64 in CI. kama's targets are `HOST`, `MACOS`, `WINDOWS`, `LINUX`, `WASM`
and `EMBEDDED`, so what remains is Windows, WebAssembly and bare metal. A leg is green when `tools/test.sh` (or its
equivalent for that target) passes there, debug and release.

### Windows (phase 7, next)

kama builds for Windows: `--target WINDOWS`, which is `<arch>-windows-gnu`, with mingw-w64 or zig. The gate's
Windows leg is CI's `windows-latest`. The maintainer has a Windows machine for a local run when CI is not enough:
ask for one rather than guess at a failure.

**Checked on 2026-10-19, by cross-building the tests from macOS with zig 0.16.0.** Nothing has run on Windows yet.
- **The package builds for Windows today**, with no error or warning:
  - for x86-64 and aarch64, on kama 0.9.675 and on 0.9.523;
  - the binary imports only system DLLs: KERNEL32, WS2_32, bcrypt, ntdll and the UCRT.
- **kama's isolates are winpthreads on Windows.** `kama_isolate.h` includes `<pthread.h>` and calls
  `pthread_create` on every target. mingw-w64 and zig both ship winpthreads, and it is linked statically: there is no
  `libwinpthread-1.dll` import.
- **`MBEDTLS_THREADING_PTHREAD` builds on Windows the same way.** I took the `!defined(_WIN32)` guard out of
  `csrc/ktls_crypto_user_config.h` in a scratch copy. On both compilers the test binary then linked
  `mbedtls_mutex_lock` over `pthread_mutex_lock`, with no new DLL.
- **Two isolates may race into `ktls_init`'s first call.** `psa_crypto_init` sets up each subsystem under
  `mbedtls_threading_psa_globaldata_mutex`. So the atomic flag only skips repeated work, as it does on POSIX.
- **Entropy is already linked.** kama's driver links `bcrypt` for every Windows target, because std::random's
  entropy is `BCryptGenRandom`. 0.9.523 does too: the binaries import `bcrypt.dll`. Mbed TLS's builtin source
  finds `BCryptGenRandom` there.
- **CI can pin the floor on Windows.** The kama v0.9.523 release has `kama-windows-x64-v0.9.523.tar.gz`, and a
  `-bundled` one with zig. `install.ps1` installs either from `$env:KAMA_VERSION`.

**So the plan written on 2026-10-18 changes:**
- **Threading: `MBEDTLS_THREADING_PTHREAD` on every target.** Drop the `_WIN32` guard and its comment.
  - The `MBEDTLS_THREADING_ALT` layer is not needed. That was a `threading_alt.h` over `SRWLOCK` and
    `CONDITION_VARIABLE`, `mbedtls_threading_set_alt()` before `psa_crypto_init`, and `ktls_init` as an
    `InitOnceExecuteOnce`.
  - It was planned against a winpthreads DLL and a toolchain without winpthreads, and kama has neither.
  - The configuration's lock from phase 6, and Mbed TLS's own locks, then follow with no code change.
- **Entropy: nothing to add.** The old plan's `bcrypt` link entry is already the driver's. Also, 0.9.523 refuses a
  `link` entry with `compileFor`: it takes strings only, and the object form arrived in 0.9.609.
- **`trustSystem()` reads the system store.** It reads a CA bundle file today, and Windows has none. So on Windows
  it reads the store through crypt32: `CertOpenSystemStoreW(0, L"ROOT")`, adding each certificate's
  `pbCertEncoded` with `mbedtls_x509_crt_parse_der`. `SSL_CERT_FILE` stays the override. Windows downloads some
  roots only when its own chain builder first needs one (automatic root update), so the ROOT store can lack a root
  the system would trust. The API comment says so, and points to `SSL_CERT_FILE`.

  **For the maintainer to decide before code:**
  - **How crypt32 is linked**, since 0.9.523 cannot gate a `link` entry to Windows. Either:
    - raise the `"kama"` floor to 0.9.609 or later and declare `{ "name": "crypt32", "compileFor": ["OS_WINDOWS"] }`.
      The release named as the floor must have its assets.
    - or load it at run time with `LoadLibraryExW(L"crypt32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)` and
      `GetProcAddress`, which keeps 0.9.523.

    A `select.TARGET.WINDOWS.link` entry passes 0.9.523's check. It is unverified whether it reaches a native
    Windows build, which is the `HOST` target there, or a consumer's build.
  - **Which stores, and which certificates in them.** Whether to read the "CA" store as well as "ROOT", and whether
    to keep only certificates trusted for serverAuth, as CPython's `ssl.create_default_context()` does on Windows.
- **The gate.** Add a `windows-latest` leg to `.github/workflows/ci.yml`:
  - `install.ps1` with `KAMA_VERSION: v0.9.523`;
  - OpenSSL 3 for `tools/gen-certs.sh`;
  - `tools/test.sh` under bash.

  Watch for two things on the first run, neither seen yet:
  - **Line endings.** A checkout with CRLF breaks `tools/*.sh` under bash. A `.gitattributes` with
    `*.sh text eol=lf` settles it.
  - **The certificate path.** Check the `KTLS_TEST_CERTS` path the tests get under Git Bash.

  Then remove "Windows is not in the matrix" from the workflow comment, and update the README's platform line.

### WebAssembly (phase 8)

`AGENTS.package.md` asks every package that vendors C for a wasm leg (`--target WASM`, run under node in a container
with emcc), and this package has none yet. To settle first, by building rather than reading:
- **Threading.** Whether kama's wasm target has threads (isolates) at all, and so whether `MBEDTLS_THREADING_C`
  stays on there. Without threads it comes off for wasm only, with the reason written in
  `csrc/ktls_crypto_user_config.h`.
- **Entropy.** Mbed TLS's builtin source on emscripten. `getentropy` is backed by `crypto.getRandomValues`; confirm
  that this is the path Mbed TLS takes.
- **I/O.** `TlsStream<S>` needs only a `ReliableStream`, so a TLS session over whatever stream the wasm host gives
  (a WebSocket, a pipe) works unchanged. The tests' in-memory pipe runs as it is. The loopback-TCP case and the
  file-based fixtures (`trustFile`, `identityFiles`, `trustSystem`) need a gate (`@compileFor`) or a wasm
  equivalent: fixtures as bytes through `trustPem` / `identityPem`.

### Bare metal (phase 11, questions first)

Mbed TLS is built for small devices, so `--target EMBEDDED` is possible. It needs answers before any code:
- **Entropy.** There is no OS source, so the device must supply one. Through which hook, a PSA entropy driver or a
  callback the caller registers?
- **Memory.** Whether the target has a heap, since Mbed TLS allocates per session.
- **Threading.** Whether it has threads.
- **Which API survives.** The file-based calls (`trustFile`, `identityFiles`, `trustSystem`, `revocationDir`) do
  not exist without a filesystem.

## Known differences from OpenSSL-based clients

- **As a TLS 1.3 server, Mbed TLS sends a client-authentication alert under its handshake keys** (it switches to
  the application keys only at wrap-up), so a client that has already switched cannot read it and reports a bad
  MAC instead of `certificate_required`. OpenSSL switches at its own Finished. This matters only when this package
  is the server; as a client it reads an OpenSSL server's alert. Under TLS 1.2, Mbed TLS sends no alert for a
  missing client certificate.
- **`mbedtls_pk_check_pair` is not used.** In TF-PSA-Crypto 1.2.0 it compares cached public halves, and a parsed
  RSA private key has none, so it refuses every RSA pair. ktls compares the public key it exports through PSA
  instead (`ktls_pair_matches`). Worth reporting upstream; drop the workaround when a release fixes it.
- **`trustSystem()` reads a CA bundle file**, not the Windows certificate store or the macOS keychain. On macOS
  that is `/etc/ssl/cert.pem`, which Apple maintains; `SSL_CERT_FILE` overrides it, as with OpenSSL.
