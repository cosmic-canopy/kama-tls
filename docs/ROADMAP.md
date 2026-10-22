# Roadmap

Where this is, 2026-10-22: `TlsConfig`, `TlsStream<S>` and `Certificate` are done and tested, debug and release, on
macOS arm64, Linux aarch64 and x86-64, and Windows x86-64. Before 0.1.0 everything was exercised end to end against PostgreSQL 14–19, which added
failures in words (alerts by name, key and PEM errors), the RFC 5929 SHA-224 fix, chain verification without SNI,
certificate names from a session or a file, CRLs with OpenSSL's every-certificate rule, whether the server asked for a
client certificate, a step-wise identity with a pair check, and key logging.

Published on the official registry: 0.1.0 (2026-10-02); 0.1.1 (2026-10-03), what the registry shows and searches, so
it needs kama 0.9.523; 0.1.2 (2026-10-13), the RFC 9266 tls-exporter channel binding (phase 4); 0.1.3 (2026-10-18),
no IP literal as SNI, an IP matched against IP SANs alone, and `TlsError` `Sendable`; 0.1.4 (2026-10-18), a server
holds several identities and chooses one per handshake by SNI (phase 5); 0.1.5 (2026-10-19), a race on shared
configurations fixed (phase 6); 0.1.6 (2026-10-20), builds on kama 0.9.690 and later, and its tests need 0.9.690.
0.1.7 is Windows (phase 7), and raises the floor to 0.9.690. It is pushed (`5f30fa2`), CI is green on Linux x86-64,
macOS arm64 and Windows x86-64, and the maintainer publishes it from the registry project on the other machine. Once the registry has published it, the CHANGELOG heading takes the
date, as `cac8a2e` did for 0.1.5.

Phase 7 left two runs for the Mac, neither of which blocks phase 8. The POSIX paths changed only in the file loader
(`ktls_load_file`), and CI's Linux x86-64 and macOS arm64 legs cover them.
- the gate on macOS arm64 and Linux aarch64 with the dev compiler;
- `tools/tsan.sh`.

**Next: the rest of the platforms kama builds for** ([Platforms](#platforms)), WebAssembly (phase 8) and then bare
metal (phase 11, questions first). Between them comes session resumption on TLS 1.3 and 1.2
([Session resumption](#session-resumption)). The maintainer settled the scope questions on 2026-10-18; the decisions
are recorded in each section.

| # | phase | state |
|---|---|---|
| 0 | Scaffold | **done** |
| 1 | `tools/vendor-mbedtls.sh`: pin mbedtls-4.1.1 by SHA256, assert the generated sources are present, fail on a foreign license or colliding header names, regenerate `csources`/`cincludes`; config deltas in `csrc/`; `tls::ready()` and `tls::version()` = `4.1.1`, debug and release | **done** |
| 2 | `TlsStream<S: ReliableStream>` over a memory BIO: handshake step (WantRead / WantWrite), read, write, close_notify; `TlsConfig` (trust roots from a file / PEM bytes / the system bundle, identity, verify full / ca-only / none, SNI, ALPN, versions); peer certificate DER and the RFC 5929 end-point hash. Tests: TLS 1.2 and 1.3, every verify mode, wrong host, untrusted CA, expired, client certificate required, ALPN, a large transfer, close_notify against truncation — over an in-memory pipe, and once over loopback TCP | **done** |
| 3 | Exercised end to end against PostgreSQL 14–19 (the sslmode matrix, SCRAM-SHA-256-PLUS, client certificates) | **done** |
| — | Publish 0.1.0 | **done** (2026-10-02) |
| 4 | RFC 9266 tls-exporter channel binding as `TlsStream.tlsExporter()`, TLS 1.3 only ([issue #1](https://github.com/cosmic-canopy/kama-tls/issues/1)); see [Channel bindings](#channel-bindings) | **done** (0.1.2, 2026-10-13) |
| 5 | A server holds several identities and serves each handshake the ones whose certificate names the SNI host; see [Server identities](#server-identities) | **done** (0.1.4, 2026-10-18) |
| 6 | Setters on a shared configuration race each other and a session being made from it; see [Shared configurations](#shared-configurations) | **done** (0.1.5, 2026-10-19) |
| 7 | Windows; see [Platforms](#platforms) | **done** (0.1.7, unpublished) |
| 8 | WebAssembly (`--target WASM`), the wasm leg `AGENTS.package.md` asks of a package that vendors C; see [Platforms](#platforms) | **next** |
| 9 | Session resumption on TLS 1.3; see [Session resumption](#session-resumption) | planned |
| 10 | Session resumption on TLS 1.2; see [Session resumption](#session-resumption) | planned |
| 11 | Bare metal (`--target EMBEDDED`); see [Platforms](#platforms) | planned, questions first |
| 12 | `trustSystem()` chains verified by the operating system, on Windows and macOS; see [OS verification](#os-verification) | planned, design first |

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

Phase 6, **done** (0.1.5, 2026-10-19). A data race found while building phase 5. No run had been seen to fail.

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

**Decided (the maintainer, 2026-10-18): every platform kama builds for.** Tested today:
- locally: macOS arm64, Linux aarch64 and Windows x86-64;
- in CI: Linux x86-64, macOS arm64 and Windows x86-64.

kama's targets are `HOST`, `MACOS`, `WINDOWS`, `LINUX`, `WASM` and `EMBEDDED`, so what remains is WebAssembly and bare
metal. A leg is green when `tools/test.sh` (or its equivalent for that target) passes there, debug and release.

### Windows (phase 7, done)

**Done on 2026-10-22, as 0.1.7 (unpublished).** kama builds for Windows with `--target WINDOWS`, which is
`<arch>-windows-gnu`. The gate is green on a Windows 11 x86-64 machine, debug and release, on three toolchains:
- kama 0.9.690 with msys2's UCRT64 clang;
- the 0.9.719 dev build with msys2's UCRT64 clang;
- kama 0.9.690's release with zig bundled, which is CI's `windows-latest` leg.

Before that, on 2026-10-19, the tests were cross-built from macOS with zig 0.16.0, for x86-64 and aarch64. Those
binaries import only system DLLs: KERNEL32, WS2_32, bcrypt, ntdll and the UCRT.

**Threading: `MBEDTLS_THREADING_PTHREAD` on every target.** The `_WIN32` guard in
`csrc/ktls_crypto_user_config.h` is gone.
- kama's isolates are pthreads everywhere: `kama_isolate.h` calls `pthread_create`. mingw-w64 and zig link
  winpthreads statically, so there is no `libwinpthread-1.dll` import.
- So the configuration's lock from phase 6, and Mbed TLS's own locks, follow with no code change.
- The `MBEDTLS_THREADING_ALT` layer planned on 2026-10-18 was not needed. That was a `threading_alt.h` over
  `SRWLOCK`, and `ktls_init` as an `InitOnceExecuteOnce`. It was planned against a winpthreads DLL and a toolchain
  without winpthreads, and kama has neither.
- Two isolates may race into `ktls_init`'s first call. `psa_crypto_init` sets up each subsystem under
  `mbedtls_threading_psa_globaldata_mutex`, so the atomic flag only skips repeated work, as on POSIX.

**Entropy: nothing added.** kama's driver links `bcrypt` for every Windows target, because std::random's entropy is
`BCryptGenRandom`, and Mbed TLS's builtin source finds `BCryptGenRandom` there.

**`trustSystem()` imports the ROOT store** (decided by the maintainer, 2026-10-22), as curl's `--ca-native` with
OpenSSL and rustls-native-certs do. The code is `ktls_config_trust_windows` in `csrc/ktls.c`.
- It reads `CertOpenSystemStoreW(0, L"ROOT")`, not the CA store, whose intermediates would become trust anchors.
- It keeps a root only when Windows allows it for server authentication (`ktls_win_root_kept`).
  - `CertGetEnhancedKeyUsage` must list `szOID_PKIX_KP_SERVER_AUTH`, or list nothing with `CRYPT_E_NOT_FOUND`,
    which means every use.
  - Nothing listed without that error means no use. An empty EKU property is how a root is turned off.
  - The usages are the intersection of the certificate's EKU extension and the store's property, as Microsoft
    documents, so a property cannot widen what a certificate allows.
- It skips a root the Disallowed store also holds (`CERT_FIND_EXISTING`).
- Each kept root goes to `mbedtls_x509_crt_parse_der`. A root Mbed TLS cannot parse is counted as skipped, as in a
  bundle.
- A store that cannot be opened, or keeps no root, is `KTLS_ERR_SYSTEM_STORE` (-9).
- crypt32 is linked by `{ "name": "crypt32", "compileFor": ["OS_WINDOWS"] }`. 0.9.523 refuses a `link` entry with
  `compileFor`, so the floor rose to 0.9.690 (decided by the maintainer, 2026-10-22). The tests already needed
  0.9.690, so CI has one install and the README one floor.
- `systemRoots` in `src/config.kama` has a `@compileFor` twin per side. The Windows one never probes the bundle
  paths: there `/etc/ssl/cert.pem` is `C:\etc\ssl\cert.pem`, under a drive root where any user may make a directory.
- `SSL_CERT_FILE` stays the override.

**What an import loses is phase 12's** ([OS verification](#os-verification)). The API comment says so, and points
to `SSL_CERT_FILE`.
- A root distrusted only for certificates issued after a date.
- Automatic root update, and that one is not hypothetical. Windows downloads a root the first time its own chain
  builder needs one, so the ROOT store holds only the roots that machine has needed so far.
  - On this Windows 11 machine it held 31 certificates. 9 were restricted to code signing or time stamping, 22 were
    kept, and 21 parsed.
  - A throwaway client with those 21 verified www.microsoft.com, github.com, kama-lang.org and www.google.com with
    `Verify::Full`. Each one refused a client trusting only the test CA.
  - A server whose root the machine has never needed would be refused.

**A path that is not ASCII failed on Windows, and is fixed.** Mbed TLS opens a file with `fopen`, which reads a
path in the ANSI code page there.
- Every file-based setter now reads through `ktls_load_file`. It opens a UTF-8 path with `_wfopen` on Windows and
  `fopen` elsewhere, and otherwise does what `mbedtls_pk_load_file` does.
- `trustFile`, `identityFiles`, `revocationFile` and `SSL_CERT_FILE` under `out/test-certs/ünïcode/` failed before
  the fix and pass after it.

**Tests.**
- `tests/src/windows_test.kama` puts certificates in stores that `tests/csrc/windows_roots.c` makes in memory, and
  never touches the machine's. The certificates are `ca.der` and `eku-ca.der`, a CA whose EKU is code signing alone
  (gen-certs generation 7). The cases:
  - no EKU at all;
  - an EKU property of server and client authentication;
  - client authentication alone;
  - an empty property;
  - the same root in Disallowed;
  - code signing alone;
  - a property claiming server authentication on the code-signing CA.
- Breaking the predicate (keep any empty list, skip the Disallowed lookup) failed three of them.
- `systemTrustTests` on Windows requires the import to keep at least one root, and an error fails rather than skips.

**Watched for, and needing no change.**
- Git Bash and msys2's bash both rewrite a POSIX path in an environment variable for a Windows program, so
  `KTLS_TEST_CERTS` arrives as `C:/…`.
- gen-certs' `openssl crl -hash` output carries no CR.
- kama reads CRLF sources, and `.gitattributes` keeps `*.sh` LF.

**The gate.** CI's `windows-latest` leg runs `tools/test.sh` under Git Bash, with OpenSSL 3 from Git for Windows. It
was green on its first run, for `5f30fa2`.
- It installs kama's release with zig bundled, by URL and SHA256.
- install.ps1 would pick the slim release, because the image has C compilers, and slim kama compiles with whichever
  `clang` is first on the PATH.

### WebAssembly (phase 8, next)

`AGENTS.package.md` asks every package that vendors C for a wasm leg (`--target WASM`, run under node in a container
with emcc), and this package has none yet. kama's `WASM` target is `wasm32-emscripten-none`, built with `emcc`. It
emits `.js` + `.wasm`, and node runs it (node ≥ 16, since kama passes `-msimd128`).

**Read on 2026-10-22, in kama's driver and docs and in the vendored sources. Nothing has been built yet.** Settle
each one by building:
- **Entropy does not come from `getentropy`, as this section first guessed.**
  - Mbed TLS's builtin source (`tf-psa-crypto/platform/platform_util.c`) uses `getrandom` only under `__linux__`
    with glibc. Emscripten defines `__unix__`, so it counts as Unix-like, but not `__linux__`.
  - So it falls back to `fopen("/dev/urandom")`, through emscripten's virtual filesystem. Emscripten backs that
    device with the host's random source, and it is there only while the filesystem is linked in.
  - The alternative: `MBEDTLS_PSA_DRIVER_GET_ENTROPY`, with a `mbedtls_platform_get_entropy` in `csrc/` calling
    `getentropy`. kama's own std::random does that on emscripten (`include/kama_random.h`).
  - Either way, a test that a session handshakes proves the source works. Choose by what the build shows.
- **Threading.** kama's isolates on wasm are emscripten pthreads: Web Workers over a SharedArrayBuffer, with
  `-sPROXY_TO_PTHREAD`. So `MBEDTLS_THREADING_PTHREAD` may stay on, but kama passes `-pthread` only at link, and only
  for a program that starts a thread. Build to see two things:
  - whether Mbed TLS's objects link into a threaded program, since wasm-ld refuses shared memory with an object
    built without atomics;
  - whether a program with no isolate links against emscripten's single-thread pthread stubs.

  If threads cannot work, `MBEDTLS_THREADING_C` comes off for wasm alone, with the reason in
  `csrc/ktls_crypto_user_config.h`.
- **Files and the environment.** The tests read every fixture from the directory `KTLS_TEST_CERTS` names. Under
  node, emscripten's filesystem lives in memory and its `getenv` does not see the host's environment, unless the
  build asks (`-sNODERAWFS=1` gives node's real filesystem). So either:
  - the wasm build gets that; or
  - the fixtures arrive as bytes (`trustPem`, `identityPem`, `revocationPem`), and the file-based cases are gated
    `@compileFor(!ARCH_WASM32)`.
- **Sockets.** `tests/src/tcp_test.kama` needs a loopback TCP listener. It is gated `!ARCH_WASM32` unless kama's
  std::net runs there.
- **The rest of the I/O.** `TlsStream<S>` needs only a `ReliableStream`, so a session over whatever stream the host
  gives works unchanged, and the tests' in-memory pipe runs as it is.

**Where it runs.** The leg needs emcc and node.
- On the Mac they are in `localhost/kama-dev` (podman), with a Linux kama inside the container, as the Linux aarch64
  leg is run (`AGENTS.tls.md`).
- The Windows machine has neither, and no WSL; emsdk and node install natively there if the leg should run on it too.
- CI: a job on `ubuntu-latest` with emsdk and node.

**First steps.**
1. Write `tools/test-wasm.sh`. In the container it runs `kama pkg install tests/kama.json`, then
   `kama build tests/kama.json --target WASM -o "$tmp/tests.js"`, then `node "$tmp/tests.js"`.
2. Run it before changing anything, and read what fails, as phase 7's baseline did on Windows.
3. Decide entropy, files and threading from what the build says, and raise each decision with the maintainer.

### Bare metal (phase 11, questions first)

Mbed TLS is built for small devices, so `--target EMBEDDED` is possible. It needs answers before any code:
- **Entropy.** There is no OS source, so the device must supply one. Through which hook, a PSA entropy driver or a
  callback the caller registers?
- **Memory.** Whether the target has a heap, since Mbed TLS allocates per session.
- **Threading.** Whether it has threads.
- **Which API survives.** The file-based calls (`trustFile`, `identityFiles`, `trustSystem`, `revocationDir`) do
  not exist without a filesystem.

## OS verification

Phase 12, planned on 2026-10-22 when phase 7 chose to import Windows' roots. Its design comes first, in this
section.

**Why.** An imported root store is the established way to trust what the system trusts, but the system's own
verifier knows more:
- On Windows, `CertGetCertificateChain` and `CertVerifyCertificateChainPolicy` with `CERT_CHAIN_POLICY_SSL` honour:
  - the Disallowed store;
  - Microsoft's date-based partial distrust of a root;
  - automatic root update;
  - enterprise policy.
- On macOS, `SecTrustEvaluateWithError` honours the keychain's trust settings. `trustSystem()` there reads
  `/etc/ssl/cert.pem` today.
- Automatic root update is the gap most likely to be met. Phase 7 found 21 usable roots in a Windows 11 machine's
  ROOT store. Enough for the servers it was tried on, but not for one whose root that machine has never needed.
- Go's crypto/x509 and rustls-platform-verifier verify this way.

**To settle in the design:**
- whether it is a `Verify` mode or the meaning of `trustSystem()`;
- how it meets this package's own rules:
  - `Verify::Chain` (no name compared);
  - the CRL options;
  - an IP literal matched against IP SANs alone;
- what Linux, which has no system verifier, does: it keeps the bundle.

## Known differences from OpenSSL-based clients

- **As a TLS 1.3 server, Mbed TLS sends a client-authentication alert under its handshake keys** (it switches to
  the application keys only at wrap-up), so a client that has already switched cannot read it and reports a bad
  MAC instead of `certificate_required`. OpenSSL switches at its own Finished. This matters only when this package
  is the server; as a client it reads an OpenSSL server's alert. Under TLS 1.2, Mbed TLS sends no alert for a
  missing client certificate.
- **`mbedtls_pk_check_pair` is not used.** In TF-PSA-Crypto 1.2.0 it compares cached public halves, and a parsed
  RSA private key has none, so it refuses every RSA pair. ktls compares the public key it exports through PSA
  instead (`ktls_pair_matches`). Worth reporting upstream; drop the workaround when a release fixes it.
- **`trustSystem()` trusts roots, not the system's verifier.** On Linux and macOS it reads a CA bundle file; on macOS
  that is `/etc/ssl/cert.pem`, which Apple maintains, not the keychain. On Windows it imports the ROOT store, which
  lacks any root Windows has not yet downloaded. `SSL_CERT_FILE` overrides it everywhere, as with OpenSSL. Phase 12
  is the system's verifier.
