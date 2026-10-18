# Roadmap

Where this is, 2026-10-18: `TlsConfig`, `TlsStream<S>` and `Certificate` are done and tested, debug and release, on
macOS arm64 and Linux aarch64. Before 0.1.0 everything was exercised end to end against PostgreSQL 14–19, which added
failures in words (alerts by name, key and PEM errors), the RFC 5929 SHA-224 fix, chain verification without SNI,
certificate names from a session or a file, CRLs with OpenSSL's every-certificate rule, whether the server asked for a
client certificate, a step-wise identity with a pair check, and key logging.

Published on the official registry: 0.1.0 (2026-10-02); 0.1.1 (2026-10-03), what the registry shows and searches, so
it needs kama 0.9.523; 0.1.2 (2026-10-13), the RFC 9266 tls-exporter channel binding (phase 4); 0.1.3 (2026-10-18),
no IP literal as SNI, an IP matched against IP SANs alone, and `TlsError` `Sendable`. 0.1.4, unpublished, lets a
server hold several identities and choose one per handshake by SNI (phase 5).

**Next: phase 6, a race on shared configurations** ([Shared configurations](#shared-configurations)): a small fix
with its design written, to ship as 0.1.5. Then every platform kama builds for ([Platforms](#platforms)), then
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
| 5 | A server holds several identities and serves each handshake the ones whose certificate names the SNI host; see [Server identities](#server-identities) | **done** (0.1.4, unpublished) |
| 6 | Setters on a shared configuration race each other and a session being made from it; see [Shared configurations](#shared-configurations) | **next** (0.1.5) |
| 7 | Windows; see [Platforms](#platforms) | planned |
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

Phase 6, **next**, as 0.1.5. A data race found while building phase 5. It has not been seen to fail, and no test
shows it yet.

**The race.** `TlsConfig` is `Sendable`, and `share()` hands out another handle on the same C configuration.
- Every setter checks `frozen` and then changes the configuration, as two steps.
- `ktls_session_new` sets `frozen` and then reads the configuration (`mbedtls_ssl_setup`).

So with two handles on two isolates:
- two setters can change the configuration at once: the ALPN array, the trust chain, the CRLs, the identity list;
- a setter that passed its check can still be changing the configuration while a session is set up from it.

Either one is a C data race, which is undefined behavior, not just a wrong answer. A program that finishes
configuring before it shares, the pattern the API documents, never hits it.

**The fix.**
- Add a mutex to `ktls_config`, using Mbed TLS's `mbedtls_mutex_*`, so it follows `MBEDTLS_THREADING_*` to Windows
  later.
- Every setter takes the mutex around its check and its change. So does `ktls_config_trust_count`, the one reader.
- `ktls_session_new` takes it around its precondition checks and the store to `frozen`, then sets the session up
  after releasing it. A frozen configuration cannot change.
- The SNI and verify callbacks keep reading without a lock, because they run only after the freeze.
- The API doesn't change, so this is a patch release, 0.1.5.

**Rejected: freezing a configuration in `share()`.** It needs no lock, but a program that shares a configuration
and then sets something on it, on one isolate, would get `-4` where it gets Ok today. That breaks callers, so it
would have to be 0.2.0.

**The test.**
- Two isolates, each with a handle on one configuration: one calls setters in a loop while the other makes
  sessions. Both must finish, and every setter must answer Ok or `-4`.
- A plain run cannot prove a race is gone. So run the tests under ThreadSanitizer once before the fix and once
  after (`-fsanitize=thread` in a `select` entry's `cflags` and `ldflags` on `tests/kama.json`; in the Linux
  container if this host's toolchain will not run it). Before the fix it should report the race; after, nothing.

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

### Windows (phase 7)

kama builds for Windows (`--target WINDOWS`, with mingw-w64 or zig). The package has never been built there. The
gate's Windows leg is CI's `windows-latest`. The maintainer has a Windows machine for a local run when CI is not
enough: ask for one rather than guess at a failure. What it takes:

- **Threading.**
  - Today `csrc/ktls_crypto_user_config.h` turns on `MBEDTLS_THREADING_C` and `MBEDTLS_THREADING_PTHREAD` only off
    `_WIN32`.
  - Windows needs `MBEDTLS_THREADING_ALT`: a `csrc/threading_alt.h` defining `mbedtls_platform_mutex_t` and
    `mbedtls_platform_condition_variable_t` over `SRWLOCK` and `CONDITION_VARIABLE`, plus
    `mbedtls_threading_set_alt()` called once before `psa_crypto_init`.
  - `ktls_init`'s atomic flag then becomes a real once (`InitOnceExecuteOnce`), because two isolates can race into
    the first call.
  - winpthreads under mingw would skip the ALT layer, but it adds a DLL and does not hold for every toolchain.
- **Entropy.** Mbed TLS's builtin source calls `BCryptGenRandom`, so link `bcrypt` on Windows only: a `link` entry
  `{ "name": "bcrypt", "compileFor": ["OS_WINDOWS"] }`.
- **`trustSystem()`.** Windows has no CA bundle file. The general answer is to read the ROOT system store through
  crypt32 (`CertOpenSystemStoreW`, with each certificate's DER added to the trust chain); `SSL_CERT_FILE` stays the
  override.
- **The gate.** A `windows-latest` leg in `.github/workflows/ci.yml` runs `tools/test.sh` with OpenSSL 3 for
  `tools/gen-certs.sh`, including the TCP test with its server in another isolate. Then remove "Windows is not in
  the matrix" there, and update the README's platform line.

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
