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
configurations fixed (phase 6); 0.1.6 (2026-10-20), builds on kama 0.9.690 and later, and its tests need 0.9.690;
0.1.7 (2026-10-22), Windows (phase 7), which raises the floor to 0.9.690.

0.1.8 is TLS 1.3 session resumption (phase 9), built and gated on the Windows machine on 2026-10-22. It also fixes a
client read that could wait on the transport for bytes it held, against any server that sends TLS 1.3 tickets. The
maintainer publishes it from the registry project on the other machine once CI is green; the CHANGELOG heading then
takes the date.

**On the Mac, next**, in this order:
1. Pull `main`.
2. Run the gate with the dev compiler on macOS arm64 (`KAMA=$PWD/../cstar/out/Darwin-arm64/kama tools/test.sh`) and on
   Linux aarch64 in `localhost/kama-dev` (`AGENTS.tls.md`). Phases 7 and 9 changed C that CI builds only with kama
   0.9.690, so these are the dev compiler's runs on POSIX.
3. Run `tools/tsan.sh`.
   - It now copies `tests/csrc` and builds `raw_client.c`, which phase 9 added for every target. That manifest was
     checked on Windows on 2026-10-23 without the TSan flags; Windows' clang has no ThreadSanitizer.
   - Phase 9 adds two things isolates share: a server configuration's ticket context (`ssl_ticket.c` locks its own
     state) and a `TlsSession` moved between isolates.
   - `shared_test` sets tickets on a shared configuration, but no test yet issues and accepts tickets on two isolates
     at once through one shared server configuration. Add one then, so ThreadSanitizer sees `ssl_ticket.c`'s lock in
     use.
4. Phase 8, WebAssembly: its [first steps](#webassembly-phase-8-next-on-the-mac).

**Next: WebAssembly (phase 8) on the Mac.** The maintainer moved phase 8 to the Mac on 2026-10-22. It needs emcc and
node, which the Mac's `kama-dev` container has and the Windows machine does not, and kama has never built for wasm on a
Windows host. Phase 9 is the same on every platform, so it went first, on Windows. Then come resumption on TLS 1.2
(phase 10) and bare metal (phase 11, questions first). The maintainer settled the scope questions on 2026-10-18 and
2026-10-22; the decisions are recorded in each section.

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
| 7 | Windows; see [Platforms](#platforms) | **done** (0.1.7, 2026-10-22) |
| 8 | WebAssembly (`--target WASM`), the wasm leg `AGENTS.package.md` asks of a package that vendors C; see [Platforms](#platforms) | **next, on the Mac** |
| 9 | Session resumption on TLS 1.3; see [Session resumption](#session-resumption) | **done** (0.1.8, unpublished) |
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

Phases 9 (TLS 1.3, **done**, 0.1.8) and 10 (TLS 1.2). Each is built the way phases 4 and 5 were built: a design in this
section, tests in `tests/`, the gate on every platform the package then supports, and one version per phase.

**Decided (the maintainer, 2026-10-18).**
- **Both versions, as production TLS stacks resume both** (OpenSSL, Go, rustls). TLS 1.3 comes first; TLS 1.2
  follows as its own phase. Neither has a security reason to leave out, given the two rules below.
- **TLS 1.3 resumes only with a fresh (EC)DHE** (psk_dhe_ke), so a resumed session keeps forward secrecy. Pure PSK
  (psk_ke) is never accepted or offered.
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

**Decided (the maintainer, 2026-10-22), for phase 9.**
- **The caller states the lifetime**, explicitly: `sessionTickets(lifetime:)`, whole seconds from 1 to 604800 (7 days,
  RFC 8446 §4.6.1's cap, which Mbed TLS also enforces). The API comment suggests 2 hours, OpenSSL's default session
  timeout. Mbed TLS ties key rotation to the lifetime, so there is no second knob. The references were Go (keys rotated
  daily, tickets accepted for 7 days), nginx (a 5-minute session timeout) and OpenSSL (2 hours).
- **A client opts in**, with the same setter on its configuration. Without it, the client advertises no PSK mode, so a
  server sends it no ticket and it holds no resumption secret.
- **A session from another configuration or for another name is refused**: `resumeWith` answers -5 rather than quietly
  running a full handshake, so a wrongly keyed pool shows up at once. An expired ticket is not a mismatch; it gives a
  full handshake, which `resumed()` reports.
- **A server that verifies or asks for client certificates cannot issue tickets** (-5, whichever is set first).
  Mbed TLS 4.1.1's TLS 1.3 ticket holds no peer certificate, so a resumed server stream would not know its client.
  OpenSSL, Go and rustls carry the client's certificate in the ticket (Go also re-checks its expiry when resuming).
  Matching them means ktls sealing its own tickets in place of `ssl_ticket.c`: a later phase, when someone needs
  resumption with client certificates. Until then such a server runs a full handshake every time, as it did.

### TLS 1.3 (phase 9, done, 0.1.8)

**The API.**
- `TlsConfig.sessionTickets(lifetime: Duration)`, on both sides.
  - A server seals tickets under random AES-256-GCM keys held only in memory (`mbedtls_ssl_ticket_setup` with
    `PSA_ALG_GCM`), so a restart ends every ticket. `ssl_ticket.c` replaces the key every `lifetime` and keeps the one
    before for another period, so a ticket stays readable for its whole lifetime, and no key lives past twice it.
    `ssl_ticket.c` locks its own state, so one configuration still serves sessions on any isolate.
  - A client offers psk_dhe_ke, keeps the tickets a server sends, and offers none older than its own `lifetime`,
    whatever the server allowed: the kept ticket's lifetime is cut to the configuration's, and Mbed TLS's own
    offer-time check (`ssl_client.c`) enforces it.
  - A second call replaces the first. Setting the ticket context up twice would leak its PSA keys, so it is freed and
    initialised again first.
- `TlsSession` (`src/session.kama`): an opaque, `Sendable` resource holding Mbed TLS's session (the ticket, the
  resumption secret, the server's certificate), the configuration's id and the server name. Dropping it calls
  `mbedtls_ssl_session_free`, which wipes the secret.
- `TlsStream.takeSession()`: the latest ticket, handed over once, as `takeKeyLog()` hands over key-log lines. RFC 8446
  (appendix C.4) has a client use a ticket once, so only the latest is kept. OpenSSL sends two by default; a small queue
  waits until a pool needs several resumptions in parallel. The ROADMAP's earlier `session()` became this.
- `TlsStream.resumeWith(session:)`: takes the session by `give`, before the handshake. It answers -5 for another
  configuration (a process-wide id, not the pointer, which can be reused), another server name (byte for byte, as Mbed
  TLS compares), a server stream, a handshake already begun, a session already offered, or a session that is not TLS
  1.3.
- `TlsStream.resumed()`, on both sides.

**What the vendored Mbed TLS 4.1.1 does, and what ktls does about it.**
1. **The client always signals a ticket.** `mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets`, which this
   section once planned to call, does not exist in 4.1.1.
2. **A ticket is held before it is processed.** A client's `mbedtls_ssl_read` reads the NewSessionTicket record, holds
   it, and answers WANT_READ (`ssl_msg.c`); only the next read or write processes it, answering
   `RECEIVED_NEW_SESSION_TICKET`. `ktls_read` passed that WANT_READ on, so the stream waited on the transport for
   bytes it may already have held, and `ktls_write` passed the ticket code up as an error.
   - Now `ktls_read` goes round again on WANT_READ while a record is held (`mbedtls_ssl_check_pending`) or fed bytes
     remain, bounded by progress, and keeps a ticket and goes on; `ktls_write` keeps a ticket and writes again.
   - This was a bug in every earlier version, for a client of any server that sends TLS 1.3 tickets. It showed when
     the last ticket and the data behind it arrived in one transport read: a 0.1.7 client that waited half a second
     before reading from `openssl s_server -rev` hung until it was killed.
3. **A server's ticket comes after the step Mbed TLS calls the end.** The NewSessionTicket states sort after
   `MBEDTLS_SSL_HANDSHAKE_OVER`, so `ktls_handshake`'s step loop stopped before the ticket was written. A server now
   finishes with `mbedtls_ssl_handshake`, which sends it.
4. **Mbed TLS's own ticket-name check is not the binding.** It compares names with a case-sensitive `strcmp`, fails the
   handshake on a mismatch rather than running a full one, and takes two sessions given no name (every IP literal, and
   a `Verify::Chain` client with no name) as a match. So `resumeWith` checks the configuration and the name first.
5. **Whether a handshake resumed is private state.** Under TLS 1.3 it is the handshake's key-exchange mode, recorded in
   `ktls_handshake`'s step loop beside `cert_requested`. It counts any PSK mode, so a pure-PSK handshake could not pass
   for a full one. TLS 1.2's resume flag is recorded too, for phase 10, because TLS 1.2's wrap-up frees the handshake.
   - On a resumed session the verify result reads `MBEDTLS_X509_BADCERT_SKIP_VERIFY` (0x80) on both sides. It never
     surfaces as a failure: `explain()` names certificate flags only for a certificate-verification error.
   - A resumed client still has the server's certificate (the session copy keeps it), so `peerCertificate()`,
     `peerNames()` and `tlsServerEndPoint()` answer as before. A resumed server has no client certificate.
   - A resumed server still hears the SNI name: Mbed TLS runs the SNI callback before it chooses a PSK.
6. **A ticket is opened only in a TLS 1.3 handshake, for a TLS 1.3 session.** Mbed TLS registers one pair of ticket
   callbacks for both versions and hands them the ticket context, not the session. So `ktls_handshake` records the
   session it is stepping in a thread-local (`ktls_stepping`), `ktls_accept_ticket` refuses a ticket unless that
   handshake is TLS 1.3 and the ticket's session is too, and `ktls_issue_ticket` seals only a TLS 1.3 session. A TLS 1.2
   server whose callback declines sends an empty ticket, as RFC 5077 allows.
7. **Pure PSK is compiled out**: `#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED` in
   `csrc/ktls_mbedtls_user_config.h`, so no configuration can negotiate it. A server sets EPHEMERAL | PSK_EPHEMERAL; a
   client EPHEMERAL alone until it opts in. `ktls.c` has an `#error` if psk_ke or `MBEDTLS_SSL_EARLY_DATA` is ever on,
   and if tickets, `MBEDTLS_HAVE_TIME` or psk_dhe_ke is off.
8. **A ticket that cannot be written fails a TLS 1.3 handshake**, and Mbed TLS refuses to send a lifetime over 7 days.
   So the setter refuses one.
9. **A resuming ClientHello offers only the session's version** (`ssl_client.c`), so a server that has dropped TLS 1.3
   since fails the handshake rather than falling back to 1.2. See Known differences.
10. **Ticket ages use `mbedtls_ms_time`**, which is the wall clock on Windows (`GetSystemTimeAsFileTime`) and a monotonic
    clock elsewhere. A clock that moves backwards makes an age negative, and the ticket is simply not offered.

**Tests.** `tests/src/resumption_test.kama`, over the in-memory pipe:
- resuming: a full handshake, then a resumed one on both sides, with data both ways; the peer accessors and SNI on a
  resumed session, and a tls-exporter of its own; a resumed connection's ticket resumes the next; a session is handed
  over once;
- on the wire, read off the pipe with a small ClientHello parser: a client without tickets sends neither
  psk_key_exchange_modes (45) nor pre_shared_key (41); one with them sends psk_key_exchange_modes as exactly
  `[psk_dhe_ke]`; a resuming ClientHello ends with pre_shared_key; neither a server nor a client without tickets ends
  up with a session;
- refusals: another name (`127.0.0.1`, `LOCALHOST`), another configuration alike in every setting, a server stream, a
  handshake begun; a `share()` of the same configuration resumes;
- fallbacks: a server with other ticket keys, a ticket past the server's 1-second lifetime, one past the client's
  1-second lifetime against a server allowing an hour (one 2.1-second sleep covers both), and TLS 1.2 pinned on both
  sides;
- the read fixes: a ticket and data in one flight read as the data; the ticket leaves with the server's handshake; a
  write after a read that took only the ticket;
- the setter: 0 s, 999 ms and 604801 s refused, 604800 s allowed, -4 once frozen; client certificates and tickets
  refused in either order; `TlsSession` is `Sendable`.

`tests/csrc/raw_client.c` drives a raw Mbed TLS client against a ktls server session through `ktls.h`'s buffer API, for
ClientHellos the package's own client never sends: a control that resumes, a TLS 1.3 ticket offered in a TLS 1.2
ClientHello (not resumed), and a TLS 1.2 client asking for a ticket (it gets an empty one). `tests/src/shared_test.kama`
calls `sessionTickets` in its loading rounds.

**Mutation checks**, each a temporary edit, reverted:
- no server tail call: the server's ticket test fails, and the raw client gets no ticket;
- no held-record retry in `ktls_read`: the first data after a handshake does not arrive, and no session is kept;
- no thread-local check in `ktls_accept_ticket`: the TLS 1.2 ClientHello case fails;
- no configuration-id check: a configuration alike in every setting resumes;
- no lifetime clamp: a ticket past the client's lifetime resumes;
- no name check: both name cases fail the handshake inside Mbed TLS ("invalid input data").

**Interop, once**, with Git Bash's OpenSSL 3.5.7 on Windows x86-64 and throwaway programs, as phases 4 and 5 were
checked:
- a 0.1.7 client reading from `openssl s_server -rev` (two tickets by default) after a half-second wait hung until it
  was killed after 10 s; the new build read the reply;
- the new client kept a ticket from `s_server` and resumed twice, each time with a fresh X25519 key; with
  `-groups secp384r1`, which forces a HelloRetryRequest, it resumed the same way, each connection with a fresh
  secp384r1 key;
- `s_client -sess_out` then `-sess_in` against a kama server: "New, TLSv1.3", then "Reused, TLSv1.3", and the server's
  `resumed()` agreed;
- `s_client -tls1_2`: the session has no session ID and an empty ticket, so OpenSSL keeps nothing to resume.

**The gate.** Green on Windows x86-64, debug and release, with kama 0.9.719 (dev, msys2 UCRT64 clang) and with
0.9.690's release with zig bundled, CI's toolchain. CI covers Linux x86-64, macOS arm64 and Windows x86-64 once
pushed. The Mac session runs `tools/tsan.sh` (the ticket context is shared by isolates) and the dev-compiler gate on
macOS arm64 and Linux aarch64.

### TLS 1.2 (phase 10, planned)

- The hooks are in place: `ktls_issue_ticket` and `ktls_accept_ticket` refuse TLS 1.2 today. Phase 10 lets a TLS 1.2
  session through when it was made with extended master secret, and keeps refusing a ticket whose session's version
  differs from the handshake's.
- A server-side session-ID cache (`ssl_cache.c`, `mbedtls_ssl_conf_session_cache`) for clients that send no ticket,
  under the same EMS rule.
- A client asks for TLS 1.2 tickets again (`mbedtls_ssl_conf_session_tickets`, off since 0.1.8), and `takeSession()`
  answers after a TLS 1.2 handshake, which has no post-handshake ticket.
- RFC 6066 §3: a server must not resume a TLS 1.2 session for a client asking for another SNI name. Mbed TLS's tickets
  do not record one, so ktls does.
- `resumed()` already records TLS 1.2's resume flag.

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

**Done on 2026-10-22, as 0.1.7, published the same day.** kama builds for Windows with `--target WINDOWS`, which is
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

### WebAssembly (phase 8, next, on the Mac)

`AGENTS.package.md` asks every package that vendors C for a wasm leg (`--target WASM`, run under node in a container
with emcc), and this package has none yet. kama's `WASM` target is `wasm32-emscripten-none`, built with `emcc` (`$EMCC`
or `--cc` overrides it). With `-o tests.js` emcc writes `tests.js` + `tests.wasm`, and node runs it (node ≥ 16, since
kama passes `-msimd128`). `kama run` refuses a wasm target, so the leg builds and then runs `node` itself.

**Read on 2026-10-22, in kama 0.9.719's driver and docs and in the vendored sources. Nothing has been built yet.**
Settle each one by building:
- **Entropy comes from `/dev/random`.**
  - Mbed TLS's builtin source (`tf-psa-crypto/platform/platform_util.c`) has a getrandom branch for Linux with glibc
    and for FreeBSD, a sysctl one for NetBSD, and BCryptGenRandom for Windows. It has no getentropy branch.
    Emscripten defines `__unix__`, so it counts as Unix-like, and matches none of them.
  - So it falls back to `fopen(MBEDTLS_PLATFORM_DEV_RANDOM)`, whose default is `"/dev/random"` (`mbedtls/platform.h`),
    through emscripten's virtual filesystem. Emscripten backs that device with the host's random source, and it is
    there only while the filesystem is linked in.
  - The alternative: `MBEDTLS_PSA_DRIVER_GET_ENTROPY`, with a `mbedtls_platform_get_entropy` in `csrc/` calling
    `getentropy`. kama's own std::random does that on emscripten (`include/kama_random.h`).
  - Either way, a test that a session handshakes proves the source works. Choose by what the build shows.
- **Threading.** kama's isolates on wasm are emscripten pthreads: Web Workers over a SharedArrayBuffer.
  - kama makes a program threaded only when it lowers a `spawn`, `isolate` or `parallel_for`. Then it adds `-pthread`
    to the link, with `-sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=0`.
  - It compiles each `csources` file as its own `-c` job, without `-pthread`. So Mbed TLS and `csrc/ktls.c` are built
    without atomics, while kama's own C is built with them.
  - `tcp_test` and `shared_test` both spawn, so the test program is threaded. Build to see whether wasm-ld links
    objects built without atomics into shared memory. `ktls.c` uses `<stdatomic.h>`; Mbed TLS has no atomics.
  - If it refuses, the lever is a gated flag: `"cflags": [{ "flag": "-pthread", "compileFor": ["ARCH_WASM32"] }]`
    (kama 0.9.651). If threads cannot work at all, `MBEDTLS_THREADING_C` comes off for wasm alone, with the reason in
    `csrc/ktls_crypto_user_config.h`.
- **Files and the environment.** The tests read every fixture from the directory `KTLS_TEST_CERTS` names, and
  `certPath` stops the run when it is unset.
  - kama passes no `-sNODERAWFS`, so `std::fs` and `fopen` see emscripten's in-memory filesystem.
  - `getenv` sees emscripten's own made-up environment, never node's `process.env`. `argv` does come through.
  - Levers in the manifest: `"emSettings": { "NODERAWFS": true }` gives node's real filesystem (it is ignored off wasm,
    so it needs no gate); `embedFiles` / `preloadFiles` (kama 0.9.602) pack files in.
  - So the leg needs node's filesystem or packed fixtures, and a wasm twin of `certPath` that takes the directory
    some other way, such as from `args()`.
- **Sockets.** `tests/src/tcp_test.kama` needs a loopback TCP listener. std::net compiles for emscripten, but real
  TCP needs a host proxy, and kama's own wasm leg skips its socket tests. So it is gated `!ARCH_WASM32`.
- **Gates.** The target's facts are `ARCH_WASM32` and `OS_EMSCRIPTEN`; a whole file is gated with
  `file @compileFor(!ARCH_WASM32);`.
- **Running.** kama always links with `-sEXIT_RUNTIME=1 -sSTACK_SIZE=262144`. kama's own wasm leg runs node with
  `--no-concurrent-recompilation`, which works around a node shutdown deadlock that `EXIT_RUNTIME` does not.
- **The rest of the I/O.** `TlsStream<S>` needs only a `ReliableStream`, so a session over whatever stream the host
  gives works unchanged, and the tests' in-memory pipe runs as it is.

**Where it runs.** The leg needs emcc and node.
- On the Mac they are in `localhost/kama-dev` (podman), with a Linux kama inside the container, as the Linux aarch64
  leg is run (`AGENTS.tls.md`).
- The Windows machine has node 24.21 in msys2's UCRT64, and emscripten 6.0.11 is a pacman package there
  (`mingw-w64-ucrt-x86_64-emscripten`). But kama has never driven emcc on a Windows host, and kama's own docs run its
  wasm leg in a container.
- CI: a job on `ubuntu-latest` with emsdk. kama's own wasm job uses `mymindstorm/setup-emsdk` with no version; this
  one pins emsdk, as the Windows leg pins kama.

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
- **A resuming client offers only TLS 1.3.** Mbed TLS limits a ClientHello that offers a session to that session's
  version, so a server that has dropped TLS 1.3 since the ticket was issued fails the handshake rather than
  negotiating TLS 1.2. Another stack would offer both and run a full TLS 1.2 handshake. The caller can drop the
  session and connect again.
- **A server that asks for client certificates issues no session tickets.** OpenSSL keeps the client's certificate in
  its tickets; Mbed TLS's TLS 1.3 ticket has no room for it (see [Session resumption](#session-resumption)).
