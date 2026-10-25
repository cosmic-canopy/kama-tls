# Triage: what remains, and the security audit

Prepared on 2026-10-24, for the next session and the maintainer. Each fact here was read that day from the tree, the
vendored sources, or upstream's releases. A claim about another TLS stack carries its source.
- **Decide** marks a question only the maintainer settles.
- **T-n** marks a finding already in hand, which becomes an audit finding once the audit opens.

The other stacks are named only as references, as `AGENTS.tls.md` allows.

1. [Where it stands](#1-where-it-stands)
2. [Carried over](#2-carried-over)
3. [Findings already in hand](#3-findings-already-in-hand)
4. [Against production TLS stacks](#4-against-production-tls-stacks)
5. [The security audit](#5-the-security-audit)
6. [Order of work](#6-order-of-work)
7. [Decisions for the maintainer](#7-decisions-for-the-maintainer)

## 1. Where it stands

- **Released:** 0.1.0 to 0.1.8; 0.1.8 (2026-10-24) is TLS 1.3 session resumption. The `"kama"` floor is 0.9.690.
- **Platforms:**
  - in CI: macOS arm64, Linux x86-64 and Windows x86-64;
  - by hand: Linux aarch64.
- **The API**: 1,056 lines of kama in `src/`, over 1,610 lines of C glue in `csrc/ktls.c`.
  - `TlsConfig`:
    - client or server;
    - `Verify::None`, `Chain` or `Full`, and `requestClientCertificate`;
    - trust from a file, PEM, or the system;
    - CRLs, with `Revocation::Listed` or `Complete`;
    - identities, several per server, chosen by SNI;
    - ALPN, versions, `sessionTickets`, and `share()`.
  - `TlsStream<S>`:
    - the handshake a step at a time, then `read`, `write`, `flush` and `close`;
    - the peer's certificate and names;
    - `tlsServerEndPoint`, `tlsExporter`, the ALPN protocol, cipher suite, version and key bits;
    - the SNI a server received, and whether the server asked for a certificate;
    - key logging;
    - `takeSession`, `resumeWith` and `resumed`;
    - `tlsError`.
  - `Certificate`: parse, DER, names.
  - `TlsSession`.
- **Evidence:**
  - 268 checks in 13 test files, run debug and release;
  - `tools/tsan.sh`;
  - a mutation check per phase;
  - interop checked by hand against OpenSSL, in phases 4, 5 and 9.
- **Mbed TLS 4.1.1, with TF-PSA-Crypto 1.1.1.** This is the latest patch of the 4.1 LTS branch, "supported with
  bug-fixes and security fixes until at least March 2029"
  ([release](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.1.1)).
  - 4.1.1 (2026-07-07) fixed 13 advisories, among them X.509 CA-bit forgery through an invalid basicConstraints,
    signature-algorithm restrictions not enforced on a chain, and a TLS 1.3 client accepting a HelloRetryRequest for
    a group it never offered.
  - 4.2.0 came out the same day with the same fixes, and is not LTS. Nothing newer had shipped as of 2026-10-24.

## 2. Carried over

From the ROADMAP's "On the Mac, next":
1. **The dev-compiler gate for phase 9's C**, on macOS arm64 and on Linux aarch64. Phase 7's ran on 2026-10-22.
2. **`tools/tsan.sh`**, and a test that issues and accepts tickets on two isolates through one shared server
   configuration, so ThreadSanitizer sees `ssl_ticket.c`'s lock in use.
3. **Phase 8, WebAssembly**: its first steps are in the ROADMAP.
4. **The remaining phases**:
   - 10, TLS 1.2 resumption;
   - 11, bare metal, questions first;
   - 12, OS verification, design first.
5. **A doc fix.** The ROADMAP's "Known differences" and `ktls_pair_matches`'s comment in `csrc/ktls.c` say
   TF-PSA-Crypto 1.2.0, where the vendored one is 1.1.1. Re-check the claim on 1.1.1, then correct the version.

## 3. Findings already in hand

- **T1. The default cipher suites include legacy and weak ones.** `mbedtls_ssl_list_ciphersuites()` on this build
  lists 67.
  - TLS 1.3 lists all five RFC 8446 suites, `TLS_AES_128_CCM_8_SHA256` among them. Its tag is 8 bytes, and IANA marks
    it not recommended.
  - TLS 1.2 lists 32 suites that use CBC, several with HMAC-SHA1, plus CCM-8, ARIA and Camellia, beside the ECDHE
    AEAD suites.
  - The TLS 1.2 key exchanges are all ECDHE, which is good: there is no RSA key transport and no finite-field DHE.
    The PSK suites apply only when a PSK is configured, and none ever is.
  - **Decide** an allow-list, and whether callers may change it. Proposed:
    - TLS 1.3: AES-GCM and ChaCha20-Poly1305;
    - TLS 1.2: ECDHE-ECDSA and ECDHE-RSA with AES-GCM or ChaCha20-Poly1305.
- **T2. A peer's TLS 1.3 KeyUpdate ends the connection, and ktls cannot send one.**
  - `ssl_tls13_handle_hs_message_post_handshake` (`library/ssl_msg.c`) accepts a NewSessionTicket to a client and
    "Fail[s] in all other cases" with `MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE`.
  - So a long-lived connection to a stack that rekeys breaks.
    - rustls sends a KeyUpdate unprompted before AES-GCM's confidentiality limit of 2^24 records (§4).
    - That limit is 256 GiB at full 16 KiB records, but 16 GiB at 1 KiB ones. A protocol of small writes reaches it
      sooner.
  - RFC 8446 §5.5 limits how much one key may protect: for AES-GCM, about 2^24.5 full records.
  - Upstream tracks it as [issue #10881](https://github.com/Mbed-TLS/mbedtls/issues/10881), opened 2026-08-06 and
    still open.
  - **First step:** reproduce it against `openssl s_server`'s `k` command (send a KeyUpdate).
  - **Decide** the remedy: carry a patch, though vendoring is byte-identical today; wait for upstream; or document a
    known difference.
- **T3. Name constraints are not enforced, and a non-critical one is ignored.** Mbed TLS 4.1.1 defines only the
  extension's flag (`MBEDTLS_X509_EXT_NAME_CONSTRAINTS`) and does not parse it (`library/x509_crt.c`, lines
  936–956). So:
  - A critical nameConstraints, which RFC 5280 requires, fails the parse. A constrained intermediate is refused: safe,
    but such PKIs do not work.
  - A non-critical one is skipped silently. Some CAs mark their constraints non-critical for older clients, so a
    sub-CA constrained that way could issue for any name. This is the security half of T3.
  - Upstream has [issue #8759](https://github.com/Mbed-TLS/mbedtls/issues/8759) and
    [PR #9894](https://github.com/Mbed-TLS/mbedtls/pull/9894), both open.
  - x509-limbo and BetterTLS show which cases.
  - **Decide**: ktls could enforce them itself, through `mbedtls_x509_crt_parse_der_with_ext_cb` and its verify
    callback.
- **T4. No post-quantum key exchange.** Neither TF-PSA-Crypto 1.1.1 nor Mbed TLS 4.1.1's TLS has ML-KEM.
  - The default groups are X25519, P-256, P-384, X448 and P-521.
  - X25519MLKEM768 became [RFC 10024](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/), a Proposed
    Standard, in August 2026.
  - An Mbed TLS maintainer wrote on 2026-07-20 that ML-KEM (mlkem-native) is planned, with no date
    ([issue #10834](https://github.com/Mbed-TLS/mbedtls/issues/10834#issuecomment-5022136605)).
  - This depends on upstream; see §4 for what the other stacks offer by default.
- **T5. Absent from Mbed TLS 4.1.1:**
  - OCSP stapling: only the `status_request` extension's number is defined;
  - certificate compression;
  - ECH;
  - EdDSA certificates: EdDSA exists only as PSA algorithm values;
  - post-handshake authentication.

  So revocation stays CRLs, with phase 12 for the system's view.
- **T6. Release builds compile the vendored C at `-O3`.** kama's release flags are
  `-O3 -DNDEBUG -ffunction-sections -fdata-sections`.
  - Mbed TLS's SECURITY.md (4.1.1) recommends `-O2` or `-Os` for its constant-time code, and calls `-O3` "still
    likely to be safe but … less scrutinized".
  - A dependency's `cflags` reach every translation unit of a consumer, so the package cannot just add `-O2`.
  - **Decide**: ask kama for a per-package optimisation level, the reverse of `debug.optimize`, or accept it with a
    note.
- **T7. Secrets that reach kama memory are not wiped.** The C side wipes:
  - its record buffers;
  - key files and PEM copies;
  - the exporter's stack copy;
  - key-log lines.

  What crosses into kama is ordinary memory, and is not:
  - `tlsExporter()`'s `DynamicArray`;
  - `takeKeyLog()`'s strings;
  - the plaintext a caller reads.

  **Decide** what the API promises: a note, or a type that wipes on drop.
- **T8. API footguns to review.**
  - `type enum Verify { None, Chain, Full }` carries no warning of its own.
  - `logKeys()`.
  - `requestClientCertificate()`, which completes whatever the client sends.
  - `Verify::Chain` with no name.
  - 46 of the 53 public methods are `unsafe fn`, and so are the constructors. Whether each needs to be is an API
    question for 1.0.
- **T9. No security policy.** There is no `SECURITY.md`, which would say:
  - how to report;
  - which versions get fixes;
  - how fast an upstream advisory ships.
- **T10. CI supply chain.**
  - `actions/checkout@v5` is pinned by tag, not commit SHA.
  - Linux and macOS install kama by piping `kama-lang.org/install.sh`. The script checks the release tarball's
    published SHA256, as the Windows leg does by hand, but the script itself is fetched unpinned.
- **T11. A host name is matched against the CN when a certificate has no SAN.**
  - Mbed TLS falls back to the subject CN, and so does ktls's SNI choice (RFC 6125 §6.4.4).
  - Go and rustls never fall back, and OpenSSL 4.1.0 stopped by default.
  - The CA/Browser Forum has required SANs for years, so a fallback mostly lets through certificates that would be
    refused elsewhere.
  - **Decide**: keep the fallback, or refuse it, perhaps behind a compatibility switch.

## 4. Against production TLS stacks

Checked on 2026-10-24 against each stack's own docs, release notes and source:
- rustls 0.23.46 (2026-10-14);
- Go 1.27.3 (2026-10-19);
- OpenSSL 4.1.0 (2026-10-23);
- BoringSSL at `main`, whose latest snapshot tag is `0.20261020.0`;
- Mbed TLS 4.1.1, from the vendored source.

The sources are listed below the table. "ktls" is this package today: what it exposes, which can be less than Mbed TLS
offers.

| Feature | ktls today | Mbed TLS 4.1.1 | rustls | Go | OpenSSL | BoringSSL |
|---|---|---|---|---|---|---|
| X25519MLKEM768 by default | no | **no** (no ML-KEM) | yes, client and server (0.23.27) | yes (1.24) | yes, two key shares (3.5) | yes (2026-07) |
| ECH | no | **no** | client (0.23.10) | client and server | client and server (4.0) | client and server |
| Certificate compression | no | **no** | opt-in: brotli, zlib | no | yes (3.2), if built with a library | hooks only |
| OCSP stapling | no | **no** | server staples; not verified | staples and exposes; not verified | staples and exposes; checked for TLS 1.3 if opted in (3.6) | staples and exposes; not verified |
| SCTs | no | no | no (removed in 0.22) | exposed, not enforced | opt-in validation | exposed, not enforced |
| Answers a peer's KeyUpdate | **no: the connection fails** | **no** | yes | yes | yes | yes |
| Sends KeyUpdate unprompted | no | no | **yes**, before AES-GCM's limit (2^24 records, 0.23.11) | no | no (QUIC only) | no |
| Post-handshake client auth | no | no | no | no | opt-in | no |
| 0-RTT | off (decided) | compiled out here | opt-in | QUIC only | opt-in | opt-in, experimental |
| Caller-supplied ticket keys | no (random, in memory) | yes (`mbedtls_ssl_ticket_rotate`) | through `ProducesTickets` | `SetSessionTicketKeys` | key callback | `set_tlsext_ticket_keys`, AEAD method |
| Raw public keys | no | no | yes (0.23.16) | no | opt-in (3.2) | yes (2026-04) |
| Caller's verification hook | no | yes (`mbedtls_ssl_set_verify`) | `ServerCertVerifier` | `VerifyConnection` | verify callbacks | `custom_verify` |
| Choice per handshake | certificate by SNI | `conf_cert_cb`, SNI callback | `ResolvesServerCert`, `Acceptor` | `GetCertificate`, `GetConfigForClient` | `cert_cb`, ClientHello callback | `select_certificate_cb`, credentials |
| Suites, groups, sigalgs configurable | versions only | yes | yes | TLS 1.2 suites and groups; no sigalgs | yes | yes, TLS 1.3 suites since 2026-08 |
| Name constraints enforced | **no** | **no** | yes (webpki) | yes | yes | yes |
| Hostname falls back to the CN | yes, when no SAN | yes | no | no | no, by default (4.1) | unconfirmed |
| CRLs | yes, Listed / Complete | yes | opt-in | no revocation at all | opt-in | opt-in |
| OS verifier | no (phase 12) | no | `rustls-platform-verifier` | Windows, macOS | Windows store URI only | no |
| FIPS 140-3 | no | no | aws-lc-rs | Go module | provider | BoringCrypto |
| QUIC API | no | no | yes | yes | yes | yes |
| Record size limit / max fragment length | no | RSL compiled off; MFL on for TLS 1.2, not exposed | neither | neither | MFL | neither |
| TLS 1.0 / 1.1 | no | removed | never | off by default | off by default | off by default |
| Kernel TLS | no | no | secret extraction | no | opt-in | no |

**What the table says.**
- **Two rows put ktls behind every other stack and are risks, not missing features.**
  - **KeyUpdate (T2):** all four answer one. rustls sends one unprompted on long AES-GCM connections, so a rustls peer
    breaks a long-lived ktls connection.
  - **Name constraints (T3):** all four enforce them.
- **Post-quantum key exchange (T4) is the default in all four.** That is the strategic gap, and it waits on Mbed TLS.
- **Mbed TLS has the hooks for these, so they are ktls work, not upstream work:**
  - the caller's verification hook, and pinning on top of it;
  - suites, groups and signature algorithms (T1);
  - caller-supplied ticket keys, for a fleet of servers;
  - choosing a whole configuration per handshake.
- **All four have these, and Mbed TLS has none of them:**
  - ECH on the client;
  - OCSP stapling, though only OpenSSL verifies a staple itself, and only under TLS 1.3;
  - a QUIC API;
  - a FIPS 140-3 route.

  Each needs upstream first. Mbed TLS does not even hand ktls the `status_request` extension. Stapling is the one most
  likely to matter to this package's users.
- **Only some of the four have these:**
  - certificate compression and raw public keys (not Go);
  - SCTs (not rustls);
  - post-handshake auth (OpenSSL only);
  - kTLS (rustls and OpenSSL).
- **T11 in §3 comes from the CN row.**

**Sources.**
- **Mbed TLS:**
  - `library/ssl_msg.c` (lines 5459–5487), `library/x509_crt.c` (lines 936–956), `include/mbedtls/ssl.h`;
  - [its TLS 1.3 support table](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/architecture/tls13-support.md).
- **rustls:**
  - [releases](https://github.com/rustls/rustls/releases);
  - [the manual's features page](https://docs.rs/rustls/latest/rustls/manual/_04_features/index.html);
  - [the key-update source](https://docs.rs/rustls/latest/src/rustls/common_state.rs.html);
  - [rustls-webpki](https://docs.rs/rustls-webpki/latest/src/webpki/verify_cert.rs.html);
  - [rustls-platform-verifier](https://docs.rs/crate/rustls-platform-verifier/latest).
- **Go:**
  - [crypto/tls](https://pkg.go.dev/crypto/tls) and [the source at go1.27.3](https://github.com/golang/go/blob/go1.27.3/src/crypto/tls/);
  - [crypto/x509's verify.go](https://github.com/golang/go/blob/go1.27.3/src/crypto/x509/verify.go);
  - [the 1.27 release notes](https://go.dev/doc/go1.27).
- **OpenSSL:**
  - [4.1.0](https://github.com/openssl/openssl/releases/tag/openssl-4.1.0) and [CHANGES.md](https://github.com/openssl/openssl/blob/openssl-4.1/CHANGES.md);
  - [the 4.1 manual](https://docs.openssl.org/4.1/).
- **BoringSSL:**
  - [ssl.h](https://github.com/google/boringssl/blob/main/include/openssl/ssl.h);
  - [`ssl_key_share.cc`](https://github.com/google/boringssl/blob/main/ssl/ssl_key_share.cc);
  - [`tls13_both.cc`](https://github.com/google/boringssl/blob/main/ssl/tls13_both.cc).

### The gaps, by priority

**P0: before calling this production grade.**
- The audit (§5) and its findings.
- T1: an allow-list of suites, with a setter for suites, groups and signature algorithms.
- T2: KeyUpdate.
- T3: name constraints.
- T9: `SECURITY.md`.
- T11: CN fallback.

**P1: what production users expect next.**
- **The caller's verification hook**, through `mbedtls_ssl_set_verify`, with SPKI pinning as its common use. Every
  other stack offers one.
- **Caller-supplied ticket keys**, through `mbedtls_ssl_ticket_rotate`, so servers behind a load balancer resume each
  other's sessions.
- **Choosing a whole configuration per handshake**: ALPN, client auth and versions by SNI, as Go's
  `GetConfigForClient` and rustls's `Acceptor` do.
- **Phase 10**, TLS 1.2 resumption.
- **Phase 12**, OS verification.
- **Post-quantum key exchange (T4)**, as soon as Mbed TLS ships ML-KEM.
- **What a session reports**: the negotiated group and signature scheme, and the peer's whole chain, not only the
  leaf.

**P2.**
- Exposing max fragment length, and turning the record size limit on, for constrained peers.
- PKCS#12 import, common on Windows.
- Keys held in hardware, through PSA opaque keys or `MBEDTLS_SSL_ASYNC_PRIVATE`.

**Not planned while Mbed TLS lacks them, or by decision.** Revisit each when Mbed TLS gains it:
- ECH, OCSP stapling, certificate compression and raw public keys;
- SCTs and post-handshake auth;
- QUIC, FIPS and kTLS;
- 0-RTT (decided 2026-10-18);
- TLS 1.0 and 1.1.

## 5. The security audit

**Goal.** A written, reproducible review of everything this package adds to Mbed TLS and every choice it makes about
Mbed TLS, with each finding fixed in a patch release behind a regression test, as each phase so far has been built. Mbed
TLS's own code is reviewed upstream; here it is in scope only as configured, called and fed by ktls.

**Deliverables.**
- `docs/THREAT_MODEL.md`, written first.
- `docs/SECURITY_AUDIT.md`: one entry per finding.
  - The fields: ID, severity, area, evidence (a test, a tool run, a source line), fix, regression test.
  - The severity scale: Critical, High, Medium, Low, Info. Severity is judged by what an attacker in the threat model
    gains.
- `SECURITY.md` (T9).
- The tools below, kept in `tools/` and documented in `AGENTS.tls.md`.

**Internal and external.** These sessions can do a thorough internal review. A production claim is usually backed by
an independent one. **Decide** whether to commission one before 1.0, and when.

### 5.1 Threat model, written first

- **Assets:**
  - private keys;
  - session and traffic secrets;
  - ticket keys, and the secret a `TlsSession` holds;
  - plaintext;
  - the trust decision itself.
- **Attackers:**
  - an active network attacker, between the two ends;
  - a malicious server facing a ktls client;
  - a malicious client facing a ktls server;
  - malicious input: a certificate, CRL or key from a file or bytes;
  - a local user, on Windows: paths and store state;
  - code in another isolate of the same process: concurrency only, not memory isolation.
- **Boundaries:**
  - kama ↔ C, through the `extern fn`s;
  - ktls ↔ Mbed TLS, through the calls and callbacks;
  - the OS: the files, the Windows stores, the entropy sources.
- **Out of scope**, as Mbed TLS's SECURITY.md sets it for itself: physical attacks, fault injection, and local
  non-timing side channels.

### 5.2 Areas and what to check in each

**A. Memory safety of `csrc/ktls.c`.** Every size computation and every copy:
- **The record buffers:**
  - `ktls_buffer_append`: `end + len` and the `cap *= 2` loop are unchecked against overflow;
  - `ktls_bio_recv`, `ktls_out_peek` and `ktls_out_consume`.
- **The copy-out answers:**
  - the full-length contract of `ktls_copy_out`;
  - the kama side's grow-and-retry `bytesFrom` loops in `src/stream.kama` and `src/certificate.kama`.
- **The fixed buffers:**
  - `ktls_names_of`;
  - `ktls_verify_text`, at 1024 and 1200 bytes;
  - `ktls_export_key`'s line;
  - `ktls_alert_name` and `ktls_error_text`.
- **The SNI copy** (`ktls_sni_seen`).
- **`ktls_load_file`:** `ftell` is a `long`, and is 32 bits on Windows; and the `size + 1` allocation.
- **The Windows import:** the EKU buffer, an early exit from the enumeration, and a partial import on an error.
- **Tickets and sessions:** who owns what, on every free and error path.
- **`NULL` with length 0** from an empty kama view, into `memcpy` and the parsers.

**B. Certificate verification semantics.** Run x509-limbo, and add ktls's own rules beside it:
- **Each `Verify` mode** against a DNS name, an IP literal, and no name.
- **`Verify::Chain`** clears only the leaf's CN mismatch. Confirm no other flag can be cleared through it.
- **The IP path** (`ktls_verify_ip_cb`): IPv4-mapped IPv6, shortened forms such as `127.1`, zone ids.
- **Hostname matching in Mbed TLS:**
  - wildcards: a partial label (`f*.example.com`), and a wildcard not in the left-most label;
  - a trailing dot, and case;
  - A-labels (IDNA).

  Compare it with RFC 6125. Also check that the server's SNI selection covers exactly what clients then accept.
- **CRLs:**
  - `Listed` and `Complete`;
  - an expired CRL;
  - a CRL with the right issuer name but signed by another key (`Complete`'s coverage test compares only issuer
    names);
  - a revoked intermediate;
  - a CRL whose issuer lacks the cRLSign key usage.
- **Chain structure:**
  - EKU on server and client certificates;
  - basicConstraints and pathLen, the area of an advisory fixed in 4.1.1;
  - critical unknown extensions;
  - name constraints (T3);
  - an expired trust anchor;
  - the certificate profile (SHA-256 and above; key sizes).
- **The Windows import**, against what the system verifier would decide (phase 12).

**C. The protocol.** Run tlsfuzzer against a ktls server, and scan one with testssl.sh or sslyze. Check:
- the suites, groups and signature algorithms offered and accepted (T1);
- the TLS 1.3 downgrade sentinel (RFC 8446 §4.1.3);
- renegotiation compiled out, while the secure-renegotiation indication is still sent;
- truncation and close_notify;
- HelloRetryRequest, the area of an advisory fixed in 4.1.1;
- KeyUpdate (T2);
- ALPN: the server's choice must be one the client offered;
- extended master secret, and record and fragment limits;
- fragmented and oversized handshake messages;
- unexpected post-handshake messages;
- alerts.

**D. Resumption (phase 9).**
- **Ticket keys:** random, held only in memory, and rotated.
- **The binding:** a configuration id and a server name.
- **The thread-local `ktls_stepping`:** set and cleared on every path, including errors and a HelloRetryRequest.
- **Refusals:**
  - `resumeWith`'s -5 cases;
  - a ticket from one TLS version presented in the other;
  - the client's lifetime clamp.
- **A resumed session's verification state:** what reads `SKIP_VERIFY` and what that means to a caller.
- **`TlsSession`:** wiped on drop, and moved between isolates.

**E. Secrets.**
- Wiping on every path:
  - the record buffers, key and PEM copies, the exporter and key-log lines;
  - the stack copies;
  - what reaches kama (T7).
- `logKeys()`: what a caller must know.

**F. Concurrency.**
- The configuration's lock and the freeze.
- The callbacks that read without the lock.
- `ssl_ticket.c`'s own lock, and `ktls_init`'s first call.
- The thread-local.
- A `TlsSession` moved across isolates.
- Evidence: `tools/tsan.sh`, plus the two-isolate ticket test from §2.

**G. The kama ↔ C seam.**
- Every `extern fn` against the header: const-ness, widths, `usize` and `isize`. A wrong const-ness is silent
  (`AGENTS.package.md`).
- Every `cast`, and where a trap is the right answer.
- Handle lifetimes: a `TlsConfig` dropped while its sessions live (it is reference-counted).
- `unsafe` on the public API (T8).

**H. Configuration and build.**
- Re-read every delta in `csrc/ktls_mbedtls_user_config.h` and `csrc/ktls_crypto_user_config.h`, and every `#error`
  guard.
- Read what upstream's defaults leave on that ktls never uses.
- The optimisation level (T6).
- The `cflags` that reach a consumer: autoconf-style names only.

**I. Supply chain.**
- `tools/vendor-mbedtls.sh`: the SHA256 pin, the license check, byte-identical sources.
- The CI pins (T10).
- The test PKI generated, never tracked.
- `publish.exclude`, and `kama publish --dry-run`'s file list.

**J. Platform specifics.**
- Windows: the ROOT/Disallowed import and `_wfopen`.
- `trustSystem()`: the paths it probes.
- macOS: `/etc/ssl/cert.pem`.
- Entropy on each target, including wasm's `/dev/random` (ROADMAP, phase 8).

**K. The API and its docs.** The T8 footguns, the error text a caller may show a user, and that the README matches the
code.

### 5.3 Tools to build

Each suite was checked against its own repository on 2026-10-24.

| Tool | What it gives | How it is wired in | Effort |
|---|---|---|---|
| `tools/asan.sh` | AddressSanitizer and UndefinedBehaviorSanitizer over the whole test program | `tools/tsan.sh`'s pattern: a `select` entry with `-fsanitize=address,undefined` | small |
| Fuzz harnesses | crashes and hangs on hostile input, in what ktls adds | libFuzzer (`-fsanitize=fuzzer,address`) on `ktls.h`'s buffer API, as `tests/csrc/raw_client.c` drives it. Targets: a server fed ClientHellos, a client fed server flights, `ktls_cert_parse` with the names and end-point answers, the trust and CRL loaders, and the SNI matcher. Mbed TLS's own parsers have targets upstream (`programs/fuzz`; [OSS-Fuzz project](https://github.com/google/oss-fuzz/tree/master/projects/mbedtls)); whether OSS-Fuzz builds the 4.x line is unconfirmed | medium |
| [x509-limbo](https://github.com/C2SP/x509-limbo) | path validation against the shared suite: RFC 5280, web PKI, BetterTLS's name-constraint and path-building cases, CRLs, CVE cases, pathologicals | a harness reads `limbo.json` on stdin and writes `LimboResult` JSON on stdout. [x509-limbo.com](https://x509-limbo.com/) lists OpenSSL, BoringSSL, Go, rustls-webpki and others, and **Mbed TLS has no harness**, so this one would be the first. It is the evidence for T3 | medium |
| [BoGo](https://boringssl.googlesource.com/boringssl/+/HEAD/ssl/test/PORTING.md) (BoringSSL's `ssl/test/runner`) | thousands of TLS 1.2 and 1.3 client and server tests | a shim binary that connects to the runner's port and speaks its flags: here a `TlsStream` over a `TcpStream`. Exit 89 marks a test unimplemented, so the shim can start small. A JSON config lists `DisabledTests` and an `ErrorMap`. Go, rustls, NSS and Botan run it; rustls pins a BoringSSL revision, and so should this | large |
| [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) | servers only: the right alert for each malformed or hostile input, plus timing scripts (Lucky13, Bleichenbacher/Marvin) that bear on T1's CBC suites | `scripts/test-*.py -h host -p port` against a ktls server over TCP | medium |
| [TLS-Anvil](https://github.com/tls-attacker/TLS-Anvil) | about 408 combinatorial RFC-compliance tests, both roles | Docker; it connects to a server, or listens while a trigger script makes the client connect | medium |
| [testssl.sh](https://github.com/testssl/testssl.sh) | what a server offers and known flaws, seen from outside | Docker, against the same TCP server | small |
| Interop matrix | real peers, both roles, TLS 1.2 and 1.3, resumption | OpenSSL `s_server` and `s_client`, as phases 4, 5 and 9 did by hand; then Go and rustls example programs, rustls for its own KeyUpdate (T2). Once T4 lands, [pq.cloudflareresearch.com](https://pq.cloudflareresearch.com/) and [test.openquantumsafe.org](https://test.openquantumsafe.org/) show the negotiated group | medium |
| [Wycheproof](https://github.com/C2SP/wycheproof) | crypto primitive vectors | TF-PSA-Crypto's own domain, not ktls's. Optional | n/a |

Upstream itself runs `tests/ssl-opt.sh` and `tests/compat.sh` against OpenSSL and GnuTLS, plus the fuzz targets. No
evidence was found that it runs tlsfuzzer, BoGo, x509-limbo or Wycheproof. So the suites above add coverage beyond
upstream's, and are not a re-run of it.

## 6. Order of work

1. **Housekeeping:** §2's items 1, 2 and 5.
2. **The maintainer's decisions** in §7, before code that depends on them.
3. **The audit:**
   1. the threat model;
   2. the tools: asan.sh first, then the fuzz harnesses, the x509-limbo harness and the TCP server for tlsfuzzer;
   3. areas A to K;
   4. findings, then fixes, each a patch release with its regression test.
4. **The hardening the decisions call for:** T1's allow-list, T2's remedy, T3, T11, `SECURITY.md`, and the CI pins.
5. **Phases 8, 10, 12 and 11**, interleaved by need.
6. **1.0:** the criteria in §7, item 12.

## 7. Decisions for the maintainer

1. **Cipher suites (T1):** the allow-list, and whether callers may set suites, groups and signature algorithms.
2. **KeyUpdate (T2):** carry a patch to Mbed TLS, wait for upstream, or document a known difference.
3. **Name constraints (T3):** enforce them in ktls, or keep refusing a constrained CA.
4. **Post-quantum (T4):** wait for upstream, and watch its roadmap.
5. **OCSP and the other absences (T5):** accept them as known differences.
6. **The optimisation level (T6):** ask kama for a per-package level, or accept `-O3` with a note.
7. **Secrets in kama memory (T7):** what the API promises.
8. **`unsafe` on the public API (T8),** before 1.0.
9. **An independent audit (§5):** whether, and when.
10. **CN fallback (T11):** keep it, or refuse it.
11. **The P1 list in §4:** its order.
12. **What 1.0 means.** Proposed:
    - the audit's High and Critical findings fixed;
    - T1, T2, T3, T9 and T11 settled;
    - phases 8 and 10 done;
    - the API reviewed for stability.
