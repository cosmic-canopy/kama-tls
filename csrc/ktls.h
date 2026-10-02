#ifndef KTLS_H
#define KTLS_H
/* The C @kama/tls writes itself: glue only. The TLS is Mbed TLS's, reached through these functions, so
   kama never spells an Mbed TLS struct and never owns a pointer into one.

   The engine never touches a socket. A session reads ciphertext from an inbound buffer the caller FEEDS,
   and writes ciphertext to an outbound buffer the caller DRAINS (peek, then consume what was really sent).
   That is the whole I/O model: kama moves those bytes over whatever stream it likes. */
#include <stddef.h>
#include <stdint.h>

/* 0 once the PSA crypto core is initialised (by this call or an earlier one), else the psa_status_t it
   failed with. Cheap after the first call — an acquire load. */
int32_t ktls_init(void);

/* The linked Mbed TLS version ("4.1.1"), as the bytes kama's string constructor takes, and a strlen for it. */
const uint8_t *ktls_version(void);
size_t ktls_strlen(const uint8_t *s);

/* Results of the step functions below that are not Mbed TLS error codes. Every Mbed TLS error is a large
   negative number (-0x1000 and below), so these cannot collide. */
#define KTLS_OK          0
#define KTLS_WANT_READ   (-1)  /* the engine needs more ciphertext: feed some, then call again */
#define KTLS_CLOSED      (-2)  /* the peer sent close_notify: the stream is over */
#define KTLS_ERR_NOMEM   (-3)
#define KTLS_ERR_FROZEN  (-4)  /* the configuration is in use by a session and can no longer change */
#define KTLS_ERR_INPUT   (-5)  /* an argument out of range (too many ALPN names, an empty one, …) */
#define KTLS_ERR_NOTRUST (-6)  /* a session that must verify its peer has no trust roots to verify against */
#define KTLS_TRUNCATED   (-7)  /* the transport ended without close_notify: a truncation, not an orderly end */

/* ---- configuration: one per role, shared by every session made from it ---------------------------------
   Reference-counted with an atomic count, so a configuration (and Mbed TLS's ssl_config inside it, which is
   read-only once in use) can be shared by sessions on any thread. Mutators refuse once a session exists. */
typedef struct ktls_config ktls_config;

ktls_config *ktls_config_new(int32_t server);          /* NULL on allocation failure */
void ktls_config_retain(ktls_config *c);
void ktls_config_release(ktls_config *c);               /* frees on the last release */

/* 0 none, 1 verify the chain only, 2 verify the chain AND the server name (client); for a server, 0 does not
   ask for a client certificate and 1 or 2 require one that chains to the trust roots. */
int32_t ktls_config_verify(ktls_config *c, int32_t mode);
int32_t ktls_config_trust_file(ktls_config *c, const char *path);   /* a PEM or DER file of CA certificates */
int32_t ktls_config_trust_pem(ktls_config *c, const uint8_t *pem, size_t len);
/* This side's certificate chain and private key: PEM files, or PEM bytes. `password` may be NULL / empty. */
int32_t ktls_config_identity_files(ktls_config *c, const char *cert, const char *key, const char *password);
int32_t ktls_config_identity_pem(ktls_config *c, const uint8_t *cert, size_t cert_len,
                                 const uint8_t *key, size_t key_len, const uint8_t *password, size_t password_len);
int32_t ktls_config_alpn(ktls_config *c, const uint8_t *protocol, size_t len);   /* append one, in preference order */
int32_t ktls_config_versions(ktls_config *c, int32_t min, int32_t max);         /* 0x0303 TLS 1.2, 0x0304 TLS 1.3 */
int32_t ktls_config_trust_count(const ktls_config *c);                           /* CA certificates loaded */
/* Certificate revocation lists: a PEM or DER file, or PEM/DER bytes; each call adds to the set. */
int32_t ktls_config_crl_file(ktls_config *c, const char *path);
int32_t ktls_config_crl_pem(ktls_config *c, const uint8_t *data, size_t len);
/* 1: every certificate in a verified chain needs a CRL from its issuer among those loaded (OpenSSL's
   CRL_CHECK_ALL); one that has none fails with KTLS_BADCERT_NO_CRL. 0 (the default): Mbed TLS's rule, a
   certificate whose issuer has no CRL passes. */
int32_t ktls_config_crl_complete(ktls_config *c, int32_t on);

/* A verification flag of this package's own, beside Mbed TLS's MBEDTLS_X509_BADCERT_* bits. */
#define KTLS_BADCERT_NO_CRL 0x01000000u

/* ---- session ------------------------------------------------------------------------------------------ */
typedef struct ktls_session ktls_session;

/* A client or a server session; retains the configuration. A client's `server_name` is sent as SNI, whatever
   it holds (an IP address too: Mbed TLS does not tell them apart), and full verification compares the
   certificate with it, so full verification needs one. Under chain-only or no verification it may be empty or
   NULL: no SNI is sent and no name is compared. NULL on failure, the reason in *err. */
ktls_session *ktls_session_new(ktls_config *c, const char *server_name, int32_t *err);
void ktls_session_free(ktls_session *s);

int32_t ktls_feed(ktls_session *s, const uint8_t *buf, size_t len);   /* ciphertext from the peer */
void ktls_feed_eof(ktls_session *s);                                   /* the transport reached end of stream */
size_t ktls_out_pending(const ktls_session *s);                        /* ciphertext waiting to be sent */
size_t ktls_out_peek(const ktls_session *s, uint8_t *buf, size_t cap); /* copy up to cap, oldest first */
void ktls_out_consume(ktls_session *s, size_t n);                      /* drop n bytes that were sent */

int32_t ktls_handshake(ktls_session *s);                            /* KTLS_OK, KTLS_WANT_READ, or an error */
int32_t ktls_read(ktls_session *s, uint8_t *buf, size_t cap);       /* > 0 bytes, KTLS_WANT_READ, KTLS_CLOSED,
                                                                       KTLS_TRUNCATED, or an error */
int32_t ktls_write(ktls_session *s, const uint8_t *buf, size_t len); /* > 0 bytes accepted, or an error */
int32_t ktls_close_notify(ktls_session *s);                         /* queue close_notify */

/* ---- after (or during) the handshake ---------------------------------------------------------------------
   Each text or byte answer is copied into the caller's buffer, truncated to cap; the return value is the
   FULL length, so a caller can size a buffer and ask again. */
uint32_t ktls_verify_flags(const ktls_session *s);                 /* MBEDTLS_X509_BADCERT_* bits; 0 = verified */
/* The reasons for `flags` in words, joined with "; ", each starting in lower case. */
size_t ktls_verify_text(uint32_t flags, uint8_t *buf, size_t cap);
/* Words for any code this package hands out: its own, Mbed TLS's, and the key/PEM/PSA codes Mbed TLS 4 has no
   text for. */
size_t ktls_error_text(int32_t code, uint8_t *buf, size_t cap);
/* The description of the fatal alert the peer sent, after a step answered MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE;
   -1 when none was received. */
int32_t ktls_fatal_alert(const ktls_session *s);
size_t ktls_alert_name(int32_t description, uint8_t *buf, size_t cap);   /* "unknown_ca", "certificate_required", … */
size_t ktls_peer_cert(const ktls_session *s, uint8_t *buf, size_t cap);   /* DER; 0 when there is none */
/* RFC 5929 tls-server-end-point: MD5 and SHA-1 signatures hash with SHA-256, every other one with its own hash.
   0 when there is no peer certificate, or its signature's hash is not one PostgreSQL would use either. */
size_t ktls_end_point(const ktls_session *s, uint8_t *buf, size_t cap);
/* The peer certificate's names, as records of [kind u8][length u16 big-endian][raw bytes]: subjectAltName dNSName
   (1) and iPAddress (2) entries in certificate order, then every subject commonName (3). 0 when there is none. */
size_t ktls_peer_names(const ktls_session *s, uint8_t *buf, size_t cap);
size_t ktls_alpn(const ktls_session *s, uint8_t *buf, size_t cap);        /* 0 when none was agreed */
size_t ktls_ciphersuite(const ktls_session *s, uint8_t *buf, size_t cap);
int32_t ktls_protocol(const ktls_session *s);                             /* 0x0303 / 0x0304; 0 before */

/* ---- a certificate on its own ----------------------------------------------------------------------------
   Parsed from PEM (the first certificate of a bundle) or DER, with no session: its DER, its names (as
   ktls_peer_names gives them) and its RFC 5929 end-point hash. NULL on failure, the reason in *err. */
typedef struct ktls_cert ktls_cert;
ktls_cert *ktls_cert_parse(const uint8_t *data, size_t len, int32_t *err);
void ktls_cert_free(ktls_cert *c);
size_t ktls_cert_der(const ktls_cert *c, uint8_t *buf, size_t cap);
size_t ktls_cert_names(const ktls_cert *c, uint8_t *buf, size_t cap);
size_t ktls_cert_end_point(const ktls_cert *c, uint8_t *buf, size_t cap);

#endif
