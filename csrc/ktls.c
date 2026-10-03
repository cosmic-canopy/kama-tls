/* The C @kama/tls writes itself. See ktls.h for the model: Mbed TLS reads and writes memory buffers, and kama
   moves the bytes. Nothing here allocates on the hot path except to grow those two buffers. */

/* The RFC 5929 end-point hash needs the certificate's signature hash, which Mbed TLS 4 keeps in a private
   field, and whether a server asked for a client certificate is known only to the private handshake state
   (ssl_misc.h, on the include path because kama puts every C source directory there). This file, and only this
   file, reads them. */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "ktls.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include "ssl_misc.h"

/* ---- process setup -------------------------------------------------------------------------------------- */

static atomic_int ktls_ready = 0;

int32_t ktls_init(void)
{
    if (atomic_load_explicit(&ktls_ready, memory_order_acquire)) return 0;
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) return (int32_t)status;
    atomic_store_explicit(&ktls_ready, 1, memory_order_release);
    return 0;
}

const uint8_t *ktls_version(void) { return (const uint8_t *)mbedtls_version_get_string(); }

size_t ktls_strlen(const uint8_t *s) { return strlen((const char *)s); }

static size_t ktls_copy_out(const void *src, size_t len, uint8_t *buf, size_t cap)
{
    if (buf != NULL && cap > 0 && len > 0) memcpy(buf, src, len < cap ? len : cap);
    return len;
}

/* ---- configuration -------------------------------------------------------------------------------------- */

static int ktls_sni_seen(void *ctx, mbedtls_ssl_context *ssl, const unsigned char *name, size_t len);

#define KTLS_MAX_ALPN 8

struct ktls_config {
    atomic_int refs;
    atomic_int frozen;            /* set when the first session is made from it */
    int32_t server;
    int32_t verify;               /* 0 none, 1 chain only, 2 chain and name; a server's 3 asks without requiring */
    mbedtls_ssl_config conf;
    mbedtls_x509_crt trust;
    int32_t trust_loaded;
    mbedtls_x509_crl crl;         /* every CRL loaded, a chain of them */
    int32_t crl_loaded;
    int32_t crl_complete;         /* OpenSSL's CRL_CHECK_ALL: every certificate in the chain needs its issuer's CRL */
    mbedtls_x509_crt own_cert;
    mbedtls_pk_context own_key;
    int32_t own_loaded;
    char *alpn[KTLS_MAX_ALPN + 1];  /* NULL-terminated, as mbedtls_ssl_conf_alpn_protocols wants */
    int32_t alpn_count;
};

/* Called by Mbed TLS for each certificate of the chain it built, the trust anchor included, with that
   certificate's verification flags so far.

   Chain-only verification: the chain must still verify, but the certificate's names are not compared with the
   server name. A client given a name sends it as SNI, and Mbed TLS then compares it too, so only that mismatch
   flag is cleared, on the leaf. A client given no name sends no SNI and says so with an explicit
   mbedtls_ssl_set_hostname(NULL), which Mbed TLS 4 takes as "verify without a name" (it refuses a verifying
   client only when the hostname was never set at all).

   Complete revocation (OpenSSL's X509_V_FLAG_CRL_CHECK_ALL, which libpq sets once it has loaded a CRL): every
   certificate needs a CRL from its issuer among those loaded, the trust anchor too (its issuer is itself). Mbed
   TLS checks a certificate against its issuer's CRL when it has one and lets it pass when it has none; this
   marks the latter KTLS_BADCERT_NO_CRL. */
static int ktls_verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    const ktls_config *c = ctx;
    if (!c->server && c->verify == 1 && depth == 0) *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH;
    /* With no CRL loaded at all, nothing is covered: OpenSSL fails such a chain too ("unable to get certificate CRL"),
       as libpq sees when sslcrldir names a directory that holds none. */
    if (c->crl_complete) {
        int covered = 0;
        for (const mbedtls_x509_crl *crl = &c->crl; crl != NULL && !covered; crl = crl->next) {
            covered = crl->version != 0 && crl->issuer_raw.len == crt->issuer_raw.len &&
                      memcmp(crl->issuer_raw.p, crt->issuer_raw.p, crt->issuer_raw.len) == 0;
        }
        if (!covered) *flags |= KTLS_BADCERT_NO_CRL;
    }
    return 0;
}

static void ktls_config_apply_verify(ktls_config *c)
{
    int authmode = c->verify == 0 ? MBEDTLS_SSL_VERIFY_NONE
                 : c->verify == 3 ? MBEDTLS_SSL_VERIFY_OPTIONAL : MBEDTLS_SSL_VERIFY_REQUIRED;
    mbedtls_ssl_conf_authmode(&c->conf, authmode);
    mbedtls_ssl_conf_verify(&c->conf, ktls_verify_cb, c);
}

ktls_config *ktls_config_new(int32_t server)
{
    if (ktls_init() != 0) return NULL;
    ktls_config *c = calloc(1, sizeof *c);
    if (c == NULL) return NULL;
    atomic_init(&c->refs, 1);
    atomic_init(&c->frozen, 0);
    c->server = server ? 1 : 0;
    c->verify = server ? 0 : 2;   /* a client verifies chain and name unless told otherwise */
    mbedtls_ssl_config_init(&c->conf);
    mbedtls_x509_crt_init(&c->trust);
    mbedtls_x509_crl_init(&c->crl);
    mbedtls_x509_crt_init(&c->own_cert);
    mbedtls_pk_init(&c->own_key);
    if (mbedtls_ssl_config_defaults(&c->conf, c->server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        ktls_config_release(c);
        return NULL;
    }
    ktls_config_apply_verify(c);
    if (c->server) mbedtls_ssl_conf_sni(&c->conf, ktls_sni_seen, NULL);
    return c;
}

void ktls_config_retain(ktls_config *c) { atomic_fetch_add_explicit(&c->refs, 1, memory_order_relaxed); }

void ktls_config_release(ktls_config *c)
{
    if (c == NULL) return;
    if (atomic_fetch_sub_explicit(&c->refs, 1, memory_order_acq_rel) != 1) return;
    mbedtls_ssl_config_free(&c->conf);
    mbedtls_x509_crt_free(&c->trust);
    mbedtls_x509_crl_free(&c->crl);
    mbedtls_x509_crt_free(&c->own_cert);
    mbedtls_pk_free(&c->own_key);
    for (int32_t i = 0; i < c->alpn_count; i++) free(c->alpn[i]);
    free(c);
}

static int ktls_mutable(const ktls_config *c) { return !atomic_load_explicit(&c->frozen, memory_order_acquire); }

int32_t ktls_config_verify(ktls_config *c, int32_t mode)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    if (mode < 0 || mode > 3 || (mode == 3 && !c->server)) return KTLS_ERR_INPUT;
    c->verify = mode;
    ktls_config_apply_verify(c);
    return 0;
}

static void ktls_config_apply_trust(ktls_config *c)
{
    mbedtls_ssl_conf_ca_chain(&c->conf, c->trust_loaded ? &c->trust : NULL, c->crl_loaded ? &c->crl : NULL);
}

int32_t ktls_config_trust_file(ktls_config *c, const char *path)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    int rc = mbedtls_x509_crt_parse_file(&c->trust, path);
    if (rc < 0) return rc;
    c->trust_loaded = 1;
    ktls_config_apply_trust(c);
    return rc;   /* > 0: that many certificates in the file could not be parsed and were skipped */
}

/* Whether bytes are PEM text (they hold a "-----BEGIN" line) rather than DER. */
static int ktls_is_pem(const uint8_t *data, size_t len)
{
    static const char begin[] = "-----BEGIN";
    for (size_t i = 0; i + (sizeof begin - 1) <= len; i++) if (memcmp(data + i, begin, sizeof begin - 1) == 0) return 1;
    return 0;
}

/* PEM parsing wants the buffer NUL-terminated, with the NUL counted in the length. */
static uint8_t *ktls_terminated(const uint8_t *buf, size_t len)
{
    uint8_t *copy = malloc(len + 1);
    if (copy == NULL) return NULL;
    if (len > 0) memcpy(copy, buf, len);
    copy[len] = 0;
    return copy;
}

int32_t ktls_config_trust_pem(ktls_config *c, const uint8_t *pem, size_t len)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    uint8_t *copy = ktls_terminated(pem, len);
    if (copy == NULL) return KTLS_ERR_NOMEM;
    int rc = mbedtls_x509_crt_parse(&c->trust, copy, len + 1);
    free(copy);
    if (rc < 0) return rc;
    c->trust_loaded = 1;
    ktls_config_apply_trust(c);
    return rc;
}

int32_t ktls_config_crl_file(ktls_config *c, const char *path)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    int rc = mbedtls_x509_crl_parse_file(&c->crl, path);
    if (rc != 0) return rc;
    c->crl_loaded = 1;
    ktls_config_apply_trust(c);
    return 0;
}

int32_t ktls_config_crl_pem(ktls_config *c, const uint8_t *data, size_t len)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    /* PEM wants the buffer NUL-terminated with the NUL counted; DER takes its exact length. */
    int rc;
    if (ktls_is_pem(data, len)) {
        uint8_t *copy = ktls_terminated(data, len);
        if (copy == NULL) return KTLS_ERR_NOMEM;
        rc = mbedtls_x509_crl_parse(&c->crl, copy, len + 1);
        free(copy);
    } else {
        rc = mbedtls_x509_crl_parse_der(&c->crl, data, len);
    }
    if (rc != 0) return rc;
    c->crl_loaded = 1;
    ktls_config_apply_trust(c);
    return 0;
}

int32_t ktls_config_crl_complete(ktls_config *c, int32_t on)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    c->crl_complete = on ? 1 : 0;
    return 0;
}

static int32_t ktls_config_apply_identity(ktls_config *c)
{
    int rc = mbedtls_ssl_conf_own_cert(&c->conf, &c->own_cert, &c->own_key);
    if (rc != 0) return rc;
    c->own_loaded = 1;
    return 0;
}

/* Whether a private key pairs with a certificate's public key: the same key type, size and public key bytes.
   mbedtls_pk_check_pair compares the two contexts' cached public halves, but TF-PSA-Crypto 1.2.0 leaves that
   cache empty for a parsed RSA private key (pk_rsa.c fills it only for public keys), so it refuses every RSA
   pair. Here the private key's public half comes from PSA when the cache is empty, as pkwrite.c does it. */
static int ktls_pair_matches(const mbedtls_pk_context *pub, const mbedtls_pk_context *prv)
{
    if (pub->pk_info == NULL || prv->pk_info == NULL || pub->pub_raw_len == 0) return 0;
    if (!PSA_KEY_TYPE_IS_KEY_PAIR(prv->psa_type) || pub->psa_type != PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(prv->psa_type)) return 0;
    if (mbedtls_pk_get_bitlen(pub) != mbedtls_pk_get_bitlen(prv)) return 0;
    const uint8_t *raw = prv->pub_raw;
    size_t len = prv->pub_raw_len;
    uint8_t exported[MBEDTLS_PK_MAX_PUBKEY_RAW_LEN];
    if (len == 0) {
        if (psa_export_public_key(prv->priv_id, exported, sizeof exported, &len) != PSA_SUCCESS) return 0;
        raw = exported;
    }
    return len == pub->pub_raw_len && memcmp(raw, pub->pub_raw, len) == 0;
}

/* The identity is loaded in two steps, so a caller can tell which one failed: the certificate chain (the first
   certificate is this side's, the rest its chain), then the private key, which must decrypt with the password
   and pair with the first certificate. Only then is the identity installed. Each step takes PEM or DER. */
int32_t ktls_config_certificate_chain(ktls_config *c, const uint8_t *data, size_t len)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    if (c->own_loaded || c->own_cert.raw.len > 0) return KTLS_ERR_INPUT;   /* one identity per configuration */
    int rc;
    if (ktls_is_pem(data, len)) {
        uint8_t *copy = ktls_terminated(data, len);
        if (copy == NULL) return KTLS_ERR_NOMEM;
        rc = mbedtls_x509_crt_parse(&c->own_cert, copy, len + 1);
        free(copy);
    } else {
        rc = mbedtls_x509_crt_parse_der(&c->own_cert, data, len);
    }
    if (rc > 0) rc = KTLS_ERR_INPUT;   /* some certificate of a PEM chain did not parse */
    if (rc == 0 && c->own_cert.raw.len == 0) rc = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
    if (rc != 0) { mbedtls_x509_crt_free(&c->own_cert); mbedtls_x509_crt_init(&c->own_cert); }
    return rc;
}

int32_t ktls_config_private_key(ktls_config *c, const uint8_t *data, size_t len, const uint8_t *password, size_t password_len)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    if (c->own_loaded || c->own_cert.raw.len == 0) return KTLS_ERR_INPUT;   /* the chain comes first */
    const uint8_t *pw = password_len > 0 ? password : NULL;
    int rc;
    if (ktls_is_pem(data, len)) {
        uint8_t *copy = ktls_terminated(data, len);
        if (copy == NULL) return KTLS_ERR_NOMEM;
        rc = mbedtls_pk_parse_key(&c->own_key, copy, len + 1, pw, password_len);
        mbedtls_platform_zeroize(copy, len + 1);
        free(copy);
    } else {
        rc = mbedtls_pk_parse_key(&c->own_key, data, len, pw, password_len);
    }
    if (rc == 0 && !ktls_pair_matches(&c->own_cert.pk, &c->own_key)) rc = KTLS_ERR_KEY_MISMATCH;
    if (rc != 0) { mbedtls_pk_free(&c->own_key); mbedtls_pk_init(&c->own_key); return rc; }
    return ktls_config_apply_identity(c);
}

/* Both steps, from files: an unreadable file is Mbed TLS's FILE_IO error for that step. */
int32_t ktls_config_identity_files(ktls_config *c, const char *cert, const char *key, const char *password)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    if (c->own_loaded || c->own_cert.raw.len > 0) return KTLS_ERR_INPUT;
    int rc = mbedtls_x509_crt_parse_file(&c->own_cert, cert);
    if (rc > 0) rc = KTLS_ERR_INPUT;
    if (rc != 0) { mbedtls_x509_crt_free(&c->own_cert); mbedtls_x509_crt_init(&c->own_cert); return rc; }
    rc = mbedtls_pk_parse_keyfile(&c->own_key, key, (password != NULL && password[0] != 0) ? password : NULL);
    if (rc == 0 && !ktls_pair_matches(&c->own_cert.pk, &c->own_key)) rc = KTLS_ERR_KEY_MISMATCH;
    if (rc != 0) {
        mbedtls_pk_free(&c->own_key); mbedtls_pk_init(&c->own_key);
        mbedtls_x509_crt_free(&c->own_cert); mbedtls_x509_crt_init(&c->own_cert);
        return rc;
    }
    return ktls_config_apply_identity(c);
}

int32_t ktls_config_identity_pem(ktls_config *c, const uint8_t *cert, size_t cert_len,
                                 const uint8_t *key, size_t key_len, const uint8_t *password, size_t password_len)
{
    int rc = ktls_config_certificate_chain(c, cert, cert_len);
    if (rc != 0) return rc;
    rc = ktls_config_private_key(c, key, key_len, password, password_len);
    if (rc != 0) { mbedtls_x509_crt_free(&c->own_cert); mbedtls_x509_crt_init(&c->own_cert); }
    return rc;
}

int32_t ktls_config_alpn(ktls_config *c, const uint8_t *protocol, size_t len)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    if (len == 0 || len > 255 || c->alpn_count >= KTLS_MAX_ALPN) return KTLS_ERR_INPUT;
    char *name = malloc(len + 1);
    if (name == NULL) return KTLS_ERR_NOMEM;
    memcpy(name, protocol, len);
    name[len] = 0;
    c->alpn[c->alpn_count++] = name;
    c->alpn[c->alpn_count] = NULL;
    return mbedtls_ssl_conf_alpn_protocols(&c->conf, (const char *const *)c->alpn);
}

int32_t ktls_config_versions(ktls_config *c, int32_t min, int32_t max)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    if (min < 0x0303 || max > 0x0304 || min > max) return KTLS_ERR_INPUT;
    mbedtls_ssl_conf_min_tls_version(&c->conf, (mbedtls_ssl_protocol_version)min);
    mbedtls_ssl_conf_max_tls_version(&c->conf, (mbedtls_ssl_protocol_version)max);
    return 0;
}

int32_t ktls_config_trust_count(const ktls_config *c)
{
    if (!c->trust_loaded) return 0;
    int32_t n = 0;
    for (const mbedtls_x509_crt *crt = &c->trust; crt != NULL && crt->raw.len > 0; crt = crt->next) n++;
    return n;
}

/* ---- session -------------------------------------------------------------------------------------------- */

typedef struct {
    uint8_t *data;
    size_t start;   /* first unread byte */
    size_t end;     /* one past the last byte */
    size_t cap;
} ktls_buffer;

struct ktls_session {
    mbedtls_ssl_context ssl;
    ktls_config *config;
    ktls_buffer in;    /* ciphertext from the peer, not yet read by the engine */
    ktls_buffer out;   /* ciphertext for the peer, not yet taken by the caller */
    int32_t eof;       /* the transport ended: once `in` is empty, the engine sees end of stream */
    int32_t cert_requested;   /* a client: the server sent a CertificateRequest */
    char *sni;                /* a server: the name the client sent as SNI, NULL if none */
    ktls_buffer keylog;       /* NSS key-log lines not yet taken (ktls_session_keylog) */
};

/* A server records the name a client asked for. Any name is accepted: the session serves its one identity. */
static int ktls_sni_seen(void *ctx, mbedtls_ssl_context *ssl, const unsigned char *name, size_t len)
{
    (void)ctx;
    ktls_session *s = mbedtls_ssl_get_user_data_p(ssl);
    if (s == NULL || s->sni != NULL) return 0;
    s->sni = malloc(len + 1);
    if (s->sni == NULL) return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    memcpy(s->sni, name, len);
    s->sni[len] = 0;
    return 0;
}

static int ktls_buffer_append(ktls_buffer *b, const uint8_t *src, size_t len)
{
    if (len == 0) return 0;
    if (b->end + len > b->cap) {
        if (b->start > 0) {   /* reclaim what has been read before growing */
            memmove(b->data, b->data + b->start, b->end - b->start);
            b->end -= b->start;
            b->start = 0;
        }
        if (b->end + len > b->cap) {
            size_t cap = b->cap ? b->cap : 16384;
            while (cap < b->end + len) cap *= 2;
            uint8_t *grown = realloc(b->data, cap);
            if (grown == NULL) return -1;
            b->data = grown;
            b->cap = cap;
        }
    }
    memcpy(b->data + b->end, src, len);
    b->end += len;
    return 0;
}

static void ktls_buffer_free(ktls_buffer *b)
{
    if (b->data != NULL) { mbedtls_platform_zeroize(b->data, b->cap); free(b->data); }
    b->data = NULL;
    b->start = b->end = b->cap = 0;
}

static int ktls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    ktls_session *s = ctx;
    if (ktls_buffer_append(&s->out, buf, len) != 0) return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    return (int)len;
}

static int ktls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    ktls_session *s = ctx;
    size_t avail = s->in.end - s->in.start;
    if (avail == 0) return s->eof ? 0 : MBEDTLS_ERR_SSL_WANT_READ;
    size_t n = avail < len ? avail : len;
    memcpy(buf, s->in.data + s->in.start, n);
    s->in.start += n;
    if (s->in.start == s->in.end) s->in.start = s->in.end = 0;
    return (int)n;
}

ktls_session *ktls_session_new(ktls_config *c, const char *server_name, int32_t *err)
{
    *err = 0;
    if (c->server && !c->own_loaded) { *err = KTLS_ERR_INPUT; return NULL; }
    /* Verifying needs something to verify against; a server that only asks for a certificate (3) does not. */
    if ((c->verify == 1 || c->verify == 2) && !c->trust_loaded) { *err = KTLS_ERR_NOTRUST; return NULL; }
    int has_name = server_name != NULL && server_name[0] != 0;
    /* Only full verification needs a name to compare; chain-only and none may go without one (and without SNI). */
    if (!c->server && c->verify == 2 && !has_name) { *err = KTLS_ERR_INPUT; return NULL; }
    ktls_session *s = calloc(1, sizeof *s);
    if (s == NULL) { *err = KTLS_ERR_NOMEM; return NULL; }
    atomic_store_explicit(&c->frozen, 1, memory_order_release);
    ktls_config_retain(c);
    s->config = c;
    mbedtls_ssl_init(&s->ssl);
    int rc = mbedtls_ssl_setup(&s->ssl, &c->conf);
    mbedtls_ssl_set_user_data_p(&s->ssl, s);
    /* A client sends its name as SNI and, under full verification, checks the certificate against it (chain-only
       mode clears just the mismatch). With no name it sends no SNI and compares no name, which Mbed TLS 4 wants
       said explicitly. */
    if (rc == 0 && !c->server) rc = mbedtls_ssl_set_hostname(&s->ssl, has_name ? server_name : NULL);
    if (rc != 0) { *err = rc; ktls_session_free(s); return NULL; }
    mbedtls_ssl_set_bio(&s->ssl, s, ktls_bio_send, ktls_bio_recv, NULL);
    return s;
}

void ktls_session_free(ktls_session *s)
{
    if (s == NULL) return;
    mbedtls_ssl_free(&s->ssl);
    ktls_buffer_free(&s->in);
    ktls_buffer_free(&s->out);
    ktls_buffer_free(&s->keylog);
    ktls_config_release(s->config);
    free(s->sni);
    free(s);
}

int32_t ktls_feed(ktls_session *s, const uint8_t *buf, size_t len)
{
    return ktls_buffer_append(&s->in, buf, len) == 0 ? 0 : KTLS_ERR_NOMEM;
}

void ktls_feed_eof(ktls_session *s) { s->eof = 1; }

size_t ktls_out_pending(const ktls_session *s) { return s->out.end - s->out.start; }

size_t ktls_out_peek(const ktls_session *s, uint8_t *buf, size_t cap)
{
    size_t n = s->out.end - s->out.start;
    if (n > cap) n = cap;
    if (n > 0) memcpy(buf, s->out.data + s->out.start, n);
    return n;
}

void ktls_out_consume(ktls_session *s, size_t n)
{
    size_t pending = s->out.end - s->out.start;
    s->out.start += n < pending ? n : pending;
    if (s->out.start == s->out.end) s->out.start = s->out.end = 0;
}

/* mbedtls_ssl_handshake is a loop over mbedtls_ssl_handshake_step; it is run here a step at a time, so that
   between steps a client can note a CertificateRequest, which Mbed TLS keeps only in its handshake state and
   frees when the handshake ends. */
int32_t ktls_handshake(ktls_session *s)
{
    int rc = 0;
    while (!mbedtls_ssl_is_handshake_over(&s->ssl)) {
        rc = mbedtls_ssl_handshake_step(&s->ssl);
        if (!s->config->server && s->ssl.handshake != NULL && s->ssl.handshake->client_auth) s->cert_requested = 1;
        if (rc != 0) break;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return KTLS_WANT_READ;
    return rc;
}

int32_t ktls_cert_requested(const ktls_session *s) { return s->cert_requested; }

/* NSS key-log lines (the SSLKEYLOGFILE format Wireshark reads): "LABEL <client random> <secret>", both in lower-case
   hex. TLS 1.2 gives one CLIENT_RANDOM line with the master secret; TLS 1.3 its traffic secrets. Mbed TLS exports no
   1.3 EXPORTER_SECRET, which OpenSSL also logs. */
static void ktls_export_key(void *ctx, mbedtls_ssl_key_export_type type, const unsigned char *secret, size_t secret_len,
                            const unsigned char client_random[32], const unsigned char server_random[32],
                            mbedtls_tls_prf_types prf)
{
    (void)server_random; (void)prf;
    ktls_session *s = ctx;
    const char *label = NULL;
    switch (type) {
        case MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET: label = "CLIENT_RANDOM"; break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_EARLY_SECRET: label = "CLIENT_EARLY_TRAFFIC_SECRET"; break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_EARLY_EXPORTER_SECRET: label = "EARLY_EXPORTER_SECRET"; break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET: label = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"; break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET: label = "SERVER_HANDSHAKE_TRAFFIC_SECRET"; break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET: label = "CLIENT_TRAFFIC_SECRET_0"; break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET: label = "SERVER_TRAFFIC_SECRET_0"; break;
        default: return;
    }
    static const char digits[] = "0123456789abcdef";
    char line[64 + 1 + 64 + 1 + 2 * 128 + 2];
    size_t n = strlen(label);
    if (secret_len > 128) return;
    memcpy(line, label, n);
    line[n++] = ' ';
    for (size_t i = 0; i < 32; i++) { line[n++] = digits[client_random[i] >> 4]; line[n++] = digits[client_random[i] & 15]; }
    line[n++] = ' ';
    for (size_t i = 0; i < secret_len; i++) { line[n++] = digits[secret[i] >> 4]; line[n++] = digits[secret[i] & 15]; }
    line[n++] = '\n';
    ktls_buffer_append(&s->keylog, (const uint8_t *)line, n);
    mbedtls_platform_zeroize(line, sizeof line);
}

int32_t ktls_session_keylog(ktls_session *s)
{
    mbedtls_ssl_set_export_keys_cb(&s->ssl, ktls_export_key, s);
    return 0;
}

size_t ktls_keylog_pending(const ktls_session *s) { return s->keylog.end - s->keylog.start; }

/* Up to cap bytes of key-log text, taken: what is copied out is wiped from the session. */
size_t ktls_keylog_take(ktls_session *s, uint8_t *buf, size_t cap)
{
    size_t n = s->keylog.end - s->keylog.start;
    if (n > cap) n = cap;
    if (n > 0) {
        memcpy(buf, s->keylog.data + s->keylog.start, n);
        mbedtls_platform_zeroize(s->keylog.data + s->keylog.start, n);
        s->keylog.start += n;
        if (s->keylog.start == s->keylog.end) s->keylog.start = s->keylog.end = 0;
    }
    return n;
}

/* Received bytes not yet handed to the caller: plaintext Mbed TLS has decrypted, and ciphertext fed but not yet
   taken. A caller about to wait for the transport must read these first. */
size_t ktls_in_pending(const ktls_session *s) { return (s->in.end - s->in.start) + mbedtls_ssl_get_bytes_avail(&s->ssl); }

int32_t ktls_key_bits(const ktls_session *s)
{
    if (!mbedtls_ssl_is_handshake_over((mbedtls_ssl_context *)&s->ssl)) return 0;
    const mbedtls_ssl_ciphersuite_t *info = mbedtls_ssl_ciphersuite_from_id(mbedtls_ssl_get_ciphersuite_id_from_ssl(&s->ssl));
    return info == NULL ? 0 : (int32_t)mbedtls_ssl_ciphersuite_get_cipher_key_bitlen(info);
}

size_t ktls_sni(const ktls_session *s, uint8_t *buf, size_t cap)
{
    return s->sni == NULL ? 0 : ktls_copy_out(s->sni, strlen(s->sni), buf, cap);
}

int32_t ktls_read(ktls_session *s, uint8_t *buf, size_t cap)
{
    if (cap > 0x7fffffff) cap = 0x7fffffff;
    for (;;) {
        int rc = mbedtls_ssl_read(&s->ssl, buf, cap);
        if (rc > 0) return rc;
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return KTLS_WANT_READ;
        if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return KTLS_CLOSED;
        /* TLS 1.3 post-handshake messages surface as this; it carries no application data. */
        if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
        /* mbedtls_ssl_read answers 0 when the transport ended WITHOUT a close_notify (its documented
           contract), and CONN_EOF when that happens mid-record. Both are truncations. */
        if (rc == 0 || rc == MBEDTLS_ERR_SSL_CONN_EOF) return KTLS_TRUNCATED;
        return rc;
    }
}

int32_t ktls_write(ktls_session *s, const uint8_t *buf, size_t len)
{
    if (len > 0x7fffffff) len = 0x7fffffff;
    int rc = mbedtls_ssl_write(&s->ssl, buf, len);
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return KTLS_WANT_READ;
    return rc;
}

int32_t ktls_close_notify(ktls_session *s)
{
    int rc = mbedtls_ssl_close_notify(&s->ssl);
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return KTLS_WANT_READ;
    return rc;
}

/* ---- after the handshake -------------------------------------------------------------------------------- */

uint32_t ktls_verify_flags(const ktls_session *s) { return mbedtls_ssl_get_verify_result(&s->ssl); }

/* Mbed TLS has no words for KTLS_BADCERT_NO_CRL (it would say "Unknown reason"), so it is set aside and said
   here, after Mbed TLS's own reasons. */
static const char ktls_no_crl_text[] = "No CRL from the certificate's issuer was loaded\n";

size_t ktls_verify_text(uint32_t flags, uint8_t *buf, size_t cap)
{
    char text[1024];
    int n = mbedtls_x509_crt_verify_info(text, sizeof text, "", flags & ~(uint32_t)KTLS_BADCERT_NO_CRL);
    if (n < 0) n = 0;
    if ((flags & ~(uint32_t)KTLS_BADCERT_NO_CRL) == 0) n = 0;
    if ((flags & KTLS_BADCERT_NO_CRL) && (size_t)n + sizeof ktls_no_crl_text < sizeof text) {
        memcpy(text + n, ktls_no_crl_text, sizeof ktls_no_crl_text - 1);
        n += (int)(sizeof ktls_no_crl_text - 1);
    }
    /* One reason per line, each ending in '\n'. They are joined with "; ", and each starts in lower case so the
       list reads inside a sentence ("certificate verify failed: the certificate validity has expired; …"). A
       reason that opens with an acronym ("CRL …") keeps it. */
    char joined[1200];
    size_t out = 0;
    int line_start = 1;
    for (int i = 0; i < n && out + 2 < sizeof joined; i++) {
        char ch = text[i];
        if (ch == '\n') {
            while (out > 0 && joined[out - 1] == ' ') out--;
            if (i + 1 < n) { joined[out++] = ';'; joined[out++] = ' '; }
            line_start = 1;
            continue;
        }
        if (line_start && ch == ' ') continue;
        if (line_start && ch >= 'A' && ch <= 'Z' && i + 1 < n && text[i + 1] >= 'a' && text[i + 1] <= 'z') ch = (char)(ch - 'A' + 'a');
        line_start = 0;
        joined[out++] = ch;
    }
    while (out > 0 && (joined[out - 1] == ' ' || joined[out - 1] == ';')) out--;
    return ktls_copy_out(joined, out, buf, cap);
}

/* Words for the key and PEM failures Mbed TLS 4's mbedtls_strerror has no text for (it prints "UNKNOWN ERROR CODE
   (3C00)"), and for the PSA status codes the key and certificate parsers now return. NULL when this table has
   nothing to say, so the caller falls back to mbedtls_strerror. */
static const char *ktls_known_text(int32_t code)
{
    if (code <= -0x1000) {
        int32_t high = -((-code) & 0xFF80);
        switch (high) {
            case MBEDTLS_ERR_PK_TYPE_MISMATCH:       return "the key is not of the type this operation needs";
            case MBEDTLS_ERR_PK_FILE_IO_ERROR:       return "the key file could not be read";
            case MBEDTLS_ERR_PK_KEY_INVALID_VERSION: return "the key's format version is not supported";
            case MBEDTLS_ERR_PK_KEY_INVALID_FORMAT:  return "the data is not a private key in a format this library reads";
            case MBEDTLS_ERR_PK_UNKNOWN_PK_ALG:      return "the key's algorithm is not supported";
            case MBEDTLS_ERR_PK_PASSWORD_REQUIRED:   return "the private key is encrypted, and no password was given";
            case MBEDTLS_ERR_PK_PASSWORD_MISMATCH:   return "the password does not decrypt the private key";
            case MBEDTLS_ERR_PK_INVALID_PUBKEY:      return "the public key is invalid";
            case MBEDTLS_ERR_PK_INVALID_ALG:         return "the key's algorithm identifier is invalid";
            case MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE: return "the key's elliptic curve is not supported";
            case MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE: return "the key needs a feature this build of Mbed TLS leaves out";
            case MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT: return "no PEM header and footer were found";
            case MBEDTLS_ERR_PEM_INVALID_DATA:       return "the PEM data is malformed";
            case MBEDTLS_ERR_PEM_INVALID_ENC_IV:     return "the PEM encryption IV is invalid";
            case MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG:    return "the PEM is encrypted with a cipher this library does not have (DES is not supported)";
            case MBEDTLS_ERR_PEM_PASSWORD_REQUIRED:  return "the private key is encrypted, and no password was given";
            case MBEDTLS_ERR_PEM_PASSWORD_MISMATCH:  return "the password does not decrypt the private key";
            case MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE: return "the PEM needs a feature this build of Mbed TLS leaves out";
            default: return NULL;
        }
    }
    switch (code) {
        case PSA_ERROR_INVALID_ARGUMENT:     return "invalid input data";
        case PSA_ERROR_INSUFFICIENT_MEMORY:  return "out of memory";
        case PSA_ERROR_BUFFER_TOO_SMALL:     return "a buffer is too small";
        case PSA_ERROR_NOT_SUPPORTED:        return "not supported by this build of Mbed TLS";
        case PSA_ERROR_NOT_PERMITTED:        return "the key does not permit this operation";
        case PSA_ERROR_INVALID_SIGNATURE:    return "a signature does not verify";
        case PSA_ERROR_INVALID_PADDING:      return "invalid padding";
        case PSA_ERROR_INSUFFICIENT_ENTROPY: return "not enough entropy";
        case PSA_ERROR_CORRUPTION_DETECTED:  return "memory corruption detected";
        case PSA_ERROR_GENERIC_ERROR:        return "a cryptographic operation failed";
        default: return NULL;
    }
}

size_t ktls_error_text(int32_t code, uint8_t *buf, size_t cap)
{
    static const char nomem[] = "out of memory";
    static const char frozen[] = "the configuration is already in use by a session";
    static const char input[] = "invalid argument";
    static const char notrust[] = "no trust roots to verify the peer against";
    static const char truncated[] = "the connection ended without a TLS close_notify (truncated)";
    static const char mismatch[] = "the private key does not match the certificate";
    switch (code) {
        case KTLS_ERR_NOMEM:   return ktls_copy_out(nomem, sizeof nomem - 1, buf, cap);
        case KTLS_ERR_FROZEN:  return ktls_copy_out(frozen, sizeof frozen - 1, buf, cap);
        case KTLS_ERR_INPUT:   return ktls_copy_out(input, sizeof input - 1, buf, cap);
        case KTLS_ERR_NOTRUST: return ktls_copy_out(notrust, sizeof notrust - 1, buf, cap);
        case KTLS_TRUNCATED:   return ktls_copy_out(truncated, sizeof truncated - 1, buf, cap);
        case KTLS_ERR_KEY_MISMATCH: return ktls_copy_out(mismatch, sizeof mismatch - 1, buf, cap);
        default: break;
    }
    const char *known = ktls_known_text(code);
    if (known != NULL) return ktls_copy_out(known, strlen(known), buf, cap);
    char text[256];
    mbedtls_strerror(code, text, sizeof text);
    return ktls_copy_out(text, strlen(text), buf, cap);
}

int32_t ktls_fatal_alert(const ktls_session *s)
{
    int rc = mbedtls_ssl_get_fatal_alert(&s->ssl);
    return rc < 0 ? -1 : (int32_t)rc;
}

/* The alert's name as RFC 8446 §6 (and RFC 5246 for the ones TLS 1.3 retired) spells it. */
size_t ktls_alert_name(int32_t description, uint8_t *buf, size_t cap)
{
    const char *name;
    switch (description) {
        case 0:   name = "close_notify"; break;
        case 10:  name = "unexpected_message"; break;
        case 20:  name = "bad_record_mac"; break;
        case 21:  name = "decryption_failed"; break;
        case 22:  name = "record_overflow"; break;
        case 30:  name = "decompression_failure"; break;
        case 40:  name = "handshake_failure"; break;
        case 41:  name = "no_certificate"; break;
        case 42:  name = "bad_certificate"; break;
        case 43:  name = "unsupported_certificate"; break;
        case 44:  name = "certificate_revoked"; break;
        case 45:  name = "certificate_expired"; break;
        case 46:  name = "certificate_unknown"; break;
        case 47:  name = "illegal_parameter"; break;
        case 48:  name = "unknown_ca"; break;
        case 49:  name = "access_denied"; break;
        case 50:  name = "decode_error"; break;
        case 51:  name = "decrypt_error"; break;
        case 60:  name = "export_restriction"; break;
        case 70:  name = "protocol_version"; break;
        case 71:  name = "insufficient_security"; break;
        case 80:  name = "internal_error"; break;
        case 86:  name = "inappropriate_fallback"; break;
        case 90:  name = "user_canceled"; break;
        case 100: name = "no_renegotiation"; break;
        case 109: name = "missing_extension"; break;
        case 110: name = "unsupported_extension"; break;
        case 111: name = "certificate_unobtainable"; break;
        case 112: name = "unrecognized_name"; break;
        case 113: name = "bad_certificate_status_response"; break;
        case 114: name = "bad_certificate_hash_value"; break;
        case 115: name = "unknown_psk_identity"; break;
        case 116: name = "certificate_required"; break;
        case 120: name = "no_application_protocol"; break;
        default:  name = "unknown alert"; break;
    }
    return ktls_copy_out(name, strlen(name), buf, cap);
}

size_t ktls_peer_cert(const ktls_session *s, uint8_t *buf, size_t cap)
{
    const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(&s->ssl);
    if (crt == NULL) return 0;
    return ktls_copy_out(crt->raw.p, crt->raw.len, buf, cap);
}

/* RFC 5929 §4.1: the hash of the certificate's DER, with the hash function of its signature algorithm — except
   that MD5 and SHA-1 become SHA-256. What SCRAM-SHA-256-PLUS binds a login to, as PostgreSQL computes it
   (be_tls_get_certificate_hash): a SHA-224 signature hashes with SHA-224, and a signature whose hash is not one
   of these has no binding at all (0), rather than a guess the server would not share. */
static size_t ktls_end_point_of(const mbedtls_x509_crt *crt, uint8_t *buf, size_t cap)
{
    if (crt == NULL) return 0;
    psa_algorithm_t alg;
    switch (crt->sig_md) {
        case MBEDTLS_MD_MD5:
        case MBEDTLS_MD_SHA1:
        case MBEDTLS_MD_SHA256: alg = PSA_ALG_SHA_256; break;
        case MBEDTLS_MD_SHA224: alg = PSA_ALG_SHA_224; break;
        case MBEDTLS_MD_SHA384: alg = PSA_ALG_SHA_384; break;
        case MBEDTLS_MD_SHA512: alg = PSA_ALG_SHA_512; break;
        default:                return 0;
    }
    uint8_t hash[PSA_HASH_MAX_SIZE];
    size_t len = 0;
    if (psa_hash_compute(alg, crt->raw.p, crt->raw.len, hash, sizeof hash, &len) != PSA_SUCCESS) return 0;
    return ktls_copy_out(hash, len, buf, cap);
}

size_t ktls_end_point(const ktls_session *s, uint8_t *buf, size_t cap)
{
    return ktls_end_point_of(mbedtls_ssl_get_peer_cert(&s->ssl), buf, cap);
}

/* The names a certificate carries, for a caller that compares them itself (libpq's host-name check), as records
   of [kind u8][length u16, big-endian][bytes]: first the subjectAltName dNSName (kind 1) and iPAddress (kind 2)
   entries in the certificate's order, then every subject commonName (kind 3) in the subject's order. Each value
   is its raw bytes: an embedded NUL, a BMPString CN or an IP address of an odd length is the caller's to judge.
   Other SAN kinds (e-mail, URI, …) are left out, as a host-name check ignores them. */
static size_t ktls_names_of(const mbedtls_x509_crt *crt, uint8_t *buf, size_t cap)
{
    if (crt == NULL) return 0;
    size_t total = 0;
    for (int pass = 0; pass < 2; pass++) {
        const mbedtls_x509_sequence *san = pass == 0 ? &crt->subject_alt_names : NULL;
        for (; san != NULL && san->buf.p != NULL; san = san->next) {
            int type = san->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK;
            uint8_t kind = type == MBEDTLS_X509_SAN_DNS_NAME ? 1 : type == MBEDTLS_X509_SAN_IP_ADDRESS ? 2 : 0;
            if (kind == 0 || san->buf.len > 0xFFFF) continue;
            uint8_t head[3] = { kind, (uint8_t)(san->buf.len >> 8), (uint8_t)san->buf.len };
            if (total + 3 + san->buf.len <= cap && buf != NULL) {
                memcpy(buf + total, head, 3);
                memcpy(buf + total + 3, san->buf.p, san->buf.len);
            }
            total += 3 + san->buf.len;
        }
        if (pass == 1) {
            for (const mbedtls_x509_name *n = &crt->subject; n != NULL; n = n->next) {
                if (n->oid.p == NULL || MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &n->oid) != 0 || n->val.len > 0xFFFF) continue;
                uint8_t head[3] = { 3, (uint8_t)(n->val.len >> 8), (uint8_t)n->val.len };
                if (total + 3 + n->val.len <= cap && buf != NULL) {
                    memcpy(buf + total, head, 3);
                    memcpy(buf + total + 3, n->val.p, n->val.len);
                }
                total += 3 + n->val.len;
            }
        }
    }
    return total;
}

size_t ktls_peer_names(const ktls_session *s, uint8_t *buf, size_t cap)
{
    return ktls_names_of(mbedtls_ssl_get_peer_cert(&s->ssl), buf, cap);
}

/* ---- a certificate on its own: parsed from PEM or DER, no session --------------------------------------- */

struct ktls_cert {
    mbedtls_x509_crt crt;
};

ktls_cert *ktls_cert_parse(const uint8_t *data, size_t len, int32_t *err)
{
    *err = 0;
    if (ktls_init() != 0) { *err = KTLS_ERR_INPUT; return NULL; }
    ktls_cert *c = calloc(1, sizeof *c);
    if (c == NULL) { *err = KTLS_ERR_NOMEM; return NULL; }
    mbedtls_x509_crt_init(&c->crt);
    int rc;
    if (ktls_is_pem(data, len)) {
        uint8_t *copy = ktls_terminated(data, len);
        if (copy == NULL) { rc = KTLS_ERR_NOMEM; }
        else { rc = mbedtls_x509_crt_parse(&c->crt, copy, len + 1); free(copy); }
    } else {
        rc = mbedtls_x509_crt_parse_der(&c->crt, data, len);
    }
    /* A PEM bundle answers how many of its certificates did not parse; only the first one is kept, and it must
       be there. */
    if (rc == 0 && c->crt.raw.len == 0) rc = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
    if (rc > 0 && c->crt.raw.len > 0) rc = 0;
    if (rc != 0) {
        *err = rc > 0 ? MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT : rc;
        mbedtls_x509_crt_free(&c->crt);
        free(c);
        return NULL;
    }
    return c;
}

void ktls_cert_free(ktls_cert *c)
{
    if (c == NULL) return;
    mbedtls_x509_crt_free(&c->crt);
    free(c);
}

size_t ktls_cert_der(const ktls_cert *c, uint8_t *buf, size_t cap) { return ktls_copy_out(c->crt.raw.p, c->crt.raw.len, buf, cap); }
size_t ktls_cert_names(const ktls_cert *c, uint8_t *buf, size_t cap) { return ktls_names_of(&c->crt, buf, cap); }
size_t ktls_cert_end_point(const ktls_cert *c, uint8_t *buf, size_t cap) { return ktls_end_point_of(&c->crt, buf, cap); }

size_t ktls_alpn(const ktls_session *s, uint8_t *buf, size_t cap)
{
    const char *p = mbedtls_ssl_get_alpn_protocol(&s->ssl);
    return p == NULL ? 0 : ktls_copy_out(p, strlen(p), buf, cap);
}

size_t ktls_ciphersuite(const ktls_session *s, uint8_t *buf, size_t cap)
{
    const char *p = mbedtls_ssl_get_ciphersuite(&s->ssl);
    return p == NULL ? 0 : ktls_copy_out(p, strlen(p), buf, cap);
}

int32_t ktls_protocol(const ktls_session *s)
{
    if (!mbedtls_ssl_is_handshake_over((mbedtls_ssl_context *)&s->ssl)) return 0;
    return (int32_t)mbedtls_ssl_get_version_number(&s->ssl);
}

/* Every code src/stream.kama and src/config.kama spell as a literal, pinned here: an upgrade that changed
   one fails to compile with the name, rather than misreading an error at run time. */
_Static_assert(KTLS_WANT_READ == -1 && KTLS_CLOSED == -2 && KTLS_TRUNCATED == -7, "stream.kama WANT_READ / CLOSED / TRUNCATED");
_Static_assert(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED == -9984, "stream.kama CERT_VERIFY_FAILED");
_Static_assert(MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE == -30592, "stream.kama FATAL_ALERT");
/* KTLS_BADCERT_NO_CRL must stay clear of every flag Mbed TLS defines. */
_Static_assert((KTLS_BADCERT_NO_CRL & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_CN_MISMATCH |
               MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCRL_NOT_TRUSTED | MBEDTLS_X509_BADCRL_EXPIRED |
               MBEDTLS_X509_BADCERT_MISSING | MBEDTLS_X509_BADCERT_SKIP_VERIFY | MBEDTLS_X509_BADCERT_OTHER |
               MBEDTLS_X509_BADCERT_FUTURE | MBEDTLS_X509_BADCRL_FUTURE | MBEDTLS_X509_BADCERT_KEY_USAGE |
               MBEDTLS_X509_BADCERT_EXT_KEY_USAGE | MBEDTLS_X509_BADCERT_NS_CERT_TYPE | MBEDTLS_X509_BADCERT_BAD_MD |
               MBEDTLS_X509_BADCERT_BAD_PK | MBEDTLS_X509_BADCERT_BAD_KEY | MBEDTLS_X509_BADCRL_BAD_MD |
               MBEDTLS_X509_BADCRL_BAD_PK | MBEDTLS_X509_BADCRL_BAD_KEY)) == 0, "KTLS_BADCERT_NO_CRL collides");
_Static_assert(KTLS_BADCERT_NO_CRL == 0x01000000, "config.kama BADCERT_NO_CRL");
_Static_assert(MBEDTLS_SSL_VERSION_TLS1_2 == 771 && MBEDTLS_SSL_VERSION_TLS1_3 == 772, "TLS version numbers");
_Static_assert(KTLS_ERR_NOMEM == -3 && KTLS_ERR_INPUT == -5 && KTLS_ERR_KEY_MISMATCH == -8, "config.kama error codes");
