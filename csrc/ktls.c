/* The C @kama/tls writes itself. See ktls.h for the model: Mbed TLS reads and writes memory buffers, and kama
   moves the bytes. Nothing here allocates on the hot path except to grow those two buffers. */

/* The RFC 5929 end-point hash needs the certificate's signature hash, which Mbed TLS 4 keeps in a private
   field. This file, and only this file, reads it. */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "ktls.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

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

#define KTLS_MAX_ALPN 8

struct ktls_config {
    atomic_int refs;
    atomic_int frozen;            /* set when the first session is made from it */
    int32_t server;
    int32_t verify;               /* 0 none, 1 chain only, 2 chain and name */
    mbedtls_ssl_config conf;
    mbedtls_x509_crt trust;
    int32_t trust_loaded;
    mbedtls_x509_crt own_cert;
    mbedtls_pk_context own_key;
    int32_t own_loaded;
    char *alpn[KTLS_MAX_ALPN + 1];  /* NULL-terminated, as mbedtls_ssl_conf_alpn_protocols wants */
    int32_t alpn_count;
};

/* Chain-only verification: the chain must still verify, but the certificate's names are not compared with
   the server name (which is still sent, as SNI). Mbed TLS 4 refuses a verifying client with no name at all,
   so the name is set and only its mismatch flag is cleared, on the leaf. */
static int ktls_verify_chain_only(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    (void)ctx; (void)crt;
    if (depth == 0) *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH;
    return 0;
}

static void ktls_config_apply_verify(ktls_config *c)
{
    int authmode = c->verify == 0 ? MBEDTLS_SSL_VERIFY_NONE : MBEDTLS_SSL_VERIFY_REQUIRED;
    mbedtls_ssl_conf_authmode(&c->conf, authmode);
    mbedtls_ssl_conf_verify(&c->conf, (!c->server && c->verify == 1) ? ktls_verify_chain_only : NULL, NULL);
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
    mbedtls_x509_crt_init(&c->own_cert);
    mbedtls_pk_init(&c->own_key);
    if (mbedtls_ssl_config_defaults(&c->conf, c->server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        ktls_config_release(c);
        return NULL;
    }
    ktls_config_apply_verify(c);
    return c;
}

void ktls_config_retain(ktls_config *c) { atomic_fetch_add_explicit(&c->refs, 1, memory_order_relaxed); }

void ktls_config_release(ktls_config *c)
{
    if (c == NULL) return;
    if (atomic_fetch_sub_explicit(&c->refs, 1, memory_order_acq_rel) != 1) return;
    mbedtls_ssl_config_free(&c->conf);
    mbedtls_x509_crt_free(&c->trust);
    mbedtls_x509_crt_free(&c->own_cert);
    mbedtls_pk_free(&c->own_key);
    for (int32_t i = 0; i < c->alpn_count; i++) free(c->alpn[i]);
    free(c);
}

static int ktls_mutable(const ktls_config *c) { return !atomic_load_explicit(&c->frozen, memory_order_acquire); }

int32_t ktls_config_verify(ktls_config *c, int32_t mode)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    if (mode < 0 || mode > 2) return KTLS_ERR_INPUT;
    c->verify = mode;
    ktls_config_apply_verify(c);
    return 0;
}

static void ktls_config_apply_trust(ktls_config *c)
{
    mbedtls_ssl_conf_ca_chain(&c->conf, c->trust_loaded ? &c->trust : NULL, NULL);
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

static int32_t ktls_config_apply_identity(ktls_config *c)
{
    int rc = mbedtls_ssl_conf_own_cert(&c->conf, &c->own_cert, &c->own_key);
    if (rc != 0) return rc;
    c->own_loaded = 1;
    return 0;
}

int32_t ktls_config_identity_files(ktls_config *c, const char *cert, const char *key, const char *password)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    if (c->own_loaded) return KTLS_ERR_INPUT;   /* one identity per configuration */
    int rc = mbedtls_x509_crt_parse_file(&c->own_cert, cert);
    if (rc != 0) return rc < 0 ? rc : KTLS_ERR_INPUT;
    rc = mbedtls_pk_parse_keyfile(&c->own_key, key, (password != NULL && password[0] != 0) ? password : NULL);
    if (rc != 0) return rc;
    return ktls_config_apply_identity(c);
}

int32_t ktls_config_identity_pem(ktls_config *c, const uint8_t *cert, size_t cert_len,
                                 const uint8_t *key, size_t key_len, const uint8_t *password, size_t password_len)
{
    if (!ktls_mutable(c)) return KTLS_ERR_FROZEN;
    if (c->own_loaded) return KTLS_ERR_INPUT;
    uint8_t *cert_z = ktls_terminated(cert, cert_len);
    uint8_t *key_z = ktls_terminated(key, key_len);
    int rc = KTLS_ERR_NOMEM;
    if (cert_z != NULL && key_z != NULL) {
        rc = mbedtls_x509_crt_parse(&c->own_cert, cert_z, cert_len + 1);
        if (rc > 0) rc = KTLS_ERR_INPUT;
        if (rc == 0) rc = mbedtls_pk_parse_key(&c->own_key, key_z, key_len + 1,
                                               password_len > 0 ? password : NULL, password_len);
        if (rc == 0) rc = ktls_config_apply_identity(c);
    }
    if (key_z != NULL) { mbedtls_platform_zeroize(key_z, key_len + 1); free(key_z); }
    free(cert_z);
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
};

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
    if (c->verify != 0 && !c->trust_loaded) { *err = KTLS_ERR_NOTRUST; return NULL; }
    int has_name = server_name != NULL && server_name[0] != 0;
    if (!c->server && c->verify != 0 && !has_name) { *err = KTLS_ERR_INPUT; return NULL; }
    ktls_session *s = calloc(1, sizeof *s);
    if (s == NULL) { *err = KTLS_ERR_NOMEM; return NULL; }
    atomic_store_explicit(&c->frozen, 1, memory_order_release);
    ktls_config_retain(c);
    s->config = c;
    mbedtls_ssl_init(&s->ssl);
    int rc = mbedtls_ssl_setup(&s->ssl, &c->conf);
    /* A client sends its name as SNI and, when it verifies, checks the certificate against it (chain-only
       mode clears just the mismatch). Without a name nothing is verified, and Mbed TLS 4 wants that said. */
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
    ktls_config_release(s->config);
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

int32_t ktls_handshake(ktls_session *s)
{
    int rc = mbedtls_ssl_handshake(&s->ssl);
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return KTLS_WANT_READ;
    return rc;
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

size_t ktls_verify_text(uint32_t flags, uint8_t *buf, size_t cap)
{
    char text[1024];
    int n = mbedtls_x509_crt_verify_info(text, sizeof text, "", flags);
    if (n < 0) n = 0;
    /* One reason per line, each ending in '\n'; turn the separators into "; " and drop the last. */
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == ' ')) n--;
    for (int i = 0; i < n; i++) if (text[i] == '\n') text[i] = ';';
    return ktls_copy_out(text, (size_t)n, buf, cap);
}

size_t ktls_error_text(int32_t code, uint8_t *buf, size_t cap)
{
    static const char nomem[] = "out of memory";
    static const char frozen[] = "the configuration is already in use by a session";
    static const char input[] = "invalid argument";
    static const char notrust[] = "no trust roots to verify the peer against";
    static const char truncated[] = "the connection ended without a TLS close_notify (truncated)";
    switch (code) {
        case KTLS_ERR_NOMEM:   return ktls_copy_out(nomem, sizeof nomem - 1, buf, cap);
        case KTLS_ERR_FROZEN:  return ktls_copy_out(frozen, sizeof frozen - 1, buf, cap);
        case KTLS_ERR_INPUT:   return ktls_copy_out(input, sizeof input - 1, buf, cap);
        case KTLS_ERR_NOTRUST: return ktls_copy_out(notrust, sizeof notrust - 1, buf, cap);
        case KTLS_TRUNCATED:   return ktls_copy_out(truncated, sizeof truncated - 1, buf, cap);
        default: break;
    }
    char text[256];
    mbedtls_strerror(code, text, sizeof text);
    return ktls_copy_out(text, strlen(text), buf, cap);
}

size_t ktls_peer_cert(const ktls_session *s, uint8_t *buf, size_t cap)
{
    const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(&s->ssl);
    if (crt == NULL) return 0;
    return ktls_copy_out(crt->raw.p, crt->raw.len, buf, cap);
}

/* RFC 5929 §4.1: the hash of the server certificate's DER, with the hash function of its signature
   algorithm — except that MD5 and SHA-1 become SHA-256. What SCRAM-SHA-256-PLUS binds a login to. */
size_t ktls_end_point(const ktls_session *s, uint8_t *buf, size_t cap)
{
    const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(&s->ssl);
    if (crt == NULL) return 0;
    psa_algorithm_t alg;
    switch (crt->sig_md) {
        case MBEDTLS_MD_SHA384: alg = PSA_ALG_SHA_384; break;
        case MBEDTLS_MD_SHA512: alg = PSA_ALG_SHA_512; break;
        default:                alg = PSA_ALG_SHA_256; break;   /* SHA-256, SHA-224, SHA-1, MD5 */
    }
    uint8_t hash[PSA_HASH_MAX_SIZE];
    size_t len = 0;
    if (psa_hash_compute(alg, crt->raw.p, crt->raw.len, hash, sizeof hash, &len) != PSA_SUCCESS) return 0;
    return ktls_copy_out(hash, len, buf, cap);
}

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
_Static_assert(KTLS_WANT_READ == -1 && KTLS_CLOSED == -2 && KTLS_TRUNCATED == -7, "stream.kama wantRead / closedByPeer / truncated");
_Static_assert(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED == -9984, "stream.kama CERT_VERIFY_FAILED");
_Static_assert(MBEDTLS_SSL_VERSION_TLS1_2 == 771 && MBEDTLS_SSL_VERSION_TLS1_3 == 772, "TLS version numbers");
_Static_assert(KTLS_ERR_NOMEM == -3 && KTLS_ERR_INPUT == -5, "config.kama error codes");
