/* A raw Mbed TLS client, run against a ktls server session in memory, for ClientHellos the package's own client never
   sends: a TLS 1.3 ticket offered in a TLS 1.2 handshake, and a TLS 1.2 client asking for a ticket. The client reads
   the server's output buffer and feeds its input buffer through ktls.h, as kama's TlsStream does. Built for every
   target (tests/kama.json). */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS   /* a session's version and ticket length */

#include <mbedtls/ssl.h>

#include "ktls.h"
#include "raw_client.h"

static int raw_send(void *ctx, const unsigned char *buf, size_t len)
{
    return ktls_feed(ctx, buf, len) == 0 ? (int)len : MBEDTLS_ERR_SSL_ALLOC_FAILED;
}

static int raw_recv(void *ctx, unsigned char *buf, size_t len)
{
    size_t n = ktls_out_peek(ctx, buf, len);
    if (n == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    ktls_out_consume(ctx, n);
    return (int)n;
}

static ktls_config *raw_server(const char *cert, const char *key)
{
    ktls_config *c = ktls_config_new(1);
    if (c == NULL) return NULL;
    if (ktls_config_identity_files(c, cert, key, NULL) != 0 || ktls_config_session_tickets(c, 3600) != 0) {
        ktls_config_release(c);
        return NULL;
    }
    return c;
}

/* A client configuration that verifies nothing (the server is the subject here) and allows `min` to `max`. */
static int raw_client_conf(mbedtls_ssl_config *conf, mbedtls_ssl_protocol_version min, mbedtls_ssl_protocol_version max)
{
    int rc = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) return rc;
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_min_tls_version(conf, min);
    mbedtls_ssl_conf_max_tls_version(conf, max);
    mbedtls_ssl_conf_session_tickets(conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
    return 0;
}

/* Both handshakes in turn, between `ssl` (set up, with whatever session it offers) and a new server session from `c`.
   With `keep`, the client then reads until the server's TLS 1.3 ticket has been processed and keeps it there. 1 the
   server resumed, 0 a full handshake, 2 a handshake failed, below 0 a broken fixture. */
static int32_t raw_connect(ktls_config *c, mbedtls_ssl_context *ssl, mbedtls_ssl_session *keep)
{
    int32_t err = 0;
    ktls_session *server = ktls_session_new(c, NULL, &err);
    if (server == NULL) return -1;
    mbedtls_ssl_set_bio(ssl, server, raw_send, raw_recv, NULL);
    int client_done = 0, server_done = 0, failed = 0;
    for (int turn = 0; turn < 64 && !(client_done && server_done) && !failed; turn++) {
        if (!client_done) {
            int rc = mbedtls_ssl_handshake(ssl);
            if (rc == 0) client_done = 1;
            else if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) failed = 1;
        }
        if (!server_done && !failed) {
            int32_t rc = ktls_handshake(server);
            if (rc == KTLS_OK) server_done = 1;
            else if (rc != KTLS_WANT_READ) failed = 1;
        }
    }
    int32_t result = failed ? 2 : (client_done && server_done) ? ktls_resumed(server) : -2;
    if (keep != NULL && (result == 0 || result == 1)) {
        result = -3;
        unsigned char buf[16];
        for (int i = 0; i < 8 && result == -3; i++) {
            int rc = mbedtls_ssl_read(ssl, buf, sizeof buf);
            if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) result = mbedtls_ssl_get_session(ssl, keep) == 0 ? 0 : -4;
            else if (rc != MBEDTLS_ERR_SSL_WANT_READ) result = -5;
        }
    }
    ktls_session_free(server);
    return result;
}

int32_t ktls_test_raw_resume(const char *cert, const char *key, int32_t which)
{
    ktls_config *c = raw_server(cert, key);
    if (c == NULL) return -10;
    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_session ticket;
    mbedtls_ssl_session_init(&ticket);
    mbedtls_ssl_context first, second;
    mbedtls_ssl_init(&first);
    mbedtls_ssl_init(&second);
    int32_t result = -11;
    if (raw_client_conf(&conf, MBEDTLS_SSL_VERSION_TLS1_2, MBEDTLS_SSL_VERSION_TLS1_3) == 0 &&
        mbedtls_ssl_setup(&first, &conf) == 0 && mbedtls_ssl_set_hostname(&first, "localhost") == 0) {
        result = raw_connect(c, &first, &ticket);
        if (result == 0 && ticket.tls_version != MBEDTLS_SSL_VERSION_TLS1_3) result = -12;
    }
    if (result == 0) {
        result = -13;
        if (mbedtls_ssl_setup(&second, &conf) == 0 && mbedtls_ssl_set_hostname(&second, "localhost") == 0 &&
            mbedtls_ssl_set_session(&second, &ticket) == 0) {
            /* The ClientHello takes its version from the session offered (ssl_client.c), so this sends the TLS 1.3
               ticket in a TLS 1.2 ClientHello's session_ticket extension. */
            if (which == KTLS_TEST_RAW_AS_TLS12) second.session_negotiate->tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
            result = raw_connect(c, &second, NULL);
        }
    }
    mbedtls_ssl_free(&second);
    mbedtls_ssl_free(&first);
    mbedtls_ssl_session_free(&ticket);
    mbedtls_ssl_config_free(&conf);
    ktls_config_release(c);
    return result;
}

int32_t ktls_test_raw_tls12_ticket(const char *cert, const char *key)
{
    ktls_config *c = raw_server(cert, key);
    if (c == NULL) return -10;
    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_session got;
    mbedtls_ssl_session_init(&got);
    int32_t result = -11;
    if (raw_client_conf(&conf, MBEDTLS_SSL_VERSION_TLS1_2, MBEDTLS_SSL_VERSION_TLS1_2) == 0 &&
        mbedtls_ssl_setup(&ssl, &conf) == 0 && mbedtls_ssl_set_hostname(&ssl, "localhost") == 0) {
        result = raw_connect(c, &ssl, NULL);
        if (result == 0) result = mbedtls_ssl_get_session(&ssl, &got) == 0 ? (int32_t)got.ticket_len : -12;
        else result = -14;
    }
    mbedtls_ssl_session_free(&got);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    ktls_config_release(c);
    return result;
}
