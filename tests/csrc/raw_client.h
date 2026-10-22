#ifndef KTLS_TEST_RAW_CLIENT_H
#define KTLS_TEST_RAW_CLIENT_H
#include <stdint.h>

/* The cases ktls_test_raw_resume runs. Each makes a fresh ktls server configuration holding `cert` and `key`, with
   session tickets on, then a raw Mbed TLS client takes a ticket from it in a full TLS 1.3 handshake and offers it back
   in a second connection. */
#define KTLS_TEST_RAW_CONTROL 0   /* offered as Mbed TLS offers it: TLS 1.3, psk_dhe_ke */
#define KTLS_TEST_RAW_AS_TLS12 1  /* the same TLS 1.3 ticket, offered in a TLS 1.2 ClientHello */

/* What the server made of the second connection: 1 it resumed, 0 a full handshake, 2 the handshake failed, and below
   0 a broken fixture (the first connection did not complete, or no ticket came). */
int32_t ktls_test_raw_resume(const char *cert, const char *key, int32_t which);

/* A raw TLS 1.2 client that asks a ktls server with tickets on for one: the length of the ticket it was sent, or below
   0 for a broken fixture. */
int32_t ktls_test_raw_tls12_ticket(const char *cert, const char *key);

#endif
