/* @kama/tls — this package's departures from Mbed TLS's default configuration (mbedtls/mbedtls_config.h),
   applied on top of it through MBEDTLS_USER_CONFIG_FILE (set in kama.json's cflags). Everything not named
   here is upstream's default: TLS 1.2 and 1.3, client and server, X.509 parsing, ALPN, SNI, session tickets.
   Each change says why. */
#ifndef KTLS_MBEDTLS_USER_CONFIG_H
#define KTLS_MBEDTLS_USER_CONFIG_H

/* Kama does every byte of socket I/O; Mbed TLS only ever sees memory buffers. So neither its socket layer
   nor its timers (which exist for DTLS retransmission) are compiled. */
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C

/* TLS over a stream only. DTLS and everything that exists for it. */
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_COOKIE_C

/* TLS 1.2 renegotiation has a long history of attacks, and nothing this package serves needs it. */
#undef MBEDTLS_SSL_RENEGOTIATION

/* Not used by TLS: PKCS#7 containers, writing certificates and CSRs, and serialising a live session. Test
   certificates come from the openssl CLI (tools/gen-certs.sh). */
#undef MBEDTLS_PKCS7_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_X509_CSR_WRITE_C
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_SSL_CONTEXT_SERIALIZATION

/* Debug logging is a development aid with a real size cost; errors still carry their text (MBEDTLS_ERROR_C). */
#undef MBEDTLS_DEBUG_C

#endif /* KTLS_MBEDTLS_USER_CONFIG_H */
