#ifndef KTLS_H
#define KTLS_H
/* The C @kama/tls writes itself: glue only. The TLS is Mbed TLS's, reached through these functions so that
   kama never has to spell an Mbed TLS struct. */
#include <stddef.h>
#include <stdint.h>

/* 0 once the PSA crypto core is initialised (by this call or an earlier one), else the psa_status_t it
   failed with. Cheap after the first call — an acquire load — so every entry point calls it.
   psa_crypto_init() is itself idempotent; the guard only skips it on the hot path. */
int32_t ktls_init(void);

/* The linked Mbed TLS version ("4.1.1"), as the bytes kama's string constructor takes, and a strlen for it. */
const uint8_t *ktls_version(void);
size_t ktls_strlen(const uint8_t *s);

#endif
