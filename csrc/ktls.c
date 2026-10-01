#include "ktls.h"

#include <stdatomic.h>
#include <string.h>

#include <mbedtls/version.h>
#include <psa/crypto.h>

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
