/* @kama/tls — this package's departures from TF-PSA-Crypto's default configuration (psa/crypto_config.h),
   applied on top of it through TF_PSA_CRYPTO_USER_CONFIG_FILE (set in kama.json's cflags). Everything not
   named here is upstream's default. Each change says why. */
#ifndef KTLS_CRYPTO_USER_CONFIG_H
#define KTLS_CRYPTO_USER_CONFIG_H

/* No persistent key storage. Keys live in memory for the life of a session; psa_its_file.c would otherwise
   write key files into the process's current directory. */
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C

/* Isolates are OS threads, and the PSA core holds process-wide state (the key slots, the DRBG). Windows
   needs MBEDTLS_THREADING_ALT with its own mutexes; until that lands, Windows is not a supported target. */
#if !defined(_WIN32)
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD
#endif

/* The self-tests certify a build; running one is not this package's job. */
#undef MBEDTLS_SELF_TEST

/* tools/vendor-mbedtls.sh does not vendor the three optional drivers. Refuse a build that turns one on,
   rather than failing later on a missing header. */
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED) || defined(MBEDTLS_PSA_P256M_DRIVER_ENABLED) || \
    defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)
#error "@kama/tls does not vendor the everest, p256-m or pqcp drivers (see tools/vendor-mbedtls.sh)"
#endif

#endif /* KTLS_CRYPTO_USER_CONFIG_H */
