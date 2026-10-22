#ifndef KTLS_TEST_WINDOWS_ROOTS_H
#define KTLS_TEST_WINDOWS_ROOTS_H
#include <stddef.h>
#include <stdint.h>

/* The usages a store's EKU property gives a certificate, beside whatever its own EKU extension says. */
#define KTLS_TEST_EKU_NONE   0   /* no property */
#define KTLS_TEST_EKU_CLIENT 1   /* clientAuth alone */
#define KTLS_TEST_EKU_BOTH   2   /* clientAuth and serverAuth */
#define KTLS_TEST_EKU_EMPTY  3   /* an empty list: the certificate is turned off for every purpose */

/* Whether the Windows root import (ktls_win_root_kept) keeps the DER certificate `der`, put in a ROOT store made in
   memory with the EKU property `eku`, and also in a Disallowed store when `disallow` is not 0: 1 kept, 0 skipped, and
   -100 or below when the stores could not be built. */
int32_t ktls_test_root_verdict(const uint8_t *der, size_t len, int32_t eku, int32_t disallow);

#endif
