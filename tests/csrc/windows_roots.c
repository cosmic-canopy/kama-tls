/* Certificate stores made in memory, so the tests check which roots the Windows import keeps without touching the
   machine's own stores. Built on Windows only (tests/kama.json). */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <stdlib.h>

#include "ktls.h"
#include "windows_roots.h"

/* Sets the EKU property a store gives `cert`: 1 on success. */
static int ktls_test_set_eku(PCCERT_CONTEXT cert, int32_t eku)
{
    if (eku == KTLS_TEST_EKU_NONE) return 1;
    LPSTR ids[2] = { (LPSTR)szOID_PKIX_KP_CLIENT_AUTH, (LPSTR)szOID_PKIX_KP_SERVER_AUTH };
    CERT_ENHKEY_USAGE usage = { eku == KTLS_TEST_EKU_BOTH ? 2 : eku == KTLS_TEST_EKU_CLIENT ? 1 : 0, ids };
    DWORD size = 0;
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &usage, NULL, &size)) return 0;
    BYTE *encoded = malloc(size);
    if (encoded == NULL) return 0;
    int ok = CryptEncodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &usage, encoded, &size);
    CRYPT_DATA_BLOB blob = { size, encoded };
    if (ok) ok = CertSetCertificateContextProperty(cert, CERT_ENHKEY_USAGE_PROP_ID, 0, &blob);
    free(encoded);
    return ok;
}

int32_t ktls_test_root_verdict(const uint8_t *der, size_t len, int32_t eku, int32_t disallow)
{
    HCERTSTORE roots = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    HCERTSTORE disallowed = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    PCCERT_CONTEXT cert = NULL;
    int32_t rc = -100;
    if (roots != NULL && disallowed != NULL &&
        CertAddEncodedCertificateToStore(roots, X509_ASN_ENCODING, der, (DWORD)len, CERT_STORE_ADD_ALWAYS, &cert)) {
        rc = ktls_test_set_eku(cert, eku) ? 0 : -101;
        if (rc == 0 && disallow != 0 &&
            !CertAddEncodedCertificateToStore(disallowed, X509_ASN_ENCODING, der, (DWORD)len, CERT_STORE_ADD_ALWAYS, NULL)) {
            rc = -102;
        }
        if (rc == 0) rc = ktls_win_root_kept(cert, disallowed);
    }
    if (cert != NULL) CertFreeCertificateContext(cert);
    if (disallowed != NULL) CertCloseStore(disallowed, 0);
    if (roots != NULL) CertCloseStore(roots, 0);
    return rc;
}
