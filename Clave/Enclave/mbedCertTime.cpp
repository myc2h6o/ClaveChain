#include <string.h>
#include "mbedMktime.h"
#include "sgx_tae_service.h"
#include "mbedtls/x509.h"

#define TIME_ZONE 8
#define SEC_OFFSET (TIME_ZONE * 3600)

sgx_time_source_nonce_t sgxTimeSourceNonce;
sgx_time_source_nonce_t newSgxTimeSourceNonce;

int sgxCurrentTime(sgx_time_t *now)
{
    if (sgx_get_trusted_time(now, &newSgxTimeSourceNonce) != SGX_SUCCESS) {
        return -1;
    }

    // check time source nonce
    if (memcmp(sgxTimeSourceNonce, newSgxTimeSourceNonce, sizeof(sgxTimeSourceNonce))) {
        return -1;
    }

    *now -= SEC_OFFSET;
    return 0;
}

int sgxCheckTime(const sgx_time_t& before, const sgx_time_t& after) {
    if (before < after) {
        return 0;
    }
    return 1;
}

int mbedtls_x509_time_is_past(const mbedtls_x509_time *to) {
    sgx_time_t now;
    if (sgxCurrentTime(&now) != 0) {
        return 1;
    }
    return sgxCheckTime(now, mbedMktime(to));
}

int mbedtls_x509_time_is_future(const mbedtls_x509_time *from) {
    sgx_time_t now;
    if (sgxCurrentTime(&now) != 0) {
        return 1;
    }
    return sgxCheckTime(mbedMktime(from), now);
}
