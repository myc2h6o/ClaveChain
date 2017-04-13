#include <string.h>
#include "Output.h"
#include "Secret.h"
#include "Enclave_t.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"

#define KEY_SIZE 2048
#define EXPONENT 65537

void ecall_generateKeyPair() {
    int ret;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    const char *pers = "rsa_genkey";

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char *)pers,
        strlen(pers))) != 0)
    {
        oprintf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        return;
    }
    oprintf(" ok\n  . Generating the RSA key [ %d-bit ]...\n", KEY_SIZE);
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
        EXPONENT)) != 0)
    {
        oprintf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n", ret);
        return;
    }
    oprintf("rsa.d: %d\n", rsa.D.p);
}

void generateKeyPair(char** privateKey, char** publicKey) {
    *privateKey = "todo";
    *publicKey = "todo";
}
