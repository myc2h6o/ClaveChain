#include <string.h>
#include "Output.h"
#include "Secret.h"
#include "Enclave_t.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"

void dump_buf(const char *title, unsigned char *buf, size_t len) {
    size_t i;
    unsigned char outbuf[129];
    oprintf("%s:\n", title);
    for (i = 0; i < len; i++) {
        outbuf[2 * i] = "0123456789ABCDEF"[buf[i] / 16];
        outbuf[2 * i + 1] = "0123456789ABCDEF"[buf[i] % 16];
    }
    outbuf[2 * i] = 0;
    oprintf("%s\n", outbuf);
}

void dump_address(const char *title, mbedtls_ecdsa_context *key) {
    unsigned char buf[65];
    size_t len;
    if (mbedtls_ecp_point_write_binary(&key->grp, &key->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf) != 0) {
        oprintf("internal error\n");
        return;
    }
    //[TODO] Add sha3
}

void dump_pubkey(const char *title, mbedtls_ecdsa_context *key)
{
    unsigned char buf[65];
    size_t len;
    if (mbedtls_ecp_point_write_binary(&key->grp, &key->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf) != 0) {
        oprintf("internal error\n");
        return;
    }

    dump_buf(title, buf, len-1);
}

void dump_prikey(const char *title, mbedtls_mpi *key) {
    unsigned char buf[33];
    size_t len = 0;
    mbedtls_mpi_write_binary(key, buf, 33);
    dump_buf(title, buf, 32);
}

void ecall_generateKeyPair() {
    int ret;
    mbedtls_ecdsa_context context;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";

    mbedtls_ecdsa_init(&context);       //init ecsda context
    mbedtls_ctr_drbg_init(&ctr_drbg);   //set entropy source
    mbedtls_entropy_init(&entropy);     //random seed

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        oprintf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        return;
    }

    if ((ret = mbedtls_ecdsa_genkey(&context, MBEDTLS_ECP_DP_SECP256K1, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        oprintf(" failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret);
        return;
    }

    oprintf(" ok (key size: %d bits)\n", (int)context.grp.pbits);
    dump_pubkey("Public key: ", &context);
    dump_prikey("Secret Key: ", &context.d);
    // Note: address use hash of binary
    dump_address("Address: ", &context);

    //clean context
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void generateKeyPair(char** privateKey, char** publicKey) {
    *privateKey = "todo";
    *publicKey = "todo";
}
