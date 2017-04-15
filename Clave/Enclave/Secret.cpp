#include <stdlib.h>
#include <string.h>
#include "Keccak.h"
#include "Output.h"
#include "Secret.h"
#include "Enclave_t.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"

/*
 * Use MBEDTLS_ECP_DP_SECP256K1, private key size is 32 bytes, public key size is 65 bytes (with 0x04 as first byte)
*/

#define ECDSA_TYPE MBEDTLS_ECP_DP_SECP256K1
#define PRIVATE_KEY_BYTE_SIZE 32
#define PUBLIC_KEY_BYTE_SIZE 65
#define ADDRESS_HEX_OFFSET 24

mbedtls_ecdsa_context ecdsaContext;

void printHexFromBytes(unsigned char *buf, size_t len) {
    size_t i;
    unsigned char *outbuf = (unsigned char*)malloc(len * 2 + 1);
    for (i = 0; i < len; i++) {
        outbuf[2 * i] = "0123456789abcdef"[buf[i] >> 4];
        outbuf[2 * i + 1] = "0123456789abcdef"[buf[i] & 15];
    }
    outbuf[2 * len] = 0;
    oprintf("0x%s\n", outbuf);
    free(outbuf);
}

void printPrivateKey() {
    oprintf("Private key:\n");
    unsigned char buf[PRIVATE_KEY_BYTE_SIZE];
    mbedtls_mpi_write_binary(&ecdsaContext.d, buf, PRIVATE_KEY_BYTE_SIZE);
    printHexFromBytes(buf, PRIVATE_KEY_BYTE_SIZE);
}

void printAddress() {
    oprintf("address:\n");
    unsigned char buf[PUBLIC_KEY_BYTE_SIZE];
    size_t len;
    if (mbedtls_ecp_point_write_binary(&ecdsaContext.grp, &ecdsaContext.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf) != 0) {
        oprintf("Secret:printAddress: internal error\n");
        return;
    }
    Keccak keccak;
    keccak.add(buf + 1, PUBLIC_KEY_BYTE_SIZE - 1);
    char *address = keccak.getHash();
    oprintf("0x%s\n", address + ADDRESS_HEX_OFFSET);
    free(address);
}

void ecall_generateKeyPair() {
    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";

    mbedtls_ecdsa_init(&ecdsaContext);       //init ecsda context
    mbedtls_ctr_drbg_init(&ctr_drbg);   //set entropy source
    mbedtls_entropy_init(&entropy);     //random seed

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        oprintf("Secret:ecall_generateKeyPair: fail! mbedtls_ctr_drbg_seed returned %d\n", ret);
        return;
    }

    if ((ret = mbedtls_ecdsa_genkey(&ecdsaContext, ECDSA_TYPE, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        oprintf("Secret:ecall_generateKeyPair: fail! mbedtls_ecdsa_genkey returned %d\n", ret);
        return;
    }

    //clean context
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    //output address
    printAddress();
    // [TODO] remove this in use, output private key only for testing convenience
    printPrivateKey();
}

void ecall_freeKeyPair() {
    mbedtls_ecdsa_free(&ecdsaContext);
}
