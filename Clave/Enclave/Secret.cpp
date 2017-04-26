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
#define PUBLIC_KEY_BYTE_SIZE 64
#define ADDRESS_HEX_OFFSET 24
#define SIGNATURE_HEX_SIZE 64

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ecdsa_context ecdsaContext;

int HexToNumber(const char& x) {
    if (x >= '0' && x <= '9') {
        return x - '0';
    }
    else if (x >= 'a' && x <= 'f') {
        return x - 'a' + 10;
    }
    else if (x >= 'A' && x <= 'F') {
        return x - 'A' + 10;
    }
    else {
        return -1;
    }
}

void convertHexToBytes(char *hex) {
    if (hex == NULL) {
        return;
    }

    size_t len = strlen(hex);
    if (len % 2 == 0) {
        for (size_t i = 0; i < len; i += 2) {
            int high = HexToNumber(hex[i]);
            int low = HexToNumber(hex[i + 1]);
            hex[i >> 1] = (high << 4) | low;
        }
        hex[len >> 1] = '\0';
    }
    else {
        hex[0] = HexToNumber(hex[0]);
        for (size_t i = 1; i < len; i += 2) {
            int high = HexToNumber(hex[i]);
            int low = HexToNumber(hex[i + 1]);
            hex[(i >> 1) + 1] = (high << 4) | low;
        }
        hex[(len >> 1) + 1] = '\0';
    }
}

void getHexFromBytes(char *hex, const unsigned char *bytes, const int& byteSize) {
    for (int i = 0; i < byteSize; ++i) {
        hex[i * 2] = "0123456789abcdef"[bytes[i] >> 4];
        hex[i * 2 + 1] = "0123456789abcdef"[bytes[i] & 15];
    }
}

void printHexFromBytes(unsigned char *buf, size_t len) {
    char *outbuf = (char*)malloc(len * 2 + 1);
    getHexFromBytes(outbuf, buf, len);
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
    unsigned char buf[PUBLIC_KEY_BYTE_SIZE + 1];
    size_t len;
    if (mbedtls_ecp_point_write_binary(&ecdsaContext.grp, &ecdsaContext.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf) != 0) {
        oprintf("Secret:printAddress: internal error\n");
        return;
    }

    Keccak keccak;
    keccak.add(buf + 1, PUBLIC_KEY_BYTE_SIZE);
    char *address = keccak.getHash();
    oprintf("0x%s\n", address + ADDRESS_HEX_OFFSET);
    free(address);
}

/*
 * Sign a message
 * input param:
 *   message: raw message to be signed
 *   messageSize: size of the message
 * output param:
 *   sigr,sigs: secp256k1 signature, 65(including the end '\0')bytes hex formed c string malloced by malloc()
 *   sigv: recovery byte, 0x1b or 0x1c
 * return:
 *   0 if succeed
 */
int sign(const char *message, const size_t& messageSize, char **sigr, char **sigs, char *sigv) {
    Keccak keccak;
    keccak.add(message, messageSize);
    char *hash = keccak.getHash();
    size_t hashSize = strlen(hash) / 2;
    convertHexToBytes(hash);
    mbedtls_mpi_uint v; // mbedtls_ecdsa_sign_bitcoin will transform char *v into mbedtls_mpi_uint*, so make it a mbedtls_mpi_uint here
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    int ret = mbedtls_ecdsa_sign_bitcoin(&ecdsaContext.grp, &r, &s, (char*)&v, &ecdsaContext.d, (unsigned char*)hash, hashSize, MBEDTLS_MD_SHA256);
    if (ret == 0) {
        *sigv = v;
        unsigned char sigBytes[SIGNATURE_BYTE_SIZE];
        *sigr = (char*)malloc(SIGNATURE_HEX_SIZE + 1);
        mbedtls_mpi_write_binary(&r, sigBytes, SIGNATURE_BYTE_SIZE);
        getHexFromBytes(*sigr, sigBytes, SIGNATURE_BYTE_SIZE);
        (*sigr)[SIGNATURE_HEX_SIZE] = '\0';
        *sigs = (char*)malloc(SIGNATURE_HEX_SIZE + 1);
        mbedtls_mpi_write_binary(&s, sigBytes, SIGNATURE_BYTE_SIZE);
        getHexFromBytes(*sigs, sigBytes, SIGNATURE_BYTE_SIZE);
        (*sigs)[SIGNATURE_HEX_SIZE] = '\0';
    }

    free(hash);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ret;
}

void ecall_generateKeyPair() {
    int ret;
    const char *pers = "ecdsa";

    mbedtls_ecdsa_init(&ecdsaContext);  //init ecsda context
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

    //output address
    printAddress();
    // [TODO] remove output of private key and test signature in use, output private key only for testing convenience
    printPrivateKey();
    char *sigr = NULL;
    char *sigs = NULL;
    char sigv = 0;
    if (sign("hello world", 11, &sigr, &sigs, &sigv) != 0) {
        oprintf("sign failed\n");
        return;
    }
    oprintf("r:%s\n", sigr);
    oprintf("s:%s\n", sigs);
    oprintf("v:%x\n", sigv);
    free(sigr);
    free(sigs);
}

void ecall_freeKeyPair() {
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecdsa_free(&ecdsaContext);
}
