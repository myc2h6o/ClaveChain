#include <stdlib.h>
#include <string.h>
#include "Keccak.h"
#include "Output.h"
#include "Secret.h"
#include "Enclave_t.h"
#include "sgx_trts.h"
#include "env.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/rsa.h"
#include "mbedTlsSgxSignV.h"


/*
 * Use MBEDTLS_ECP_DP_SECP256K1, private key size is 32 bytes, public key size is 65 bytes (with 0x04 as first byte)
*/

#define ECDSA_TYPE MBEDTLS_ECP_DP_SECP256K1
#define PRIVATE_KEY_BYTE_SIZE 32
#define PUBLIC_KEY_BYTE_SIZE 64
#define ADDRESS_HEX_OFFSET 24
#define SIGNATURE_HEX_SIZE 64
#define RSA_KEY_SIZE 2048
#define RSA_EXPONENT 65537
#define HEX_ENC_PWD_SIZE 512
#define NONCE_LENGTH  16
#define SALT_LENGTH NONCE_LENGTH
#define MAX_PASSWORD_SIZE 80

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ecdsa_context ecdsaContext;
mbedtls_rsa_context rsaContext;
unsigned char salt[SALT_LENGTH];

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
    if (len == 0) {
        return;
    }

    if (len % 2 == 0) {
        for (size_t i = 0; i < len; i += 2) {
            int high = HexToNumber(hex[i]);
            int low = HexToNumber(hex[i + 1]);
            hex[i >> 1] = (high << 4) | low;
        }
    }
    else {
        hex[0] = HexToNumber(hex[0]);
        for (size_t i = 1; i < len; i += 2) {
            int high = HexToNumber(hex[i]);
            int low = HexToNumber(hex[i + 1]);
            hex[(i >> 1) + 1] = (high << 4) | low;
        }
    }
}

void getHexFromBytes(char *hex, const unsigned char *bytes, const int& byteSize) {
    for (int i = 0; i < byteSize; ++i) {
        hex[i * 2] = "0123456789abcdef"[bytes[i] >> 4];
        hex[i * 2 + 1] = "0123456789abcdef"[bytes[i] & 15];
    }
}

void printHexFromBytes(unsigned char *buf, size_t len, bool withPrefix = true) {
    char *outbuf = (char*)malloc(len * 2 + 1);
    getHexFromBytes(outbuf, buf, len);
    outbuf[2 * len] = 0;
    if (withPrefix) {
        oprintf("0x");
    }

    oprintf("%s\n", outbuf);
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

void printRsaPublicKey() {
    oprintf("rsa public key:\n");
    const int size = RSA_KEY_SIZE / 8;
    unsigned char buf[size];
    mbedtls_mpi_write_binary(&rsaContext.N, buf, size);
    oprintf("N = ");
    printHexFromBytes(buf, size, false);
    oprintf("E = %x\n", RSA_EXPONENT);
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
    uint8_t v;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    *sigr = (char*)malloc(SIGNATURE_HEX_SIZE + 1);
    *sigs = (char*)malloc(SIGNATURE_HEX_SIZE + 1);

    int ret = 1;
    while (ret != 0) {
        ret = win32_mbedtls_ecdsa_sign_with_v(&ecdsaContext.grp, &r, &s, &v, &ecdsaContext.d, (unsigned char*)hash, hashSize, mbedtls_ctr_drbg_random, &ctr_drbg);
        *sigv = v;
        unsigned char sigBytes[SIGNATURE_BYTE_SIZE];
        mbedtls_mpi_write_binary(&r, sigBytes, SIGNATURE_BYTE_SIZE);
        getHexFromBytes(*sigr, sigBytes, SIGNATURE_BYTE_SIZE);
        (*sigr)[SIGNATURE_HEX_SIZE] = '\0';
        mbedtls_mpi_write_binary(&s, sigBytes, SIGNATURE_BYTE_SIZE);
        getHexFromBytes(*sigs, sigBytes, SIGNATURE_BYTE_SIZE);
        (*sigs)[SIGNATURE_HEX_SIZE] = '\0';

        // signature start with zero byte is not allowed
        if (((*sigr)[0] == '0' && (*sigr)[1] == '0') || ((*sigs)[0] == '0' && (*sigs)[1] == '0')) {
            ret = 1;
        }
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

    // RSA
    mbedtls_rsa_init(&rsaContext, MBEDTLS_RSA_PKCS_V15, 0);
    if ((ret = mbedtls_rsa_gen_key(&rsaContext, mbedtls_ctr_drbg_random, &ctr_drbg, RSA_KEY_SIZE, RSA_EXPONENT)) != 0) {
        oprintf("Secret:ecall_generateKeyPair: fail! mbedtls_rsa_gen_key returned %d\n", ret);
        return;
    }

    // salt
    sgx_read_rand(salt, SALT_LENGTH);
#ifdef ENV_TEST
    oprintf("salt: ");
    printHexFromBytes(salt, SALT_LENGTH);
#endif

    //output rsa public key
    printRsaPublicKey();

    //output address
    printAddress();

#ifdef ENV_TEST
    printPrivateKey();
#endif
}

char *getHexHashPasswordFromHexEnc(char * hexEncPassword) {
    // generate password with salt
    unsigned char password[MAX_PASSWORD_SIZE];
    size_t length;
    mbedtls_rsa_pkcs1_decrypt(&rsaContext, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &length, (unsigned char*)hexEncPassword, (unsigned char*)password, MAX_PASSWORD_SIZE);
    memcpy(password, salt, SALT_LENGTH);

    // generate hash salt password
    Keccak keccak;
    keccak.add(password, length);
    return keccak.getHash();
}

void ecall_freeKeyPair() {
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecdsa_free(&ecdsaContext);
    mbedtls_rsa_free(&rsaContext);
}
