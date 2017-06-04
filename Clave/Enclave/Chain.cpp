#include <stdlib.h>
#include <string.h>
#include "Chain.h"
#include "env.h"
#include "Keccak.h"
#include "OuterData.h"
#include "Output.h"
#include "RLP.h"
#include "Secret.h"
#include "Enclave_t.h"

#define FUNC_BYTE_CODE_SIZE 4
#define UINT_256_BYTE_SIZE 32
#define UINT_64_BYTE_OFFSET 24
#define UINT_64_BYTE_SIZE 8
#define CONTRACT_ADDRESS_BYTE_SIZE 20
#define SIGNED_TRANSACTION_MAX_SIZE 2048
#define HEX_USER_SIZE 64
#define HASH_PASSWORD_SIZE 32

char contractAddress[CONTRACT_ADDRESS_BYTE_SIZE * 2 + 1];

void printRlp(const unsigned char *rlp, unsigned int length) {
    // check rlp
    for (unsigned int i = 0; i < length; ++i) {
        oprintf("%c", "0123456789abcdef"[rlp[i] >> 4]);
        oprintf("%c", "0123456789abcdef"[rlp[i] & 15]);
    }
    oprintf("\n");
}

void ecall_setContractAddress(const char *address) {
    memcpy(contractAddress, address, CONTRACT_ADDRESS_BYTE_SIZE * 2);
    contractAddress[CONTRACT_ADDRESS_BYTE_SIZE * 2] = '\0';
    convertHexToBytes(contractAddress);
}

void ecall_getSignedTransactionFromRequest(const char *nonce, unsigned long long id, char *hexUser, char *hexEncPassword, char *result) {
    // get data from tusted outer source

#ifdef ENV_TEST
    // after entering enclave
    // before fetching outer source data
    ocall_printTime();
#endif

    char *hashPassword = getHashPasswordFromHexEnc(hexEncPassword);

#ifdef ENV_TEST
    // after fetching outer source data
    // before serializing transaction
    ocall_printTime();
#endif

    //get serialized transaction
    char *t_nonce = (char*)malloc(strlen(nonce) + 1);
    if (strlen(nonce) == 1 && memcmp(nonce, "0", 1) == 0) {
        // nonce is set to empty string if nonce is 0x0
        t_nonce[0] = '\0';
    }
    else {
        memcpy(t_nonce, nonce, strlen(nonce) + 1);
    }
    char t_gasPrice[] = "800000000";  // here is hex format, should be larger than 18shannon (18 * 10**9)
    char t_gasLimit[] = "20000";     // here is hex format, should be large enough
    char t_value[] = "";
    char *t_data = NULL;
    int t_dataLength = generateTransactionData(&t_data, id, hexUser, hashPassword);
    RLPStringItem items[9];
    unsigned char *rlp = NULL;
    unsigned int rlpLength = 0;

    setRLPStringItem(items, t_nonce, (strlen(t_nonce) + 1) / 2);
    setRLPStringItem(items + 1, t_gasPrice, (strlen(t_gasPrice) + 1) / 2);
    setRLPStringItem(items + 2, t_gasLimit, (strlen(t_gasLimit) + 1) / 2);
    setRLPStringItem(items + 3, contractAddress, CONTRACT_ADDRESS_BYTE_SIZE, false);
    setRLPStringItem(items + 4, t_value, (strlen(t_value) + 1) / 2);
    setRLPStringItem(items + 5, t_data, t_dataLength, false);
    rlpLength = RLP::encodeArray(&rlp, items, 6);

#ifdef ENV_TEST
    // after serializing transaction
    // before signing transaction
    ocall_printTime();
#endif

    // sign transaction
    char *sigr = NULL;
    char *sigs = NULL;
    char sigv = '\0';
    sign((char*)rlp, rlpLength, &sigr, &sigs, &sigv);

#ifdef ENV_TEST
    // after signing transaction
    // before serializing signed transaction
    ocall_printTime();
#endif

    // get rlp with signature
    setRLPStringItem(items + 6, &sigv, 1, false);
    setRLPStringItem(items + 7, sigr, SIGNATURE_BYTE_SIZE);
    setRLPStringItem(items + 8, sigs, SIGNATURE_BYTE_SIZE);
    rlpLength = RLP::encodeArray(&rlp, items, 9);

    // output result
    if (rlpLength > SIGNED_TRANSACTION_MAX_SIZE / 2) {
        result[0] = '\0';
    }
    else {
        getHexFromBytes(result, rlp, rlpLength);
        result[2 * rlpLength] = '\0';
    }

    // clean up
    free(hashPassword);
    free(t_nonce);
    free(t_data);
    free(rlp);
    free(sigr);
    free(sigs);

#ifdef ENV_TEST
    // after serializing signed transaction
    // before leaving enclave
    ocall_printTime();
#endif
}


void setRLPStringItem(RLPStringItem * item, char *str, const unsigned int length, bool toBytes) {
    if ((length != 0) && toBytes) {
        convertHexToBytes((char*)str);
    }
    item->str = (unsigned char*)str;
    item->length = length;
}

unsigned int padTo32(const unsigned int v) {
    return (v + 31) / 32 * 32;
}

void setUint64ToBytes(char *dst, unsigned long long u) {
    for (int i = 0; i < UINT_64_BYTE_SIZE; ++i){
        dst[UINT_64_BYTE_SIZE - i - 1] = u & 0xff;
        u >>= 8;
    }
}

unsigned int generateTransactionData(char **dst, const unsigned long long& id, char *hexUser, char *hashPassword) {
    unsigned int length = FUNC_BYTE_CODE_SIZE + UINT_256_BYTE_SIZE + HEX_USER_SIZE / 2 + HASH_PASSWORD_SIZE;

    // init data to all '0'
    *dst = (char*)malloc(length);
    memset(*dst, 0, length);
    char *pos = *dst;

    // byte code of function SendResult()
    char funcByteCode[] = { (char)0xfa, (char)0x1d, (char)0xb1, (char)0xe7 };
    memcpy(pos, funcByteCode, FUNC_BYTE_CODE_SIZE);
    pos += FUNC_BYTE_CODE_SIZE;

    // id
    setUint64ToBytes(pos + UINT_64_BYTE_OFFSET, id);
    pos += UINT_256_BYTE_SIZE;

    // user
    convertHexToBytes(hexUser);
    memcpy(pos, hexUser, HEX_USER_SIZE / 2);
    pos += HEX_USER_SIZE / 2;

    // hash password
    memcpy(pos, hashPassword, HASH_PASSWORD_SIZE);

    return length;
}
