#include <stdlib.h>
#include <string.h>
#include "Chain.h"
#include "Keccak.h"
#include "Net.h"
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

void ecall_getSignedTransactionFromRequest(const char *nonce, unsigned long long id, const char *uri, char *result) {
    // get data
    char *outerData = getDataFromUri(uri);
    if (outerData == NULL) {
        char noDataHint[] = "No outer data";
        int hintLength = strlen(noDataHint);
        outerData = (char*)malloc(hintLength + 1);
        memcpy(outerData, "No outer data", hintLength + 1);
    }

    //get serialized transaction
    char *t_nonce = (char*)malloc(strlen(nonce) + 1);
    memcpy(t_nonce, nonce, strlen(nonce) + 1);
    char t_gasPrice[] = "";
    char t_gasLimit[] = "100000";
    char t_value[] = "";
    char *t_data = NULL;
    int t_dataLength = generateTransactionData(&t_data, id, uri, outerData);
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

    // sign transaction
    char *sigr = NULL;
    char *sigs = NULL;
    char sigv = '\0';
    sign((char*)rlp, rlpLength, &sigr, &sigs, &sigv);

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
    free(outerData);
    free(t_nonce);
    free(t_data);
    free(rlp);
    free(sigr);
    free(sigs);
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

unsigned int generateTransactionData(char **dst, const unsigned long long& id, const char *uri, const char *data) {
    unsigned int uriLength = strlen(uri);
    unsigned int dataLength = strlen(data);
    unsigned int uriPaddedLength = padTo32(uriLength);
    unsigned int dataPaddedLength = padTo32(dataLength);
    unsigned int length = FUNC_BYTE_CODE_SIZE + UINT_256_BYTE_SIZE * 5 + uriPaddedLength + dataPaddedLength;

    // init data to all '0'
    *dst = (char*)malloc(length);
    memset(*dst, 0, length);
    char *pos = *dst;

    // byte code of function Send()
    char funcByteCode[] = { (char)0x88, (char)0x13, (char)0xb4, (char)0x77 };
    memcpy(pos, funcByteCode, 4);
    pos += FUNC_BYTE_CODE_SIZE;

    // id
    setUint64ToBytes(pos + UINT_64_BYTE_OFFSET, id);
    pos += UINT_256_BYTE_SIZE;

    // uri string position
    setUint64ToBytes(pos + UINT_64_BYTE_OFFSET, UINT_256_BYTE_SIZE * 3);
    pos += UINT_256_BYTE_SIZE;

    // data string position
    setUint64ToBytes(pos + UINT_64_BYTE_OFFSET, UINT_256_BYTE_SIZE * 4 + uriPaddedLength);
    pos += UINT_256_BYTE_SIZE;

    // uri string length
    setUint64ToBytes(pos + UINT_64_BYTE_OFFSET, uriLength);
    pos += UINT_256_BYTE_SIZE;

    // uri string
    memcpy(pos, uri, uriLength);
    pos += uriPaddedLength;

    // data string length
    setUint64ToBytes(pos + UINT_64_BYTE_OFFSET, dataLength);
    pos += UINT_256_BYTE_SIZE;

    // data string
    memcpy(pos, data, dataLength);

    return length;
}
