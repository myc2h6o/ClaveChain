#include <stdlib.h>
#include <string.h>
#include "Chain.h"
#include "Keccak.h"
#include "Net.h"
#include "Output.h"
#include "RLP.h"
#include "Secret.h"
#include "Enclave_t.h"

#define CONTRACT_ADDRESS_BYTE_SIZE 20
#define SIGNED_TRANSACTION_MAX_SIZE 2048

char contractAddress[CONTRACT_ADDRESS_BYTE_SIZE * 2];

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
    convertHexToBytes(contractAddress);
}

void ecall_getSignedTransactionFromRequest(const char *nonce, const char *uri, char *result) {
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
    char t_data[] = "f47f3aecb83e3a75f67420571b3d52ae26c64489376e4e3700000000000000000000000001234567000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000d6162636465666768696a6b6c6d00000000000000000000000000000000000000";
    RLPStringItem items[9];
    unsigned char *rlp = NULL;
    unsigned int rlpLength = 0;

    setRLPStringItem(items, t_nonce, (strlen(t_nonce) + 1) / 2);
    setRLPStringItem(items + 1, t_gasPrice, (strlen(t_gasPrice) + 1) / 2);
    setRLPStringItem(items + 2, t_gasLimit, (strlen(t_gasLimit) + 1) / 2);
    setRLPStringItem(items + 3, contractAddress, CONTRACT_ADDRESS_BYTE_SIZE, false);
    setRLPStringItem(items + 4, t_value, (strlen(t_value) + 1) / 2);
    setRLPStringItem(items + 5, t_data, (strlen(t_data) + 1) / 2);
    rlpLength = RLP::encodeArray(&rlp, items, 6);

    // sign transaction
    char *sigr = NULL;
    char *sigs = NULL;
    char sigv = '\0';
    sign((char*)rlp, rlpLength, &sigr, &sigs, &sigv);

    // get rlp with signature
    setRLPStringItem(items + 6, sigr, SIGNATURE_BYTE_SIZE);
    setRLPStringItem(items + 7, sigs, SIGNATURE_BYTE_SIZE);
    setRLPStringItem(items + 8, &sigv, 1, false);
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
    free(rlp);
    free(sigr);
    free(sigs);
}


void setRLPStringItem(RLPStringItem * item, char *str, const unsigned long long length, bool toBytes) {
    if ((length != 0) && toBytes) {
        convertHexToBytes((char*)str);
    }
    item->str = (unsigned char*)str;
    item->length = length;
}
