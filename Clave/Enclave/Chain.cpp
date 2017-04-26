#include <stdlib.h>
#include <string.h>
#include "Chain.h"
#include "Keccak.h"
#include "Net.h"
#include "Output.h"
#include "RLP.h"
#include "Secret.h"
#include "Enclave_t.h"

#define CONTRACT_ADDRESS_SIZE 40
#define SIGNED_TRANSACTION_MAX_SIZE 2048

char contractAddress[CONTRACT_ADDRESS_SIZE + 1];

void printRlp(const unsigned char *rlp, unsigned int length) {
    // check rlp
    for (int i = 0; i < length; ++i) {
        oprintf("%c", "0123456789abcdef"[rlp[i] >> 4]);
        oprintf("%c", "0123456789abcdef"[rlp[i] & 15]);
    }
    oprintf("\n");
}

void ecall_setContractAddress(const char *address) {
    memcpy(contractAddress, address, CONTRACT_ADDRESS_SIZE);
    contractAddress[CONTRACT_ADDRESS_SIZE] = '\0';
}

void ecall_getSignedTransactionFromRequest(const char *uri, char *result) {
    // get data
    char *data = getDataFromUri(uri);
    if (data == NULL) {
        data = (char*)malloc(1);
        data[0] = '\0';
    }

    //get serialized transaction
    unsigned char t_nonce[] = "01";
    unsigned char t_gasPrice[] = "";
    unsigned char t_gasLimit[] = "100000";
    unsigned char t_addr[] = "9126f3fc2b6a5c554ffda1d7ae231092ad74ffb0";
    unsigned char t_value[] = "";
    unsigned char t_data[] = "f47f3aecb83e3a75f67420571b3d52ae26c64489376e4e3700000000000000000000000001234567000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000d6162636465666768696a6b6c6d00000000000000000000000000000000000000";
    RLPStringItem items[6];

    convertHexToBytes((char*)t_nonce);
    convertHexToBytes((char*)t_gasLimit);
    convertHexToBytes((char*)t_addr);
    convertHexToBytes((char*)t_data);
    items[0].str = t_nonce;
    items[0].length = 1;
    items[1].str = t_gasPrice;
    items[1].length = 0;
    items[2].str = t_gasLimit;
    items[2].length = 3;
    items[3].str = t_addr;
    items[3].length = 20;
    items[4].str = t_value;
    items[4].length = 0;
    items[5].str = t_data;
    items[5].length = 164;
    unsigned char *rlp = NULL;
    unsigned int length = RLP::encodeArray(&rlp, items, 6);

    // sign transaction
    char *sigr = NULL;
    char *sigs = NULL;
    char sigv;
    sign((char*)rlp, length, &sigr, &sigs, &sigv);

    // get rlp with signature
    convertHexToBytes(sigr);
    convertHexToBytes(sigs);
    items[6].str = (unsigned char*)sigr;
    items[6].length = SIGNATURE_BYTE_SIZE;
    items[7].str = (unsigned char*)sigs;
    items[7].length = SIGNATURE_BYTE_SIZE;
    items[8].str = (unsigned char*)&sigv;
    items[8].length = 1;
    length = RLP::encodeArray(&rlp, items, 9);

    // output result
    if (length > SIGNED_TRANSACTION_MAX_SIZE / 2) {
        result[0] = '\0';
    }
    else {
        getHexFromBytes(result, rlp, length);
        result[2 * length] = '\0';
    }

    // clean up
    free(data);
    free(rlp);
    free(sigr);
    free(sigs);
}
