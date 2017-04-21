//max supported length is 2**32-1(uint32 max) in this implementation
#include "rlp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEX_BYTES_CAPITAL "0123456789ABCDEF"
#define HEX_BYTES_NON_CAPITAL "0123456789abcdef"

const char CHAR_LIMIT = (char)0x80;
const int NORMAL_LENGTH = 0x37;
const int ARRAY_OFFSET = 0xc0;
const int STRING_OFFSET = 0x80;
const int LENGTH_ARRAY_MAX_LENGTH = 16;

bool RLP::isCapital = false;

// set *output as encoded string
// generate *output using malloc(), *output is ended by '\0'
// set *output to NULL is input is not valid
void RLP::encodeArray(char **output, const RLPStringItem *input, const unsigned int& size) {
    //get encoded string array
    char **outputHolder = (char**)malloc(size * sizeof(char**));
    unsigned int length = 0;
    for (unsigned int i = 0; i < size; ++i) {
        encodeString(outputHolder + i, input[i].str, input[i].length);
        length += strlen(outputHolder[i]);
    }

    //get encoded total length
    char *hexLength = NULL;
    encodeLength(&hexLength, ARRAY_OFFSET, length);
    int hexLengthSize = strlen(hexLength);

    //output length
    *output = (char*)malloc(hexLengthSize + length + 1);
    memcpy(*output, hexLength, hexLengthSize);
    free(hexLength);

    unsigned int pos = hexLengthSize;
    unsigned int itemLength = 0;
    for (unsigned int i = 0; i < size; ++i) {
        itemLength = strlen(outputHolder[i]);
        memcpy(*output + pos, outputHolder[i], itemLength);
        pos += itemLength;
    }
    (*output)[hexLengthSize + length] = '\0';
    free(outputHolder);
}


// set *output as encoded string
// generate *output using malloc(), *output is ended by '\0'
// set *output to NULL is input is not valid
void RLP::encodeString(char **output, const char *input, const unsigned int& length) {
    *output = NULL;
    if (length == 1 && input[0] < CHAR_LIMIT) {
        *output = (char*)malloc(1);
        (*output)[0] = input[0];
    }
    else {
        char *hexLength = NULL;
        encodeLength(&hexLength, STRING_OFFSET, length);
        int hexLengthSize = strlen(hexLength);

        *output = (char*)malloc(hexLengthSize + length + 1);
        memcpy(*output, hexLength, hexLengthSize);
        memcpy(*output + hexLengthSize, input, length);
        (*output)[hexLengthSize + length] = '\0';
        free(hexLength);
    }
}

// set *output as the length hex
// generate *output using malloc(), *output is ended by '\0'
void RLP::encodeLength(char **output, const int& offset, const unsigned int& length) {
    if (length <= NORMAL_LENGTH) {
        *output = (char*)malloc(1);
        (*output)[0] = offset + (unsigned int)length;
    }
    else{
        // it is sure that length <= MAX_LENGTH(max of unsigned int)
        char *hexLength = NULL;
        lengthToHex(&hexLength, length);
        int hexLengthSize = strlen(hexLength);
        int lengthOfLength = hexLengthSize / 2;
        *output = (char*)malloc(hexLengthSize + 2);
        (*output)[0] = offset + NORMAL_LENGTH + lengthOfLength;
        memcpy(*output + 1, hexLength, hexLengthSize + 1);
        free(hexLength);
    }
}

// 0x456 -> "0456"
// generate *hex using malloc(), *hex is ended by '\0'
// set *hex to NULL if length is zero
void RLP::lengthToHex(char **hex, unsigned int length) {
    if (length == 0) {
        *hex = NULL;
        return;
    }

    char hexHolder[LENGTH_ARRAY_MAX_LENGTH];
    int count = 0;
    while (length != 0) {
        count++;
        hexHolder[LENGTH_ARRAY_MAX_LENGTH - count] = digitToHex((unsigned int)length & 0xf);
        length >>= 4;
    }
    if (count % 2) {
        count++;
        hexHolder[LENGTH_ARRAY_MAX_LENGTH - count] = '0';
    }
    *hex = (char*)malloc(count + 1);
    memcpy(*hex, hexHolder + LENGTH_ARRAY_MAX_LENGTH - count, count);
    (*hex)[count] = '\0';
}

// 0x0~0xF -> '0'~'F'
char RLP::digitToHex(const int& digit) {
    if (isCapital) {
        return HEX_BYTES_CAPITAL[digit];
    }
    else {
        return HEX_BYTES_NON_CAPITAL[digit];
    }
}
