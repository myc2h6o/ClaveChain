//max supported length is 2**32-1(uint32 max) in this implementation
#include "rlp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const unsigned char CHAR_LIMIT = (unsigned char)0x80;
const unsigned int NORMAL_LENGTH = 0x37;
const unsigned int ARRAY_OFFSET = 0xc0;
const unsigned int STRING_OFFSET = 0x80;
const unsigned int LENGTH_ARRAY_MAX_LENGTH = 8;

// return: length of output
// set *output as encoded string
// generate *output using malloc(), *output has no ending '\0'
// set *output to NULL is input is not valid
unsigned int RLP::encodeArray(unsigned char **output, const RLPStringItem *input, const unsigned int& size) {
    if (size == 0) {
        *output = NULL;
        return 0;
    }

    //get encoded string array
    unsigned char **outputHolder = (unsigned char**)malloc(size * sizeof(unsigned char**));
    unsigned int *lengthOfItems = (unsigned int*)malloc(size * sizeof(unsigned int));
    unsigned int length = 0;
    for (unsigned int i = 0; i < size; ++i) {
        lengthOfItems[i] = encodeString(outputHolder + i, input[i].str, input[i].length);
        length += lengthOfItems[i];
    }

    //get encoded total length
    unsigned char *hexLength = NULL;
    int hexLengthSize = encodeLength(&hexLength, ARRAY_OFFSET, length);

    //output length
    *output = (unsigned char*)malloc(hexLengthSize + length);
    memcpy(*output, hexLength, hexLengthSize);
    free(hexLength);

    unsigned int pos = hexLengthSize;
    unsigned int itemLength = 0;
    for (unsigned int i = 0; i < size; ++i) {
        memcpy(*output + pos, outputHolder[i], lengthOfItems[i]);
        pos += lengthOfItems[i];
    }

    //clean
    for (unsigned int i = 0; i < size; ++i) {
        free(outputHolder[i]);
    }
    free(outputHolder);
    return hexLengthSize + length;
}


// return: length of output
// set *output as encoded string
// generate *output using malloc(), *output has no ending '\0'
// set *output to NULL is input is not valid
unsigned int RLP::encodeString(unsigned char **output, const unsigned char *input, const unsigned int& length) {
    *output = NULL;
    if (length == 1 && input[0] < CHAR_LIMIT) {
        *output = (unsigned char*)malloc(1);
        (*output)[0] = input[0];
        return 1;
    }

    unsigned char *hexLength = NULL;
    unsigned int hexLengthSize = encodeLength(&hexLength, STRING_OFFSET, length);
    *output = (unsigned char*)malloc(hexLengthSize + length);
    memcpy(*output, hexLength, hexLengthSize);
    memcpy(*output + hexLengthSize, input, length);
    free(hexLength);
    return hexLengthSize + length;
}

// return: length of output
// offset is ARRAY_OFFSET of STRING_OFFSET
// set *output as the length hex
// generate *output using malloc(), *output has no ending '\0'
unsigned int RLP::encodeLength(unsigned char **output, const unsigned int& offset, const unsigned int& length) {
    if (length <= NORMAL_LENGTH) {
        lengthToHex(output, offset + length);
        return 1;
    }

    // it is sure that length <= MAX_LENGTH(max of unsigned int)
    unsigned char *hexLength = NULL;
    unsigned int hexLengthSize = lengthToHex(&hexLength, length);
    *output = (unsigned char*)malloc(hexLengthSize + 1);
    (*output)[0] = offset + NORMAL_LENGTH + hexLengthSize;
    memcpy(*output + 1, hexLength, hexLengthSize);
    free(hexLength);
    return hexLengthSize + 1;
}

// return: length of hex
// 0x45 -> { 0x45 }
// 0x456 -> { 0x04, 0x56 }
// 0x14002400 -> { 0x14, 0x00, 0x24, 0x00 }
// generate *hex using malloc(), *hex has no ending '\0'
// set *hex to NULL if length is zero
unsigned int RLP::lengthToHex(unsigned char **hex, unsigned int length) {
    if (length == 0) {
        *hex = NULL;
        return 0;
    }

    unsigned char hexHolder[LENGTH_ARRAY_MAX_LENGTH];
    unsigned int count = 0;
    while (length != 0) {
        count++;
        hexHolder[LENGTH_ARRAY_MAX_LENGTH - count] = length & 0xff;
        length >>= 8;
    }
    *hex = (unsigned char*)malloc(count);
    memcpy(*hex, hexHolder + LENGTH_ARRAY_MAX_LENGTH - count, count);
    return count;
}
