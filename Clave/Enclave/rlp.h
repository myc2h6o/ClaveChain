#ifndef _RLP_H_
#define _RLP_H_

struct RLPStringItem {
    unsigned char *str;
    unsigned int length;
};

class RLP {
public:
    static unsigned int encodeArray(unsigned char **output, const RLPStringItem *input, const unsigned int& size);
    static unsigned int encodeString(unsigned char **output, const unsigned char *input, const unsigned int& length);
    static unsigned int encodeLength(unsigned char **output, const unsigned int& offset, const unsigned int& length);
    static unsigned int lengthToHex(unsigned char **hex, unsigned int length);
private:
};

#endif
