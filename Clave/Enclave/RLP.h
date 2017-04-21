#ifndef _RLP_H_
#define _RLP_H_

struct RLPStringItem {
    char *str;
    unsigned int length;
};

class RLP {
public:
    static void useCapitalLength() { isCapital = true; }
    static void useNonCapitalLength() { isCapital = false; }
    static void encodeArray(char **output, const RLPStringItem *input, const unsigned int& size);
    static void encodeString(char **output, const char *input, const unsigned int& length);
    static void encodeLength(char **output, const int& offset, const unsigned int& length);
    static void lengthToHex(char **hex, unsigned int length);
    static char digitToHex(const int& digit);
private:
    static bool isCapital;
};

#endif
