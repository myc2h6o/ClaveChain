#ifndef _SECRET_H_
#define _SECRET_H_

#define SIGNATURE_BYTE_SIZE 32

void convertHexToBytes(char *hex);
void getHexFromBytes(char *hex, const unsigned char *bytes, const int& byteSize);
int sign(const char *message, const size_t& messageSize, char **sigr, char **sigs, char *sigv);
char *getHashPasswordFromHexEnc(char * hexEncPassword);

#endif
