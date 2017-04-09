#ifndef _SECRET_H_
#define _SECRET_H_

#if defined(__cplusplus)
extern "C" {
#endif

    // malloc new space for privateKey and publicKey
    void generateKeyPair(char** privateKey, char** publicKey);

#if defined(__cplusplus)
}
#endif

#endif
