#ifndef _CHAIN_H_
#define _CHAIN_H_

#include "RLP.h"

void setRLPStringItem(RLPStringItem * item, char *str, const unsigned int length, bool toBytes = true);
unsigned int generateTransactionData(char **dst, const unsigned long long& id, char *hexUser, char *hashPassword);

#endif
