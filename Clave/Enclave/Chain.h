#ifndef _CHAIN_H_
#define _CHAIN_H_

#include "RLP.h"

void setRLPStringItem(RLPStringItem * item, char *str, const unsigned int length, bool toBytes = true);
unsigned int generateTransactionData(char **dst, const unsigned long long& id, const char *index, const char *name, const char *phone);

#endif
