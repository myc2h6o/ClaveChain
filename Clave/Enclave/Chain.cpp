#include <stdlib.h>
#include "Chain.h"
#include "Enclave_t.h"

void ecall_setContractAddress(const char *address) {

}

#include "Output.h"
void ecall_getSignedTransactionFromRequest(const char *uri, char **result) {
    *result = (char*)malloc(2);
    (*result)[0] = '1';
    (*result)[1] = '\0';
}

