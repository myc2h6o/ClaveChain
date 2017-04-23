#ifndef _CLAVE_H_
#define _CLAVE_H_

#include <string>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "Chain.h"

class Clave {
public:
    int init();
    int destroy() { return sgx_destroy_enclave(global_eid); }
    sgx_status_t generateKeyPair() { return ecall_generateKeyPair(global_eid); }
    sgx_status_t freeKeyPair() { return ecall_freeKeyPair(global_eid); }
    sgx_status_t setContractAddress(const char *address) { return ecall_setContractAddress(global_eid, address); }
    std::string getSignedTransactionFromRequest(const Request& req) {
        char *result = NULL;
        sgx_status_t ret = ecall_getSignedTransactionFromRequest(global_eid, req.uri.c_str(), &result);
        return std::string(result);
    }
private:
    sgx_enclave_id_t global_eid = 0;
};

#endif
