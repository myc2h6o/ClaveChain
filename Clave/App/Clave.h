#ifndef _CLAVE_H_
#define _CLAVE_H_

#include <string>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "Chain.h"

#define SIGNED_TRANSACTION_MAX_SIZE 2048

class Clave {
public:
    int init();
    int destroy() { return sgx_destroy_enclave(global_eid); }
    sgx_status_t generateKeyPair() { return ecall_generateKeyPair(global_eid); }
    sgx_status_t freeKeyPair() { return ecall_freeKeyPair(global_eid); }
    sgx_status_t setContractAddress(const char *address) { return ecall_setContractAddress(global_eid, address); }
    sgx_status_t initOuterDataServer(const char *name, const char *port) { return ecall_initOuterDataServer(global_eid, name, port); }
    sgx_status_t destroyOuterDataServer() { return ecall_destroyOuterDataServer(global_eid); }
    std::string getSignedTransactionFromRequest(const std::string& nonce, const Request& req) {
        sgx_status_t ret = ecall_getSignedTransactionFromRequest(global_eid, nonce.c_str(), req.id, req.index.c_str(), eResult);
        std::string result = std::string(eResult);
        return result;
    }
private:
    sgx_enclave_id_t global_eid = 0;
    char eResult[SIGNED_TRANSACTION_MAX_SIZE + 1];
};

#endif
