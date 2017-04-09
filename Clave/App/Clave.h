#ifndef _CLAVE_H_
#define _CLAVE_H_

#include "Enclave_u.h"
#include "sgx_urts.h"



class Clave {
public:
    int init();
    int destroy() { return sgx_destroy_enclave(global_eid); }
    sgx_status_t printPublicInfo() { return ecall_printPublicInfo(global_eid); }
    sgx_status_t setContractAddress(const char *address) { return ecall_setContractAddress(global_eid, address); }
    sgx_status_t getRequestData(Request req) { return ecall_getRequestData(global_eid, req); }
private:
    sgx_enclave_id_t global_eid = 0;
};

#endif
