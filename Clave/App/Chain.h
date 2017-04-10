#ifndef _CHAIN_H_
#define _CHAIN_H_

#include <vector>
#include "Enclave_u.h"

class Chain {
public:
    static std::vector<Request> getRequests();
    static void callContract(const std::string& signedTransaction);
private:
};

#endif
