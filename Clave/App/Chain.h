#ifndef _CHAIN_H_
#define _CHAIN_H_

#include <vector>
#include "Enclave_u.h"

class Chain {
public:
    std::vector<Request> getRequests();
    void callRequest(const Request&);
private:

};

#endif
