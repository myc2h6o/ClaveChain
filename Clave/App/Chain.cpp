#include "Chain.h"

/*
 * getRequests: get pending requests from blockchain
 * return: pending requests, size equals zero when there are no pending requests
 * throw Exception: when failing to reach blockchain server
 */
std::vector<Request> Chain::getRequests() {
    std::vector<Request> result;
    // [TODO] call block chain to get data
    return result;
}


/*
 * callContract: call contract on blockchain
 * signedTransaction: signed transaction for calling contract
 * throw Exception: when failing to call contract
 */
void Chain::callContract(const std::string& signedTransaction) {
    // [TODO] call block chain contract
}
