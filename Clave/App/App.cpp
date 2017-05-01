#include <iostream>
#include <string>
#include <vector>
#include <time.h>
#include "Chain.h"
#include "Clave.h"

#define MILLI_SECOND_WAIT_TIME 5000
#define HOST "http://localhost:8545"

int main() {
    // Initialize enclave
    Clave clave;
    if (clave.init() < 0) {
        std::cout << "Failed to init enclave\n";
        getchar();
        return -1;
    }

    clave.generateKeyPair();

    //Set middle contract address on blockchain
    std::string address;
    std::string confirmStr = "";
    while (confirmStr != "yes") {
        std::cout << "Input middleman contract address(without 0x and quote sign):" << std::endl;
        std::cin >> address;
        std::cout << "Is this the correct middleman contract address:" << std::endl << address << std::endl;
        std::cout << "(Input yes to confirm, other to reinput):";
        std::cin >> confirmStr;
        getchar();
    }

    if (clave.setContractAddress(address.c_str()) < 0) {
        std::cout << "Failed to set contract address\n";
        getchar();
        return -1;
    }

    // Initialize chain
    Chain::init(HOST, address);

    // Main loop
    std::cout << "Start main loop\n";
    size_t nRequests = 0;
    std::string signedTransaction = "";
    while (1) {
        std::vector<Request> requests = Chain::getRequests();
        nRequests = requests.size();
        std::cout << "Got " << nRequests << " request(s)" << std::endl;
        if (nRequests == 0) {
            Sleep(MILLI_SECOND_WAIT_TIME);
        }
        else {
            for (size_t i = 0; i < nRequests; ++i) {
                // output requests
                std::cout << (requests[i].isDone ? "done   " : "undone ") << requests[i].index << std::endl;
                if (requests[i].isDone) {
                    Chain::increaseId();
                    continue;
                }

                bool fail = false;
                // get data and send result
                while (1) {
                    signedTransaction = clave.getSignedTransactionFromRequest(Chain::getHexNonce(), requests[i]);
                    if (signedTransaction.empty()) {
                        // data or uri too large
                        Chain::increaseId();
                        break;
                    }
                    T_CallContract ret = Chain::callContract(signedTransaction);
                    if (ret == CALL_CONTRACT_OK) {
                        Chain::increaseId();
                        Chain::increaseNonce();
                        break;
                    }
                    else if (ret == CALL_CONTRACT_NONCE_TOO_LOW) {
                        Chain::increaseNonce();
                    }
                    else if (ret == CALL_CONTRACT_FAIL) {
                        fail = true;
                        break;
                    }
                }
                if (fail) {
                    break;
                }
            }
        }
    }

    std::cout << "Some Error happened\n";

    // Destroy the enclave
    clave.freeKeyPair();
    clave.destroy();

    // Destroy chain
    Chain::destroy();

    getchar();
    return 0;
}
