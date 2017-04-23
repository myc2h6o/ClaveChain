#include <iostream>
#include <string>
#include <vector>
#include <time.h>
#include "Chain.h"
#include "Clave.h"

#define MILLI_SECOND_WAIT_TIME 5000

int main() {
    // Initialize chain
    Chain::init();

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
        std::cout << "Input middleman contract address:" << std::endl;
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
                for (size_t i = 0; i < requests.size(); ++i) {
                    std::cout << (requests[i].isDone ? "done   " : "undone ") << requests[i].uri << std::endl;
                }

                // get data and send result
                if (!requests[i].isDone) {
                    signedTransaction = clave.getSignedTransactionFromRequest(requests[i]);
                    if (Chain::callContract(signedTransaction) == 0) {
                        Chain::increaseId();
                    }
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
