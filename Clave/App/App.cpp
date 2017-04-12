#include <iostream>
#include <string>
#include <vector>
#include <time.h>
#include "Chain.h"
#include "Clave.h"

#define MILLI_SECOND_WAIT_TIME 5000

int main() {
    // Initialize enclave
    Clave clave;
    if (clave.init() < 0) {
        std::cout << "Failed to init enclave\n";
        getchar();
        return -1;
    }

    clave.generateKeyPair();
    clave.printPublicInfo();

    //Set middle contract address on blockchain
    std::string address;
    std::string confirmStr = "";
    while (confirmStr != "yes") {
        std::cout << "Input middleman contracct address:" << std::endl;
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
        if (nRequests == 0) {
            Sleep(MILLI_SECOND_WAIT_TIME);
        }
        else {
            for (size_t i = 0; i < nRequests; ++i) {
                signedTransaction = clave.getSignedTransactionFromRequest(requests[i]);
                Chain::callContract(signedTransaction);
            }
        }
    }

    std::cout << "Some Error happened\n";

    // Destroy the enclave
    clave.destroy();
    getchar();
    return 0;
}
