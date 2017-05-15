#include <iostream>
#include <string>
#include <vector>
#include "Chain.h"
#include "Clave.h"

#ifdef _WIN32
#else
#include "unistd.h"
#endif

#define MILLI_SECOND_WAIT_TIME 5000
#define GETH_ADDRESS "http://localhost:8545"
#define OUTER_SERVER_NAME "localhost"
#define OUTER_SERVER_PORT "4433"

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

    // Set contract address in clave
    if (clave.setContractAddress(address.c_str()) < 0) {
        std::cout << "Failed to set contract address\n";
        getchar();
        return -1;
    }
    // Initialize outer data server in clave
    if (clave.initOuterDataServer(OUTER_SERVER_NAME, OUTER_SERVER_PORT) < 0) {
        std::cout << "Failed to init outer data server\n";
        getchar();
        return -1;
    }

    // Initialize chain
    Chain::init(GETH_ADDRESS, address);

    // Main loop
    std::cout << "Start main loop\n";
    size_t nRequests = 0;
    std::string signedTransaction = "";
    while (1) {
        std::vector<Request> requests = Chain::getRequests();
        nRequests = requests.size();
        std::cout << "Got " << nRequests << " request(s)" << std::endl;
        if (nRequests == 0) {
#ifdef _WIN32
            Sleep(MILLI_SECOND_WAIT_TIME);
#else
            sleep(MILLI_SECOND_WAIT_TIME / 1000);
#endif
        }
        else {
            for (size_t i = 0; i < nRequests; ++i) {
                // output requests
                std::cout << (requests[i].isDone ? "done   " : "undone ") << requests[i].id << std::endl;
                if (requests[i].isDone) {
                    Chain::increaseId();
                    continue;
                }

                bool fail = false;
                // get data and send result
                while (1) {
                    signedTransaction = clave.getSignedTransactionFromRequest(Chain::getHexNonce(), requests[i]);
                    if (signedTransaction.empty()) {
                        // cannot connect to outer data server
                        std::cout << "Cannot connect to outer data server" << std::endl;
#ifdef _WIN32
                        Sleep(MILLI_SECOND_WAIT_TIME);
#else
                        sleep(MILLI_SECOND_WAIT_TIME / 1000);
#endif
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

    std::cout << "Main loop end\n";

    // Destroy the enclave
    clave.freeKeyPair();
    clave.destroyOuterDataServer();
    clave.destroy();

    // Destroy chain
    Chain::destroy();

    getchar();
    return 0;
}
