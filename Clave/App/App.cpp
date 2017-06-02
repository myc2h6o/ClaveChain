#include <iostream>
#include <string>
#include <vector>
#include "Chain.h"
#include "Clave.h"
#include "env.h"
#include "TimeDelay.h"

#ifdef _WIN32
#else
#include "unistd.h"
#endif

#define MILLI_SECOND_WAIT_TIME 5000
// here use 192.168.13.138 for remote test address, change this in deployment
#define GETH_ADDRESS "http://192.168.13.138:8545"
#define OUTER_SERVER_NAME "192.168.13.138"
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

#ifdef ENV_TEST
    // evaluate switching time
    evaluateTimeOutputDelay();
    clave.evaluateTimeOutputDelay();
#endif

    Request r;
    r.id = 1;
    r.isDone = false;
    clave.getSignedTransactionFromRequest(Chain::getHexNonce(), r);

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
#ifdef ENV_TEST
                    // before entering enclave
                    ocall_printTime();
#endif
                    signedTransaction = clave.getSignedTransactionFromRequest(Chain::getHexNonce(), requests[i]);
#ifdef ENV_TEST
                    // after leaving enclave
                    ocall_printTime();
#endif
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
