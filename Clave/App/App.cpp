#include <iostream>
#include <string>
#include "Chain.h"
#include "Clave.h"

int main() {
    // Initialize enclave
    Clave clave;
    if (clave.init() < 0) {
        std::cout << "Failed to init enclave\n";
        getchar();
        return -1;
    }

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
    while (1) {
        break;
    }

    std::cout << "Some Error happened\n";

    // Destroy the enclave
    clave.destroy();
    getchar();
    return 0;
}
