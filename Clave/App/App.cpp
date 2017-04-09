#include <stdio.h>
#include "Clave.h"

int main() {
    // Initialize enclave
    Clave clave;
    if (clave.init() < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    // Test print function
    clave.printHello();

    // Destroy the enclave
    clave.destroy();

    printf("Info: SampleEnclave successfully returned.\nEnter a character before exit ...\n");
    getchar();
    return 0;
}
