#include <stdlib.h>
#include <string.h>
#include "OuterData.h"
#include "Output.h"
#include "Enclave_t.h"
#include "s_client.h"

char *serverName;
char *serverPort;

void ecall_initOuterDataServer(const char *name, const char *port) {
    size_t nameLength = strlen(name);
    serverName = (char*)malloc(nameLength);
    memcpy(serverName, name, nameLength);
    serverName[nameLength] = '\0';
    size_t portLength = strlen(port);
    serverPort = (char*)malloc(portLength);
    memcpy(serverPort, port, portLength);
    serverPort[portLength] = '\0';

    clinet_context_init(serverName, serverPort);

    // [TODO] remove this
    // test
    char test_name[OUTER_DATA_NAME_SIZE + 1];
    char test_phone[OUTER_DATA_PHONE_SIZE + 1];
    getCustomerInfo("abcde", test_name, test_phone);
    oprintf("Testing outer data: %s %s\n", test_name, test_phone);
}

void ecall_destroyOuterDataServer() {
    free(serverName);
    free(serverPort);
    client_context_destroy();
}

void getCustomerInfo(const char *index, char name[OUTER_DATA_NAME_SIZE + 1], char phone[OUTER_DATA_PHONE_SIZE + 1]) {
    const int bufSize = 5120;
    unsigned char buf[bufSize];
    int outputLength = ssl_client(buf, bufSize);
    oprintf("%d\n", outputLength);
    for (int t = 0; t < outputLength; ++t) {
        oprintf("%c", ((char*)buf)[t]);
    }
    oprintf("\n\n\n\n\nreplay\n\n\n\n\n");
    outputLength = ssl_client(buf, 8192);
    oprintf("%d\n", outputLength);
    for (int t = 0; t < outputLength; ++t) {
        oprintf("%c", ((char*)buf)[t]);
    }

    memcpy(name, "StubName", 9);
    memcpy(phone, "StubPhone", 10);
}
