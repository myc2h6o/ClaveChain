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
}

void ecall_destroyOuterDataServer() {
    free(serverName);
    free(serverPort);
    client_context_destroy();
}

int getLotteryNumber() {
    // prepare buffer and request page
    const int bufSize = 1024;
    unsigned char buf[bufSize];
    char *requestPage = (char*)malloc(2);
    requestPage[0] = '/';
    requestPage[1] = '\0';

    // get data from server
    int outputLength = ssl_client(requestPage, buf, bufSize);
    if (outputLength <= 0) {
        return -1;
    }

    //clean request page
    free(requestPage);

    // parse return data
    // name
    int length = strlen((char*)buf);
    int pos = 1;
    for (; pos < length; ++pos) {
        if (buf[pos] == '\n') {
            buf[pos] = '\0';
            break;
        }
    }
    if (pos == length) {
        oprintf("OuterData:getLotteryNumber(): Error, data returned by server is withinvalid format\n");
    }
    return atoi((char*)buf);
}
