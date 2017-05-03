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

void getCustomerInfo(const char *index, char name[OUTER_DATA_NAME_SIZE + 1], char phone[OUTER_DATA_PHONE_SIZE + 1]) {
    // prepare buffer and request page
    const int bufSize = 1024;
    unsigned char buf[bufSize];
    char *requestPage = (char*)malloc(strlen(index) + 2);
    requestPage[0] = '/';
    memcpy(requestPage + 1, index, strlen(index) + 1);

    // get data from server
    int outputLength = ssl_client(requestPage, buf, bufSize);
    if (outputLength <= 0) {
        name[0] = '\0';
        phone[0] = '\0';
        return;
    }

    //clean request page
    free(requestPage);

    // parse return data
    // name
    int length = strlen((char*)buf);
    int pos = 1;
    for (; pos < length; ++pos) {
        if (buf[pos] == '\n') {
            break;
        }
    }
    if (pos == length) {
        oprintf("OuterData:getCustomerInfo(): Error, data returned by server is withinvalid format\n");
    }
    if (pos > OUTER_DATA_NAME_SIZE) {
        oprintf("OuterData:getCustomerInfo(): Error, name returned by server too long\n");
    }
    memcpy(name, buf, pos);
    name[pos] = '\0';

    // phone
    pos++;
    int pos2 = pos + 1;
    for (; pos2 < length; ++pos2) {
        if (buf[pos2] == '\n') {
            break;
        }
    }
    if (pos2 == length) {
        oprintf("OuterData:getCustomerInfo(): Error, data returned by server is withinvalid format\n");
    }
    if (pos2 - pos > OUTER_DATA_PHONE_SIZE) {
        oprintf("OuterData:getCustomerInfo(): Error, phone returned by server too long\n");
    }
    memcpy(phone, buf + pos, pos2 - pos);
    phone[pos2 - pos] = '\0';
}
