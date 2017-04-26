#include <stdlib.h>
#include <string.h>
#include "Net.h"

char *getDataFromUri(const char *uri) {
    char *result = (char*)malloc(16);
    memcpy(result, "Stub outer data", 16);
    return result;
}
