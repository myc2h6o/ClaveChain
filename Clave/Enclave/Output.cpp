#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Output.h"
#include "Enclave_t.h"

/*
* oprintf:
* Helper function to print to terminal outside enclave
*/
void oprintf(const char *fmt, ...) {
    char buf[BUFSIZ * 2] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ * 2, fmt, ap);
    va_end(ap);
    ocall_printString(buf);
}
