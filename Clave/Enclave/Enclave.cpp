#include <stdio.h>
#include <stdlib.h>
#include "Enclave.h"
#include "Enclave_t.h"

/*
 * oprintf:
 * Helper function to print to terminal outside enclave
 */
void oprintf(const char *fmt, ...) {
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_printString(buf);
}

/*
 * ecall_printHello:
 * Test function for oprintf
 */
void ecall_printHello(void) {
    oprintf("%s %d!\n", "Hello From Enclave", 1);
}
