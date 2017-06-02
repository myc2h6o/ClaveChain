#include <stdio.h>
#include "Enclave_t.h"
#include "Output.h"

#define DURATION_COUNT 100
#define OUTPUT_COUNT (DURATION_COUNT + 1)

void ecall_evaluateTimeOutputDelay() {
    oprintf("Time function cache:");
    ocall_printTime();
    oprintf("-----------Evaluating time output delay in enclave-----------\n");
    for (int i = 0; i < OUTPUT_COUNT; ++i) {
        ocall_printTime();
    }
    oprintf("---------End evaluating time output delay in enclave---------\n");
}
