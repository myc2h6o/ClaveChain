#include <stdio.h>
#include "Clave.h"
#include "TimeDelay.h"

#define DURATION_COUNT 100
#define OUTPUT_COUNT (DURATION_COUNT + 1)

void evaluateTimeOutputDelay() {
    printf("Time function cache:");
    ocall_printTime();
    printf("-----------Evaluating time output delay in app-----------\n");
    for (int i = 0; i < OUTPUT_COUNT; ++i) {
        ocall_printTime();
    }
    printf("---------End evaluating time output delay in app---------\n");
}
