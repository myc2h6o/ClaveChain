#ifndef _MBED_MAKE_TIME_H_
#define _MBED_MAKE_TIME_H_

#include "sgx_tae_service.h"
#include "mbedtls/x509.h"

sgx_time_t mbedMktime(const mbedtls_x509_time *t);

#endif
