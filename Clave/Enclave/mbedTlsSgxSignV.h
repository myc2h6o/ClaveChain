// [TODO] Add license

#ifndef _MBED_TLS_SGX_SIGN_V_H_
#define _MBED_TLS_SGX_SIGN_V_H_

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"

int derive_mpi(const mbedtls_ecp_group *grp, mbedtls_mpi *x, const unsigned char *buf, size_t blen);
int mbedtls_ecdsa_sign_with_v(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s, uint8_t *v, const mbedtls_mpi *d, const unsigned char *buf, size_t blen, int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);

#endif
