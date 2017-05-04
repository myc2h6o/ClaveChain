// [TODO] Add license

#include "mbedTlsSgxSignV.h"

int win32_derive_mpi(const mbedtls_ecp_group *grp, mbedtls_mpi *x, const unsigned char *buf, size_t blen) {
    int ret;
    size_t n_size = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(x, buf, use_size));
    if (use_size * 8 > grp->nbits)
        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(x, use_size * 8 - grp->nbits));

    /* While at it, reduce modulo N */
    if (mbedtls_mpi_cmp_mpi(x, &grp->N) >= 0)
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(x, x, &grp->N));

cleanup:
    return(ret);
}

int win32_mbedtls_ecdsa_sign_with_v(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s, uint8_t *v, const mbedtls_mpi *d, const unsigned char *buf, size_t blen, int(*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
    int ret, key_tries, sign_tries, blind_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t, vv;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (grp && grp->N.p == NULL)
        return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);


    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&t);
    mbedtls_mpi_init(&vv);

    mbedtls_mpi tmp;
    mbedtls_mpi halfN;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&halfN);
    //mbedtls_mpi_read_string(&SECP256K1_N, 16, S_SECP256K1_N);
    //mbedtls_mpi_read_string(&SECP256K1_N_H, 16, S_SECP256K1_N_H);
    mbedtls_mpi_div_int(&halfN, &tmp, &grp->N, 2);

    sign_tries = 0;
    do
    {
        /*
        * Steps 1-3: generate a suitable ephemeral keypair
        * and set r = xR mod n
        */
        key_tries = 0;
        do
        {
            MBEDTLS_MPI_CHK(mbedtls_ecp_gen_keypair(grp, &k, &R, f_rng, p_rng));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&vv, &R.Y, &grp->N));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_int((mbedtls_mpi_uint*)v, &vv, 2));

            if (mbedtls_mpi_cmp_abs(&R.X, &grp->N) >= 0) {
                *v |= 2;
            }
            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(r, &R.X, &grp->N));
            //*v += 27;

            if (key_tries++ > 10)
            {
                ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }
        } while (mbedtls_mpi_cmp_int(r, 0) == 0);

        /*
        * Step 5: derive MPI from hashed message
        */
        MBEDTLS_MPI_CHK(win32_derive_mpi(grp, &e, buf, blen));

        /*
        * Generate a random value to blind inv_mod in next step,
        * avoiding a potential timing leak.
        */
        blind_tries = 0;
        do
        {
            size_t n_size = (grp->nbits + 7) / 8;
            MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&t, n_size, f_rng, p_rng));
            MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&t, 8 * n_size - grp->nbits));

            /* See mbedtls_ecp_gen_keypair() */
            if (++blind_tries > 30)
                return(MBEDTLS_ERR_ECP_RANDOM_FAILED);
        } while (mbedtls_mpi_cmp_int(&t, 1) < 0 ||
            mbedtls_mpi_cmp_mpi(&t, &grp->N) >= 0);

        /*
        * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
        */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, r, d));
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&e, &e, s));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&e, &e, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&k, &k, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(s, &k, &grp->N));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, s, &e));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(s, s, &grp->N));

        if (sign_tries++ > 10)
        {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }
    } while (mbedtls_mpi_cmp_int(s, 0) == 0);

    if (mbedtls_mpi_cmp_abs(s, &halfN) == 1) {
        mbedtls_mpi_sub_abs(s, &grp->N, s);
        *v ^= 1;
    }

    *v += 27;

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&k); mbedtls_mpi_free(&e); mbedtls_mpi_free(&t);
    mbedtls_mpi_free(&tmp); mbedtls_mpi_free(&halfN);
    return(ret);
}
