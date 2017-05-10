/*
 *  SSL client with certificate authentication
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Enclave_t.h"
#include "Output.h"
#include "ca_bundle.h"
#include "s_client.h"
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_f.h"
#include "mbedtls/net_v.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "sgx_tae_service.h"

client_opt_t opt;

mbedtls_net_context server_fd;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_ssl_session saved_session;
mbedtls_x509_crt cacert;
mbedtls_x509_crt clicert;
mbedtls_pk_context pkey;
mbedtls_entropy_context s_entropy;
mbedtls_ctr_drbg_context s_ctr_drbg;
unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];

static int my_recv(void *ctx, unsigned char *buf, size_t len) {
    static int first_try = 1;
    if (first_try) {
        first_try = 0;
        return(MBEDTLS_ERR_SSL_WANT_READ);
    }

    int ret = mbedtls_net_recv(ctx, buf, len);
    if (ret != MBEDTLS_ERR_SSL_WANT_READ) {
        first_try = 1; /* Next call will be a new operation */
    }
    return ret;
}

static int my_send(void *ctx, const unsigned char *buf, size_t len) {
    static int first_try = 1;
    if (first_try) {
        first_try = 0;
        return(MBEDTLS_ERR_SSL_WANT_WRITE);
    }

    int ret = mbedtls_net_send(ctx, buf, len);
    if (ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        first_try = 1; /* Next call will be a new operation */
    }
    return ret;
}

void clinet_context_init(const char *serverName, const char *serverPort) {
    // sgx time service
    extern sgx_time_source_nonce_t sgxTimeSourceNonce;
    sgx_create_pse_session();
    sgx_time_t sgxNow;
    if (sgx_get_trusted_time(&sgxNow, &sgxTimeSourceNonce) != SGX_SUCCESS) {
        oprintf("s_client:client_context_init() : fail! Cannot init sgx time\n");
        return;
    }

    // mbedtls context
    client_opt_init(&opt);
    opt.server_name = serverName;
    opt.server_port = serverPort;

    const char *pers = "ssl_client";
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    memset(&saved_session, 0, sizeof(mbedtls_ssl_session));
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_ctr_drbg);

    int ret = 0;
    if ((ret = mbedtls_ctr_drbg_seed(&s_ctr_drbg, mbedtls_entropy_func, &s_entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        oprintf("s_client:client_context_init(): fail! mbedtls_ctr_drbg_seed returned %d\n", ret);
        return;
    }
    if ((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)root_cas_pem, root_cas_pem_len)) != 0) {
        return;
    }
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, opt.transport, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        oprintf("s_client:client_context_init(): fail! x509 mbedtls_ssl_config_defaults() returned %d\n", ret);
        return;
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (opt.hs_to_min != DFL_HS_TO_MIN || opt.hs_to_max != DFL_HS_TO_MAX) {
        mbedtls_ssl_conf_handshake_timeout(&conf, opt.hs_to_min, opt.hs_to_max);
    }
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    if ((ret = mbedtls_ssl_conf_max_frag_len(&conf, opt.mfl_code)) != 0) {
        oprintf("s_client:client_context_init(): fail! mbedtls_ssl_conf_max_frag_len() returned %d\n", ret);
        return;
    }
#endif
#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    if (opt.trunc_hmac != DFL_TRUNC_HMAC) {
        mbedtls_ssl_conf_truncated_hmac(&conf, opt.trunc_hmac);
    }
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    if (opt.extended_ms != DFL_EXTENDED_MS) {
        mbedtls_ssl_conf_extended_master_secret(&conf, opt.extended_ms);
    }
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    if (opt.etm != DFL_ETM) {
        mbedtls_ssl_conf_encrypt_then_mac(&conf, opt.etm);
    }
#endif
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    if (opt.recsplit != DFL_RECSPLIT) {
        mbedtls_ssl_conf_cbc_record_splitting(&conf, opt.recsplit ? MBEDTLS_SSL_CBC_RECORD_SPLITTING_ENABLED : MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED);
    }
#endif
#if defined(MBEDTLS_DHM_C)
    if (opt.dhmlen != DFL_DHMLEN) {
        mbedtls_ssl_conf_dhm_min_bitlen(&conf, opt.dhmlen);
    }
#endif
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &s_ctr_drbg);
    mbedtls_ssl_conf_read_timeout(&conf, opt.read_timeout);
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_conf_session_tickets(&conf, opt.tickets);
#endif
    if (opt.force_ciphersuite[0] != DFL_FORCE_CIPHER) {
        mbedtls_ssl_conf_ciphersuites(&conf, opt.force_ciphersuite);
    }
#if defined(MBEDTLS_ARC4_C)
    if (opt.arc4 != DFL_ARC4) {
        mbedtls_ssl_conf_arc4_support(&conf, opt.arc4);
    }
#endif
    if (opt.allow_legacy != DFL_ALLOW_LEGACY) {
        mbedtls_ssl_conf_legacy_renegotiation(&conf, opt.allow_legacy);
    }
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(&conf, opt.renegotiation);
#endif
    if (strcmp(opt.ca_path, "none") != 0 && strcmp(opt.ca_file, "none") != 0) {
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    }
    if (strcmp(opt.crt_file, "none") != 0 && strcmp(opt.key_file, "none") != 0) {
        if ((ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey)) != 0) {
            oprintf("s_client:client_context_init(): fail! mbedtls_ssl_conf_own_cert() returned %d\n", ret);
            return;
        }
    }
    if (opt.min_version != DFL_MIN_VERSION) {
        mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.min_version);
    }
    if (opt.max_version != DFL_MAX_VERSION) {
        mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.max_version);
    }
#if defined(MBEDTLS_SSL_FALLBACK_SCSV)
    if (opt.fallback != DFL_FALLBACK) {
        mbedtls_ssl_conf_fallback(&conf, opt.fallback);
    }
#endif
}

void client_context_destroy() {
    // sgx time service
    sgx_close_pse_session();

    // mbedtls context
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_session_free(&saved_session);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&clicert);
    mbedtls_pk_free(&pkey);
    mbedtls_entropy_free(&s_entropy);
    mbedtls_ctr_drbg_free(&s_ctr_drbg);
}

int findSubString(const char *from, const char *target) {
    char firstCh = target[0];
    size_t fromLength = strlen(from);
    size_t targetLength = strlen(target);
    for (size_t i = 0; i < fromLength; ++i) {
        if (from[i] == firstCh && strncmp(from + i, target, targetLength) == 0) {
            return i;
        }
    }
    return -1;
}

int getContentLengthFromHeader(const char *header) {
    char contentLengthStr[] = "Content-Length: ";
    int pos = findSubString(header, contentLengthStr);
    const char *posl = header + pos + strlen(contentLengthStr);
    const char *posr = posl;
    while (*posr != '\r') {
        posr++;
        if (*posr == '\0') {
            return -1;
        }
    }
    int length = posr - posl;
    char *resultStr = (char*)malloc(length + 1);
    strncpy(resultStr, posl, length);
    int result = atoi(resultStr);
    free(resultStr);
    return result;
}

int ssl_client(const char *page, unsigned char* output, int length) {
    int ret = 0;

    opt.request_page = page;

    // Start the connection
    if ((ret = mbedtls_net_connect(&server_fd, opt.server_name, opt.server_port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        oprintf("s_client:ssl_client(): fail! cannot connect to server, mbedtls_net_connect() returned %d\n", ret);
        return ret;
    }
    if (opt.nbio > 0) {
        ret = mbedtls_net_set_nonblock(&server_fd);
    }
    else {
        ret = mbedtls_net_set_block(&server_fd);
    }
    if (ret != 0) {
        oprintf("s_client:ssl_client(): fail! set nbio error, mbedtls_net_set(non)block() returned %d\n", ret);
        return ret;
    }

    // Setup ssl
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_init(&ssl);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        oprintf("s_client:ssl_client(): fail! mbedtls_ssl_setup() returned %d\n", ret);
        return ret;
    }
    if ((ret = mbedtls_ssl_set_hostname(&ssl, opt.server_name)) != 0) {
        oprintf("s_client:ssl_client(): fail! mbedtls_ssl_set_hostname() returned %d\n", ret);
        return ret;
    }
    if (opt.nbio == 2) {
        mbedtls_ssl_set_bio(&ssl, &server_fd, my_send, my_recv, NULL);
    }
    else {
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, opt.nbio == 0 ? mbedtls_net_recv_timeout : NULL);
    }

    // Handshake
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            oprintf("s_client:ssl_client(): handshake failed, mbedtls_ssl_handshake() returned %d\n", ret);
            return ret;
        }
    }

    // Verify the server certificate
    uint32_t flags;
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
    }

    // Write the GET request
    int len = mbedtls_snprintf((char *)buf, sizeof(buf) - 1, GET_REQUEST, opt.request_page, opt.server_name);
    int tail_len = (int)strlen(GET_REQUEST_END);

    /* Add padding to GET request to reach opt.request_size in length */
    if (opt.request_size != DFL_REQUEST_SIZE && len + tail_len < opt.request_size) {
        memset(buf + len, 'A', opt.request_size - len - tail_len);
        len += opt.request_size - len - tail_len;
    }
    strncpy((char *)buf + len, GET_REQUEST_END, sizeof(buf) - len - 1);
    len += tail_len;

    /* Truncate if request size is smaller than the "natural" size */
    if (opt.request_size != DFL_REQUEST_SIZE && len > opt.request_size) {
        len = opt.request_size;
        /* Still end with \r\n unless that's really not possible */
        if (len >= 2) buf[len - 2] = '\r';
        if (len >= 1) buf[len - 1] = '\n';
    }

    int written = 0;
    for (int frags = 0; written < len; written += ret, frags++) {
        while ((ret = mbedtls_ssl_write(&ssl, buf + written, len - written)) <= 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                oprintf("s_client:ssl_client(): fail! mbedtls_ssl_write() returned %d\n", ret);
                return ret;
            }
        }
    }
    buf[written] = '\0';

    // Read the HTTP response
    bool isReadingBody = false;
    int currentLength = 0;
    int resultLength = 0;
    unsigned char *originOutput = output;
    int originLength = length;
    while (1) {
        // get data chunk
        len = mbedtls_ssl_read(&ssl, output, length - 1);
        if (len >= length - 1) {
            oprintf("s_client:ssl_client(): fail! buffer length have to be larger\n");
            return ret;
        }
        if (len == MBEDTLS_ERR_SSL_WANT_READ || len == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        else if (len == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            do {
                len = mbedtls_ssl_close_notify(&ssl);
            } while (len == MBEDTLS_ERR_SSL_WANT_WRITE);
            return resultLength;
        }
        else if (len <= 0) {
            oprintf("s_client:ssl_client(): fail! error getting data from server, mbedtls_ssl_read() returned %d\n", len);
            return len;
        }
        output[len] = '\0';

        if (!isReadingBody) {
            // get Content-Length from header
            int pos = findSubString((char*)output, "\r\n\r\n");
            if (pos > 0) {
                isReadingBody = true;
                resultLength = getContentLengthFromHeader((char*)output);
                if (resultLength < 0) {
                    oprintf("s_client:ssl_client(): fail! cannot get Content-Length from header\n");
                    return 0;
                }
                if (pos + 4 < len) {
                    memmove(originOutput, output + pos + 4, len - pos - 3);  // bring in the '\0'
                    output = originOutput + len - pos - 4;
                    currentLength = len - pos - 4;
                    if (currentLength == resultLength) {
                        return resultLength;
                    }
                }
                else {
                    currentLength = 0;
                    length = originLength;
                    output = originOutput;
                }
            }
            else {
                currentLength += len;
                length -= len;
                output += len;
            }
        }
        else{
            currentLength += len;
            length -= len;
            output += len;
            if (currentLength == resultLength) {
                return resultLength;
            }
        }
    }

    return resultLength;
}

void client_opt_init(client_opt_t* opt) {
    opt->server_name = DFL_SERVER_NAME;
    opt->server_port = DFL_SERVER_PORT;
    opt->debug_level = DFL_DEBUG_LEVEL;
    opt->nbio = DFL_NBIO;
    opt->read_timeout = DFL_READ_TIMEOUT;
    opt->max_resend = DFL_MAX_RESEND;
    opt->request_page = DFL_REQUEST_PAGE;
    opt->request_size = DFL_REQUEST_SIZE;
    opt->ca_file = DFL_CA_FILE;
    opt->ca_path = DFL_CA_PATH;
    opt->crt_file = DFL_CRT_FILE;
    opt->key_file = DFL_KEY_FILE;
    opt->psk = DFL_PSK;
    opt->psk_identity = DFL_PSK_IDENTITY;
    opt->ecjpake_pw = DFL_ECJPAKE_PW;
    opt->force_ciphersuite[0] = DFL_FORCE_CIPHER;
    opt->renegotiation = DFL_RENEGOTIATION;
    opt->allow_legacy = DFL_ALLOW_LEGACY;
    opt->renegotiate = DFL_RENEGOTIATE;
    opt->exchanges = DFL_EXCHANGES;
    opt->min_version = DFL_MIN_VERSION;
    opt->max_version = DFL_MAX_VERSION;
    opt->arc4 = DFL_ARC4;
    opt->auth_mode = DFL_AUTH_MODE;
    opt->mfl_code = DFL_MFL_CODE;
    opt->trunc_hmac = DFL_TRUNC_HMAC;
    opt->recsplit = DFL_RECSPLIT;
    opt->dhmlen = DFL_DHMLEN;
    opt->reconnect = DFL_RECONNECT;
    opt->reco_delay = DFL_RECO_DELAY;
    opt->reconnect_hard = DFL_RECONNECT_HARD;
    opt->tickets = DFL_TICKETS;
    opt->alpn_string = DFL_ALPN_STRING;
    opt->transport = DFL_TRANSPORT;
    opt->hs_to_min = DFL_HS_TO_MIN;
    opt->hs_to_max = DFL_HS_TO_MAX;
    opt->fallback = DFL_FALLBACK;
    opt->extended_ms = DFL_EXTENDED_MS;
    opt->etm = DFL_ETM;
}
