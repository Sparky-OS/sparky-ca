/* SPDX-License-Identifier: ISC
 * Copyright (c) 2026 Daniel Campos Ramos
 *
 * A mutated certificate through X509_verify_cert with ITI's v7 as the only
 * trust anchor, self-signatures checked and strict X.509 rules on, at a fixed
 * time, so that chain building reaches the provider with arbitrary
 * to-be-signed bytes, signature fields and keys.
 */
#include "common.h"
#include "v7.h"
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

static X509_STORE *store;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    ed521_fuzz_setup();
    const unsigned char *position = v7_der;
    X509 *v7 = d2i_X509(NULL, &position, sizeof(v7_der));
    store = X509_STORE_new();
    if (v7 == NULL || store == NULL || !X509_STORE_add_cert(store, v7))
        abort();
    X509_free(v7);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const unsigned char *position = data;
    X509 *cert = d2i_X509(NULL, &position, (long)size);
    if (cert == NULL)
        return 0;
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx != NULL && X509_STORE_CTX_init(ctx, store, cert, NULL)) {
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CHECK_SS_SIGNATURE | X509_V_FLAG_X509_STRICT);
        X509_VERIFY_PARAM_set_time(param, 1793232000); /* 2026-10-29 */
        X509_verify_cert(ctx);
    }
    X509_STORE_CTX_free(ctx);
    X509_free(cert);
    ERR_clear_error();
    return 0;
}
