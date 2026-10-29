/* SPDX-License-Identifier: ISC
 * Copyright (c) 2026 Daniel Campos Ramos
 *
 * EVP_DigestVerify through the provider.
 *   fuzz-verify:    input = public key (66) || signature (132) || message
 *   fuzz-verify-v7: input = signature (132) || message, with ITI's real v7 key
 * Each input is also verified with a signature one octet short and with the
 * last octet of the message dropped, to reach the length checks.
 */
#include "common.h"
#include "v7.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

static EVP_PKEY *v7_key;

#ifndef ED521_FUZZ_FIXED_V7
static EVP_PKEY *public_key(const unsigned char *bytes)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ED521", NULL);
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)bytes, 66), OSSL_PARAM_END
    };
    if (ctx != NULL && EVP_PKEY_fromdata_init(ctx) > 0)
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(ctx);
    return key;
}
#endif

static void verify(EVP_PKEY *key, const unsigned char *signature, size_t signature_size,
                   const unsigned char *message, size_t message_size)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx != NULL && EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL) > 0)
        EVP_DigestVerify(ctx, signature, signature_size, message, message_size);
    EVP_MD_CTX_free(ctx);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    ed521_fuzz_setup();
    const unsigned char *position = v7_der;
    X509 *cert = d2i_X509(NULL, &position, sizeof(v7_der));
    if (cert == NULL || (v7_key = X509_get_pubkey(cert)) == NULL || !EVP_PKEY_is_a(v7_key, "ED521"))
        abort();
    X509_free(cert);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef ED521_FUZZ_FIXED_V7
    const size_t offset = 132;
    if (size < offset)
        return 0;
    EVP_PKEY *key = v7_key;
    const unsigned char *signature = data;
#else
    const size_t offset = 66 + 132;
    if (size < offset)
        return 0;
    EVP_PKEY *key = public_key(data);
    const unsigned char *signature = data + 66;
#endif
    if (key != NULL) {
        verify(key, signature, 132, data + offset, size - offset);
        verify(key, signature, 131, data + offset, size - offset);
        if (size > offset)
            verify(key, signature, 132, data + offset, size - offset - 1);
    }
#ifndef ED521_FUZZ_FIXED_V7
    EVP_PKEY_free(key);
#endif
    ERR_clear_error();
    return 0;
}
