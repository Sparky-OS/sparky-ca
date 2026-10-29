/* SPDX-License-Identifier: ISC
 * Copyright (c) 2026 Daniel Campos Ramos
 *
 * Arbitrary bytes as a public key or a certificate: OpenSSL's generic DER
 * decoding (no key type), ED521 SubjectPublicKeyInfo decoding, d2i_PUBKEY
 * and d2i_X509, then everything a program does with an Ed521 key it got.
 * Every OpenSSL TLS client reaches decoder.c this way with a peer's
 * certificate once the provider is installed.
 */
#include "common.h"
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

static void exercise(EVP_PKEY *key)
{
    unsigned char encoded[200], *der = NULL;
    size_t encoded_size = 0;
    if (key == NULL || !EVP_PKEY_is_a(key, "ED521"))
        return;
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, encoded, sizeof(encoded), &encoded_size);
    EVP_PKEY_get_bits(key);
    EVP_PKEY_get_security_bits(key);
    EVP_PKEY_get_size(key);
    EVP_PKEY_eq(key, key);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx != NULL)
        EVP_PKEY_public_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    i2d_PUBKEY(key, &der);
    OPENSSL_free(der);
}

static void decode(const uint8_t *data, size_t size, const char *structure, const char *type)
{
    EVP_PKEY *key = NULL;
    const unsigned char *position = data;
    size_t remaining = size;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&key, "DER", structure, type, EVP_PKEY_PUBLIC_KEY, NULL, NULL);
    if (ctx != NULL)
        OSSL_DECODER_from_data(ctx, &position, &remaining);
    exercise(key);
    EVP_PKEY_free(key);
    OSSL_DECODER_CTX_free(ctx);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    ed521_fuzz_setup();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const unsigned char *position;
    ed521_fuzz_setup();
    decode(data, size, NULL, NULL);
    decode(data, size, "SubjectPublicKeyInfo", "ED521");
    position = data;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &position, (long)size);
    exercise(key);
    EVP_PKEY_free(key);
    position = data;
    X509 *cert = d2i_X509(NULL, &position, (long)size);
    if (cert != NULL) {
        EVP_PKEY *subject = X509_get0_pubkey(cert);
        exercise(subject);
        if (subject != NULL)
            X509_verify(cert, subject);
        unsigned char *der = NULL;
        i2d_X509(cert, &der);
        OPENSSL_free(der);
        X509_free(cert);
    }
    ERR_clear_error();
    return 0;
}
