/* SPDX-License-Identifier: ISC
 * Copyright (c) 2026 Daniel Campos Ramos
 */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *message = NULL, *signature = NULL;
    long message_length = 0, signature_length = 0;
    int result = 2;
    if ((argc != 4 && argc != 5) || !OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        goto end;
    BIO *input = BIO_new_file(argv[1], "rb");
    if (input == NULL)
        goto end;
    key = PEM_read_bio_PUBKEY(input, NULL, NULL, NULL);
    BIO_free(input);
    if (key == NULL)
        goto end;
    if (argc == 5 && strcmp(argv[4], "public-only") == 0) {
        EVP_PKEY_CTX *generation = EVP_PKEY_CTX_new_from_name(NULL, "ED521", NULL);
        ctx = EVP_MD_CTX_new();
        result = generation != NULL && ctx != NULL
            && EVP_PKEY_keygen_init(generation) <= 0
            && EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL) <= 0 ? 0 : 1;
        EVP_PKEY_CTX_free(generation);
        goto end;
    }
    message = OPENSSL_hexstr2buf(argv[2], &message_length);
    signature = OPENSSL_hexstr2buf(argv[3], &signature_length);
    ctx = EVP_MD_CTX_new();
    if (message == NULL || signature == NULL || ctx == NULL
        || !EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL))
        goto end;
    result = EVP_DigestVerify(ctx, signature, (size_t)signature_length,
                             message, (size_t)message_length) == 1 ? 0 : 1;
end:
    if (result == 2)
        ERR_print_errors_fp(stderr);
    OPENSSL_free(message);
    OPENSSL_free(signature);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return result;
}
