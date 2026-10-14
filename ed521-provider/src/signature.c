/* SPDX-License-Identifier: ISC
 * Copyright (c) 2025 Pedro F. Albanese
 * Copyright (c) 2026 Daniel Campos Ramos
 */
#include "internal.h"
#include <string.h>

typedef struct {
    ED521_PROVIDER *provider;
    ED521_KEY key;
} SIGNATURE_CTX;

static void *signature_new(void *provctx, const char *properties)
{
    SIGNATURE_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    (void)properties;
    if (ctx != NULL)
        ctx->provider = provctx;
    return ctx;
}

static void signature_free(void *ctx)
{
    OPENSSL_free(ctx);
}

static void *signature_dup(void *data)
{
    return OPENSSL_memdup(data, sizeof(SIGNATURE_CTX));
}

static int signature_init(void *data, const char *digest, void *keydata,
                           const OSSL_PARAM params[])
{
    SIGNATURE_CTX *ctx = data;
    ED521_KEY *key = keydata;
    if (key == NULL || !key->present || (digest != NULL && digest[0] != '\0')
        || (params != NULL && params[0].key != NULL))
        return 0;
    ctx->key = *key;
    return 1;
}

static int signature_verify(void *data, const unsigned char *signature,
                             size_t signature_size, const unsigned char *message,
                             size_t message_size)
{
    SIGNATURE_CTX *ctx = data;
    return ctx->key.present && signature_size == 132 && signature != NULL
        && (message != NULL || message_size == 0)
        && ed521_verify(ctx->provider->libctx, ctx->key.public_key, signature, message, message_size);
}

const OSSL_DISPATCH ed521_signature[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))signature_new },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))signature_free },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))signature_dup },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))signature_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))signature_verify },
    { 0, NULL }
};
