/* SPDX-License-Identifier: ISC
 * Copyright (c) 2025 Pedro F. Albanese
 * Copyright (c) 2026 Daniel Campos Ramos
 */
#include "internal.h"

static const OSSL_ALGORITHM keymgmt[] = {
    { ED521_NAMES, "provider=ed521", ed521_keymgmt, "Public Ed521 keys" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM signature[] = {
    { ED521_NAMES, "provider=ed521", ed521_signature, "PureEd521 verification" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM decoder[] = {
    { ED521_NAMES, "provider=ed521,input=der,structure=SubjectPublicKeyInfo", ed521_decoder, "Ed521 SubjectPublicKeyInfo" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *query(void *ctx, int operation, int *no_cache)
{
    (void)ctx;
    *no_cache = 0;
    switch (operation) {
    case OSSL_OP_KEYMGMT: return keymgmt;
    case OSSL_OP_SIGNATURE: return signature;
    case OSSL_OP_DECODER: return decoder;
    default: return NULL;
    }
}

static void teardown(void *data)
{
    ED521_PROVIDER *provider = data;
    OSSL_LIB_CTX_free(provider->libctx);
    OPENSSL_free(provider);
}

static const OSSL_PARAM *gettable_params(void *ctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL), OSSL_PARAM_END
    };
    (void)ctx;
    return params;
}

static int get_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)ctx;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Ed521 verification, after Pedro F. Albanese's e521"))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) != NULL && !OSSL_PARAM_set_utf8_ptr(p, ED521_VERSION))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS)) != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_DISPATCH dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))get_params },
    { 0, NULL }
};

__attribute__((visibility("default")))
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    OSSL_FUNC_core_obj_create_fn *create = NULL;
    OSSL_FUNC_core_obj_add_sigid_fn *add_sigid = NULL;
    ED521_PROVIDER *provider = OPENSSL_zalloc(sizeof(*provider));
    if (provider == NULL)
        return 0;
    provider->libctx = OSSL_LIB_CTX_new_child(handle, in);
    for (const OSSL_DISPATCH *entry = in; entry->function_id != 0; ++entry) {
        switch (entry->function_id) {
        case OSSL_FUNC_CORE_OBJ_CREATE: create = OSSL_FUNC_core_obj_create(entry); break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID: add_sigid = OSSL_FUNC_core_obj_add_sigid(entry); break;
        case OSSL_FUNC_BIO_READ_EX: provider->read_ex = OSSL_FUNC_BIO_read_ex(entry); break;
        }
    }
    if (provider->libctx == NULL || provider->read_ex == NULL || create == NULL || add_sigid == NULL
        || !create(handle, ED521_OID, "ED521", "Ed521")
        || !add_sigid(handle, "ED521", "", "ED521")) {
        teardown(provider);
        return 0;
    }
    *provctx = provider;
    *out = dispatch;
    return 1;
}
