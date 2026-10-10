/* SPDX-License-Identifier: ISC
 * Copyright (c) 2025 Pedro F. Albanese
 * Copyright (c) 2026 Daniel Campos Ramos
 */
#include "internal.h"
#include <string.h>

static void *key_new(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(ED521_KEY));
}

static void key_free(void *key)
{
    OPENSSL_free(key);
}

static void *key_load(const void *reference, size_t reference_size)
{
    ED521_KEY **key = (ED521_KEY **)reference;
    ED521_KEY *result;
    if (reference_size != sizeof(*key))
        return NULL;
    result = *key;
    *key = NULL;
    return result;
}

static int key_has(const void *data, int selection)
{
    const ED521_KEY *key = data;
    return key != NULL && key->present
        && !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
}

static int key_import(void *data, int selection, const OSSL_PARAM params[])
{
    ED521_KEY *key = data;
    const OSSL_PARAM *public = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY
        || !(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        || public == NULL || public->data_type != OSSL_PARAM_OCTET_STRING
        || public->data == NULL || public->data_size != 66
        || !ed521_public_valid(public->data))
        return 0;
    memcpy(key->public_key, public->data, 66);
    key->present = 1;
    return 1;
}

static const OSSL_PARAM *key_import_types(int selection)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0), OSSL_PARAM_END
    };
    return selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY ? types : NULL;
}

static int key_export(void *data, int selection, OSSL_CALLBACK *callback, void *arg)
{
    ED521_KEY *key = data;
    OSSL_PARAM params[2];
    if (!key_has(key, selection))
        return 0;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, key->public_key, 66);
    params[1] = OSSL_PARAM_construct_end();
    return callback(params, arg);
}

static int key_get_params(void *data, OSSL_PARAM params[])
{
    ED521_KEY *key = data;
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL && !OSSL_PARAM_set_int(p, 521))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL && !OSSL_PARAM_set_size_t(p, 132))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL && !OSSL_PARAM_set_utf8_string(p, ""))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL && (!key->present || !OSSL_PARAM_set_octet_string(p, key->public_key, 66)))
        return 0;
    return 1;
}

static const OSSL_PARAM *key_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provctx;
    return params;
}

static int key_match(const void *a, const void *b, int selection)
{
    const ED521_KEY *left = a, *right = b;
    return key_has(left, selection) && key_has(right, selection)
        && memcmp(left->public_key, right->public_key, 66) == 0;
}

static int key_validate(const void *data, int selection, int checktype)
{
    const ED521_KEY *key = data;
    (void)checktype;
    return key_has(key, selection) && ed521_public_valid(key->public_key);
}

static const char *key_query_name(int operation)
{
    return operation == OSSL_OP_SIGNATURE ? "ED521" : NULL;
}

const OSSL_DISPATCH ed521_keymgmt[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))key_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))key_load },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))key_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))key_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))key_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))key_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))key_import_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))key_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))key_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))key_query_name },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))key_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))key_validate },
    { 0, NULL }
};
