/* SPDX-License-Identifier: ISC
 * Copyright (c) 2025 Pedro F. Albanese
 * Copyright (c) 2026 Daniel Campos Ramos
 */
#include "internal.h"
#include <openssl/core_object.h>
#include <openssl/x509.h>
#include <string.h>

static void *decoder_new(void *provctx)
{
    return provctx;
}

static void decoder_free(void *ctx)
{
    (void)ctx;
}

static int decoder_selection(void *ctx, int selection)
{
    (void)ctx;
    return selection == 0 || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
}

static int decoder_decode(void *data, OSSL_CORE_BIO *input, int selection,
                           OSSL_CALLBACK *callback, void *arg,
                           OSSL_PASSPHRASE_CALLBACK *password, void *password_arg)
{
    ED521_PROVIDER *provider = data;
    unsigned char der[256];
    size_t length = 0, read = 0;
    const unsigned char *position, *public = NULL;
    int public_length = 0, type = 0, object_type = OSSL_OBJECT_PKEY, ok = 1;
    ASN1_OBJECT *algorithm = NULL;
    X509_ALGOR *identifier = NULL;
    STACK_OF(ASN1_TYPE) *spki = NULL;
    ED521_KEY *key = NULL;
    char oid[80];
    (void)selection;
    (void)password;
    (void)password_arg;
    while (length < sizeof(der) && provider->read_ex(input, der + length, sizeof(der)-length, &read) && read != 0)
        length += read;
    position = der;
    spki = d2i_ASN1_SEQUENCE_ANY(NULL, &position, (long)length);
    if (spki == NULL || position != der + length || length == sizeof(der)
        || sk_ASN1_TYPE_num(spki) != 2)
        goto end;
    ASN1_TYPE *alg = sk_ASN1_TYPE_value(spki, 0), *bits = sk_ASN1_TYPE_value(spki, 1);
    if (alg->type != V_ASN1_SEQUENCE || bits->type != V_ASN1_BIT_STRING
        || (bits->value.bit_string->flags & 7) != 0)
        goto end;
    position = ASN1_STRING_get0_data(alg->value.sequence);
    const unsigned char *alg_end = position + ASN1_STRING_length(alg->value.sequence);
    identifier = d2i_X509_ALGOR(NULL, &position, ASN1_STRING_length(alg->value.sequence));
    if (identifier == NULL || position != alg_end)
        goto end;
    public = ASN1_STRING_get0_data(bits->value.bit_string);
    public_length = ASN1_STRING_length(bits->value.bit_string);
    X509_ALGOR_get0((const ASN1_OBJECT **)&algorithm, &type, NULL, identifier);
    OBJ_obj2txt(oid, sizeof(oid), algorithm, 1);
    if (strcmp(oid, ED521_OID) != 0 || type != V_ASN1_UNDEF || public_length != 66
        || !ed521_public_valid(public))
        goto end;
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ok = 0;
        goto end;
    }
    memcpy(key->public_key, public, 66);
    key->present = 1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, &object_type),
        OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, "ED521", sizeof("ED521")),
        OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key)),
        OSSL_PARAM_END
    };
    ok = callback(params, arg);
end:
    OPENSSL_free(key);
    X509_ALGOR_free(identifier);
    sk_ASN1_TYPE_pop_free(spki, ASN1_TYPE_free);
    return ok;
}

const OSSL_DISPATCH ed521_decoder[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))decoder_new },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))decoder_free },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))decoder_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))decoder_decode },
    { 0, NULL }
};
