/* SPDX-License-Identifier: ISC
 * Copyright (c) 2026 Daniel Campos Ramos
 *
 * Print every algorithm the loaded providers offer, one line per
 * implementation: operation, names, provider, properties.  Then try every
 * operation the Ed521 provider must not offer.  tests/safety.py compares the
 * output with and without the provider.
 */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <stdio.h>
#include <string.h>

static void print_names(const char *name, void *data)
{
    int *first = data;
    printf("%s%s", *first ? "" : ":", name);
    *first = 0;
}

#define LIST(type, kind, provider_of, properties_of, names_of) \
    static void list_##type(type *item, void *data) \
    { \
        int first = 1; \
        (void)data; \
        printf("%s\t", kind); \
        names_of(item, print_names, &first); \
        printf("\t%s\t%s\n", OSSL_PROVIDER_get0_name(provider_of(item)), \
               properties_of(item) ? properties_of(item) : ""); \
    }

static const char *no_properties(const void *item)
{
    (void)item;
    return NULL;
}

LIST(EVP_MD, "digest", EVP_MD_get0_provider, no_properties, EVP_MD_names_do_all)
LIST(EVP_CIPHER, "cipher", EVP_CIPHER_get0_provider, no_properties, EVP_CIPHER_names_do_all)
LIST(EVP_MAC, "mac", EVP_MAC_get0_provider, no_properties, EVP_MAC_names_do_all)
LIST(EVP_KDF, "kdf", EVP_KDF_get0_provider, no_properties, EVP_KDF_names_do_all)
LIST(EVP_RAND, "rand", EVP_RAND_get0_provider, no_properties, EVP_RAND_names_do_all)
LIST(EVP_KEYMGMT, "keymgmt", EVP_KEYMGMT_get0_provider, no_properties, EVP_KEYMGMT_names_do_all)
LIST(EVP_SIGNATURE, "signature", EVP_SIGNATURE_get0_provider, no_properties, EVP_SIGNATURE_names_do_all)
LIST(EVP_ASYM_CIPHER, "asym_cipher", EVP_ASYM_CIPHER_get0_provider, no_properties, EVP_ASYM_CIPHER_names_do_all)
LIST(EVP_KEM, "kem", EVP_KEM_get0_provider, no_properties, EVP_KEM_names_do_all)
LIST(EVP_KEYEXCH, "keyexch", EVP_KEYEXCH_get0_provider, no_properties, EVP_KEYEXCH_names_do_all)
LIST(OSSL_ENCODER, "encoder", OSSL_ENCODER_get0_provider, OSSL_ENCODER_get0_properties, OSSL_ENCODER_names_do_all)
LIST(OSSL_DECODER, "decoder", OSSL_DECODER_get0_provider, OSSL_DECODER_get0_properties, OSSL_DECODER_names_do_all)
LIST(OSSL_STORE_LOADER, "store", OSSL_STORE_LOADER_get0_provider, OSSL_STORE_LOADER_get0_properties, OSSL_STORE_LOADER_names_do_all)

static int capability(const OSSL_PARAM params[], void *data)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_SIGALG_NAME);
    if (p == NULL)
        p = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME);
    printf("capability\t%s\t%s\t\n", p != NULL && p->data_type == OSSL_PARAM_UTF8_STRING ? (const char *)p->data : "?",
           (const char *)data);
    return 1;
}

static int provider(OSSL_PROVIDER *item, void *data)
{
    (void)data;
    printf("provider\t%s\t%s\t\n", OSSL_PROVIDER_get0_name(item), OSSL_PROVIDER_available(NULL, OSSL_PROVIDER_get0_name(item)) ? "available" : "");
    OSSL_PROVIDER_get_capabilities(item, "TLS-SIGALG", capability, (void *)OSSL_PROVIDER_get0_name(item));
    OSSL_PROVIDER_get_capabilities(item, "TLS-GROUP", capability, (void *)OSSL_PROVIDER_get0_name(item));
    return 1;
}

/* Every operation that would create, import or use an Ed521 private key. */
static void refusals(const char *public_pem)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ED521", NULL);
    printf("refusal\tkeygen\t%s\n", ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ? "refused" : "ALLOWED");
    printf("refusal\tparamgen\t%s\n", ctx == NULL || EVP_PKEY_paramgen_init(ctx) <= 0 ? "refused" : "ALLOWED");
    unsigned char secret[66] = {7};
    OSSL_PARAM private_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, secret, sizeof(secret)), OSSL_PARAM_END
    };
    EVP_PKEY *imported = NULL;
    int fromdata = ctx != NULL && EVP_PKEY_fromdata_init(ctx) > 0
        && EVP_PKEY_fromdata(ctx, &imported, EVP_PKEY_KEYPAIR, private_params) > 0;
    printf("refusal\timport-private\t%s\n", fromdata ? "ALLOWED" : "refused");
    EVP_PKEY_free(imported);
    EVP_PKEY_CTX_free(ctx);
    EVP_SIGNATURE *signature = EVP_SIGNATURE_fetch(NULL, "ED521", NULL);
    printf("refusal\tsignature-fetch-verify-only\t%s\n", signature == NULL ? "missing" : "present");
    EVP_SIGNATURE_free(signature);

    BIO *in = public_pem ? BIO_new_file(public_pem, "r") : NULL;
    EVP_PKEY *key = in ? PEM_read_bio_PUBKEY(in, NULL, NULL, NULL) : NULL;
    BIO_free(in);
    printf("refusal\tpublic-key-loaded\t%s\n", key ? "yes" : "no");
    if (key != NULL) {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        printf("refusal\tdigest-sign-init\t%s\n", EVP_DigestSignInit_ex(md, NULL, NULL, NULL, NULL, key, NULL) > 0 ? "ALLOWED" : "refused");
        EVP_MD_CTX_free(md);
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
        printf("refusal\tsign-init\t%s\n", pctx && EVP_PKEY_sign_init(pctx) > 0 ? "ALLOWED" : "refused");
        printf("refusal\tsign-message-init\t%s\n", pctx && EVP_PKEY_sign_message_init(pctx, NULL, NULL) > 0 ? "ALLOWED" : "refused");
        printf("refusal\tderive-init\t%s\n", pctx && EVP_PKEY_derive_init(pctx) > 0 ? "ALLOWED" : "refused");
        printf("refusal\tencrypt-init\t%s\n", pctx && EVP_PKEY_encrypt_init(pctx) > 0 ? "ALLOWED" : "refused");
        printf("refusal\tencapsulate-init\t%s\n", pctx && EVP_PKEY_encapsulate_init(pctx, NULL) > 0 ? "ALLOWED" : "refused");
        unsigned char out[132];
        size_t out_size = 0;
        printf("refusal\tprivate-key-present\t%s\n",
               EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, out, sizeof(out), &out_size) ? "ALLOWED" : "refused");
        md = EVP_MD_CTX_new();
        printf("refusal\tdigest-verify-with-sha512\t%s\n", EVP_DigestVerifyInit_ex(md, NULL, "SHA512", NULL, NULL, key, NULL) > 0 ? "ALLOWED" : "refused");
        EVP_MD_CTX_free(md);
        md = EVP_MD_CTX_new();
        printf("refusal\tdigest-verify-pure\t%s\n", EVP_DigestVerifyInit_ex(md, NULL, NULL, NULL, NULL, key, NULL) > 0 ? "allowed" : "REFUSED");
        EVP_MD_CTX_free(md);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(key);
    }
    ERR_clear_error();
}

int main(int argc, char **argv)
{
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 2;
    OSSL_PROVIDER_do_all(NULL, provider, NULL);
    EVP_MD_do_all_provided(NULL, list_EVP_MD, NULL);
    EVP_CIPHER_do_all_provided(NULL, list_EVP_CIPHER, NULL);
    EVP_MAC_do_all_provided(NULL, list_EVP_MAC, NULL);
    EVP_KDF_do_all_provided(NULL, list_EVP_KDF, NULL);
    EVP_RAND_do_all_provided(NULL, list_EVP_RAND, NULL);
    EVP_KEYMGMT_do_all_provided(NULL, list_EVP_KEYMGMT, NULL);
    EVP_SIGNATURE_do_all_provided(NULL, list_EVP_SIGNATURE, NULL);
    EVP_ASYM_CIPHER_do_all_provided(NULL, list_EVP_ASYM_CIPHER, NULL);
    EVP_KEM_do_all_provided(NULL, list_EVP_KEM, NULL);
    EVP_KEYEXCH_do_all_provided(NULL, list_EVP_KEYEXCH, NULL);
    OSSL_ENCODER_do_all_provided(NULL, list_OSSL_ENCODER, NULL);
    OSSL_DECODER_do_all_provided(NULL, list_OSSL_DECODER, NULL);
    OSSL_STORE_LOADER_do_all_provided(NULL, list_OSSL_STORE_LOADER, NULL);
    refusals(argc > 1 ? argv[1] : NULL);
    return 0;
}
