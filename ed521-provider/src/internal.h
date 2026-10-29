/* SPDX-License-Identifier: ISC
 * Copyright (c) 2025 Pedro F. Albanese
 * Copyright (c) 2026 Daniel Campos Ramos
 */
#ifndef ED521_INTERNAL_H
#define ED521_INTERNAL_H
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#define ED521_OID "1.3.6.1.4.1.44588.2.1"
#define ED521_VERSION "0.2.0"
#define ED521_NAMES "ED521:Ed521:" ED521_OID
typedef struct {
    OSSL_LIB_CTX *libctx;
    OSSL_FUNC_BIO_read_ex_fn *read_ex;
} ED521_PROVIDER;
typedef struct {
    unsigned char public_key[66];
    int present;
} ED521_KEY;
int ed521_public_decodes(const unsigned char public_key[66]);
int ed521_public_valid(const unsigned char public_key[66]);
int ed521_verify(OSSL_LIB_CTX *libctx, const unsigned char public_key[66],
                 const unsigned char signature[132], const unsigned char *message,
                 size_t message_size);
extern const OSSL_DISPATCH ed521_keymgmt[];
extern const OSSL_DISPATCH ed521_decoder[];
extern const OSSL_DISPATCH ed521_signature[];
#endif
