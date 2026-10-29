/* SPDX-License-Identifier: ISC
 * Copyright (c) 2026 Daniel Campos Ramos
 *
 * The harnesses link the provider's sources and register it as a built-in
 * provider, so its code is instrumented for coverage and the sanitizers,
 * then load it beside OpenSSL's default provider, as the shipped
 * configuration does.
 */
#ifndef ED521_FUZZ_COMMON_H
#define ED521_FUZZ_COMMON_H
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <stdlib.h>

extern OSSL_provider_init_fn OSSL_provider_init;

/* The providers stay referenced here for the whole run: OSSL_PROVIDER_load hands
 * its reference to the caller, and without one LeakSanitizer reports the
 * provider objects (even OpenSSL's default provider alone) as lost. */
static OSSL_PROVIDER *ed521_fuzz_default, *ed521_fuzz_provider;

static inline void ed521_fuzz_setup(void)
{
    if (ed521_fuzz_provider != NULL)
        return;
    if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)
        || !OSSL_PROVIDER_add_builtin(NULL, "ed521", OSSL_provider_init)
        || (ed521_fuzz_default = OSSL_PROVIDER_load(NULL, "default")) == NULL
        || (ed521_fuzz_provider = OSSL_PROVIDER_load(NULL, "ed521")) == NULL)
        abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
#endif
