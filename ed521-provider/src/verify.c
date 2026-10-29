/* SPDX-License-Identifier: ISC
 * Copyright (c) 2025 Pedro F. Albanese
 * Copyright (c) 2026 Daniel Campos Ramos
 * Public-operation port of Pedro Albanese's E-521 Go reference, corrected
 * against ITI v7 and DOC-ICP-01.01. This code handles no private scalars.
 *
 * Points are kept in projective coordinates (X : Y : Z), x = X/Z, y = Y/Z,
 * and added with the complete formulas RFC 8032 section 5.2.4 gives for
 * untwisted Edwards curves (a = 1) with non-square d: E-521 is one
 * (d = -376014 is not a square mod 2^521 - 1, checked in tests/spec.py).
 * Only public values pass through here, so variable time is acceptable.
 */
#include "internal.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <string.h>

typedef struct { BIGNUM *x, *y, *z; } POINT;
typedef struct { BIGNUM *p, *n, *d; POINT base; BN_CTX *ctx; } CURVE;

static void point_free(POINT *point)
{
    BN_free(point->x);
    BN_free(point->y);
    BN_free(point->z);
}

static int point_new(POINT *point)
{
    point->x = BN_new();
    point->y = BN_new();
    point->z = BN_new();
    return point->x != NULL && point->y != NULL && point->z != NULL;
}

static int point_identity(POINT *point)
{
    BN_zero(point->x);
    return BN_one(point->y) && BN_one(point->z);
}

static void curve_free(CURVE *curve)
{
    BN_free(curve->p);
    BN_free(curve->n);
    BN_free(curve->d);
    point_free(&curve->base);
    BN_CTX_free(curve->ctx);
}

/* DOC-ICP-01.01 v6.0, section 2: p, d, the base point B and its order L. */
static int curve_new(CURVE *curve)
{
    curve->p = BN_new();
    curve->d = BN_new();
    curve->ctx = BN_CTX_new();
    return curve->p != NULL && curve->d != NULL && curve->ctx != NULL
        && point_new(&curve->base) && BN_one(curve->p)
        && BN_lshift(curve->p, curve->p, 521) && BN_sub_word(curve->p, 1)
        && BN_dec2bn(&curve->n, "1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523")
        && BN_copy(curve->d, curve->p) != NULL && BN_sub_word(curve->d, 376014)
        && BN_dec2bn(&curve->base.x, "1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324")
        && BN_set_word(curve->base.y, 12) && BN_one(curve->base.z);
}

/* RFC 8032 section 5.2.4, addition; out may be a or b. */
static int point_add(CURVE *curve, POINT *out, const POINT *a, const POINT *b)
{
    int ok = 0;
    BN_CTX *ctx = curve->ctx;
    const BIGNUM *p = curve->p;
    BN_CTX_start(ctx);
    BIGNUM *A = BN_CTX_get(ctx), *B = BN_CTX_get(ctx), *C = BN_CTX_get(ctx);
    BIGNUM *D = BN_CTX_get(ctx), *E = BN_CTX_get(ctx), *F = BN_CTX_get(ctx);
    BIGNUM *G = BN_CTX_get(ctx), *H = BN_CTX_get(ctx), *t = BN_CTX_get(ctx);
    if (t == NULL)
        goto end;
    if (!BN_mod_mul(A, a->z, b->z, p, ctx)
        || !BN_mod_sqr(B, A, p, ctx)
        || !BN_mod_mul(C, a->x, b->x, p, ctx)
        || !BN_mod_mul(D, a->y, b->y, p, ctx)
        || !BN_mod_mul(E, C, D, p, ctx)
        || !BN_mod_mul(E, E, curve->d, p, ctx)
        || !BN_mod_sub(F, B, E, p, ctx)
        || !BN_mod_add(G, B, E, p, ctx)
        || !BN_mod_add(H, a->x, a->y, p, ctx)
        || !BN_mod_add(t, b->x, b->y, p, ctx)
        || !BN_mod_mul(H, H, t, p, ctx)
        || !BN_mod_sub(H, H, C, p, ctx)
        || !BN_mod_sub(H, H, D, p, ctx)
        || !BN_mod_mul(t, A, F, p, ctx)
        || !BN_mod_mul(out->x, t, H, p, ctx)
        || !BN_mod_sub(t, D, C, p, ctx)
        || !BN_mod_mul(t, t, G, p, ctx)
        || !BN_mod_mul(out->y, A, t, p, ctx)
        || !BN_mod_mul(out->z, F, G, p, ctx))
        goto end;
    ok = 1;
end:
    BN_CTX_end(ctx);
    return ok;
}

/* RFC 8032 section 5.2.4, doubling; out may be a. */
static int point_double(CURVE *curve, POINT *out, const POINT *a)
{
    int ok = 0;
    BN_CTX *ctx = curve->ctx;
    const BIGNUM *p = curve->p;
    BN_CTX_start(ctx);
    BIGNUM *B = BN_CTX_get(ctx), *C = BN_CTX_get(ctx), *D = BN_CTX_get(ctx);
    BIGNUM *E = BN_CTX_get(ctx), *H = BN_CTX_get(ctx), *J = BN_CTX_get(ctx);
    if (J == NULL)
        goto end;
    if (!BN_mod_add(B, a->x, a->y, p, ctx)
        || !BN_mod_sqr(B, B, p, ctx)
        || !BN_mod_sqr(C, a->x, p, ctx)
        || !BN_mod_sqr(D, a->y, p, ctx)
        || !BN_mod_add(E, C, D, p, ctx)
        || !BN_mod_sqr(H, a->z, p, ctx)
        || !BN_mod_lshift1(H, H, p, ctx)
        || !BN_mod_sub(J, E, H, p, ctx)
        || !BN_mod_sub(B, B, E, p, ctx)
        || !BN_mod_mul(out->x, B, J, p, ctx)
        || !BN_mod_sub(C, C, D, p, ctx)
        || !BN_mod_mul(out->y, E, C, p, ctx)
        || !BN_mod_mul(out->z, E, J, p, ctx))
        goto end;
    ok = 1;
end:
    BN_CTX_end(ctx);
    return ok;
}

static int multiply(CURVE *curve, POINT *out, const POINT *point, const BIGNUM *scalar)
{
    if (!point_identity(out))
        return 0;
    for (int bit = BN_num_bits(scalar) - 1; bit >= 0; --bit) {
        if (!point_double(curve, out, out)
            || (BN_is_bit_set(scalar, bit) && !point_add(curve, out, out, point)))
            return 0;
    }
    return 1;
}

/* x1/z1 == x2/z2 and y1/z1 == y2/z2; Z is never zero for points on the curve. */
static int point_equal(CURVE *curve, const POINT *a, const POINT *b)
{
    int equal = 0;
    BN_CTX *ctx = curve->ctx;
    BN_CTX_start(ctx);
    BIGNUM *left = BN_CTX_get(ctx), *right = BN_CTX_get(ctx);
    if (right != NULL
        && BN_mod_mul(left, a->x, b->z, curve->p, ctx) && BN_mod_mul(right, b->x, a->z, curve->p, ctx)
        && BN_cmp(left, right) == 0
        && BN_mod_mul(left, a->y, b->z, curve->p, ctx) && BN_mod_mul(right, b->y, a->z, curve->p, ctx)
        && BN_cmp(left, right) == 0)
        equal = 1;
    BN_CTX_end(ctx);
    return equal;
}

static int is_identity(const POINT *point)
{
    return BN_is_zero(point->x) && BN_cmp(point->y, point->z) == 0 && !BN_is_zero(point->z);
}

/* RFC 8032 section 5.2.3, with the 66-octet encoding of DOC-ICP-01.01. */
static int decode(CURVE *curve, POINT *point, const unsigned char encoded[66])
{
    unsigned char bytes[66];
    int ok = 0, sign = encoded[65] >> 7;
    memcpy(bytes, encoded, sizeof(bytes));
    bytes[65] &= 127;
    if (BN_lebin2bn(bytes, sizeof(bytes), point->y) == NULL
        || BN_cmp(point->y, curve->p) >= 0 || !BN_one(point->z))
        return 0;
    BN_CTX *ctx = curve->ctx;
    BN_CTX_start(ctx);
    BIGNUM *y2 = BN_CTX_get(ctx), *u = BN_CTX_get(ctx), *v = BN_CTX_get(ctx);
    BIGNUM *inverse = BN_CTX_get(ctx), *square = BN_CTX_get(ctx);
    if (square == NULL || !BN_mod_sqr(y2, point->y, curve->p, ctx)
        || !BN_one(u) || !BN_mod_sub(u, u, y2, curve->p, ctx)
        || !BN_mod_mul(v, y2, curve->d, curve->p, ctx)
        || !BN_mod_sub(v, BN_value_one(), v, curve->p, ctx)
        || BN_mod_inverse(inverse, v, curve->p, ctx) == NULL
        || !BN_mod_mul(square, u, inverse, curve->p, ctx)
        || BN_mod_sqrt(point->x, square, curve->p, ctx) == NULL
        || (BN_is_zero(point->x) && sign))
        goto end;
    if (BN_is_odd(point->x) != sign && !BN_sub(point->x, curve->p, point->x))
        goto end;
    ok = 1;
end:
    BN_CTX_end(ctx);
    return ok;
}

static int public_decodes(CURVE *curve, POINT *public, const unsigned char encoded[66])
{
    return decode(curve, public, encoded) && !is_identity(public);
}

/* A key must also lie in the subgroup of order L: no small-order or mixed-order keys. */
static int public_valid(CURVE *curve, POINT *public, POINT *scratch,
                        const unsigned char encoded[66])
{
    return public_decodes(curve, public, encoded)
        && multiply(curve, scratch, public, curve->n) && is_identity(scratch);
}

int ed521_public_decodes(const unsigned char public_key[66])
{
    CURVE curve = {0};
    POINT public = {0};
    int ok = curve_new(&curve) && point_new(&public)
        && public_decodes(&curve, &public, public_key);
    point_free(&public);
    curve_free(&curve);
    return ok;
}

int ed521_public_valid(const unsigned char public_key[66])
{
    CURVE curve = {0};
    POINT public = {0}, scratch = {0};
    int ok = curve_new(&curve) && point_new(&public) && point_new(&scratch)
        && public_valid(&curve, &public, &scratch, public_key);
    point_free(&public);
    point_free(&scratch);
    curve_free(&curve);
    return ok;
}

/* RFC 8032 section 5.2.7 with H(x) = SHAKE256(dom5(0, empty) || x, 132),
 * dom5 = "SigEd521" || 0x00 || 0x00 (DOC-ICP-01.01 sections 2 and 2.3).
 * Step 3 uses the cofactorless check [S]B = R + [k]A, which RFC 8032 allows. */
int ed521_verify(OSSL_LIB_CTX *libctx, const unsigned char public_key[66],
                 const unsigned char signature[132], const unsigned char *message,
                 size_t message_size)
{
    static const unsigned char dom[] = {'S','i','g','E','d','5','2','1',0,0};
    CURVE curve = {0};
    POINT a = {0}, r = {0}, left = {0}, right = {0};
    BIGNUM *s = BN_lebin2bn(signature + 66, 66, NULL), *k = BN_new();
    EVP_MD *md = EVP_MD_fetch(libctx, "SHAKE256", "provider=default");
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    unsigned char challenge[132];
    int ok = 0;
    if (s == NULL || k == NULL || md == NULL || hash == NULL
        || !curve_new(&curve) || !point_new(&a) || !point_new(&r)
        || !point_new(&left) || !point_new(&right) || BN_cmp(s, curve.n) >= 0
        || !decode(&curve, &r, signature)
        || !public_valid(&curve, &a, &right, public_key)
        || !EVP_DigestInit_ex2(hash, md, NULL)
        || !EVP_DigestUpdate(hash, dom, sizeof(dom))
        || !EVP_DigestUpdate(hash, signature, 66)
        || !EVP_DigestUpdate(hash, public_key, 66)
        || !EVP_DigestUpdate(hash, message, message_size)
        || !EVP_DigestFinalXOF(hash, challenge, sizeof(challenge))
        || BN_lebin2bn(challenge, sizeof(challenge), k) == NULL
        || !BN_nnmod(k, k, curve.n, curve.ctx)
        || !multiply(&curve, &left, &curve.base, s)
        || !multiply(&curve, &right, &a, k)
        || !point_add(&curve, &right, &r, &right))
        goto end;
    ok = point_equal(&curve, &left, &right);
end:
    BN_free(s);
    BN_free(k);
    EVP_MD_CTX_free(hash);
    EVP_MD_free(md);
    point_free(&a);
    point_free(&r);
    point_free(&left);
    point_free(&right);
    curve_free(&curve);
    return ok;
}
