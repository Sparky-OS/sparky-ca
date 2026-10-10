/* SPDX-License-Identifier: ISC
 * Copyright (c) 2025 Pedro F. Albanese
 * Copyright (c) 2026 Daniel Campos Ramos
 * Public-operation port of Pedro Albanese's E-521 Go reference, corrected
 * against ITI v7 and DOC-ICP-01.01. This code handles no private scalars.
 */
#include "internal.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <string.h>

typedef struct { BIGNUM *x, *y; } POINT;
typedef struct { BIGNUM *p, *n, *d; POINT base; BN_CTX *ctx; } CURVE;

static void point_free(POINT *point)
{
    BN_free(point->x);
    BN_free(point->y);
}

static int point_new(POINT *point)
{
    point->x = BN_new();
    point->y = BN_new();
    return point->x != NULL && point->y != NULL;
}

static void curve_free(CURVE *curve)
{
    BN_free(curve->p);
    BN_free(curve->n);
    BN_free(curve->d);
    point_free(&curve->base);
    BN_CTX_free(curve->ctx);
}

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
        && BN_set_word(curve->base.y, 12);
}

static int point_add(CURVE *curve, POINT *out, const POINT *a, const POINT *b)
{
    int ok = 0;
    BN_CTX *ctx = curve->ctx;
    BN_CTX_start(ctx);
    BIGNUM *xy = BN_CTX_get(ctx), *yx = BN_CTX_get(ctx);
    BIGNUM *xx = BN_CTX_get(ctx), *yy = BN_CTX_get(ctx);
    BIGNUM *t = BN_CTX_get(ctx), *dx = BN_CTX_get(ctx), *dy = BN_CTX_get(ctx);
    BIGNUM *ix = BN_CTX_get(ctx), *iy = BN_CTX_get(ctx);
    BIGNUM *x = BN_CTX_get(ctx), *y = BN_CTX_get(ctx);
    if (y == NULL)
        goto end;
    if (!BN_mod_mul(xy, a->x, b->y, curve->p, ctx)
        || !BN_mod_mul(yx, a->y, b->x, curve->p, ctx)
        || !BN_mod_mul(xx, a->x, b->x, curve->p, ctx)
        || !BN_mod_mul(yy, a->y, b->y, curve->p, ctx)
        || !BN_mod_mul(t, xx, yy, curve->p, ctx)
        || !BN_mod_mul(t, t, curve->d, curve->p, ctx)
        || !BN_one(dx) || !BN_one(dy)
        || !BN_mod_add(dx, dx, t, curve->p, ctx)
        || !BN_mod_sub(dy, dy, t, curve->p, ctx)
        || BN_mod_inverse(ix, dx, curve->p, ctx) == NULL
        || BN_mod_inverse(iy, dy, curve->p, ctx) == NULL
        || !BN_mod_add(x, xy, yx, curve->p, ctx)
        || !BN_mod_sub(y, yy, xx, curve->p, ctx)
        || !BN_mod_mul(x, x, ix, curve->p, ctx)
        || !BN_mod_mul(y, y, iy, curve->p, ctx))
        goto end;
    ok = BN_copy(out->x, x) != NULL && BN_copy(out->y, y) != NULL;
end:
    BN_CTX_end(ctx);
    return ok;
}

static int multiply(CURVE *curve, POINT *out, const POINT *point, const BIGNUM *scalar)
{
    BN_zero(out->x);
    if (!BN_one(out->y))
        return 0;
    for (int bit = BN_num_bits(scalar) - 1; bit >= 0; --bit) {
        if (!point_add(curve, out, out, out)
            || (BN_is_bit_set(scalar, bit) && !point_add(curve, out, out, point)))
            return 0;
    }
    return 1;
}

static int decode(CURVE *curve, POINT *point, const unsigned char encoded[66])
{
    unsigned char bytes[66];
    int ok = 0, sign = encoded[65] >> 7;
    memcpy(bytes, encoded, sizeof(bytes));
    bytes[65] &= 127;
    if (BN_lebin2bn(bytes, sizeof(bytes), point->y) == NULL
        || BN_cmp(point->y, curve->p) >= 0)
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

static int identity(const POINT *point)
{
    return BN_is_zero(point->x) && BN_is_one(point->y);
}

static int public_valid(CURVE *curve, POINT *public, POINT *scratch,
                        const unsigned char encoded[66])
{
    return decode(curve, public, encoded) && !identity(public)
        && multiply(curve, scratch, public, curve->n) && identity(scratch);
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
        || !public_valid(&curve, &a, &right, public_key)
        || !decode(&curve, &r, signature)
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
    ok = BN_cmp(left.x, right.x) == 0 && BN_cmp(left.y, right.y) == 0;
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
