# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""Independent EdDSA reference for untwisted Edwards curves (a = 1).

Written from RFC 8032 sections 3 and 5.2 and from the E-521 table of ITI's
DOC-ICP-01.01 v6.0, section 2, so that it shares no code with the C provider
or with the Go library.  It uses affine coordinates and Python integers,
while the provider uses projective coordinates and OpenSSL BIGNUMs, so the
two implementations agree only if both follow the specification.

The same generic code runs Ed448 (checked against the RFC 8032 section 7.4
and 7.5 test vectors) and Ed521.  Signing exists here only to make test
vectors from public test seeds; it is not constant time and must never see
a real private key.
"""
import hashlib


class Curve:
    def __init__(self, name, p, d, base, order, c, n, b, hash_bytes, prefix):
        self.name, self.p, self.d, self.base, self.L = name, p, d % p, base, order
        self.c, self.n, self.b, self.hash_bytes, self.prefix = c, n, b, hash_bytes, prefix
        self.size = b // 8

    def dom(self, phflag, context):
        """dom4 of RFC 8032 section 5.2, dom5 of DOC-ICP-01.01 section 2.3."""
        if len(context) > 255:
            raise ValueError('context longer than 255 octets')
        return self.prefix + bytes([phflag, len(context)]) + context

    def hash(self, data):
        return hashlib.shake_256(data).digest(self.hash_bytes)

    def on_curve(self, point):
        x, y = point
        p = self.p
        return (x * x + y * y - 1 - self.d * x * x * y * y) % p == 0

    def add(self, first, second):
        x1, y1 = first
        x2, y2 = second
        p = self.p
        t = self.d * x1 * x2 * y1 * y2 % p
        x3 = (x1 * y2 + y1 * x2) * pow(1 + t, -1, p) % p
        y3 = (y1 * y2 - x1 * x2) * pow(1 - t, -1, p) % p
        return x3, y3

    def multiply(self, scalar, point):
        result = (0, 1)
        addend = point
        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            scalar >>= 1
        return result

    def encode_point(self, point):
        x, y = point
        value = y | ((x & 1) << (self.b - 1))
        return value.to_bytes(self.size, 'little')

    def decode_point(self, data):
        """RFC 8032 section 5.2.3, generalised to b bits; None on failure."""
        if len(data) != self.size:
            return None
        value = int.from_bytes(data, 'little')
        sign = value >> (self.b - 1)
        y = value & ((1 << (self.b - 1)) - 1)
        p = self.p
        if y >= p:
            return None
        u = (y * y - 1) % p
        v = (self.d * y * y - 1) % p
        assert p % 4 == 3
        candidate = u * pow(v, -1, p) % p
        x = pow(candidate, (p + 1) // 4, p)
        if v * x * x % p != u:
            return None
        if x == 0 and sign:
            return None
        if x & 1 != sign:
            x = p - x
        return x, y

    def secret_expand(self, secret):
        """RFC 8032 section 5.2.5: the scalar s and the prefix."""
        digest = self.hash(secret)
        low = int.from_bytes(digest[:self.size], 'little')
        scalar = (1 << self.n) | (low & ((1 << self.n) - 1) & ~((1 << self.c) - 1))
        return scalar, digest[self.size:]

    def public_key(self, secret):
        scalar, _ = self.secret_expand(secret)
        return self.encode_point(self.multiply(scalar, self.base))

    def sign(self, secret, message, context=b'', phflag=0, dom=None, challenge_bytes=None):
        """RFC 8032 section 5.2.6; dom and challenge_bytes exist only to build negative vectors."""
        scalar, prefix = self.secret_expand(secret)
        public = self.encode_point(self.multiply(scalar, self.base))
        domain = self.dom(phflag, context) if dom is None else dom
        r = int.from_bytes(self.hash(domain + prefix + message), 'little') % self.L
        encoded_r = self.encode_point(self.multiply(r, self.base))
        digest = self.hash(domain + encoded_r + public + message)
        if challenge_bytes is not None:
            digest = digest[:challenge_bytes]
        k = int.from_bytes(digest, 'little') % self.L
        s = (r + k * scalar) % self.L
        return encoded_r + s.to_bytes(self.size, 'little')

    def verify(self, public, message, signature, context=b'', phflag=0, cofactored=False):
        """RFC 8032 section 5.2.7.  The cofactorless check is the strict one."""
        if len(signature) != 2 * self.size:
            return False
        r = self.decode_point(signature[:self.size])
        a = self.decode_point(public)
        s = int.from_bytes(signature[self.size:], 'little')
        if r is None or a is None or s >= self.L:
            return False
        digest = self.hash(self.dom(phflag, context) + signature[:self.size] + public + message)
        k = int.from_bytes(digest, 'little') % self.L
        left = self.multiply(s, self.base)
        right = self.add(r, self.multiply(k, a))
        if cofactored:
            factor = 1 << self.c
            return self.multiply(factor, left) == self.multiply(factor, right)
        return left == right


ED448 = Curve(
    'Ed448', p=2**448 - 2**224 - 1, d=-39081,
    base=(224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710,
          298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660),
    order=2**446 - 13818066809895115352007386748515426880336692474882178609894547503885,
    c=2, n=447, b=456, hash_bytes=114, prefix=b'SigEd448')

# DOC-ICP-01.01 v6.0, section 2, "Parâmetros para a curva E521".
ED521 = Curve(
    'Ed521', p=2**521 - 1, d=-376014,
    base=(1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324, 12),
    order=1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523,
    c=2, n=520, b=528, hash_bytes=132, prefix=b'SigEd521')


def ed448ph(message):
    """RFC 8032 section 5.2: PH(M) = SHAKE256(M, 64) for Ed448ph."""
    return hashlib.shake_256(message).digest(64)
