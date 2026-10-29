#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""Check the independent oracle against the specifications before it judges the provider.

1. RFC 8032 section 7.4 and 7.5: every Ed448 and Ed448ph vector, key generation,
   signing and verification, through the same generic code that runs Ed521.
2. DOC-ICP-01.01 v6.0 section 2: the E-521 parameters.
3. ITI's real Ed521 signatures: the AC Raiz v7 self-signature and the v7 CRL.
"""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from oracle import ED448, ED521, ed448ph  # noqa: E402
from der import certificate_parts  # noqa: E402

DATA = Path(__file__).parent / 'data'
checks = 0


def check(condition, message):
    global checks
    assert condition, message
    checks += 1


def probable_prime(number):
    if number % 2 == 0:
        return number == 2
    d, r = number - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53):
        x = pow(base, d, number)
        if x in (1, number - 1):
            continue
        for _ in range(r - 1):
            x = x * x % number
            if x == number - 1:
                break
        else:
            return False
    return True


rfc = json.loads((DATA / 'rfc8032-ed448.json').read_text())['vectors']
check(len(rfc) == 11, 'RFC 8032 has nine Ed448 and two Ed448ph vectors')
for vector in rfc:
    secret, public = bytes.fromhex(vector['secret']), bytes.fromhex(vector['public'])
    message, context = bytes.fromhex(vector['message']), bytes.fromhex(vector['context'])
    signature = bytes.fromhex(vector['signature'])
    phflag = 1 if vector['algorithm'] == 'Ed448ph' else 0
    signed = ed448ph(message) if phflag else message
    check(ED448.public_key(secret) == public, vector['title'] + ': public key')
    check(ED448.sign(secret, signed, context, phflag) == signature, vector['title'] + ': signature')
    check(ED448.verify(public, signed, signature, context, phflag), vector['title'] + ': verifies')
    check(not ED448.verify(public, signed + b'x', signature, context, phflag), vector['title'] + ': altered message fails')
    check(not ED448.verify(public, signed, signature, context + b'x', phflag), vector['title'] + ': other context fails')
    check(not ED448.verify(public, signed, signature, context, 1 - phflag), vector['title'] + ': other phflag fails')

curve = ED521
p, d, L = curve.p, curve.d, curve.L
check(p == 2**521 - 1 and probable_prime(p), 'p = 2^521 - 1 is prime')
check(probable_prime(L), 'L is prime')
check(L.bit_length() == 519, 'L has 519 bits')
check(pow(d, (p - 1) // 2, p) == p - 1, 'd = -376014 is not a square, so the Edwards addition law is complete (RFC 8032 section 5.2.4)')
check(p % 4 == 3, 'p = 3 mod 4: square roots by one exponentiation (RFC 8032 section 5.2.3)')
check(curve.on_curve(curve.base), 'B is on E-521')
check(curve.multiply(L, curve.base) == (0, 1), '[L]B is the neutral point')
check(curve.multiply(4, curve.base) != (0, 1), 'B is not a small-order point')
check(curve.decode_point(curve.encode_point(curve.base)) == curve.base, 'B encodes and decodes')
check(curve.size == 66 and curve.hash_bytes == 132, 'b = 528 bits, H gives 132 octets')
check(curve.dom(0, b'') == b'SigEd521\x00\x00', 'dom5(0, empty) of DOC-ICP-01.01 section 2.3')

v7 = (DATA / 'ICP-Brasilv7.der').read_bytes()
tbs, algorithm, public, signature = certificate_parts(v7)
check(algorithm == bytes.fromhex('060a2b0601040182dc2c0201'), 'v7 is signed with OID 1.3.6.1.4.1.44588.2.1, no parameters')
check(len(public) == 66 and len(signature) == 132, 'v7 key 66 octets, signature 132 octets')
check(curve.verify(public, tbs, signature), 'ITI v7 self-signature verifies (PureEd521, empty context)')
check(not curve.verify(public, tbs, signature, phflag=1), 'v7 is not Ed521ph')
check(not curve.verify(public, tbs + b'\x00', signature), 'v7 altered TBS fails')
crl = (DATA / 'LCRacraizv7.crl').read_bytes()
crl_tbs, crl_algorithm, _, crl_signature = certificate_parts(crl, crl=True)
check(crl_algorithm == algorithm and len(crl_signature) == 132, 'v7 CRL signed with Ed521')
check(curve.verify(public, crl_tbs, crl_signature), "ITI's v7 CRL signature verifies with the v7 key")
print(f'{checks} specification checks passed: RFC 8032 Ed448/Ed448ph vectors through the generic oracle, DOC-ICP-01.01 E-521 parameters, ITI v7 self-signature and CRL')
