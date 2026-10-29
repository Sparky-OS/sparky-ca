#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""Write tests/data/ed521-vectors.json from the independent oracle.

The keys come from public TEST seeds printed in the file: they are test
fixtures, never anyone's key.  Each negative vector names the rule of RFC 8032
section 5.2.7 or DOC-ICP-01.01 section 2 that it breaks.
"""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from oracle import ED521 as C  # noqa: E402


def seed(number):
    return hashlib.shake_256(f'Sparky CA Ed521 TEST key {number}: public seed, never for real use'.encode()).digest(C.size)


def message(size, tag=0):
    return hashlib.shake_256(f'Sparky CA Ed521 TEST message {size}/{tag}'.encode()).digest(size)


def point_sum(first, second):
    return C.add(first, second)


keys = [seed(n) for n in range(3)]
publics = [C.public_key(k) for k in keys]
scalars = [C.secret_expand(k)[0] for k in keys]
vectors = []


def add(name, public, data, signature, valid, rule, cofactored=None):
    entry = {'name': name, 'public': public.hex(), 'message': data.hex(), 'signature': signature.hex(),
             'valid': valid, 'rule': rule}
    if cofactored is not None:
        entry['cofactored'] = cofactored
    assert C.verify(public, data, signature) == valid, name
    if cofactored is not None:
        assert C.verify(public, data, signature, cofactored=True) == cofactored, name
    vectors.append(entry)


for size in (0, 1, 2, 11, 64, 65, 66, 67, 131, 132, 133, 256, 1023):
    data = message(size)
    add(f'pure-{size}-octets', publics[0], data, C.sign(keys[0], data), True, 'RFC 8032 5.2.6/5.2.7, dom5(0, empty)')
for number in (1, 2):
    data = message(41, number)
    add(f'pure-key-{number}', publics[number], data, C.sign(keys[number], data), True, 'RFC 8032 5.2.6/5.2.7')

data = message(100, 7)
good = C.sign(keys[0], data)
add('wrong-key', publics[1], data, good, False, 'signature by another key')
add('altered-message', publics[0], data[:-1] + bytes([data[-1] ^ 1]), good, False, 'message bound by k')
add('domain-SigEd448', publics[0], data, C.sign(keys[0], data, dom=b'SigEd448\x00\x00'), False, 'dom5 must start with "SigEd521" (DOC-ICP-01.01 2.3)')
add('domain-absent', publics[0], data, C.sign(keys[0], data, dom=b''), False, 'Ed521 always hashes dom5 (DOC-ICP-01.01 2: H(x) = SHAKE256(dom5||x, 132))')
add('domain-without-octets', publics[0], data, C.sign(keys[0], data, dom=b'SigEd521'), False, 'dom5 carries octet(phflag) and octet(OLEN(context))')
add('domain-phflag-1', publics[0], data, C.sign(keys[0], data, phflag=1), False, 'phflag 1 is Ed521ph; pure verification uses 0')
add('domain-context', publics[0], data, C.sign(keys[0], data, context=b'ctx'), False, 'a context the verifier did not ask for')
add('challenge-truncated-66', publics[0], data, C.sign(keys[0], data, challenge_bytes=66), False, 'k from all 132 octets of SHAKE256 (the Go interop bug used 66)')
r_part, s_part = good[:C.size], int.from_bytes(good[C.size:], 'little')
add('s-plus-L', publics[0], data, r_part + (s_part + C.L).to_bytes(C.size, 'little'), False, 'S must be below L (RFC 8032 5.2.7 step 1)', cofactored=False)
add('s-all-ones', publics[0], data, r_part + b'\xff' * C.size, False, 'S out of range')
add('signature-zero', publics[0], data, bytes(2 * C.size), False, 'R = 0 does not decode')

y = 2
while C.decode_point(y.to_bytes(C.size, 'little')) is not None:
    y += 1
add('r-not-on-curve', publics[0], data, y.to_bytes(C.size, 'little') + good[C.size:], False, 'R must decode (RFC 8032 5.2.3 step 3)')
add('r-y-equals-p', publics[0], data, C.p.to_bytes(C.size, 'little') + good[C.size:], False, 'y >= p does not decode (RFC 8032 5.2.3 step 1)')
add('r-negative-zero-x', publics[0], data, (1 | 1 << 527).to_bytes(C.size, 'little') + good[C.size:], False, 'x = 0 with sign bit 1 does not decode (RFC 8032 5.2.3 step 4)')

order2 = (0, C.p - 1)
order4 = (1, 0)
assert C.multiply(2, order2) == (0, 1) and C.multiply(4, order4) == (0, 1) and C.multiply(2, order4) != (0, 1)
for label, torsion in (('order-2', order2), ('order-4', order4)):
    r_point = C.decode_point(r_part)
    shifted = C.encode_point(point_sum(r_point, torsion))
    k = int.from_bytes(C.hash(C.dom(0, b'') + shifted + publics[0] + data), 'little') % C.L
    s = (C.secret_expand(keys[0])[0] * k + (s_part - int.from_bytes(C.hash(C.dom(0, b'') + r_part + publics[0] + data), 'little') % C.L * scalars[0])) % C.L
    add(f'r-plus-{label}-torsion', publics[0], data, shifted + s.to_bytes(C.size, 'little'), False,
        'cofactorless check [S]B = R + [k]A rejects R with a small-order part; the cofactored check accepts it (RFC 8032 5.2.7 step 3 allows either)',
        cofactored=True)

def forge_for_weak_key(name, weak, rule):
    """A signature that passes the bare equation [S]B = R + [k]A for a key outside the prime subgroup."""
    s = int.from_bytes(message(66, 5000), 'little') % C.L
    r_encoded = C.encode_point(C.multiply(s, C.base))
    tag = 0
    while True:
        candidate = message(80, 2000 + tag)
        k = int.from_bytes(C.hash(C.dom(0, b'') + r_encoded + weak + candidate), 'little') % C.L
        signature = r_encoded + s.to_bytes(C.size, 'little')
        weak_point = C.decode_point(weak)
        if weak_point is not None and C.verify(weak, candidate, signature):
            break
        tag += 1
    vectors.append({'name': name, 'public': weak.hex(), 'message': candidate.hex(), 'signature': signature.hex(),
                    'valid': False, 'oracle_without_subgroup_check': True, 'rule': rule})


forge_for_weak_key('key-identity', C.encode_point((0, 1)),
                   'the neutral point verifies any (R = [S]B, S); the provider refuses it as a key')
forge_for_weak_key('key-order-2', C.encode_point(order2),
                   'a small-order key verifies forgeries when k is even; the provider requires [L]A = 0')
forge_for_weak_key('key-order-4', C.encode_point(order4),
                   'a small-order key verifies forgeries when 4 divides k; the provider requires [L]A = 0')
mixed = C.encode_point(point_sum(C.decode_point(publics[0]), order2))
tag = 0
while True:
    candidate = message(80, 1000 + tag)
    signature = C.sign(keys[0], candidate)
    k = int.from_bytes(C.hash(C.dom(0, b'') + signature[:C.size] + mixed + candidate), 'little') % C.L
    r = int.from_bytes(C.hash(C.dom(0, b'') + C.secret_expand(keys[0])[1] + candidate), 'little') % C.L
    forged = signature[:C.size] + ((r + k * scalars[0]) % C.L).to_bytes(C.size, 'little')
    if k % 2 == 0 and C.verify(mixed, candidate, forged):
        break
    tag += 1
vectors.append({'name': 'key-mixed-order', 'public': mixed.hex(), 'message': candidate.hex(), 'signature': forged.hex(),
                'valid': False, 'oracle_without_subgroup_check': True,
                'rule': 'A + T2 passes [S]B = R + [k]A when k is even; the provider requires [L]A = 0 (strict policy)'})
add('key-y-equals-p', C.p.to_bytes(C.size, 'little'), data, good, False, 'y >= p does not decode')
add('key-not-on-curve', y.to_bytes(C.size, 'little'), data, good, False, 'public key must decode')
add('signature-131-octets', publics[0], data, good[:-1], False, 'signature is 132 octets')
add('signature-133-octets', publics[0], data, good + b'\x00', False, 'signature is 132 octets')

output = {
    'comment': 'Ed521 TEST vectors from the independent oracle (tests/oracle.py), checked by tests/spec.py against RFC 8032 and ITI v7. Public TEST seeds, never real keys.',
    'seeds': [k.hex() for k in keys],
    'vectors': vectors,
}
Path(sys.argv[1]).write_text(json.dumps(output, indent=1) + '\n')
print(len(vectors), 'vectors written')
