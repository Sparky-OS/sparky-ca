#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""Seed corpora for the harnesses, from the public fixtures and TEST seeds.

  make-seeds.py OUTDIR      writes OUTDIR/{spki,verify,verify-v7,x509}
  make-seeds.py --header    rewrites v7.h from ../data/ICP-Brasilv7.der
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import der  # noqa: E402
from oracle import ED521  # noqa: E402

DATA = HERE.parent / 'data'


def header():
    data = (DATA / 'ICP-Brasilv7.der').read_bytes()
    lines = ['    ' + ', '.join(f'0x{x:02x}' for x in data[i:i + 16]) + ',' for i in range(0, len(data), 16)]
    (HERE / 'v7.h').write_text(
        '/* SPDX-License-Identifier: ISC\n'
        ' * ITI\'s public AC Raiz v7 certificate (DER SHA-256\n'
        f' * {hashlib.sha256(data).hexdigest()}), written out\n'
        ' * by tests/fuzz/make-seeds.py so that the harnesses need no file at run time.\n'
        ' */\n#ifndef ED521_FUZZ_V7_H\n#define ED521_FUZZ_V7_H\nstatic const unsigned char v7_der[] = {\n'
        + '\n'.join(lines) + '\n};\n#endif\n')


def seed(number):
    return hashlib.shake_256(f'Sparky CA Ed521 TEST key {number}: public seed, never for real use'.encode()).digest(ED521.size)


def test_chain():
    """Root, intermediate and signer of the TEST hierarchy (chain.py), as DER."""
    sys.path.insert(0, str(HERE.parent))
    import chain
    names = {k: f'TEST ONLY Ed521 {k} (Sparky CA test hierarchy, not ICP-Brasil)' for k in ('root', 'intermediate', 'signer')}
    keys = {k: seed(n) for k, n in (('root', 10), ('intermediate', 11), ('signer', 12))}
    raw = {k: ED521.public_key(s) for k, s in keys.items()}
    root = chain.certificate(1, names['root'], names['root'], der.ed521_spki(raw['root']), raw['root'], keys['root'], raw['root'], True)
    intermediate = chain.certificate(2, names['root'], names['intermediate'], der.ed521_spki(raw['intermediate']), raw['intermediate'], keys['root'], raw['root'], True)
    signer = chain.certificate(3, names['intermediate'], names['signer'], der.ed521_spki(raw['signer']), raw['signer'], keys['intermediate'], raw['intermediate'], False)
    return {'test-root': root, 'test-intermediate': intermediate, 'test-signer': signer}


def main():
    if sys.argv[1] == '--header':
        header()
        return
    out = Path(sys.argv[1])
    for name in ('spki', 'verify', 'verify-v7', 'x509'):
        (out / name).mkdir(parents=True, exist_ok=True)
    v7 = (DATA / 'ICP-Brasilv7.der').read_bytes()
    tbs, _, v7_public, v7_signature = der.certificate_parts(v7)
    crl_tbs, _, _, crl_signature = der.certificate_parts((DATA / 'LCRacraizv7.crl').read_bytes(), crl=True)
    certificates = {'v7': v7}
    for name in ('synthetic-root', 'synthetic-intermediate', 'synthetic-leaf'):
        certificates[name] = (DATA / f'{name}.der').read_bytes()
    certificates.update(test_chain())
    for name, value in certificates.items():
        (out / 'x509' / name).write_bytes(value)
        (out / 'spki' / f'cert-{name}').write_bytes(value)
        fields = der.children(der.read(der.children(der.read(value)[1])[0][2])[1])
        offset = 1 if fields[0][0] == 0xa0 else 0
        (out / 'spki' / f'spki-{name}').write_bytes(fields[offset + 5][2])
    algorithm = bytes.fromhex('300c060a2b0601040182dc2c0201')
    identity = bytes([1]) + bytes(65)
    malformed = {
        'identity': identity, 'negative-zero': identity[:-1] + b'\x80',
        'y-equals-p': ((1 << 521) - 1).to_bytes(66, 'little'), 'order-2': ((1 << 521) - 2).to_bytes(66, 'little'),
        'short': v7_public[:65], 'long': v7_public + b'\x00',
    }
    for name, key in malformed.items():
        (out / 'spki' / f'malformed-{name}').write_bytes(der.sequence(algorithm, der.bit_string(key)))
    (out / 'spki' / 'malformed-unused-bits').write_bytes(der.sequence(algorithm, der.tlv(0x03, b'\x01' + v7_public)))
    (out / 'spki' / 'malformed-null-parameters').write_bytes(der.sequence(der.sequence(der.oid(der.ED521_OID), b'\x05\x00'), der.bit_string(v7_public)))
    (out / 'spki' / 'malformed-trailing').write_bytes(der.ed521_spki(v7_public) + b'\x00')
    ec = subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'], capture_output=True, check=True).stdout
    (out / 'spki' / 'other-p256').write_bytes(subprocess.run(['openssl', 'pkey', '-pubout', '-outform', 'DER'], input=ec, capture_output=True, check=True).stdout)
    vectors = json.loads((DATA / 'ed521-vectors.json').read_text())['vectors']
    for vector in vectors:
        public, message, signature = (bytes.fromhex(vector[k]) for k in ('public', 'message', 'signature'))
        (out / 'spki' / f'vector-{vector["name"]}').write_bytes(der.ed521_spki(public))
        if len(public) == 66 and len(signature) == 132:
            (out / 'verify' / vector['name']).write_bytes(public + signature + message)
    (out / 'verify' / 'v7-self-signature').write_bytes(v7_public + v7_signature + tbs)
    (out / 'verify' / 'v7-crl').write_bytes(v7_public + crl_signature + crl_tbs)
    (out / 'verify-v7' / 'v7-self-signature').write_bytes(v7_signature + tbs)
    (out / 'verify-v7' / 'v7-crl').write_bytes(crl_signature + crl_tbs)
    for name in ('spki', 'verify', 'verify-v7', 'x509'):
        print(name, len(list((out / name).iterdir())), 'seeds')


if __name__ == '__main__':
    main()
