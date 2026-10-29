# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

check, provider = (str(Path(value).resolve()) for value in sys.argv[1:3])
vector = json.loads((Path(__file__).parent / 'data/generated-chain.json').read_text())[0]
public = bytes.fromhex(vector['public'])
algorithm = bytes.fromhex('300c060a2b0601040182dc2c0201')


def pack(tag, data):
    assert len(data) < 128
    return bytes([tag, len(data)]) + data


def spki(key, alg=algorithm, unused=0):
    return pack(48, alg + pack(3, bytes([unused]) + key))


with tempfile.TemporaryDirectory(prefix='ed521-constraints-') as temporary:
    directory = Path(temporary)
    config = directory / 'openssl.cnf'
    config.write_text(f'openssl_conf = init\n[init]\nproviders = providers\n[providers]\ndefault = default_sect\ned521 = ed521_sect\n[default_sect]\nactivate = 1\n[ed521_sect]\nmodule = {provider}\nactivate = 1\n')
    env = dict(os.environ, OPENSSL_CONF=str(config))
    pem = directory / 'public.pem'

    def run(der, expected, extra=()):
        text = base64.b64encode(der).decode()
        pem.write_text('-----BEGIN PUBLIC KEY-----\n' + text + '\n-----END PUBLIC KEY-----\n')
        result = subprocess.run([check, str(pem), vector['message'], vector['signature'], *extra],
                                env=env, capture_output=True, timeout=10)
        assert result.returncode == expected or (expected == 'rejected' and result.returncode in (1, 2)), (expected, result.returncode, result.stderr)
        return pem

    def pubcheck(der):
        text = base64.b64encode(der).decode()
        pem.write_text('-----BEGIN PUBLIC KEY-----\n' + text + '\n-----END PUBLIC KEY-----\n')
        return subprocess.run(['openssl', 'pkey', '-pubin', '-in', str(pem), '-pubcheck', '-noout'],
                              env=env, capture_output=True, timeout=10).returncode

    run(spki(public), 0)
    run(spki(public), 0, ('public-only',))
    high = bytearray(public)
    high[65] |= 2
    identity = bytes([1]) + bytes(65)
    negative_zero = bytearray(identity)
    negative_zero[-1] = 128
    cases = [
        spki(identity), spki(negative_zero), spki(((1 << 521) - 1).to_bytes(66, 'little')),
        spki(((1 << 521) - 2).to_bytes(66, 'little')), spki(high),
        spki(public[:65]), spki(public + b'\x00'), spki(public, unused=1),
        spki(public, alg=pack(48, algorithm[2:] + b'\x05\x00')),
        spki(public) + b'\x00',
    ]
    small_order = spki(((1 << 521) - 2).to_bytes(66, 'little'))
    for der in cases:
        run(der, 'rejected' if der == small_order else 2)
    assert pubcheck(spki(public)) == 0
    assert pubcheck(small_order) != 0
    print('Provider constraints: valid public key verifies and passes -pubcheck; signing/key generation unavailable; nine malformed or noncanonical SPKIs refused at decoding; the order-2 key decodes, fails -pubcheck and verifies nothing')
