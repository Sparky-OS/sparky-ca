#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""The provider against ITI's real Ed521 signatures and the oracle's TEST vectors.

Known answers: the v7 self-signature (2018) and the v7 CRL (ITI's current list).
Negatives: every rule in tests/data/ed521-vectors.json, all 132 single-bit
signature mutations of the v7 self-signature and of the CRL, and the same
vectors without the provider (OpenSSL's default provider alone must fail).
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).parent))
from der import certificate_parts, ed521_spki, pem  # noqa: E402

CHECK, PROVIDER = (str(Path(value).resolve()) for value in sys.argv[1:3])
DATA = Path(__file__).parent / 'data'
checks = 0


def check(condition, message):
    global checks
    assert condition, message
    checks += 1


with tempfile.TemporaryDirectory(prefix='ed521-vectors-') as temporary:
    directory = Path(temporary)
    config = directory / 'openssl.cnf'
    config.write_text(f'openssl_conf = init\n[init]\nproviders = providers\n[providers]\ndefault = default_sect\ned521 = ed521_sect\n[default_sect]\nactivate = 1\n[ed521_sect]\nmodule = {PROVIDER}\nactivate = 1\n')
    configured = dict(os.environ, OPENSSL_CONF=str(config))
    plain = dict(os.environ, OPENSSL_CONF='/dev/null')
    key = directory / 'key.pem'

    def verify(public, message, signature, env=configured):
        key.write_text(pem('PUBLIC KEY', ed521_spki(public)))
        result = subprocess.run([CHECK, str(key), message.hex(), signature.hex()], env=env, capture_output=True, timeout=30)
        return result.returncode

    real = []
    v7 = (DATA / 'ICP-Brasilv7.der').read_bytes()
    tbs, _, public, signature = certificate_parts(v7)
    real.append(('v7 self-signature', tbs, signature))
    crl_tbs, _, _, crl_signature = certificate_parts((DATA / 'LCRacraizv7.crl').read_bytes(), crl=True)
    real.append(('v7 CRL', crl_tbs, crl_signature))
    for name, message, sig in real:
        check(verify(public, message, sig) == 0, name + ' verifies with the provider')
        check(verify(public, message, sig, plain) != 0, name + ' fails with the default provider alone')
        for index in range(len(sig)):
            bad = bytearray(sig)
            bad[index] ^= 1 << (index % 8)
            check(verify(public, message, bytes(bad)) != 0, f'{name}: bit flip in signature octet {index} rejected')
        check(verify(public, message[:-1] + bytes([message[-1] ^ 1]), sig) != 0, name + ': altered message rejected')

    vectors = json.loads((DATA / 'ed521-vectors.json').read_text())['vectors']
    for vector in vectors:
        public, message, sig = (bytes.fromhex(vector[field]) for field in ('public', 'message', 'signature'))
        code = verify(public, message, sig)
        if vector['valid']:
            check(code == 0, vector['name'] + ' verifies')
            check(verify(public, message, sig, plain) != 0, vector['name'] + ' fails without the provider')
        else:
            check(code != 0, vector['name'] + ' rejected: ' + vector['rule'])
print(f'{checks} provider checks passed: ITI v7 self-signature and CRL, {len(vectors)} oracle vectors, 264 signature mutations, default-only controls')
