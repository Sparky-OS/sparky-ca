#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""The provider offers Ed521 verification and nothing else.

Compares the complete algorithm inventory of OpenSSL with the system
configuration alone and with the shipped configuration file that adds the
provider: the only new implementations are the Ed521 key manager, signature
and decoder, all from the provider, and every other line is identical.
Then every private-key operation is refused.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).parent))
from der import ed521_spki, pem  # noqa: E402
import json  # noqa: E402

INVENTORY, PROVIDER, TEMPLATE = (str(Path(value).resolve()) for value in sys.argv[1:4])
DATA = Path(__file__).parent / 'data'
NAMES = 'ED521:1.3.6.1.4.1.44588.2.1'
checks = 0


def check(condition, message):
    global checks
    assert condition, message
    checks += 1
    print('PASS', message)


def configured(directory):
    """The shipped configuration, pointed at the module under test."""
    text = Path(TEMPLATE).read_text()
    assert '\nactivate = 1\n' in text
    text = text.replace('[ed521_sect]\n', f'[ed521_sect]\nmodule = {PROVIDER}\n')
    path = directory / 'openssl.cnf'
    path.write_text(text)
    return path


def inventory(env, key):
    result = subprocess.run([INVENTORY, str(key)], env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


with tempfile.TemporaryDirectory(prefix='ed521-safety-') as temporary:
    directory = Path(temporary)
    stock = dict(os.environ)
    stock.pop('OPENSSL_CONF', None)
    with_provider = dict(stock, OPENSSL_CONF=str(configured(directory)))
    key = directory / 'key.pem'
    vector = json.loads((DATA / 'ed521-vectors.json').read_text())['vectors'][0]
    key.write_text(pem('PUBLIC KEY', ed521_spki(bytes.fromhex(vector['public']))))

    before, after = inventory(stock, key), inventory(with_provider, key)
    algorithms_before = {line for line in before if not line.startswith('refusal\t')}
    algorithms_after = {line for line in after if not line.startswith('refusal\t')}
    added = algorithms_after - algorithms_before
    removed = algorithms_before - algorithms_after
    check(not removed, f'no implementation disappears ({len(algorithms_before)} lines with the system configuration)')
    expected = {
        'provider\ted521\tavailable\t',
        f'keymgmt\t{NAMES}\ted521\t',
        f'signature\t{NAMES}\ted521\t',
        f'decoder\t{NAMES}\ted521\tprovider=ed521,input=der,structure=SubjectPublicKeyInfo',
    }
    normalised = {line.rstrip('\t') for line in added}
    check(normalised == {line.rstrip('\t') for line in expected}, 'the provider adds exactly the Ed521 key manager, signature and decoder: ' + repr(sorted(added)))
    check(not any(line.startswith('capability\t') and line.endswith('\ted521\t') for line in after), 'the provider registers no TLS signature scheme or group')
    for line in algorithms_after - added:
        name_field = line.split('\t')[1] if '\t' in line else ''
        assert 'ED521' not in name_field.upper() or line.startswith('provider'), line
    check(all('\ted521\t' not in line for line in algorithms_after - added), 'every other algorithm is still answered by the providers that answered it before')
    check(any(line == 'provider\tdefault\tavailable\t' for line in after), 'the default provider stays active beside it')

    refusals_before = dict(line.split('\t')[1:3] for line in before if line.startswith('refusal\t'))
    refusals = dict(line.split('\t')[1:3] for line in after if line.startswith('refusal\t'))
    check(refusals_before.get('public-key-loaded') == 'no', 'without the provider an Ed521 public key does not even load')
    check(refusals['public-key-loaded'] == 'yes', 'with the provider the Ed521 public key loads')
    for operation in ('keygen', 'paramgen', 'import-private', 'digest-sign-init', 'sign-init', 'sign-message-init',
                      'derive-init', 'encrypt-init', 'encapsulate-init', 'private-key-present', 'digest-verify-with-sha512'):
        check(refusals[operation] == 'refused', f'{operation} is refused')
    check(refusals['digest-verify-pure'] == 'allowed', 'pure verification is the one operation offered')

    for command in (['openssl', 'genpkey', '-algorithm', 'ED521'],
                    ['openssl', 'pkeyutl', '-sign', '-inkey', str(key), '-pubin', '-in', str(key)]):
        result = subprocess.run(command, env=with_provider, capture_output=True, timeout=30)
        check(result.returncode != 0, ' '.join(command[:3]) + ' fails with the provider loaded')
print(f'{checks} safety checks passed')
