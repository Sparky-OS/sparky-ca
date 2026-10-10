# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check real v7 capability detection and fully verified synthetic Ed521 chains."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

binary, provider = (str(Path(value).resolve()) for value in sys.argv[1:3])
source = Path(__file__).resolve().parents[1]
fixtures = source / 'ed521-provider/tests/data'
checks = 0


def pem(der):
    text = base64.b64encode(der).decode()
    return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(text[i:i+64] for i in range(0, len(text), 64)) + '\n-----END CERTIFICATE-----\n'


def check(value, message):
    global checks
    assert value, message
    checks += 1
    print('PASS ' + message, flush=True)


with tempfile.TemporaryDirectory(prefix='sparky-ca-provider-') as temporary:
    directory = Path(temporary)
    config = directory / 'openssl.cnf'
    config.write_text(f'openssl_conf = init\n[init]\nproviders = providers\n[providers]\ndefault = default_sect\ned521 = ed521_sect\n[default_sect]\nactivate = 1\n[ed521_sect]\nmodule = {provider}\nactivate = 1\n')
    env = dict(os.environ, OPENSSL_CONF=str(config))

    def run(args, success=True, configured=True):
        result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True, timeout=60,
                                env=env if configured else dict(env, OPENSSL_CONF='/dev/null'))
        if success and result.returncode:
            raise AssertionError(result.stderr)
        return result

    records = json.loads(run(['--data', source / 'data', 'list']).stdout)
    v7 = next(item for item in records if item['sha256'] == '5657e70580eb678983f3ed7dfce091d84cae6549389a47fccda8d0e4dc2cf576')
    check(len(records) == 331 and v7['installable'] and not v7['requiresChoice'] and v7['note'] == '',
          'real v7 signature capability clears only its unsupported marker in the complete catalogue')
    plain = json.loads(run(['--data', source / 'data', 'list'], configured=False).stdout)
    check(next(item for item in plain if item['sha256'] == v7['sha256'])['requiresChoice'],
          'without a provider the real v7 still requires explicit choice')

    data = directory / 'data'
    (data / 'roots').mkdir(parents=True)
    real = (fixtures / 'ICP-Brasilv7.der').read_bytes()
    root = (fixtures / 'synthetic-root.der').read_bytes()
    intermediate = (fixtures / 'synthetic-intermediate.der').read_bytes()
    roots = []
    for name, der in [('v7.crt', real), ('synthetic.crt', root)]:
        (data / 'roots' / name).write_text(pem(der))
        roots.append({'file': name, 'sha256': hashlib.sha256(der).hexdigest()})
    (data / 'pins.json').write_text(json.dumps({'roots': roots}))
    catalogue = directory / 'catalogue.json'
    document = {'schema': 1, 'certificates': [{'name': 'AC_OAB_synthetic.crt', 'pem': pem(intermediate)}]}
    catalogue.write_text(json.dumps(document))
    args = ['--data', data, '--catalogue', catalogue]
    records = json.loads(run([*args, 'list']).stdout)
    check(len(records) == 1 and records[0]['verification'] == 'signature-verified' and records[0]['installable'],
          'synthetic Ed521 intermediate verifies its actual signature without bundle-integrity exemptions')
    check(run([*args, 'list'], success=False, configured=False).returncode != 0,
          'synthetic Ed521 chain fails when the provider is absent')
    altered = bytearray(intermediate)
    altered[-1] ^= 1
    document['certificates'][0]['pem'] = pem(altered)
    catalogue.write_text(json.dumps(document))
    check(run([*args, 'list'], success=False).returncode != 0,
          'an altered Ed521 signature fails with the provider loaded')
    document['certificates'][0]['pem'] = pem(intermediate)
    catalogue.write_text(json.dumps(document))
    (data / 'pins.json').write_text(json.dumps({'roots': roots[:1]}))
    check(run([*args, 'list'], success=False).returncode != 0,
          'a valid Ed521 signature cannot introduce an unpinned root')
    (data / 'pins.json').write_text(json.dumps({'roots': roots}))

    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, 'w') as archive:
        archive.writestr('AC_OAB_synthetic.crt', intermediate)
    bundle, digest = directory / 'bundle.zip', directory / 'hash.txt'
    bundle.write_bytes(zipped.getvalue())
    digest.write_text('0' * 128)
    update = [*args, 'update', '--zip', bundle, '--hash', digest, '--output', catalogue]
    check(run(update, success=False).returncode != 0, 'provider loading cannot bypass the bundle hash')
    digest.write_text(hashlib.sha512(zipped.getvalue()).hexdigest())
    run(update)
    check(not json.loads(catalogue.read_text())['provenance'],
          'fully verified Ed521 refresh needs no unsupported-signature provenance')
    store = [*args, '--system-dir', directory / 'system', '--system-bundle', directory / 'derived/ca-certificates.crt']
    run([*store, 'install', 'e521'])
    installed = json.loads(run([*store, 'status']).stdout)
    check({item['sha256'] for item in installed} == {hashlib.sha256(real).hexdigest(), hashlib.sha256(intermediate).hexdigest()}
          and all(item['note'] == '' for item in installed),
          'provider-backed Ed521 installs the exact chosen group into an isolated system store')
    run([*store, 'remove', 'all'])
    check(json.loads(run([*store, 'status']).stdout) == [], 'provider-backed removal clears the isolated store')
print(f'{checks} provider/core checks passed', flush=True)
