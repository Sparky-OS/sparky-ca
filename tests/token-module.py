# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary, proxy, opensc = map(lambda p: str(Path(p).absolute()), sys.argv[1:4])
data = Path(__file__).resolve().parents[1] / 'data'
def run(args, good=True):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == good, (args, result.stdout, result.stderr)
    return result
with tempfile.TemporaryDirectory(prefix='sparky-ca-token-') as temporary:
    database = Path(temporary) / 'nss'
    args = [binary, '--data', data, '--nss', database]
    run([*args, 'register-token', proxy])
    modules = run(['modutil', '-list', 'Sparky CA tokens', '-dbdir', 'sql:' + str(database)]).stdout
    assert proxy in modules and (database / '.sparky-ca-token.json').exists(), modules
    print('PASS actual NSS registers the p11-kit proxy and records its ownership', flush=True)
    run([*args, 'register-token', proxy], good=False)
    print('PASS duplicate registration is refused', flush=True)
    run([*args, 'register-token', '/not/an/installed/module.so'], good=False)
    print('PASS an absent module is refused', flush=True)
    before = run(['certutil', '-L', '-d', 'sql:' + str(database)]).stdout
    key, certificate = Path(temporary) / 'key', Path(temporary) / 'certificate.pem'
    run(['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=Unrelated token-module control', '-keyout', key, '-out', certificate])
    key.unlink()
    run(['certutil', '-A', '-d', 'sql:' + str(database), '-n', 'Unrelated control', '-t', ',,', '-i', certificate])
    before = run(['certutil', '-L', '-d', 'sql:' + str(database)]).stdout
    assert 'Unrelated control' in before
    run([*args, 'unregister-token'])
    assert 'Sparky CA tokens' not in run(['modutil', '-list', '-dbdir', 'sql:' + str(database)]).stdout
    assert not (database / '.sparky-ca-token.json').exists()
    assert run(['certutil', '-L', '-d', 'sql:' + str(database)]).stdout == before
    print('PASS removal deletes only our registration and preserves the unrelated NSS certificate', flush=True)
    run([*args, 'unregister-token'], good=False)
    print('PASS an unowned registration cannot be removed', flush=True)
    output = run([binary, '--data', data, 'tokens', opensc]).stdout
    assert 'No token slots detected' in output, output
    print('PASS the isolated no-reader OpenSC control reports no detected token', flush=True)
print('6 PKCS#11 registration/detection checks passed', flush=True)
