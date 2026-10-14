# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""An A3 token path with SoftHSM as the stand-in token, through p11-kit's proxy and a real NSS database.

The token, its keys and its certificate are generated here. No physical token, reader or personal certificate is used."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary, proxy, softhsm = map(lambda p: str(Path(p).absolute()), sys.argv[1:4])
data = Path(sys.argv[4]) if len(sys.argv) > 4 else Path(__file__).resolve().parents[1] / 'data'
checks = 0
PIN, SO_PIN, LABEL = '4321', '87654321', 'Sparky Test Token'


def check(condition, message):
    global checks
    assert condition, message
    checks += 1
    print('PASS ' + message, flush=True)


def run(args, good=True, env=None):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=60, env=env)
    assert (result.returncode == 0) == good, (args[:3], result.returncode, result.stdout, result.stderr)
    return result


with tempfile.TemporaryDirectory(prefix='sparky-ca-softhsm-') as temporary:
    root = Path(temporary)
    (root / 'tokens').mkdir()
    (root / 'config/pkcs11/modules').mkdir(parents=True)
    (root / 'softhsm2.conf').write_text(f'directories.tokendir = {root}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n')
    (root / 'config/pkcs11/modules/softhsm2.module').write_text(f'module: {softhsm}\n')
    env = dict(os.environ, SOFTHSM2_CONF=str(root / 'softhsm2.conf'), XDG_CONFIG_HOME=str(root / 'config'), HOME=str(root))
    run(['softhsm2-util', '--init-token', '--free', '--label', LABEL, '--so-pin', SO_PIN, '--pin', PIN], env=env)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=Token test authority', '-keyout', root / 'ca.key', '-out', root / 'ca.pem'])
    run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Test A3 holder', '-keyout', root / 'holder.key', '-out', root / 'holder.csr'])
    run(['openssl', 'x509', '-req', '-in', root / 'holder.csr', '-CA', root / 'ca.pem', '-CAkey', root / 'ca.key', '-CAcreateserial', '-days', '30', '-out', root / 'holder.pem'])
    run(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', root / 'holder.key', '-out', root / 'holder.p8'])
    run(['openssl', 'x509', '-in', root / 'holder.pem', '-outform', 'DER', '-out', root / 'holder.der'])
    run(['softhsm2-util', '--import', root / 'holder.p8', '--token', LABEL, '--label', 'Test A3 key', '--id', '01', '--pin', PIN], env=env)
    run(['pkcs11-tool', '--module', softhsm, '--login', '--pin', PIN, '--write-object', root / 'holder.der', '--type', 'cert', '--id', '01', '--label', 'Test A3 certificate'], env=env)

    shown = run([binary, '--data', data, 'tokens', softhsm], env=env).stdout
    check(LABEL in shown and 'Test A3 certificate' in shown and 'No token slots' not in shown, 'the token is detected and its certificate is shown without a PIN')
    check(PIN not in shown, 'the listing never contains the PIN')
    through_proxy = run([binary, '--data', data, 'tokens', proxy], env=env).stdout
    check(LABEL in through_proxy and 'Test A3 certificate' in through_proxy, "p11-kit's proxy shows the same token and certificate")

    database = root / 'nss'
    args = [binary, '--data', data, '--nss', database]
    run([*args, 'register-token', proxy], env=env)
    check((database / '.sparky-ca-token.json').exists(), 'registering the proxy records our ownership')
    pin_file = root / 'pin'
    pin_file.write_text(PIN + '\n')
    pin_file.chmod(0o600)
    listing = run(['certutil', '-L', '-d', 'sql:' + str(database), '-h', 'all', '-f', pin_file], env=env).stdout
    check('Test A3 certificate' in listing, 'NSS reaches the token certificate through the registered proxy')
    keys = run(['certutil', '-K', '-d', 'sql:' + str(database), '-h', LABEL, '-f', pin_file], env=env).stdout
    check('Test A3 key' in keys, 'NSS finds the private key on the token after the PIN is given')
    wrong = root / 'wrong'
    wrong.write_text('0000\n')
    wrong.chmod(0o600)
    denied = run(['certutil', '-K', '-d', 'sql:' + str(database), '-h', LABEL, '-f', wrong], good=False, env=env)
    check(denied.returncode != 0, 'a wrong PIN is refused by the token, not by us')
    stored = b''.join(path.read_bytes() for path in database.rglob('*') if path.is_file())
    check(PIN.encode() not in stored and SO_PIN.encode() not in stored, 'no PIN is stored in the NSS database or in our manifest')
    run([*args, 'unregister-token'], env=env)
    check('Sparky CA tokens' not in run(['modutil', '-list', '-dbdir', 'sql:' + str(database)], env=env).stdout, 'unregistering removes only our module')
    again = run(['pkcs11-tool', '--module', softhsm, '--list-objects', '--type', 'cert'], env=env).stdout
    check('Test A3 certificate' in again, 'the certificate stays on the token after unregistering')
print(f'{checks} token checks passed', flush=True)
