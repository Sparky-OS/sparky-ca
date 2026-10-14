# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Kleopatra's side: the chosen chain goes into gpgsm, and trust is only ever the user's own answer.

A fresh GNUPGHOME, a generated chain, and a stand-in pinentry whose answer the test file controls.
The program never answers the trust question; the stand-in plays the user."""
import json
import os
from pathlib import Path
import pty
import shutil
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
checks = 0
MANAGED_BEGIN, MANAGED_END = '# sparky-ca managed roots begin\n', '# sparky-ca managed roots end\n'


def check(condition, message):
    global checks
    assert condition, message
    checks += 1
    print('PASS ' + message, flush=True)


def run(args, good=True, env=None, **kwargs):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=120, env=env, **kwargs)
    assert (result.returncode == 0) == good, (args[:4], result.returncode, result.stdout, result.stderr)
    return result


def parse(text):
    return json.JSONDecoder().raw_decode(text.lstrip())[0]


def certificate(name, issuer=None, ca=True, extra=''):
    run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN={name}', '-keyout', f'{name}.key', '-out', f'{name}.csr'])
    kind = 'CA:TRUE' if ca else 'CA:FALSE'
    usage = 'keyCertSign,cRLSign' if ca else 'digitalSignature'
    Path(f'{name}.ext').write_text(f'basicConstraints=critical,{kind}\nkeyUsage=critical,{usage}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n{extra}')
    command = ['openssl', 'x509', '-req', '-in', f'{name}.csr', '-days', '90', '-extfile', f'{name}.ext', '-out', f'{name}.pem']
    command += ['-CA', f'{issuer}.pem', '-CAkey', f'{issuer}.key', '-CAcreateserial'] if issuer else ['-signkey', f'{name}.key']
    run(command)
    return Path(f'{name}.pem').read_text()


with tempfile.TemporaryDirectory(prefix='sparky-ca-gpgsm-') as temporary:
    os.chdir(temporary)
    root = certificate('ICP-Test-Root')
    certificate('AC_OAB_JUS', 'ICP-Test-Root')
    certificate('signer', 'AC_OAB_JUS', ca=False, extra='extendedKeyUsage=emailProtection\nsubjectAltName=email:signer@example.invalid\n')
    import hashlib
    der = subprocess.check_output(['openssl', 'x509', '-in', 'ICP-Test-Root.pem', '-outform', 'DER'])
    data = Path('data')
    (data / 'roots').mkdir(parents=True)
    (data / 'roots/root.pem').write_text(root)
    (data / 'pins.json').write_text(json.dumps({'roots': [{'file': 'root.pem', 'sha256': hashlib.sha256(der).hexdigest()}]}))
    (data / 'catalogue.json').write_text(json.dumps({'schema': 1, 'certificates': [
        {'name': 'ICP-Test-Root.crt', 'pem': root}, {'name': 'AC_OAB_JUS.crt', 'pem': Path('AC_OAB_JUS.pem').read_text()}]}))
    Path('message.txt').write_text('a signed message\n')
    run(['openssl', 'cms', '-sign', '-binary', '-in', 'message.txt', '-signer', 'signer.pem', '-inkey', 'signer.key', '-certfile', 'AC_OAB_JUS.pem', '-outform', 'DER', '-out', 'message.p7s'])

    answer = Path('answer').resolve()
    Path('pinentry').write_text(f'''#!/bin/sh
echo "OK stand-in pinentry"
while read -r line; do
  case "$line" in
    BYE*) echo "OK closing"; exit 0;;
    CONFIRM*) if [ "$(cat {answer})" = yes ]; then echo OK; else echo "ERR 83886179 Operation cancelled"; fi;;
    GETPIN*) echo "D 0000"; echo OK;;
    *) echo OK;;
  esac
done
''')
    Path('pinentry').chmod(0o755)

    def fresh_home(name):
        home = Path(temporary) / name
        home.mkdir(mode=0o700)
        (home / 'gpg-agent.conf').write_text(f'pinentry-program {Path("pinentry").resolve()}\n')
        return home

    def tool(home, *args, good=True, env=None):
        return run([binary, '--data', data.resolve(), '--gpg-home', home, *args], good, env)

    def keybox(home):
        listing = run(['gpgsm', '--homedir', home, '--batch', '--list-keys', '--with-colons']).stdout
        return [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]

    def trustlist(home):
        path = home / 'trustlist.txt'
        return path.read_text() if path.exists() else ''

    def verify(home):
        return subprocess.run(['gpgsm', '--homedir', str(home), '--batch', '--verify', 'message.p7s', 'message.txt'], capture_output=True, text=True, timeout=60)

    def sha1(name):
        return run(['openssl', 'x509', '-in', f'{name}.pem', '-noout', '-fingerprint', '-sha1']).stdout.split('=')[1].strip().replace(':', '')
    ours = {sha1('ICP-Test-Root'), sha1('AC_OAB_JUS')}
    home = fresh_home('home')
    answer.write_text('no')
    check(json.loads(tool(home, 'gpgsm-status').stdout) == [], 'nothing is imported or owned before the user chooses')
    result = parse(tool(home, 'gpgsm-import', 'oab').stdout)
    check(sorted(result['imported']) == ['AC_OAB_JUS.crt', 'ICP-Test-Root.crt'] and result['skipped'] == [], 'the chosen group goes in with its chain up to the root')
    check(len(keybox(home)) == 2, "gpgsm's keybox holds the intermediate and its root")
    check(trustlist(home) == '' or 'S relax' not in trustlist(home), 'importing sets no trust: the trust list has no entry')
    status = {item['name']: item['trust'] for item in json.loads(tool(home, 'gpgsm-status').stdout)}
    check(status == {'ICP-Test-Root.crt': 'not confirmed', 'AC_OAB_JUS.crt': 'through its root'}, 'the root waits for confirmation and the intermediate depends on it')
    before = verify(home)
    check(before.returncode != 0 and 'Not trusted' in before.stderr, 'a signature that chains to the imported root is not accepted yet')

    tool(home, 'gpgsm-confirm')
    check(trustlist(home) == '' or 'S relax' not in trustlist(home), 'when the user says no, nothing is trusted')
    check({item['name']: item['trust'] for item in json.loads(tool(home, 'gpgsm-status').stdout)}['ICP-Test-Root.crt'] == 'not confirmed', 'the root stays unconfirmed after a refusal')
    check(verify(home).returncode != 0, 'the signature still fails after a refusal')

    answer.write_text('yes')
    tool(home, 'gpgsm-confirm')
    confirmed = {item['name']: item['trust'] for item in json.loads(tool(home, 'gpgsm-status').stdout)}
    check(confirmed['ICP-Test-Root.crt'] == 'confirmed by you' and ' S relax' in trustlist(home), "after the user's own yes, gpgsm records the trust and the status says so")
    after = verify(home)
    check(after.returncode == 0 and 'Good signature' in after.stderr, 'the S/MIME signature now verifies through the chain')
    again = parse(tool(home, 'gpgsm-import', 'oab').stdout)
    check(again['imported'] == [], 'importing again changes nothing')

    removed = parse(tool(home, 'gpgsm-remove', 'oab').stdout)
    check(sorted(removed['removed']) == ['AC_OAB_JUS.crt', 'ICP-Test-Root.crt'] and not set(keybox(home)) & ours and len(keybox(home)) == 1, "removal takes out exactly what was imported; the signer's certificate gpgsm collected while verifying stays")
    check(' S relax' in trustlist(home), "trust the user confirmed stays in the user's own trust list")
    check(json.loads(tool(home, 'gpgsm-status').stdout) == [], 'nothing is owned afterwards')

    owner = fresh_home('owner')
    run(['gpgsm', '--homedir', owner, '--batch', '--import', 'ICP-Test-Root.pem'])
    first = parse(tool(owner, 'gpgsm-import', 'oab').stdout)
    check(first['imported'] == ['AC_OAB_JUS.crt'] and first['alreadyPresent'] == ['ICP-Test-Root.crt'], "a root the user already had is not claimed as ours")
    tool(owner, 'gpgsm-remove', 'all')
    check(len(keybox(owner)) == 1, "removal leaves the user's own root in place")

    legacy = fresh_home('legacy')
    run(['gpgsm', '--homedir', legacy, '--batch', '--import', 'ICP-Test-Root.pem'])
    root_fpr = keybox(legacy)[0]
    spaced = ':'.join(root_fpr[i:i + 2] for i in range(0, 40, 2))
    (legacy / 'trustlist.txt').write_text(f'# the user\'s own note\n{"AB" * 20} S\n{MANAGED_BEGIN}{root_fpr} S\n{MANAGED_END}')
    (legacy / 'sparky-ca-trust.json').write_text('{"icp-roots": []}')
    outcome = tool(legacy, 'gpgsm-import', 'oab')
    text = trustlist(legacy)
    check(root_fpr not in text and MANAGED_BEGIN not in text and "the user's own note" in text and ('AB' * 20) in text, "the trust entries 2.0.0 added without asking are taken back, the user's own lines stay")
    check('2.0.0' in outcome.stderr and not (legacy / 'sparky-ca-trust.json').exists(), 'the user is told, and the old record is gone')

    nogpg = fresh_home('nogpg')
    env = dict(os.environ, PATH='/nonexistent')
    failure = tool(nogpg, 'gpgsm-import', 'oab', good=False, env=env)
    check('gpgsm is not installed' in failure.stderr, 'without gpgsm the command says so instead of failing oddly')

    def menu(path):
        master, slave = pty.openpty()
        process = subprocess.Popen([binary, '--data', str(data.resolve())], stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=dict(os.environ, PATH=path))
        os.close(slave)
        os.write(master, b'0\n')
        output, _ = process.communicate(timeout=60)
        os.close(master)
        return output
    check('Kleopatra' in menu(os.environ['PATH']) and 'Kleopatra' not in menu('/nonexistent'), 'the console menu offers the gpgsm items only where gpgsm exists')
print(f'{checks} checks passed', flush=True)
