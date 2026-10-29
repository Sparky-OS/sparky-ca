#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""The same certificate and TLS operations give the same results with and without Ed521.

  unchanged.py fixtures DIR        make TEST keys, chains, CMS messages and signatures
  unchanged.py run DIR OUT.json    run every operation in the current environment
  unchanged.py compare A B [--exact]
  unchanged.py ctest MODULE CONFIG fixtures, then run with the system configuration
                                   and with CONFIG pointed at MODULE, then compare

The fixtures are made once with OpenSSL's default provider, so both runs judge
the same bytes.  Allowed differences, and only these: lines naming Ed521 added
to "openssl list" output, and ITI's v7 root, which verifies only with Ed521.
--exact allows nothing (the check after the package is removed).
"""
import difflib
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ALGORITHMS = {
    'rsa2048': ['-newkey', 'rsa:2048'],
    'rsapss': ['-newkey', 'rsa-pss', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'p256': ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256'],
    'p384': ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-384'],
    'p521': ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-521'],
    'brainpool256': ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:brainpoolP256r1'],
    'ed25519': ['-newkey', 'ed25519'],
    'ed448': ['-newkey', 'ed448'],
    'mldsa65': ['-newkey', 'ML-DSA-65'],
}
TLS_ALGORITHMS = ('rsa2048', 'p256', 'p384', 'ed25519', 'ed448', 'mldsa65')
ED521_MARKS = ('ed521', '1.3.6.1.4.1.44588.2.1')
LIST_OPTIONS = ('-digest-algorithms', '-cipher-algorithms', '-mac-algorithms', '-kdf-algorithms', '-random-generators',
                '-key-exchange-algorithms', '-kem-algorithms', '-signature-algorithms', '-asymcipher-algorithms',
                '-public-key-algorithms', '-public-key-methods', '-key-managers', '-encoders', '-decoders',
                '-store-loaders', '-tls-signature-algorithms', '-tls-groups', '-providers', '-objects')


def openssl(*args, cwd=None, env=None, input=None, check=True, timeout=120):
    result = subprocess.run(['openssl', *map(str, args)], cwd=cwd, env=env, input=input, capture_output=True, timeout=timeout)
    if check and result.returncode != 0:
        raise AssertionError(f'openssl {" ".join(map(str, args))}: {result.stderr.decode(errors="replace")}')
    return result


def fixtures(directory):
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.pop('OPENSSL_CONF', None)
    (d / 'ca.ext').write_text('basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
    (d / 'leaf.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth,emailProtection\nsubjectAltName=DNS:localhost,IP:127.0.0.1,email:test@example.invalid\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
    (d / 'message.txt').write_bytes(b'Sparky CA unchanged-default TEST message\n' * 20)
    made = []
    for name, options in ALGORITHMS.items():
        a = d / name
        a.mkdir(exist_ok=True)
        try:
            make(d, a, name, options, env)
        except AssertionError as error:
            print('skip', name, error)
            continue
        made.append(name)
    (d / 'algorithms.json').write_text(json.dumps(made))
    print('fixtures for', ', '.join(made))


def make(d, a, name, options, env):
    openssl('req', '-x509', '-new', *options, '-nodes', '-keyout', a / 'ca.key', '-out', a / 'ca.pem', '-days', '3650',
            '-subj', f'/CN=TEST {name} root, unchanged-default check', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign', env=env)
    for child, parent, ext in (('int', 'ca', 'ca.ext'), ('leaf', 'int', 'leaf.ext')):
        openssl('req', '-new', *options, '-nodes', '-keyout', a / f'{child}.key', '-out', a / f'{child}.csr',
                '-subj', f'/CN=TEST {name} {child}', env=env)
        openssl('x509', '-req', '-in', a / f'{child}.csr', '-CA', a / f'{parent}.pem', '-CAkey', a / f'{parent}.key',
                '-CAcreateserial', '-out', a / f'{child}.pem', '-days', '3650', '-extfile', d / ext, env=env)
    tampered = bytearray((a / 'leaf.pem').read_bytes())
    lines = tampered.split(b'\n')
    middle = bytearray(lines[5])
    middle[10] = ord('A') if middle[10] != ord('A') else ord('B')
    lines[5] = bytes(middle)
    (a / 'tampered.pem').write_bytes(b'\n'.join(lines))
    # RFC 8419 section 3 (EdDSA) and RFC 9882 (ML-DSA) name the message digest these keys need in CMS.
    digest = {'ed25519': ['-md', 'sha512'], 'ed448': ['-md', 'shake256'], 'mldsa65': ['-md', 'sha512']}.get(name, [])
    openssl('cms', '-sign', '-in', d / 'message.txt', '-signer', a / 'leaf.pem', '-inkey', a / 'leaf.key', *digest,
            '-certfile', a / 'int.pem', '-binary', '-outform', 'DER', '-out', a / 'signed.der', env=env)
    signed = bytearray((a / 'signed.der').read_bytes())
    position = signed.find(b'Sparky CA unchanged-default')
    signed[position] ^= 1
    (a / 'signed-tampered.der').write_bytes(bytes(signed))
    openssl('pkeyutl', '-sign', '-rawin', '-inkey', a / 'leaf.key', '-in', d / 'message.txt', '-out', a / 'raw.sig',
            *(['-digest', 'SHA256'] if name in ('rsa2048', 'rsapss', 'p256', 'p384', 'p521', 'brainpool256') else []), env=env)
    openssl('x509', '-in', a / 'leaf.pem', '-pubkey', '-noout', '-out', a / 'leaf.pub', env=env)


def listening(port):
    entry = f':{port:04X} '
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1].endswith(entry.strip()) and fields[3] == '0A':
            return True
    return False


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run(directory, output):
    d = Path(directory).resolve()
    env = dict(os.environ)
    results = []

    def record(name, *args, input=None, digest=False, cwd=None):
        result = openssl(*args, cwd=cwd, env=env, input=input, check=False)
        out = result.stdout.decode(errors='replace').replace(str(d), '$D')
        err = result.stderr.decode(errors='replace').replace(str(d), '$D')
        out = normalise_errors(out)
        if digest:
            out = hashlib.sha256(out.encode()).hexdigest()
        results.append({'name': name, 'rc': result.returncode, 'out': out, 'err': normalise_errors(err)})

    for option in LIST_OPTIONS:
        record('list ' + option, 'list', option)
    record('ciphers ALL', 'ciphers', '-v', 'ALL')
    record('ciphers DEFAULT', 'ciphers', '-v', '-s', '-tls1_3')
    for digest in ('sha256', 'sha512', 'sha3-256', 'shake256', 'sha1', 'md5', 'sm3', 'blake2b512'):
        record('dgst ' + digest, 'dgst', '-' + digest, d / 'message.txt')
    algorithms = json.loads((d / 'algorithms.json').read_text())
    for name in algorithms:
        a = d / name
        record(f'{name} verify chain', 'verify', '-check_ss_sig', '-x509_strict', '-CAfile', a / 'ca.pem', '-untrusted', a / 'int.pem', a / 'leaf.pem')
        record(f'{name} verify tampered', 'verify', '-check_ss_sig', '-CAfile', a / 'ca.pem', '-untrusted', a / 'int.pem', a / 'tampered.pem')
        record(f'{name} verify wrong root', 'verify', '-CAfile', a / 'int.pem', a / 'ca.pem')
        record(f'{name} verify purpose', 'verify', '-purpose', 'sslserver', '-CAfile', a / 'ca.pem', '-untrusted', a / 'int.pem', a / 'leaf.pem')
        for cert in ('ca', 'int', 'leaf'):
            record(f'{name} x509 text {cert}', 'x509', '-in', a / f'{cert}.pem', '-noout', '-text')
        record(f'{name} pkey text', 'pkey', '-pubin', '-in', a / 'leaf.pub', '-noout', '-text_pub')
        record(f'{name} pkey check', 'pkey', '-pubin', '-in', a / 'leaf.pub', '-pubcheck', '-noout')
        record(f'{name} cms verify', 'cms', '-verify', '-inform', 'DER', '-in', a / 'signed.der', '-CAfile', a / 'ca.pem', '-binary', '-out', '/dev/stdout')
        record(f'{name} cms verify tampered', 'cms', '-verify', '-inform', 'DER', '-in', a / 'signed-tampered.der', '-CAfile', a / 'ca.pem', '-binary', '-out', '/dev/null')
        record(f'{name} pkeyutl verify', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', a / 'leaf.pub', '-in', d / 'message.txt', '-sigfile', a / 'raw.sig',
               *(['-digest', 'SHA256'] if name in ('rsa2048', 'rsapss', 'p256', 'p384', 'p521', 'brainpool256') else []))
    bundle = Path('/etc/ssl/certs/ca-certificates.crt')
    if bundle.is_file():
        text = bundle.read_text()
        certificates = ['-----BEGIN CERTIFICATE-----' + part for part in text.split('-----BEGIN CERTIFICATE-----')[1:]]
        system = d / 'system'
        system.mkdir(exist_ok=True)
        for index, pem in enumerate(certificates):
            path = system / f'{index:03}.pem'
            path.write_text(pem)
            record(f'system root {index:03} text', 'x509', '-in', path, '-noout', '-text', digest=True)
            record(f'system root {index:03} verify', 'verify', '-check_ss_sig', '-CAfile', bundle, path)
    roots = HERE.parents[1] / 'data/roots'
    for root in sorted(roots.glob('*.crt')) if roots.is_dir() else []:
        record(f'icp {root.name} text', 'x509', '-in', root, '-noout', '-text', digest=True)
        record(f'icp {root.name} verify', 'verify', '-check_ss_sig', '-CAfile', root, root)
    for name in TLS_ALGORITHMS:
        if name not in algorithms:
            continue
        a = d / name
        for version in ('-tls1_2', '-tls1_3'):
            port = free_port()
            server = subprocess.Popen(['openssl', 's_server', '-accept', f'127.0.0.1:{port}', '-naccept', '1', '-cert', a / 'leaf.pem',
                                       '-key', a / 'leaf.key', '-cert_chain', a / 'int.pem', version, '-quiet'],
                                      env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            for _ in range(200):
                if listening(port):
                    break
                time.sleep(0.02)
            record(f'{name} tls {version}', 's_client', '-connect', f'127.0.0.1:{port}', '-servername', 'localhost', '-brief', '-no_ign_eof',
                   '-CAfile', a / 'ca.pem', '-verify_return_error', '-verify_hostname', 'localhost', version, input=b'')
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
    Path(output).write_text(json.dumps(results, indent=0))
    print(len(results), 'operations recorded in', output)


def normalise_errors(err):
    """Error lines carry the thread id; s_client prints DONE only when it saw the close first (timing)."""
    lines = []
    for line in err.splitlines():
        if line == 'DONE':
            continue
        if ':error:' in line:
            line = line.split(':', 1)[1]
        lines.append(line)
    return '\n'.join(lines)


def ed521_only(text_a, text_b):
    """Only inserted lines that name Ed521, or the blocks around them in openssl list output."""
    a, b = text_a.splitlines(), text_b.splitlines()
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == 'equal':
            continue
        if tag != 'insert':
            return False
        chunk = '\n'.join(b[j1:j2]).lower()
        if not any(mark in chunk for mark in ED521_MARKS):
            return False
    return True


def compare(first, second, exact=False):
    a = {item['name']: item for item in json.loads(Path(first).read_text())}
    b = {item['name']: item for item in json.loads(Path(second).read_text())}
    assert a.keys() == b.keys(), sorted(set(a) ^ set(b))
    same = allowed = 0
    problems = []
    for name in a:
        x, y = a[name], b[name]
        if x == y:
            same += 1
            continue
        if not exact and name.startswith('list ') and x['rc'] == y['rc'] == 0 and x['err'] == y['err'] and ed521_only(x['out'], y['out']):
            allowed += 1
            continue
        if not exact and name.startswith('icp ICP-Brasilv7.crt') and name.endswith('verify'):
            if x['rc'] != 0 and y['rc'] == 0:
                allowed += 1
                continue
        if not exact and name == 'icp ICP-Brasilv7.crt text':
            allowed += 1
            continue
        problems.append((name, x, y))
    for name, x, y in problems:
        print('DIFFERENT:', name)
        print('  without:', json.dumps(x)[:600])
        print('  with:   ', json.dumps(y)[:600])
    print(f'{same} identical, {allowed} expected Ed521 differences, {len(problems)} other differences, of {len(a)} operations')
    return not problems


def main():
    mode = sys.argv[1]
    if mode == 'fixtures':
        fixtures(sys.argv[2])
    elif mode == 'run':
        run(sys.argv[2], sys.argv[3])
    elif mode == 'compare':
        sys.exit(0 if compare(sys.argv[2], sys.argv[3], '--exact' in sys.argv) else 1)
    elif mode == 'ctest':
        module, template = (Path(value).resolve() for value in sys.argv[2:4])
        with tempfile.TemporaryDirectory(prefix='ed521-unchanged-') as temporary:
            t = Path(temporary)
            config = t / 'openssl.cnf'
            config.write_text(template.read_text().replace('[ed521_sect]\n', f'[ed521_sect]\nmodule = {module}\n'))
            fixtures(t / 'fixtures')
            os.environ.pop('OPENSSL_CONF', None)
            run(t / 'fixtures', t / 'without.json')
            os.environ['OPENSSL_CONF'] = str(config)
            run(t / 'fixtures', t / 'with.json')
            assert json.loads((t / 'with.json').read_text())[0]['name'] == 'list -digest-algorithms'
            providers = next(item for item in json.loads((t / 'with.json').read_text()) if item['name'] == 'list -providers')
            assert 'ed521' in providers['out'] and 'default' in providers['out'], providers
            ok = compare(t / 'without.json', t / 'with.json')
            v7 = [item for item in json.loads((t / 'with.json').read_text()) if item['name'] == 'icp ICP-Brasilv7.crt verify']
            if v7:
                assert v7[0]['rc'] == 0, v7
            sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
