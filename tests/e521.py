# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the integrity exception with synthetic, deliberately unsigned descendants."""
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

binary = str(Path(sys.argv[1]).resolve())
root_file = Path(__file__).resolve().parent.parent / 'data/roots/ICP-Brasilv7.crt'
checks = 0


def run(args, success=True):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=45)
    if success and result.returncode:
        raise AssertionError(result.stderr)
    return result


def check(condition, message):
    global checks
    assert condition, message
    checks += 1
    print('PASS ' + message, flush=True)


def fields(der):
    """Return raw DER children, including their tag and length."""
    size = der[1] if der[1] < 128 else int.from_bytes(der[2:2 + (der[1] & 127)])
    start = 2 if der[1] < 128 else 2 + (der[1] & 127)
    end = start + size
    children = []
    while start < end:
        length = der[start + 1]
        header = 2 if length < 128 else 2 + (length & 127)
        size = length if length < 128 else int.from_bytes(der[start + 2:start + header])
        children.append(der[start:start + header + size])
        start += header + size
    assert start == end
    return children


def pack(tag, content):
    size = len(content)
    raw = size.to_bytes((size.bit_length() + 7) // 8, 'big')
    length = bytes([size]) if size < 128 else bytes([128 + len(raw)]) + raw
    return bytes([tag]) + length + content


def pem(der):
    body = base64.b64encode(der).decode()
    return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(body[i:i + 64] for i in range(0, len(body), 64)) + '\n-----END CERTIFICATE-----\n'


def archive(cert):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('AC_OAB_E521_fixture.crt', cert)
    return output.getvalue()


with tempfile.TemporaryDirectory(prefix='sparky-ca-e521-') as temporary:
    os.chdir(temporary)
    data = Path('data')
    (data / 'roots').mkdir(parents=True)
    root = subprocess.check_output(['openssl', 'x509', '-in', str(root_file), '-outform', 'DER'])
    (data / 'roots/v7.crt').write_bytes(root)
    root_tbs = fields(fields(root)[0])
    # The real v7 issuer name, signature OID and SKI are public fixture inputs.
    ski_text = run(['openssl', 'x509', '-in', str(root_file), '-noout', '-ext', 'subjectKeyIdentifier']).stdout.splitlines()[-1].strip()
    ski = bytes.fromhex(ski_text.replace(':', ''))
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'fixture.key', '-out', 'base.pem', '-subj', '/CN=AC OAB E521 fixture', '-days', '30', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'authorityKeyIdentifier=keyid:always'])
    base = subprocess.check_output(['openssl', 'x509', '-in', 'base.pem', '-outform', 'DER'])

    def descendant(wrong_issuer=False, wrong_aki=False, wrong_oid=False):
        outer = fields(base)
        tbs = fields(outer[0])
        tbs[2] = outer[1] = root_tbs[2] if not wrong_oid else pack(0x30, bytes.fromhex('06092b0601040182dc1401'))
        if not wrong_issuer:
            tbs[3] = root_tbs[5]
        extensions = fields(fields(tbs[-1])[0])
        for index, extension in enumerate(extensions):
            parts = fields(extension)
            if parts[0] == bytes.fromhex('0603551d23'):
                keyid = bytes([ski[0] ^ 1]) + ski[1:] if wrong_aki else ski
                parts[-1] = pack(4, pack(0x30, pack(0x80, keyid)))
                extensions[index] = pack(0x30, b''.join(parts))
        tbs[-1] = pack(0xa3, pack(0x30, b''.join(extensions)))
        outer[0] = pack(0x30, b''.join(tbs))
        return pack(0x30, b''.join(outer))

    pin = {'file': 'v7.crt', 'sha256': hashlib.sha256(root).hexdigest()}
    cert = descendant()
    zip_bytes = archive(cert)
    digest = hashlib.sha512(zip_bytes).hexdigest()
    def pins(hashes):
        (data / 'pins.json').write_text(json.dumps({'roots': [pin], 'bundleSha512': hashes}))
    def update(cert_bytes):
        zipped = archive(cert_bytes)
        Path('bundle.zip').write_bytes(zipped)
        Path('hash.txt').write_text(hashlib.sha512(zipped).hexdigest())
        return run([binary, '--data', data, 'update', '--zip', 'bundle.zip', '--hash', 'hash.txt', '--output', 'catalogue.json'], False)
    args = [binary, '--data', data, '--catalogue', 'catalogue.json']
    pins([])
    check(update(cert).returncode != 0, 'E-521 descendant rejects an unapproved bundle even with a correct supplied hash')
    pins([digest])
    check(update(cert).returncode == 0, 'approved E-521 fixture accepts matching v7 issuer and AKI without claiming signature verification')
    original = Path('catalogue.json').read_text()
    run([*args, 'update', '--zip', 'bundle.zip', '--hash', 'hash.txt', '--output', 'catalogue.json'])
    check(Path('catalogue.json').read_text() == original, 'unchanged E-521 refresh preserves exact catalogue and provenance bytes')
    records = json.loads(run([*args, 'list']).stdout)
    check(len(records) == 2 and {r['verification'] for r in records} == {'pinned-root', 'transport-integrity-only'}, 'v7 and descendant expose distinct verification evidence')
    check(all('E-521' in r['note'] and 'own E-521 code' in r['note'] for r in records), 'E-521 limitations remain visible after catalogue reload')
    for description, changed in [('wrong issuer', descendant(wrong_issuer=True)), ('wrong AKI', descendant(wrong_aki=True)), ('different unsupported OID', descendant(wrong_oid=True))]:
        pins([digest, hashlib.sha512(archive(changed)).hexdigest()])
        check(update(changed).returncode != 0, 'E-521 exception rejects ' + description + ' even in an approved bundle')
    pins([digest])
    altered = cert[:-1] + bytes([cert[-1] ^ 1])
    check(update(altered).returncode != 0, 'altered E-521 bytes cannot obtain integrity from a supplied hash')
    document = json.loads(original)
    document['certificates'][0]['pem'] = pem(altered)
    Path('catalogue.json').write_text(json.dumps(document))
    check(run([*args, 'list'], False).returncode != 0, 'stored E-521 bytes must match the embedded approved bundle')
    document = json.loads(original)
    document['provenance'] = []
    Path('catalogue.json').write_text(json.dumps(document))
    check(run([*args, 'list'], False).returncode != 0, 'E-521 descendant without provenance cannot load')
    Path('catalogue.json').write_text(original)
    system_args = [*args, '--system-dir', Path('system').resolve(), '--system-bundle', Path('derived/ca-certificates.crt').resolve()]
    rejected = run([*system_args, 'install', 'e521'], False)
    check(rejected.returncode != 0 and 'own E-521 code' in rejected.stderr, 'default installation skips E-521 and explains why')
    chosen = run([*system_args, '--allow-e521', 'install', 'e521'])
    installed = json.loads(run([*system_args, 'status']).stdout)
    check({r['sha256'] for r in installed} == {hashlib.sha256(root).hexdigest(), hashlib.sha256(cert).hexdigest()}, 'explicit E-521 choice installs exact anchor and integrity-only bytes in isolated system store')
    check('E-521' in chosen.stderr and all('E-521' in r['note'] for r in installed), 'explicit installation and installed listing retain E-521 explanation')
    run([*system_args, 'remove', 'all'])
    check(json.loads(run([*system_args, 'status']).stdout) == [], 'E-521 removal clears isolated system store')
print(f'{checks} E-521 checks passed', flush=True)
