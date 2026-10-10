# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generated identities, protected NSS stores, previews and real Okular signing."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary, request, okular = map(lambda p: str(Path(p).resolve()), sys.argv[1:4])
source = Path(__file__).resolve().parents[1]
checks = 0


def run(args, good=True, **kwargs):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=60, **kwargs)
    assert (result.returncode == 0) == good, (args[:4], result.returncode, result.stdout, result.stderr)
    return result


def check(condition, message):
    global checks
    assert condition, message
    checks += 1
    print('PASS ' + message, flush=True)


def pdf(path):
    stream = b'BT /F1 12 Tf 50 700 Td (Certificate fixture) Tj ET\n'
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Count 1 /Kids [3 0 R] >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
               b'<< /Length ' + str(len(stream)).encode() + b' >>\nstream\n' + stream + b'endstream']
    data = b'%PDF-1.4\n'
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += str(number).encode() + b' 0 obj\n' + obj + b'\nendobj\n'
    start = len(data)
    data += b'xref\n0 6\n0000000000 65535 f \n'
    for offset in offsets[1:]:
        data += f'{offset:010} 00000 n \n'.encode()
    data += b'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n' + str(start).encode() + b'\n%%EOF\n'
    path.write_bytes(data)


with tempfile.TemporaryDirectory(prefix='sparky-ca-desktop-') as temporary:
    directory = Path(temporary)
    password = directory / 'password'
    password.write_text(' Generated identity password \n')
    password.chmod(0o600)
    nss_password = directory / 'nss-password'
    nss_password.write_text(' Generated database password \n')
    nss_password.chmod(0o600)
    empty_password = directory / 'empty-password'
    empty_password.write_text('\n')
    empty_password.chmod(0o600)
    for algorithm in ('RSA', 'ECDSA'):
        fixture = directory / algorithm
        fixture.mkdir()
        root, root_key, leaf, leaf_key = [fixture / p for p in ('root.pem', 'root.key', 'leaf.pem', 'leaf.key')]
        keyargs = ['rsa:2048'] if algorithm == 'RSA' else ['ec', '-pkeyopt', 'ec_paramgen_curve:P-256']
        run(['openssl', 'req', '-new', '-x509', '-newkey', *keyargs, '-nodes', '-days', '3', '-subj', '/CN=M3 ' + algorithm + ' root',
             '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
             '-keyout', root_key, '-out', root])
        csr = fixture / 'leaf.csr'
        nickname = 'M3 ' + algorithm + ' identity'
        run(['openssl', 'req', '-new', '-newkey', *keyargs, '-nodes', '-subj', '/CN=' + nickname, '-keyout', leaf_key, '-out', csr])
        extensions = fixture / 'extensions'
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\nextendedKeyUsage=emailProtection,clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        run(['openssl', 'x509', '-req', '-in', csr, '-CA', root, '-CAkey', root_key, '-set_serial', '2', '-days', '2', '-extfile', extensions, '-out', leaf])
        der = fixture / 'root.der'
        run(['openssl', 'x509', '-in', root, '-outform', 'DER', '-out', der])
        leaf_der = fixture / 'leaf.der'
        run(['openssl', 'x509', '-in', leaf, '-outform', 'DER', '-out', leaf_der])
        data = fixture / 'data'
        (data / 'roots').mkdir(parents=True)
        (data / 'roots/root.crt').write_bytes(root.read_bytes())
        (data / 'pins.json').write_text(json.dumps({'roots': [{'file': 'root.crt', 'sha256': hashlib.sha256(der.read_bytes()).hexdigest()}]}))
        (data / 'catalogue.json').write_text(json.dumps({'schema': 1, 'certificates': [{'name': 'ICP-Brasil fixture.crt', 'pem': root.read_text()}]}))
        args = [binary, '--data', data]
        foreign = fixture / 'foreign.json'
        record = {'name': 'Another PKI root', 'pem': root.read_text(), 'groups': ['foreign-roots']}
        foreign.write_text(json.dumps({'schema': 1, 'certificates': [record]}))
        output = json.loads(run([*args, '--catalogue', foreign, 'list']).stdout)
        check(output[0]['groups'] == ['foreign-roots'], algorithm + ' catalogue format supports another PKI without Brazilian group assumptions')
        record['groups'] = ['../unsafe']
        foreign.write_text(json.dumps({'schema': 1, 'certificates': [record]}))
        run([*args, '--catalogue', foreign, 'groups'], good=False)
        check(True, algorithm + ' custom catalogue groups reject unsafe identifiers')
        p12 = fixture / 'identity.p12'
        run(['openssl', 'pkcs12', '-export', '-inkey', leaf_key, '-in', leaf, '-certfile', root, '-name', nickname, '-out', p12, '-passout', 'file:' + str(password)])
        for certificate in (root, leaf, der, leaf_der):
            output = json.loads(run([*args, 'preview', certificate]).stdout)
            check(len(output) == 1 and output[0]['issuer'] and len(output[0]['sha256']) == 64, algorithm + ' PEM/DER preview exposes issuer and exact fingerprint')
        p7b = fixture / 'chain.p7b'
        run(['openssl', 'crl2pkcs7', '-nocrl', '-certfile', leaf, '-certfile', root, '-outform', 'DER', '-out', p7b])
        check(len(json.loads(run([*args, 'preview', p7b]).stdout)) == 2, algorithm + ' PKCS#7 previews both certificates')
        check(len(json.loads(run([*args, '--password-file', password, 'preview', p12]).stdout)) == 2, algorithm + ' PKCS#12 previews identity and chain')
        run([*args, 'preview', p12], good=False)
        check(True, algorithm + ' locked identity rejects an absent/wrong passphrase')
        password.chmod(0o644)
        rejected_nss = fixture / 'rejected-nss'
        result = run([*args, '--nss', rejected_nss, '--password-file', password, 'import', p12], good=False)
        check(not rejected_nss.exists() and 'owner-only' in result.stderr, algorithm + ' public password file is rejected before store creation')
        password.chmod(0o600)
        nss = fixture / 'protected-nss'
        run([*args, '--nss', nss, '--password-file', password, '--nss-password-file', nss_password, 'import', p12])
        records = json.loads(run([*args, '--nss', nss, 'status']).stdout)
        check(any(item['name'] == nickname and 'u' in item['trust'] for item in records), algorithm + ' protected NSS database contains the imported identity')
        run([*args, '--nss', nss, '--password-file', password, 'import', p12], good=False)
        check(True, algorithm + ' wrong NSS database password is rejected')
        previous = {item['sha256']: item['trust'] for item in records}
        run([*args, '--nss', nss, '--nss-password-file', nss_password, 'install', 'icp-roots'])
        installed = json.loads(run([*args, '--nss', nss, 'status']).stdout)
        check(any(item['sha256'] == hashlib.sha256(der.read_bytes()).hexdigest() and item['trust'].startswith('C,') for item in installed), algorithm + ' explicit install trusts the existing identity chain root')
        run([*args, '--nss', nss, '--nss-password-file', nss_password, 'remove', 'all'])
        records = json.loads(run([*args, '--nss', nss, 'status']).stdout)
        check(any(item['name'] == nickname for item in records) and not any(item['name'].startswith('sparky-ca-') for item in records), algorithm + ' root install/remove preserves personal identity in a protected database')
        check({item['sha256']: item['trust'] for item in records} == previous, algorithm + ' removal restores the exact earlier NSS trust settings')
        symlink = fixture / 'linked-nss'
        symlink.symlink_to(nss, target_is_directory=True)
        run([*args, '--nss', symlink, '--password-file', password, 'import', p12], good=False)
        check(True, algorithm + ' symlinked NSS directory is refused')
        print(run([request, data, fixture / 'request']).stdout, flush=True)
        check(True, algorithm + ' constrained helper request reaches only its known fixture paths')
        gpg = fixture / 'gpg'
        run([*args, '--gpg-home', gpg, 'gpgsm-trust', 'icp-roots'])
        trust = (gpg / 'trustlist.txt').read_text()
        check('sparky-ca managed roots begin' in trust and ' S\n' in trust, algorithm + ' GnuPG gets a separate managed root decision')
        with (gpg / 'trustlist.txt').open('a') as file: file.write('# user note retained\n')
        run([*args, '--gpg-home', gpg, 'gpgsm-untrust', 'icp-roots'])
        check((gpg / 'trustlist.txt').read_text() == '# user note retained\n', algorithm + ' GnuPG removal preserves unrelated user text')
        run(['gpgconf', '--homedir', gpg, '--kill', 'all'])
        signing_nss = fixture / 'signing-nss'
        run([*args, '--nss', signing_nss, '--password-file', password, 'import', p12])
        run([*args, '--nss', signing_nss, 'install', 'icp-roots'])
        unsigned, signed = fixture / 'unsigned.pdf', fixture / 'signed.pdf'
        pdf(unsigned)
        print(run([okular, signing_nss, unsigned, signed, nickname]).stdout, flush=True)
        result = run(['pdfsig', '-nssdir', signing_nss, signed])
        check('Signature is Valid' in result.stdout and "issuer isn't Trusted" in result.stdout, algorithm + ' browser TLS trust remains separate from PDF certificate trust')
        roots = json.loads(run([*args, '--nss', signing_nss, 'status']).stdout)
        root_name = next(item['name'] for item in roots if item['sha256'] == hashlib.sha256(der.read_bytes()).hexdigest())
        run(['certutil', '-M', '-d', 'sql:' + str(signing_nss), '-n', root_name, '-t', 'C,C,'])
        result = run(['pdfsig', '-nssdir', signing_nss, signed])
        print(result.stdout, flush=True)
        check('Signature is Valid' in result.stdout and 'Certificate is Trusted' in result.stdout, algorithm + ' actual Okular signature and NSS certificate chain validate')
        altered = fixture / 'altered.pdf'
        content = signed.read_bytes()
        assert b'Certificate fixture' in content
        altered.write_bytes(content.replace(b'Certificate fixture', b'Certificate changed'))
        result = subprocess.run(['pdfsig', '-nssdir', str(signing_nss), str(altered)], capture_output=True, text=True, timeout=30)
        check('Digest Mismatch' in result.stdout or 'Signature is Invalid' in result.stdout, algorithm + ' changed signed PDF content fails validation')
print(f'{checks} desktop/core/Okular checks passed', flush=True)
