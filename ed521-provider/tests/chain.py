#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""ICP-Brasil v7 and a TEST Ed521 hierarchy through OpenSSL's own tools.

  chain.py system          use the system configuration (an installed package)
  chain.py CONFIG MODULE   use CONFIG (the shipped file) pointed at MODULE

ITI has published no certificate issued by v7 (the measured bundles hold the
root alone), so the hierarchy below is a TEST one: an Ed521 root, an Ed521
intermediate, an Ed521 signing leaf and an EC P-256 TLS leaf, every name
saying TEST, signed by the independent oracle from public TEST seeds.  It is
not ITI's and imitates no real authority.

Checks, each also run with OpenSSL's default provider alone, where it must fail:
ITI's real v7 root (-check_ss_sig) and ITI's v7 CRL; the TEST chain with
-x509_strict; a TEST CRL that revokes the leaf; CMS SignedData by the Ed521
leaf (good, altered content, altered signature); a TLS 1.3 and 1.2 server whose
EC certificate an Ed521 intermediate signed, through s_client and Python's ssl.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import os
import shutil
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).parent))
from oracle import ED521  # noqa: E402
import der  # noqa: E402

DATA = Path(__file__).parent / 'data'
checks = 0


def check(condition, message):
    global checks
    assert condition, message
    checks += 1
    print('PASS', message, flush=True)


def seed(number):
    return hashlib.shake_256(f'Sparky CA Ed521 TEST key {number}: public seed, never for real use'.encode()).digest(ED521.size)


def when(delta_days):
    return (datetime.now(timezone.utc) + timedelta(days=delta_days)).strftime('%y%m%d%H%M%SZ')


def key_id(public):
    return hashlib.sha1(public).digest()


def certificate(serial, issuer, subject, public_spki, public_raw, signer_seed, issuer_raw, ca, extra=()):
    extensions = [
        der.extension('2.5.29.19', der.sequence(*([der.boolean(True)] if ca else [])), critical=True),
        der.extension('2.5.29.15', der.key_usage(5, 6) if ca else der.key_usage(0), critical=True),
        der.extension('2.5.29.14', der.octet_string(key_id(public_raw))),
        der.extension('2.5.29.35', der.sequence(der.implicit(0, key_id(issuer_raw), constructed=False))),
        *extra,
    ]
    tbs = der.sequence(
        der.explicit(0, der.integer(2)), der.integer(serial), der.ed521_algorithm(), der.name(issuer),
        der.sequence(der.utc_time(when(-30)), der.utc_time(when(3650))), der.name(subject), public_spki,
        der.explicit(3, der.sequence(*extensions)))
    return der.sequence(tbs, der.ed521_algorithm(), der.bit_string(ED521.sign(signer_seed, tbs)))


def crl(issuer, issuer_raw, signer_seed, revoked_serial):
    tbs = der.sequence(
        der.integer(1), der.ed521_algorithm(), der.name(issuer), der.utc_time(when(-1)), der.utc_time(when(30)),
        der.sequence(der.sequence(der.integer(revoked_serial), der.utc_time(when(-1)))),
        der.explicit(0, der.sequence(
            der.extension('2.5.29.35', der.sequence(der.implicit(0, key_id(issuer_raw), constructed=False))),
            der.extension('2.5.29.20', der.integer(1)))))
    return der.sequence(tbs, der.ed521_algorithm(), der.bit_string(ED521.sign(signer_seed, tbs)))


def signed_data(content, signer_cert, chain, issuer, serial, signer_seed):
    """CMS SignedData (RFC 5652 section 5) with signed attributes; SHA-512 message digest as RFC 8419 uses for Ed25519."""
    sha512 = der.sequence(der.oid('2.16.840.1.101.3.4.2.3'))
    attributes = [
        der.sequence(der.oid('1.2.840.113549.1.9.3'), der.set_of(der.oid('1.2.840.113549.1.7.1'))),
        der.sequence(der.oid('1.2.840.113549.1.9.5'), der.set_of(der.utc_time(when(0)))),
        der.sequence(der.oid('1.2.840.113549.1.9.4'), der.set_of(der.octet_string(hashlib.sha512(content).digest()))),
    ]
    signed_attributes = der.set_of(*attributes)
    signature = ED521.sign(signer_seed, signed_attributes)
    signer = der.sequence(
        der.integer(1), der.sequence(der.name(issuer), der.integer(serial)), sha512,
        b'\xa0' + signed_attributes[1:], der.ed521_algorithm(), der.octet_string(signature))
    body = der.sequence(
        der.integer(1), der.set_of(sha512),
        der.sequence(der.oid('1.2.840.113549.1.7.1'), der.explicit(0, der.octet_string(content))),
        der.implicit(0, signer_cert + b''.join(chain)), der.set_of(signer))
    return der.sequence(der.oid('1.2.840.113549.1.7.2'), der.explicit(0, body))


def listening(port):
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1].endswith(f':{port:04X}') and fields[3] == '0A':
            return True
    return False


def main():
    if sys.argv[1] == 'system':
        configured = dict(os.environ)
        configured.pop('OPENSSL_CONF', None)
    else:
        config, module = (Path(value).resolve() for value in sys.argv[1:3])
        configured = None
    plain = dict(os.environ, OPENSSL_CONF='/dev/null')
    with tempfile.TemporaryDirectory(prefix='ed521-chain-') as temporary:
        d = Path(temporary)
        if configured is None:
            text = config.read_text().replace('[ed521_sect]\n', f'[ed521_sect]\nmodule = {module}\n')
            (d / 'openssl.cnf').write_text(text)
            configured = dict(os.environ, OPENSSL_CONF=str(d / 'openssl.cnf'))

        def openssl(*args, env, input=None):
            return subprocess.run(['openssl', *map(str, args)], env=env, input=input, capture_output=True, timeout=60)

        def both(name, *args, input=None, expect=None):
            bad = openssl(*args, env=plain, input=input)
            good = openssl(*args, env=configured, input=input)
            ok = good.returncode == 0 and (expect is None or expect in (good.stdout + good.stderr).decode())
            check(ok, f'{name}: verifies with Ed521 ({(good.stdout + good.stderr).decode().strip().splitlines()[-1:]})')
            check(bad.returncode != 0, f'{name}: fails with the default provider alone')

        def fails(name, *args, input=None):
            result = openssl(*args, env=configured, input=input)
            check(result.returncode != 0, f'{name}: rejected ({(result.stdout + result.stderr).decode().strip().splitlines()[:1]})')

        v7 = d / 'v7.pem'
        v7.write_text(der.pem('CERTIFICATE', (DATA / 'ICP-Brasilv7.der').read_bytes()))
        both('ITI AC Raiz v7 self-signature', 'verify', '-check_ss_sig', '-CAfile', v7, v7)
        both("ITI's v7 CRL (current list, signed with Ed521)", 'crl', '-inform', 'DER', '-in', DATA / 'LCRacraizv7.crl', '-noout', '-CAfile', v7, expect='verify OK')

        names = {k: f'TEST ONLY Ed521 {k} (Sparky CA test hierarchy, not ICP-Brasil)' for k in ('root', 'intermediate', 'signer', 'server')}
        keys = {k: seed(n) for k, n in (('root', 10), ('intermediate', 11), ('signer', 12))}
        raw = {k: ED521.public_key(s) for k, s in keys.items()}
        root = certificate(1, names['root'], names['root'], der.ed521_spki(raw['root']), raw['root'], keys['root'], raw['root'], True)
        intermediate = certificate(2, names['root'], names['intermediate'], der.ed521_spki(raw['intermediate']), raw['intermediate'], keys['root'], raw['root'], True)
        signer_cert = certificate(3, names['intermediate'], names['signer'], der.ed521_spki(raw['signer']), raw['signer'], keys['intermediate'], raw['intermediate'], False,
                                  extra=[der.extension('2.5.29.37', der.sequence(der.oid('1.3.6.1.5.5.7.3.4')))])
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', d / 'server.key'], env=plain, check=True, capture_output=True)
        server_spki = subprocess.run(['openssl', 'pkey', '-in', d / 'server.key', '-pubout', '-outform', 'DER'], env=plain, check=True, capture_output=True).stdout
        server_raw = der.children(der.read(server_spki)[1])[1][1][1:]
        san = der.sequence(der.implicit(2, b'localhost', constructed=False), der.implicit(7, bytes([127, 0, 0, 1]), constructed=False))
        server = certificate(4, names['intermediate'], names['server'], server_spki, server_raw, keys['intermediate'], raw['intermediate'], False,
                             extra=[der.extension('2.5.29.37', der.sequence(der.oid('1.3.6.1.5.5.7.3.1'))), der.extension('2.5.29.17', san)])
        for name, value in (('root', root), ('intermediate', intermediate), ('signer', signer_cert), ('server', server)):
            (d / f'{name}.pem').write_text(der.pem('CERTIFICATE', value))
        (d / 'crl.pem').write_text(der.pem('X509 CRL', crl(names['intermediate'], raw['intermediate'], keys['intermediate'], 3)))

        both('TEST Ed521 chain, -x509_strict', 'verify', '-check_ss_sig', '-x509_strict', '-CAfile', d / 'root.pem', '-untrusted', d / 'intermediate.pem', d / 'signer.pem')
        both('TEST EC server certificate signed by the Ed521 intermediate', 'verify', '-x509_strict', '-purpose', 'sslserver', '-CAfile', d / 'root.pem', '-untrusted', d / 'intermediate.pem', d / 'server.pem')
        revoked = openssl('verify', '-crl_check', '-CAfile', d / 'root.pem', '-untrusted', d / 'intermediate.pem', '-CRLfile', d / 'crl.pem', d / 'signer.pem', env=configured)
        check(revoked.returncode != 0 and b'certificate revoked' in revoked.stdout + revoked.stderr, 'TEST CRL signed with Ed521 revokes the signer')
        both('TEST CRL leaves the server certificate valid', 'verify', '-crl_check', '-CAfile', d / 'root.pem', '-untrusted', d / 'intermediate.pem', '-CRLfile', d / 'crl.pem', d / 'server.pem')
        tampered = bytearray(intermediate)
        tampered[-5] ^= 1
        (d / 'intermediate-tampered.pem').write_text(der.pem('CERTIFICATE', bytes(tampered)))
        fails('TEST chain with an altered intermediate signature', 'verify', '-check_ss_sig', '-CAfile', d / 'root.pem', '-untrusted', d / 'intermediate-tampered.pem', d / 'signer.pem')

        content = b'TEST document signed with Ed521 for Sparky CA; it proves CMS verification, nothing more.\n'
        cms = signed_data(content, signer_cert, [intermediate], names['intermediate'], 3, keys['signer'])
        (d / 'signed.der').write_bytes(cms)
        both('CMS SignedData by the Ed521 TEST signer', 'cms', '-verify', '-inform', 'DER', '-in', d / 'signed.der', '-CAfile', d / 'root.pem', '-purpose', 'smimesign', '-out', d / 'content.out', expect='Verification successful')
        check((d / 'content.out').read_bytes() == content, 'CMS returns the signed content unchanged')
        altered = bytearray(cms)
        position = altered.find(b'TEST document')
        altered[position] ^= 1
        (d / 'altered-content.der').write_bytes(bytes(altered))
        fails('CMS with altered content', 'cms', '-verify', '-inform', 'DER', '-in', d / 'altered-content.der', '-CAfile', d / 'root.pem', '-purpose', 'smimesign', '-out', '/dev/null')
        altered = bytearray(cms)
        altered[-10] ^= 1
        (d / 'altered-signature.der').write_bytes(bytes(altered))
        fails('CMS with an altered signature', 'cms', '-verify', '-inform', 'DER', '-in', d / 'altered-signature.der', '-CAfile', d / 'root.pem', '-purpose', 'smimesign', '-out', '/dev/null')

        for version in ('-tls1_3', '-tls1_2'):
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                port = s.getsockname()[1]
            server_process = subprocess.Popen(['openssl', 's_server', '-accept', f'127.0.0.1:{port}', '-naccept', '2', '-cert', d / 'server.pem', '-key', d / 'server.key',
                                               '-cert_chain', d / 'intermediate.pem', version, '-quiet'], env=configured,
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(250):
                if listening(port):
                    break
                time.sleep(0.02)
            good = openssl('s_client', '-connect', f'127.0.0.1:{port}', '-servername', 'localhost', '-brief', '-no_ign_eof', '-CAfile', d / 'root.pem',
                           '-verify_return_error', '-verify_hostname', 'localhost', version, env=configured, input=b'')
            text = (good.stdout + good.stderr).decode()
            check(good.returncode == 0 and 'Verification: OK' in text, f'TLS {version[1:]}: s_client verifies the Ed521-signed server chain' + ('' if good.returncode == 0 else ': ' + text))
            if version == '-tls1_3':
                code = (f'import ssl, socket\nc = ssl.create_default_context(cafile={str(d / "root.pem")!r})\n'
                        f's = c.wrap_socket(socket.create_connection(("127.0.0.1", {port})), server_hostname="localhost")\n'
                        'print(s.version(), s.getpeercert()["subject"])\ns.close()\n')
                python = subprocess.run([sys.executable, '-I', '-c', code], env=configured, capture_output=True, text=True, timeout=30)
                check(python.returncode == 0 and 'TLSv1.3' in python.stdout, 'TLS 1.3: Python ssl verifies the Ed521-signed server chain: ' + python.stdout.strip()[:80])
            else:
                bad = openssl('s_client', '-connect', f'127.0.0.1:{port}', '-servername', 'localhost', '-brief', '-no_ign_eof', '-CAfile', d / 'root.pem',
                              '-verify_return_error', version, env=plain, input=b'')
                check(bad.returncode != 0, 'TLS 1.2: the default provider alone rejects the Ed521-signed chain')
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
                server_process.wait()
        if shutil.which('curl'):
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                port = s.getsockname()[1]
            server_process = subprocess.Popen(['openssl', 's_server', '-accept', f'127.0.0.1:{port}', '-naccept', '2', '-www', '-cert', d / 'server.pem',
                                               '-key', d / 'server.key', '-cert_chain', d / 'intermediate.pem', '-quiet'], env=configured,
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(250):
                if listening(port):
                    break
                time.sleep(0.02)
            curl = ['curl', '-sS', '--max-time', '20', '--cacert', str(d / 'root.pem'), f'https://localhost:{port}/']
            good = subprocess.run(curl, env=configured, capture_output=True, timeout=30)
            check(good.returncode == 0 and b'Ciphers supported' in good.stdout, 'curl (OpenSSL backend) fetches over the Ed521-signed chain')
            bad = subprocess.run(curl, env=plain, capture_output=True, timeout=30)
            check(bad.returncode != 0, f'curl with the default provider alone refuses it ({bad.stderr.decode().strip()[:70]})')
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
                server_process.wait()
    print(f'{checks} chain checks passed')


if __name__ == '__main__':
    main()
