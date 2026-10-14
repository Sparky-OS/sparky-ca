# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare CLI output to independent OpenSSL fingerprints and the 2020 baseline."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

records = json.loads(Path(sys.argv[1]).read_text())
actual = {record['sha256'] for record in records}
assert len(actual) == len(records), 'Repeated certificate fingerprints in output'
with tempfile.TemporaryDirectory(prefix='sparky-ca-audit-') as temporary:
    certificate = Path(temporary) / 'input.crt'
    for path in map(Path, sys.argv[2:]):
        with zipfile.ZipFile(path) as archive:
            missing = []
            for name in archive.namelist():
                certificate.write_bytes(archive.read(name))
                der = subprocess.check_output(['openssl', 'x509', '-in', str(certificate), '-outform', 'DER'])
                if hashlib.sha256(der).hexdigest() not in actual:
                    missing.append(name)
            expected = {'AC_Online_Brasil.crt', 'AC_Valid_Brasil.crt', 'AC_Valid_PLUS.crt', 'AC_Valid_SPB.crt'} if path.name == 'ACcompactadox.zip' else set()
            assert set(missing) == expected, f'{path.name}: unexpected missing certificates: {missing}'
            print(f'PASS {path.name}: {len(archive.namelist())} entries compared to OpenSSL DER fingerprints; withheld {missing}')
legacy = {
    'AC_Certisign_G6.crt': 'certisign', 'AC_Certisign_G7.crt': 'certisign',
    'AC_Certisign_Multipla_G6.crt': 'certisign', 'AC_Certisign_Multipla_G7.crt': 'certisign',
    'AC_Certisign_Multipla_CodeSigning.crt': 'code-signing', 'AC_Certisign_Multipla_SSL.crt': 'ssl',
    'AC_OAB_G3.crt': 'oab', 'Autoridade_Certificadora_da_Justica_v4.crt': 'justica',
    'Autoridade_Certificadora_da_Justica_v5.crt': 'justica',
}
for name, group in legacy.items():
    assert any(r['name'] == name and group in r['groups'] for r in records), f'Lost 2020 capability: {name}'
roots = [r for r in records if r['root']]
assert len(roots) == 12
assert all({'icp-roots', 'chrome-roots'}.issubset(r['groups']) for r in roots)
assert any(r['state'] == 'revoked' and ' v3' in r['subject'] and not r['installable'] for r in roots)
e521 = [r for r in records if r['requiresChoice']]
assert len(e521) == 1 and e521[0]['root'] and ' v7' in e521[0]['subject']
assert all(not r['installable'] for r in records if r['state'] in {'expired', 'revoked'})
print('PASS all nine non-root 2020 filenames retain their groups; all 12 roots retain ICP and Chrome capabilities')
print('PASS expiry/revocation exclusions and exactly one E-521 entry (v7 anchor), zero E-521 intermediates')
from collections import Counter
print('CATALOGUE', len(records), 'STATES', dict(Counter(r['state'] for r in records)), 'DEFAULT INSTALLABLE', sum(r['installable'] for r in records))
print('VALID BUT POLICY-EXCLUDED', [(r['name'], r['installationIssue']) for r in records if r['state'] == 'valid' and r['installationIssue']])
