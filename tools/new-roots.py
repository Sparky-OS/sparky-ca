# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""List self-signed certificates in a downloaded ITI bundle that no pin covers.

usage: new-roots.py <pins.json> <download-dir>
Exit 0: nothing unpinned. Exit 3: unpinned roots found. Exit 4: the download is not usable.
The job never adds a pin. A person checks each fingerprint against ITI's page and commits it."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

pins_file, directory = Path(sys.argv[1]), Path(sys.argv[2])
archive, digest = directory / 'ACcompactado.zip', directory / 'hashsha512.txt'
if not archive.exists() or not digest.exists():
    print('No bundle was downloaded, so there is nothing to compare.')
    sys.exit(4)
if hashlib.sha512(archive.read_bytes()).hexdigest() != digest.read_text().split()[0].lower():
    print("The bundle does not match ITI's SHA-512. Do not review it; try again later.")
    sys.exit(4)
pinned = {item['sha256'] for item in json.loads(pins_file.read_text())['roots']}
found = []
with zipfile.ZipFile(archive) as bundle:
    for name in bundle.namelist():
        if Path(name).name != name or not name.lower().endswith('.crt'):
            continue
        data = bundle.read(name)
        text = subprocess.run(['openssl', 'x509', '-noout', '-subject', '-issuer', '-fingerprint', '-sha256', '-dates'], input=data, capture_output=True, check=False)
        if text.returncode:
            text = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-subject', '-issuer', '-fingerprint', '-sha256', '-dates'], input=data, capture_output=True, check=True)
        fields = dict(line.split('=', 1) for line in text.stdout.decode().splitlines() if '=' in line)
        if fields.get('subject', '').strip() != fields.get('issuer', '').strip():
            continue
        fingerprint = fields['sha256 Fingerprint'].replace(':', '').lower()
        if fingerprint not in pinned:
            found.append((name, fields['subject'].strip(), fingerprint, fields['notBefore'], fields['notAfter']))
if not found:
    print('Every self-signed certificate in the bundle is covered by a pin.')
    sys.exit(0)
print('## Roots in ITI\'s bundle that no pin covers')
print()
print('A job never trusts a new root. Check each fingerprint against the page ITI publishes at https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz, then add the certificate to `data/roots/` and its SHA-256 to `data/pins.json` in a reviewed commit.')
print()
for name, subject, fingerprint, start, end in found:
    print(f'- `{name}`: {subject}')
    print(f'  - SHA-256 `{fingerprint}`')
    print(f'  - valid from {start} to {end}')
sys.exit(3)
