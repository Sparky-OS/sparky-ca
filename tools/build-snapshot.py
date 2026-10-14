# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assemble authenticated ITI archives; the C++ core verifies the resulting chains."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--current', required=True, type=Path)
parser.add_argument('--current-hash', required=True, type=Path)
parser.add_argument('--historical', required=True, type=Path)
parser.add_argument('--historical-hash', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
parser.add_argument('--index', required=True, type=Path)
args = parser.parse_args()
# These four optional historical entries have no issuer in either published archive.
# They are not in the current archive or in the 2020 feature baseline.
withheld = {'AC_Online_Brasil.crt', 'AC_Valid_Brasil.crt', 'AC_Valid_PLUS.crt', 'AC_Valid_SPB.crt'}
sources = []
entries = {}
for path, hash_path, historic in [(args.current, args.current_hash, False), (args.historical, args.historical_hash, True)]:
    data = path.read_bytes()
    digest = hashlib.sha512(data).hexdigest()
    if digest != hash_path.read_text().split()[0].lower():
        raise ValueError(f'Published SHA-512 mismatch: {path.name}')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        omitted = []
        for name in names:
            if Path(name).name != name or '..' in name or '\\' in name or not name.lower().endswith('.crt'):
                raise ValueError('Unsafe input entry: ' + name)
            cert = archive.read(name)
            if historic and name in withheld:
                omitted.append({'name': name, 'sourceSha256': hashlib.sha256(cert).hexdigest(), 'reason': 'Missing issuer AC VALID under root v2; chain cannot be verified.'})
                continue
            # Preserve a different historical certificate even when its filename repeats.
            if name in entries and cert != entries[name]:
                name = 'historical_' + name
            entries[name] = cert
        sources.append({'name': path.name, 'sha512': digest, 'bytes': len(data), 'entries': len(names), 'withheld': omitted})
output = io.BytesIO()
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
    for name, cert in sorted(entries.items()):
        archive.writestr(name, cert)
args.output.write_bytes(output.getvalue())
args.output.with_suffix('.sha512').write_text(hashlib.sha512(output.getvalue()).hexdigest() + '\n')
args.index.write_text(json.dumps({'sources': sources, 'assemblyEntries': len(entries)}, indent=2) + '\n')
print(json.dumps({'sources': sources, 'assemblyEntries': len(entries)}, indent=2))
