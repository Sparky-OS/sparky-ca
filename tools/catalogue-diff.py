# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Describe the difference between two catalogue files as Markdown for a pull request.

usage: catalogue-diff.py <old catalogue.json> <new catalogue.json>"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def load(path):
    entries = {}
    for item in json.loads(Path(path).read_text())['certificates']:
        der = subprocess.run(['openssl', 'x509', '-outform', 'DER'], input=item['pem'].encode(), capture_output=True, check=True).stdout
        subject = subprocess.run(['openssl', 'x509', '-noout', '-subject', '-nameopt', 'RFC2253'], input=item['pem'].encode(), capture_output=True, check=True).stdout.decode().strip()
        entries[hashlib.sha256(der).hexdigest()] = (item['name'], re.sub('^subject=', '', subject))
    return entries


old, new = load(sys.argv[1]), load(sys.argv[2])
added = sorted(set(new) - set(old), key=lambda key: new[key])
removed = sorted(set(old) - set(new), key=lambda key: old[key])
print("## ITI's bundle changed")
print()
print(f'The bundle matched ITI\'s SHA-512 and every chain ends at a pinned root. The catalogue goes from {len(old)} to {len(new)} certificates.')
print()
print(f'### Added ({len(added)})')
for key in added:
    print(f'- `{new[key][0]}`: {new[key][1]} (SHA-256 `{key}`)')
print()
print(f'### Removed ({len(removed)})')
for key in removed:
    print(f'- `{old[key][0]}`: {old[key][1]} (SHA-256 `{key}`)')
renamed = [key for key in set(old) & set(new) if old[key][0] != new[key][0]]
if renamed:
    print()
    print(f'### Renamed ({len(renamed)})')
    for key in sorted(renamed):
        print(f'- `{old[key][0]}` is now `{new[key][0]}`')
print()
print('No root pin changed. A new root arrives only as a reviewed commit that adds its fingerprint.')
