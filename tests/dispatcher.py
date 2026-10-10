# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
from pathlib import Path
import pty
import shutil
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve()
data = Path(__file__).resolve().parents[1] / 'data'
plain = dict(os.environ)
for name in ('DISPLAY', 'WAYLAND_DISPLAY'): plain.pop(name, None)
display = dict(plain, WAYLAND_DISPLAY='isolated-routing-fixture')
with tempfile.TemporaryDirectory(prefix='sparky-ca-dispatch-') as temporary:
    directory = Path(temporary)
    dispatcher = directory / 'sparky-ca'
    shutil.copy2(binary, dispatcher)
    for front in ('cli', 'gui'):
        stub = directory / ('sparky-ca-' + front)
        stub.write_text('#!/usr/bin/python3\nimport json,sys\nprint(json.dumps([' + repr(front) + ',sys.argv[1:]]))\n')
        stub.chmod(0o700)
    for arguments, env, expected in [
        ([], display, ['gui', []]),
        (['groups'], display, ['cli', ['groups']]),
        (['--gui'], plain, ['gui', []]),
        (['--tty'], display, ['cli', []]),
        (['--tty', '--gui'], display, ['cli', []]),
        (['fixture.crt'], plain, ['cli', ['preview', str(Path('fixture.crt').resolve())]]),
        (['fixture.crt'], display, ['gui', ['fixture.crt']]),
    ]:
        result = subprocess.run([str(dispatcher), *arguments], env=env, text=True, capture_output=True, timeout=10)
        assert result.returncode == 0 and json.loads(result.stdout) == expected, (arguments, result.stdout, result.stderr)
        print('PASS dispatcher selects and forwards ' + repr(expected), flush=True)
master, slave = pty.openpty()
process = subprocess.Popen([str(binary), '--tty', '--data', str(data)], env=plain, stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
os.write(master, b'0\n')
process.wait(timeout=10)
content = b''
while True:
    try:
        chunk = os.read(master, 4096)
        if not chunk: break
        content += chunk
    except OSError: break
os.close(master)
assert process.returncode == 0 and b'1. List catalogue' in content and b'Choice:' in content, content
print('PASS actual numbered TTY menu exits through option 0', flush=True)
result = subprocess.run([str(binary), '--data', str(data), 'groups'], env=display, capture_output=True, text=True, timeout=10)
assert result.returncode == 0 and 'icp-roots' in result.stdout and 'oab' in result.stdout, result
print('PASS actual script subcommand stays text-only with a display present', flush=True)
print('9 dispatcher checks passed', flush=True)
