#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

CHECK, PROVIDER = map(lambda value: str(Path(value).resolve()), sys.argv[1:3])
SOURCE = Path(__file__).resolve().parents[1]

def run(args, expected=0, env=None):
    result = subprocess.run(args, env=env, text=True, capture_output=True)
    if result.returncode != expected:
        raise AssertionError(f"{args[:3]} returned {result.returncode}, expected {expected}: {result.stdout}{result.stderr}")
    return result.stdout

def pem(label, der):
    encoded = base64.b64encode(der).decode()
    return f"-----BEGIN {label}-----\n" + "\n".join(encoded[i:i+64] for i in range(0, len(encoded), 64)) + f"\n-----END {label}-----\n"

with tempfile.TemporaryDirectory(prefix="ed521-provider-") as directory:
    root = Path(directory)
    config = root / "openssl.cnf"
    config.write_text(f"openssl_conf = init\n[init]\nproviders = providers\n[providers]\ndefault = default_sect\ned521-provider = ed521\n[default_sect]\nactivate = 1\n[ed521]\nmodule = {PROVIDER}\nactivate = 1\n")
    env = dict(os.environ, OPENSSL_CONF=str(config))
    certificate = SOURCE / "tests/data/ICP-Brasilv7.der"
    v7 = root / "v7.pem"
    v7.write_text(pem("CERTIFICATE", certificate.read_bytes()))
    run(["openssl", "verify", "-check_ss_sig", "-CAfile", str(v7), str(v7)], env=env)
    der = subprocess.check_output(["openssl", "x509", "-in", str(v7), "-outform", "DER"])
    assert hashlib.sha256(der).hexdigest() == "5657e70580eb678983f3ed7dfce091d84cae6549389a47fccda8d0e4dc2cf576"
    def children(data):
        result, pos = [], 0
        while pos < len(data):
            start = pos
            tag, size = data[pos:pos+2]; pos += 2
            if size & 128:
                count = size & 127; size = int.from_bytes(data[pos:pos+count], "big"); pos += count
            content = data[pos:pos+size]; pos += size
            result.append((tag, content, data[start:pos]))
        return result
    cert = children(children(der)[0][1])
    tbs = cert[0][2]
    public_der = children(cert[0][1])[6][2]
    public = root / "public.pem"
    public.write_text(pem("PUBLIC KEY", public_der))
    signature = cert[2][1][1:]
    run([CHECK, str(public), tbs.hex(), signature.hex()], env=env)
    for index in range(132):
        bad = bytearray(signature); bad[index] ^= 1
        run([CHECK, str(public), tbs.hex(), bad.hex()], expected=1, env=env)
    bad = bytearray(tbs); bad[50] ^= 1
    run([CHECK, str(public), bad.hex(), signature.hex()], expected=1, env=env)
    altered = bytearray(public_der); altered[-10] ^= 1
    public.write_text(pem("PUBLIC KEY", altered))
    result = subprocess.run([CHECK, str(public), tbs.hex(), signature.hex()], env=env, capture_output=True)
    assert result.returncode in (1, 2), result.returncode
    # Trusting a root alone does not prove its signature: check_ss_sig is mandatory.
    tampered = bytearray(der); tampered[-1] ^= 1
    v7.write_text(pem("CERTIFICATE", tampered))
    result = subprocess.run(["openssl", "verify", "-check_ss_sig", "-CAfile", str(v7), str(v7)], env=env, capture_output=True)
    assert result.returncode != 0
    synthetic = {}
    for label in ("root", "intermediate", "leaf"):
        synthetic[label] = root / f"synthetic-{label}.pem"
        synthetic[label].write_text(pem("CERTIFICATE", (SOURCE / f"tests/data/synthetic-{label}.der").read_bytes()))
    args = ["openssl", "verify", "-check_ss_sig", "-CAfile", str(synthetic["root"]), "-untrusted", str(synthetic["intermediate"]), str(synthetic["leaf"])]
    run(args, env=env)
    assert subprocess.run(args, env=dict(env, OPENSSL_CONF="/dev/null"), capture_output=True).returncode != 0
    intermediate = bytearray((SOURCE / "tests/data/synthetic-intermediate.der").read_bytes())
    intermediate[-10] ^= 1
    synthetic["intermediate"].write_text(pem("CERTIFICATE", intermediate))
    assert subprocess.run(args, env=env, capture_output=True).returncode != 0
    for vector in json.loads((SOURCE / "tests/data/generated-chain.json").read_text()):
        spki = bytes.fromhex("3053300c060a2b0601040182dc2c0201034300") + bytes.fromhex(vector["public"])
        public.write_text(pem("PUBLIC KEY", spki))
        run([CHECK, str(public), vector["message"], vector["signature"]], env=env)
        bad = bytearray.fromhex(vector["signature"]); bad[100] ^= 1
        run([CHECK, str(public), vector["message"], bad.hex()], expected=1, env=env)
    print("Provider: real ITI v7 self-signature valid; 132 signature mutations, message/key mutations and altered X.509 self-signature rejected; independent three-level synthetic chain validates, altered intermediate and absent provider fail")
