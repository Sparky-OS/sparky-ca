# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real crypto, HTTPS, Debian updater and NSS; all state is under a temporary directory."""
import hashlib
import http.server
import io
import json
import os
import pty
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import zipfile

binary = str(Path(sys.argv[1]).resolve())
checks = 0


def checked(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1
    print(f"PASS {message}", flush=True)


def execute(args, success=True):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=45)
    if success and result.returncode:
        raise AssertionError(f"Command failed: {args}: {result.stderr}")
    return result


def make_certificate(name, issuer=None, ca=True, san=None, days=30):
    key = f"{name}.key"
    cert = f"{name}.pem"
    execute(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", f"{name}.csr", "-subj", f"/CN={name}"])
    extension = f"basicConstraints=critical,CA:{'TRUE' if ca else 'FALSE'}\n"
    extension += "keyUsage=critical," + ("keyCertSign,cRLSign" if ca else "digitalSignature,keyEncipherment") + "\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
    if san:
        extension += f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n"
    Path(f"{name}.ext").write_text(extension)
    args = ["openssl", "x509", "-req", "-in", f"{name}.csr", "-out", cert, "-days", max(days, 30), "-extfile", f"{name}.ext"]
    if days < 0:
        args += ["-not_before", "20200101000000Z", "-not_after", "20210101000000Z"]
    args += ["-CA", f"{issuer}.pem", "-CAkey", f"{issuer}.key", "-CAcreateserial"] if issuer else ["-signkey", key]
    execute(args)
    return Path(cert).read_bytes()


def fingerprint(cert):
    # Binary data requires a binary subprocess, rather than text decoding.
    raw = subprocess.check_output(["openssl", "x509", "-in", cert, "-outform", "DER"])
    return hashlib.sha256(raw).hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    responses = {}

    def do_GET(self):
        body = self.responses.get(self.path)
        self.send_response(200 if body is not None else 404)
        self.end_headers()
        if body is not None:
            self.wfile.write(body)

    def log_message(self, *args):
        pass


def bundle(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, cert in entries:
            archive.writestr(name, cert)
    return output.getvalue()


with tempfile.TemporaryDirectory(prefix="sparky-ca-test-") as temporary:
    os.chdir(temporary)
    root = make_certificate("icp-test")
    intermediate = make_certificate("AC_OAB_JUS", "icp-test")
    expired = make_certificate("AC_Certisign_expired", "icp-test", days=-1)
    foreign = make_certificate("foreign")
    tls_root = make_certificate("tls-test")
    tls_issuer = make_certificate("tls-issuer", "tls-test")
    make_certificate("localhost", "tls-issuer", ca=False, san="DNS:localhost")
    data = Path("data")
    (data / "roots").mkdir(parents=True)
    (data / "roots/root.pem").write_bytes(root)
    pin = fingerprint("icp-test.pem")
    (data / "pins.json").write_text(json.dumps({"roots": [{"file": "root.pem", "sha256": pin}]}))
    archive = bundle([("AC_OAB_JUS.crt", intermediate), ("AC_Certisign_expired.crt", expired)])
    Handler.responses = {"/bundle": archive, "/hash": hashlib.sha512(archive).hexdigest().encode() + b"  ACcompactado.zip\n"}
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("localhost.pem", "localhost.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"https://localhost:{server.server_port}"
    base = [binary, "--data", data.resolve(), "--catalogue", Path("catalogue.json").resolve()]
    refresh = [*base, "update", "--bundle-url", url + "/bundle", "--hash-url", url + "/hash", "--tls-ca", "tls-test.pem", "--output", "catalogue.json"]
    checked(execute(refresh, False).returncode != 0, "missing TLS intermediate rejected")
    refresh += ["--tls-issuer", "tls-issuer.pem"]
    execute(refresh)
    checked(Path("catalogue.json").exists(), "verified issuer repairs incomplete HTTPS chain")
    original = Path("catalogue.json").read_bytes()
    execute(refresh)
    checked(Path("catalogue.json").read_bytes() == original, "unchanged refresh produces identical catalogue bytes")
    records = json.loads(execute([*base, "list"]).stdout)
    checked(len(records) == 3, "catalogue includes intermediates and shipped root")
    checked(any(r["state"] == "expired" for r in records), "expired certificate remains listed")
    checked(any(set(r["groups"]) == {"oab", "justica"} for r in records), "certificate belongs to overlapping legacy groups")
    checked(all(r["issuer"] and r["expires"] for r in records), "listing exposes issuer and expiry")
    Handler.responses["/hash"] = b"0" * 128
    rejected = execute(refresh, False)
    checked(rejected.returncode != 0 and "SHA-512" in rejected.stderr, "wrong bundle hash rejected")
    checked(Path("catalogue.json").read_bytes() == original, "failed update leaves previous catalogue unchanged")
    der = subprocess.check_output(["openssl", "x509", "-in", "AC_OAB_JUS.pem", "-outform", "DER"])
    tampered = der[:-1] + bytes([der[-1] ^ 1])
    execute(["openssl", "x509", "-in", "icp-test.pem", "-signkey", "icp-test.key", "-set_serial", "12345", "-days", "30", "-out", "alternate.pem"])
    for description, entries in [
        ("tampered certificate", [("AC_OAB.crt", tampered)]),
        ("unpinned root", [("foreign.crt", foreign)]),
        ("unpinned root with the same key and subject", [("alternate.crt", Path("alternate.pem").read_bytes())]),
        ("ZIP path traversal", [("../AC_OAB.crt", intermediate)]),
        ("non-CA certificate", [("localhost.crt", Path("localhost.pem").read_bytes())]),
    ]:
        bad = bundle(entries)
        Handler.responses.update({"/bundle": bad, "/hash": hashlib.sha512(bad).hexdigest().encode()})
        checked(execute(refresh, False).returncode != 0, description + " rejected after correct bundle hash")
    bad_issuer = [a if str(a) != "tls-issuer.pem" else "foreign.pem" for a in refresh]
    checked(execute(bad_issuer, False).returncode != 0, "untrusted TLS issuer rejected")
    wrong_host = [str(a).replace("https://localhost:", "https://127.0.0.1:") for a in refresh]
    checked(execute(wrong_host, False).returncode != 0, "TLS hostname mismatch rejected")
    Handler.responses.update({"/bundle": archive, "/hash": hashlib.sha512(archive).hexdigest().encode()})
    execute(refresh)
    system = Path("system").resolve()
    system.mkdir()
    derived = Path("derived/ca-certificates.crt").resolve()
    system_args = [*base, "--system-dir", system, "--system-bundle", derived]
    execute([*system_args, "install", "icp-roots"])
    roots = json.loads(execute([*system_args, "list", "installed"]).stdout)
    checked([r["sha256"] for r in roots] == [pin], "real Debian updater adds the expected root to isolated system bundle")
    execute([*system_args, "install", "oab"])
    checked(len(json.loads(execute([*system_args, "status"]).stdout)) == 2, "system store installs selected valid intermediate")
    execute([*system_args, "install", "justica"])
    execute([*system_args, "remove", "oab"])
    checked(len(json.loads(execute([*system_args, "status"]).stdout)) == 2, "removing one group preserves shared certificate")
    execute([*system_args, "remove", "all"])
    checked(json.loads(execute([*system_args, "status"]).stdout) == [], "system removal rebuilds empty isolated bundle")
    checked(execute([*system_args, "install", "certisign"], False).returncode != 0, "expired-only group cannot install")
    database = Path("nss").resolve()
    nss_args = [*base, "--nss", database]
    execute([*nss_args, "install", "icp-roots"])
    execute(["certutil", "-A", "-d", "sql:" + str(database), "-n", "unrelated", "-t", "C,,", "-i", "foreign.pem"])
    execute([*nss_args, "install", "oab"])
    installed = json.loads(execute([*nss_args, "list", "installed"]).stdout)
    checked(len(installed) == 3, "real NSS listing includes owned and unrelated certificates")
    checked(next(r["trust"] for r in installed if r["sha256"] == pin) == "C,,", "NSS roots receive CA trust")
    checked(next(r["trust"] for r in installed if r["sha256"] == fingerprint("AC_OAB_JUS.pem")) == ",,", "NSS intermediates do not become trust anchors")
    execute(["certutil", "-D", "-d", "sql:" + str(database), "-n", "sparky-ca-" + pin])
    execute(["certutil", "-A", "-d", "sql:" + str(database), "-n", "sparky-ca-" + pin, "-t", "C,,", "-i", "tls-test.pem"])
    checked(execute([*nss_args, "install", "icp-roots"], False).returncode != 0, "NSS reinstall detects changed owned bytes")
    checked(execute([*nss_args, "remove", "all"], False).returncode != 0, "NSS removal refuses a changed owned nickname")
    altered_listing = json.loads(execute([*nss_args, "status"]).stdout)
    checked(any(r["name"] == "sparky-ca-" + pin and r["sha256"] == fingerprint("tls-test.pem") for r in altered_listing), "NSS changed entry survives refused removal")
    execute(["certutil", "-D", "-d", "sql:" + str(database), "-n", "sparky-ca-" + pin])
    execute(["certutil", "-A", "-d", "sql:" + str(database), "-n", "sparky-ca-" + pin, "-t", "C,,", "-i", "icp-test.pem"])
    execute([*nss_args, "remove", "all"])
    remaining = json.loads(execute([*nss_args, "status"]).stdout)
    checked(len(remaining) == 1 and remaining[0]["name"] == "unrelated", "NSS removal preserves unrelated trust")
    home = Path("home").resolve()
    (home / ".pki/nssdb").mkdir(parents=True)
    (home / ".waterfox/test").mkdir(parents=True)
    (home / ".waterfox/test/cert9.db").touch()
    (home / ".waterfox/profiles.ini").write_text("[Profile0]\nPath=test\nIsRelative=1\n")
    profile_env = dict(os.environ, HOME=str(home))
    profiles = subprocess.check_output([*map(str, base), "profiles"], env=profile_env, text=True).splitlines()
    checked(str(home / ".pki/nssdb") in profiles and str(home / ".local/share/pki/nssdb") not in profiles, "existing Chromium legacy database wins")
    checked(str(home / ".waterfox/test") in profiles, "Waterfox profile discovered without opening browser")
    (home / ".mozilla/firefox/test").mkdir(parents=True)
    (home / ".mozilla/firefox/test/cert9.db").touch()
    (home / ".mozilla/firefox/profiles.ini").write_text("[Profile0]\nPath=test\nIsRelative=1\n")
    profiles = subprocess.check_output([*map(str, base), "profiles"], env=profile_env, text=True).splitlines()
    checked(str(home / ".mozilla/firefox/test") in profiles, "Firefox profile discovered without opening browser")
    master, slave = pty.openpty()
    menu = subprocess.Popen([*map(str, base)], stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    os.close(slave)
    os.write(master, b"1\n")
    output, errors = menu.communicate(timeout=45)
    os.close(master)
    checked(menu.returncode == 0 and "1. List catalogue" in output and pin in output and not errors, "numbered TTY menu executes catalogue listing without a display")
    execute(["openssl", "ecparam", "-name", "prime256v1", "-param_enc", "explicit", "-genkey", "-out", "explicit.key"])
    execute(["openssl", "req", "-new", "-key", "explicit.key", "-out", "explicit.csr", "-subj", "/CN=AC Serpro explicit-curve fixture"])
    execute(["openssl", "x509", "-req", "-in", "explicit.csr", "-CA", "icp-test.pem", "-CAkey", "icp-test.key", "-CAcreateserial", "-days", "30", "-extfile", "AC_OAB_JUS.ext", "-out", "explicit.pem"])
    explicit = subprocess.check_output(["openssl", "x509", "-in", "explicit.pem", "-outform", "DER"])
    expanded = bundle([("AC_Serpro_explicit.crt", explicit)])
    Handler.responses.update({"/bundle": expanded, "/hash": hashlib.sha512(expanded).hexdigest().encode()})
    execute(refresh)
    records = json.loads(execute([*base, "list"]).stdout)
    checked(len(records) == 4, "refresh retains historical entries absent from the new bundle")
    entry = next(r for r in records if r["name"] == "AC_Serpro_explicit.crt")
    checked(entry["verification"] == "signature-verified" and not entry["installable"] and "explicit ECC" in entry["installationIssue"], "explicit-curve archive signature verifies while installation retains current crypto policy")
    checked(execute([*system_args, "install", "serpro"], False).returncode != 0, "explicit-curve archive certificate cannot install")
    altered = explicit[:-1] + bytes([explicit[-1] ^ 1])
    expanded = bundle([("AC_Serpro_explicit.crt", altered)])
    Handler.responses.update({"/bundle": expanded, "/hash": hashlib.sha512(expanded).hexdigest().encode()})
    rejected = execute(refresh, False)
    checked(rejected.returncode != 0 and "signature failure" in rejected.stderr, "archive format exception still rejects a tampered ECC certificate signature")
    revoked_pin = json.loads((data / "pins.json").read_text())
    revoked_pin["roots"][0]["revoked"] = True
    (data / "pins.json").write_text(json.dumps(revoked_pin))
    records = json.loads(execute([*base, "list"]).stdout)
    checked(next(r["state"] for r in records if r["sha256"] == pin) == "revoked", "published root revocation overrides validity")
    checked(execute([*system_args, "install", "icp-roots"], False).returncode != 0, "revoked root cannot install")
    checked(execute([*system_args, "install", "oab"], False).returncode != 0, "chain below revoked root cannot install")
    bad_pin = json.loads((data / "pins.json").read_text())
    bad_pin["roots"][0]["sha256"] = "0" * 64
    (data / "pins.json").write_text(json.dumps(bad_pin))
    checked(execute([*base, "list"], False).returncode != 0, "shipped root pin mismatch rejected")
    server.shutdown()
    server.server_close()
print(f"{checks} checks passed", flush=True)
