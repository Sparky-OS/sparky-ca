# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Automatic updates: HTTPS bundle refresh, CRLs, expiry, opt-out and the user's NSS stores.

Real OpenSSL, NSS and Debian updater; all state is under a temporary directory.
Time-dependent steps run under libfaketime, so no certificate is edited to look old."""
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import socket
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


def execute(args, success=True, env=None):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=120, env=env)
    if success and result.returncode:
        raise AssertionError(f"Command failed: {args}: {result.stderr}")
    return result


def make_certificate(name, issuer=None, ca=True, san=None, days=3650, crl=None):
    key, cert = f"{name}.key", f"{name}.pem"
    execute(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", f"{name}.csr", "-subj", f"/CN={name}"])
    extension = f"basicConstraints=critical,CA:{'TRUE' if ca else 'FALSE'}\n"
    extension += "keyUsage=critical," + ("keyCertSign,cRLSign" if ca else "digitalSignature,keyEncipherment") + "\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
    if san:
        extension += f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n"
    if crl:
        extension += f"crlDistributionPoints=URI:{crl}\n"
    Path(f"{name}.ext").write_text(extension)
    args = ["openssl", "x509", "-req", "-in", f"{name}.csr", "-out", cert, "-days", days, "-extfile", f"{name}.ext"]
    args += ["-CA", f"{issuer}.pem", "-CAkey", f"{issuer}.key", "-CAcreateserial"] if issuer else ["-signkey", key]
    execute(args)
    return Path(cert).read_bytes()


def der(name):
    return subprocess.check_output(["openssl", "x509", "-in", f"{name}.pem", "-outform", "DER"])


def fingerprint(name):
    return hashlib.sha256(der(name)).hexdigest()


def serial(name):
    return execute(["openssl", "x509", "-in", f"{name}.pem", "-noout", "-serial"]).stdout.strip().split("=")[1]


def make_crl(revoked):
    """A CRL signed by the fixture root listing the named certificates."""
    Path("crl").mkdir(exist_ok=True)
    Path("crl/index.txt").write_text("".join(f"R\t300101000000Z\t260101000000Z,keyCompromise\t{serial(n)}\tunknown\t/CN={n}\n" for n in revoked))
    Path("crl/crlnumber").write_text("01\n")
    Path("crl/ca.cnf").write_text("[ca]\ndefault_ca=CA_default\n[CA_default]\ndatabase=crl/index.txt\ncrlnumber=crl/crlnumber\ndefault_md=sha256\ndefault_crl_days=7\n")
    execute(["openssl", "ca", "-config", "crl/ca.cnf", "-gencrl", "-cert", "icp-test.pem", "-keyfile", "icp-test.key", "-crldays", "7", "-out", "root.crl.pem"])
    return subprocess.check_output(["openssl", "crl", "-in", "root.crl.pem", "-outform", "DER"])


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


def publish(entries):
    data = bundle(entries)
    Handler.responses.update({"/bundle": data, "/hash": hashlib.sha512(data).hexdigest().encode() + b"  ACcompactado.zip\n"})


with tempfile.TemporaryDirectory(prefix="sparky-ca-auto-") as temporary:
    os.chdir(temporary)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    crl_url = f"https://localhost:{port}/root.crl"
    root = make_certificate("icp-test")
    oab = make_certificate("AC_OAB_JUS", "icp-test", days=60, crl=crl_url)
    serasa = make_certificate("AC_Serasa_B", "icp-test", crl=crl_url)
    serpro = make_certificate("AC_Serpro_B", "icp-test", crl=crl_url)
    make_certificate("tls-test")
    make_certificate("tls-issuer", "tls-test")
    make_certificate("localhost", "tls-issuer", ca=False, san="DNS:localhost")
    data = Path("data")
    (data / "roots").mkdir(parents=True)
    (data / "roots/root.pem").write_bytes(root)
    (data / "pins.json").write_text(json.dumps({"roots": [{"file": "root.pem", "sha256": fingerprint("icp-test")}]}))
    publish([("AC_OAB_JUS.crt", oab), ("AC_Serasa_B.crt", serasa), ("AC_Serpro_B.crt", serpro)])
    Handler.responses["/root.crl"] = make_crl([])
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("localhost.pem", "localhost.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"https://localhost:{port}"
    state, config, system, derived = Path("state").resolve(), Path("config").resolve(), Path("system").resolve(), Path("derived/ca-certificates.crt").resolve()
    network = ["--tls-ca", "tls-test.pem", "--tls-issuer", "tls-issuer.pem", "--bundle-url", url + "/bundle", "--hash-url", url + "/hash"]
    common = [binary, "--data", data.resolve(), "--cache-dir", state, "--config-dir", config]
    system_args = [*common, "--system-dir", system, "--system-bundle", derived]
    execute([binary, "--data", data.resolve(), "--catalogue", "none.json", "update", "--output", data.resolve() / "catalogue.json", *network])
    packaged = (data / "catalogue.json").read_bytes()

    def listing(*extra):
        return {r["name"]: r for r in json.loads(execute([*system_args, *extra, "list"]).stdout)}

    def installed():
        return {r["name"]: r for r in json.loads(execute([*system_args, "list", "installed"]).stdout)}

    def status():
        return json.loads((state / "status.json").read_text())

    def run_auto(*extra, prefix=(), env=None, success=True):
        return execute([*prefix, *system_args, "auto", "run", "--scope", "system", *network, *extra], success, env)

    first = json.loads(execute([*system_args, "auto", "status", "--scope", "system"]).stdout)
    checked(first["enabled"] and first["selectedGroups"] == [] and first["catalogue"] == "package", "status shows automatic updates on, no selection, packaged catalogue")
    run_auto()
    checked(status()["stores"][0]["added"] == [] and status()["outcome"] == "ok", "a run with no chosen group installs nothing and never chooses one")
    checked(installed() == {}, "no certificate reached the isolated store without the user's choice")

    for group in ("icp-roots", "oab", "serasa", "serpro"):
        execute([*system_args, "install", group])
    checked(len(installed()) == 4, "user-chosen groups installed: root and three intermediates")
    report = run_auto()
    now = status()
    checked(now["catalogue"]["refreshed"] and not now["catalogue"]["changed"] and not (state / "catalogue.json").exists(), "an unchanged bundle writes no cache")
    checked(now["revocation"]["good"] == 3 and now["revocation"]["revoked"] == [] and now["outcome"] == "ok", "three intermediates answer good from the signed CRL")
    checked((state / "revocation.json").stat().st_mode & 0o022 == 0, "the revocation answers are not group or other writable")
    checked("catalogue refreshed" in report.stdout.lower() or "refreshed" in report.stdout, "the journal lines report the refresh")

    oab_new = make_certificate("AC_OAB_JUS_renewed", "icp-test", crl=crl_url)
    certisign_new = make_certificate("AC_Certisign_new", "icp-test", crl=crl_url)
    publish([("AC_OAB_JUS.crt", oab), ("AC_Serasa_B.crt", serasa), ("AC_Serpro_B.crt", serpro), ("AC_OAB_JUS_renewed.crt", oab_new), ("AC_Certisign_new.crt", certisign_new)])
    run_auto()
    now = status()
    added = [r["name"] for r in now["stores"][0]["added"]]
    checked(now["catalogue"]["changed"] and (state / "catalogue.json").exists(), "a changed bundle is verified and cached")
    checked(added == ["AC_OAB_JUS_renewed.crt"], "the renewed intermediate of a chosen group is added")
    checked(fingerprint("AC_Certisign_new") not in {r["sha256"] for r in installed().values()}, "a new intermediate of an unchosen group is not installed")
    checked(any(r["name"] == "AC_Certisign_new.crt" for r in listing().values()) and listing()["AC_Certisign_new.crt"]["state"] == "valid", "the refreshed catalogue lists it for the user to choose")
    checked(json.loads(execute([*system_args, "auto", "status", "--scope", "system"]).stdout)["catalogue"] == "refreshed", "status reports the refreshed catalogue in use")

    Handler.responses["/root.crl"] = make_crl(["AC_Serasa_B"])
    run_auto()
    now = status()
    checked([r["name"] for r in now["revocation"]["revoked"]] == ["AC_Serasa_B.crt"], "the CRL signed by the pinned root revokes exactly one intermediate")
    checked([(r["name"], r["reason"]) for r in now["stores"][0]["removed"]] == [("AC_Serasa_B.crt", "revoked")], "the revoked owned certificate is removed with its reason")
    names = set(installed())
    checked(not any(fingerprint("AC_Serasa_B") == r["sha256"] for r in installed().values()) and len(names) == 4, "the other chosen certificates stay installed")
    checked(listing()["AC_Serasa_B.crt"]["state"] == "revoked", "the listing shows the revoked state from the verified CRL")
    checked(execute([*system_args, "install", "serasa"], False).returncode != 0, "a CRL-revoked group cannot be installed again")

    execute(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "impostor.key", "-out", "impostor.pem", "-subj", "/CN=icp-test", "-days", "30"])
    execute(["openssl", "ca", "-config", "crl/ca.cnf", "-gencrl", "-cert", "impostor.pem", "-keyfile", "impostor.key", "-crldays", "7", "-out", "forged.pem"])
    checked(Path("forged.pem").exists(), "a CRL with the root's name but another key is generated for the negative case")
    Handler.responses["/root.crl"] = subprocess.check_output(["openssl", "crl", "-in", "forged.pem", "-outform", "DER"])
    run_auto()
    now = status()
    checked(any("signature" in e for e in now["revocation"]["errors"]), "the CRL signature failure is reported")
    checked([r["name"] for r in now["revocation"]["revoked"]] == ["AC_Serasa_B.crt"], "a verified revocation survives a CRL that fails verification")
    checked(len(installed()) == 4, "an unverifiable CRL removes nothing")
    Handler.responses["/root.crl"] = make_crl(["AC_Serasa_B"])

    before = status()["runId"]
    execute([*common, "auto", "disable", "--scope", "system"])
    checked((config / "auto-update.disabled").exists(), "turning updates off writes the switch")
    off = run_auto()
    checked("turned off" in off.stdout and status()["runId"] == before, "a run while turned off does nothing")
    run_auto("--force")
    checked(status()["runId"] != before, "the user can still force one run")
    checked(not json.loads(execute([*common, "auto", "status", "--scope", "system"]).stdout)["enabled"], "status shows the switch off")
    execute([*common, "auto", "enable", "--scope", "system"])
    checked(not (config / "auto-update.disabled").exists(), "turning updates on removes the switch")

    bad = bundle([("x.crt", oab)])
    Handler.responses.update({"/bundle": bad, "/hash": b"0" * 128})
    run_auto()
    now = status()
    checked("SHA-512" in now["catalogue"]["error"] and now["outcome"] == "attention" and not now["catalogue"]["refreshed"], "a wrong bundle hash fails the refresh and asks for attention")
    checked(len(installed()) == 4 and listing()["AC_OAB_JUS_renewed.crt"]["state"] == "valid", "a failed refresh keeps the last verified catalogue and the stores")
    publish([("AC_OAB_JUS.crt", oab), ("AC_Serasa_B.crt", serasa), ("AC_Serpro_B.crt", serpro), ("AC_OAB_JUS_renewed.crt", oab_new), ("AC_Certisign_new.crt", certisign_new)])

    cache = (state / "catalogue.json").read_bytes()
    (state / "catalogue.json").chmod(0o666)
    checked("AC_Certisign_new.crt" not in listing(), "a world-writable cache is ignored")
    (state / "catalogue.json").chmod(0o644)
    document = json.loads(cache)
    document["certificates"] = [c for c in document["certificates"] if c["name"] != "AC_OAB_JUS.crt"]
    (state / "catalogue.json").write_text(json.dumps(document))
    checked("AC_Certisign_new.crt" not in listing(), "a cache that drops a packaged certificate is ignored")
    tampered = json.loads(cache)
    pem = next(c for c in tampered["certificates"] if c["name"] == "AC_Certisign_new.crt")
    pem["pem"] = pem["pem"].replace("A", "B", 1) if "A" in pem["pem"].split("\n")[3] else pem["pem"].replace("B", "A", 1)
    (state / "catalogue.json").write_text(json.dumps(tampered))
    checked("AC_Certisign_new.crt" not in listing(), "a cache with a damaged certificate is ignored")
    (state / "catalogue.json").write_bytes(cache)
    checked("AC_Certisign_new.crt" in listing(), "the genuine cache is used again")

    nss = Path("nss").resolve()
    execute([*system_args, "--nss", nss, "install", "oab"])
    nss_before = {r["name"] for r in json.loads(execute([*system_args, "--nss", nss, "list", "installed"]).stdout)}
    checked({"sparky-ca-" + fingerprint("AC_OAB_JUS_renewed")} <= nss_before, "the user's NSS store holds the chosen group")
    user = [*common, "--scope", "user", "--nss", nss, "--home", Path("home").resolve()]
    (nss / "lock").symlink_to("127.0.0.1:+4242")
    deferred = execute([*user, "auto", "run"])
    checked("in use by a browser" in deferred.stdout, "an open browser profile is deferred, not touched")
    (nss / "lock").unlink()

    faraway = ["faketime", "-f", "+90d"]
    Handler.responses["/root.crl"] = make_crl(["AC_Serasa_B"])
    run_auto(prefix=faraway)
    now = status()
    removed = {r["name"]: r["reason"] for r in now["stores"][0]["removed"]}
    checked(removed == {"AC_OAB_JUS.crt": "expired"}, "ninety days later only the expired intermediate leaves the system store")
    checked(now["revocation"]["unknown"] > 0 and any("stale" in e for e in now["revocation"]["errors"]), "a CRL past its next update is stale and gives no answer")
    checked(fingerprint("AC_Serpro_B") in {r["sha256"] for r in installed().values()}, "a stale CRL does not remove valid certificates")

    execute([*faraway, *user, "auto", "run"])
    user_status = json.loads((Path("home/.local/state/sparky-ca/status.json")).read_text())
    nss_names = {r["name"] for r in json.loads(execute([*system_args, "--nss", nss, "list", "installed"]).stdout)}
    checked([r["name"] for r in user_status["stores"][0]["removed"]] == ["AC_OAB_JUS.crt"], "the user's run removes the same expired intermediate from NSS")
    checked("sparky-ca-" + fingerprint("AC_OAB_JUS") not in nss_names and "sparky-ca-" + fingerprint("AC_OAB_JUS_renewed") in nss_names, "NSS keeps the renewed intermediate")
    checked(user_status["scope"] == "user" and user_status["catalogue"]["refreshed"] is False and "revocation" not in user_status, "a user run never uses the network")

    journal = execute([*system_args, "auto", "run", "--scope", "system", "--no-network"], env=dict(os.environ, JOURNAL_STREAM="1:1"))
    checked(all(line.startswith("<") for line in journal.stdout.strip().splitlines()), "output carries journal priorities under systemd")
    plain = execute([*system_args, "auto", "run", "--scope", "system", "--no-network"])
    checked(not any(line.startswith("<") for line in plain.stdout.splitlines()), "output is plain text on a terminal")
    unprivileged = execute([binary, "--data", data.resolve(), "--cache-dir", state, "--config-dir", config, "auto", "run", "--scope", "system"], False)
    checked(unprivileged.returncode != 0 and "root" in unprivileged.stderr, "a system update without root is refused before any change")
    checked((data / "catalogue.json").read_bytes() == packaged, "the packaged catalogue was never modified")
    server.shutdown()
    server.server_close()
print(f"{checks} checks passed", flush=True)
