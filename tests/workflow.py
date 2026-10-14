# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""The repository job's script against a local HTTPS server, a bare origin and a recording gh stub."""
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import zipfile

binary = str(Path(sys.argv[1]).resolve())
source = Path(sys.argv[2]).resolve()
checks = 0


def checked(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1
    print(f"PASS {message}", flush=True)


def execute(args, success=True, env=None, cwd=None):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=180, env=env, cwd=cwd)
    if success and result.returncode:
        raise AssertionError(f"Command failed: {args}: {result.stdout}{result.stderr}")
    return result


def make_certificate(name, issuer=None, ca=True, san=None):
    key = f"{name}.key"
    execute(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", f"{name}.csr", "-subj", f"/CN={name}"])
    extension = f"basicConstraints=critical,CA:{'TRUE' if ca else 'FALSE'}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
    if san:
        extension += f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n"
    Path(f"{name}.ext").write_text(extension)
    args = ["openssl", "x509", "-req", "-in", f"{name}.csr", "-out", f"{name}.pem", "-days", "3650", "-extfile", f"{name}.ext"]
    args += ["-CA", f"{issuer}.pem", "-CAkey", f"{issuer}.key", "-CAcreateserial"] if issuer else ["-signkey", key]
    execute(args)
    return Path(f"{name}.pem").read_bytes()


def bundle(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, cert in entries:
            archive.writestr(name, cert)
    return output.getvalue()


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


def publish(entries, digest=None):
    data = bundle(entries)
    Handler.responses.update({"/bundle": data, "/hash": (digest or hashlib.sha512(data).hexdigest()).encode() + b"  ACcompactado.zip\n"})


with tempfile.TemporaryDirectory(prefix="sparky-ca-workflow-") as temporary:
    os.chdir(temporary)
    root = make_certificate("icp-test")
    first = make_certificate("AC_Certisign_A", "icp-test")
    second = make_certificate("AC_Certisign_B", "icp-test")
    foreign = make_certificate("foreign-root")
    make_certificate("tls-test")
    make_certificate("tls-issuer", "tls-test")
    make_certificate("localhost", "tls-issuer", ca=False, san="DNS:localhost")
    repository = Path("repository").resolve()
    (repository / "data/roots").mkdir(parents=True)
    shutil.copytree(source / "tools", repository / "tools")
    (repository / "data/roots/root.pem").write_bytes(root)
    pin = hashlib.sha256(subprocess.check_output(["openssl", "x509", "-in", "icp-test.pem", "-outform", "DER"])).hexdigest()
    (repository / "data/pins.json").write_text(json.dumps({"roots": [{"file": "root.pem", "sha256": pin}]}))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("localhost.pem", "localhost.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"https://localhost:{server.server_port}"
    network = ["--tls-ca", str(Path("tls-test.pem").resolve()), "--tls-issuer", str(Path("tls-issuer.pem").resolve()), "--bundle-url", url + "/bundle", "--hash-url", url + "/hash"]
    publish([("AC_Certisign_A.crt", first)])
    execute([binary, "--data", repository / "data", "--catalogue", "none.json", "update", "--output", repository / "data/catalogue.json", *network])

    origin = Path("origin.git").resolve()
    execute(["git", "init", "-q", "--bare", "-b", "main", origin])
    git_env = dict(os.environ, GIT_AUTHOR_NAME="fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid", GIT_COMMITTER_NAME="fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
    for command in (["init", "-q", "-b", "main"], ["add", "."], ["commit", "-q", "-m", "fixture"], ["remote", "add", "origin", str(origin)], ["push", "-q", "origin", "main"]):
        execute(["git", *command], cwd=repository, env=git_env)
    stubs = Path("stubs").resolve()
    stubs.mkdir()
    log = Path("gh.log").resolve()
    (stubs / "gh").write_text(f'#!/bin/sh\necho "$@" >> {log}\ncase "$1 $2" in\n"pr list") cat {stubs}/existing-pr 2>/dev/null;;\n"issue list") cat {stubs}/existing-issue 2>/dev/null;;\nesac\nexit 0\n')
    (stubs / "gh").chmod(0o755)
    env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}", REFRESH_ARGS=" ".join(network), GH_TOKEN="unused")

    def job(extra=None):
        """Verify, then propose, as the two workflow jobs do; the verify step sees no gh and no token."""
        environment = dict(env, **(extra or {}))
        verify = execute(["sh", repository / "tools/refresh-catalogue.sh", binary, Path("out").resolve()], False, {k: v for k, v in dict(environment, PATH=os.environ["PATH"]).items() if k != "GH_TOKEN"}, repository)
        result = Path("out/result").read_text().strip()
        if result in ("changed", "unpinned"):
            proposal = execute(["sh", repository / "tools/propose-catalogue.sh", Path("out").resolve()], False, environment, repository)
            verify.returncode = proposal.returncode
            verify.stdout += proposal.stdout
        return verify, result

    def gh_calls():
        return log.read_text().splitlines() if log.exists() else []

    committed = (repository / "data/catalogue.json").read_bytes()
    run, result = job()
    checked(run.returncode == 0 and result == "current" and not gh_calls(), "an unchanged bundle ends quietly with no branch and no pull request")

    publish([("AC_Certisign_A.crt", first), ("AC_Certisign_B.crt", second)])
    run, result = job({"DRY_RUN": "1"})
    summary = Path("out/summary.md").read_text()
    checked(run.returncode == 0 and result == "changed" and "Added (1)" in summary and "AC_Certisign_B.crt" in summary and "Removed (0)" in summary, "a changed bundle is described: one certificate added, none removed")
    checked((repository / "data/catalogue.json").read_bytes() == committed and not gh_calls(), "a dry run changes nothing and calls nothing")

    run, result = job()
    checked(run.returncode == 0 and result == "changed", "a changed bundle proposes the change")
    pushed = execute(["git", "--git-dir", origin, "show", "catalogue-refresh:data/catalogue.json"]).stdout
    checked(json.loads(pushed) != json.loads(committed) and "AC_Certisign_B.crt" in pushed, "the bot branch on the origin carries the new catalogue")
    checked(execute(["git", "--git-dir", origin, "show", "main:data/catalogue.json"]).stdout.encode() == committed, "the main branch is untouched")
    checked(any(call.startswith("pr create --head catalogue-refresh") for call in gh_calls()), "a pull request is opened from the bot branch")
    checked(execute(["git", "log", "-1", "--format=%an", "catalogue-refresh"], cwd=repository).stdout.strip() == "sparky-ca catalogue refresh", "the commit names the refresh job as its author")
    checked(json.loads((repository / "data/pins.json").read_text())["roots"][0]["sha256"] == pin and execute(["git", "diff", "--name-only", "main", "catalogue-refresh"], cwd=repository).stdout.split() == ["data/catalogue.json"], "the proposal touches only the catalogue, no pin")

    (stubs / "existing-pr").write_text("7\n")
    log.unlink()
    execute(["git", "checkout", "-q", "main"], cwd=repository)
    job()
    calls = gh_calls()
    checked(any(call.startswith("pr edit catalogue-refresh") for call in calls) and not any(call.startswith("pr create") for call in calls), "an open pull request is updated rather than duplicated")

    log.unlink()
    publish([("AC_Certisign_A.crt", first), ("foreign-root.crt", foreign)])
    run, result = job()
    summary = Path("out/summary.md").read_text()
    fingerprint = hashlib.sha256(subprocess.check_output(["openssl", "x509", "-in", "foreign-root.pem", "-outform", "DER"])).hexdigest()
    checked(result == "unpinned" and "not pinned" in summary and fingerprint in summary, "an unpinned root is classed apart and the report names its fingerprint")
    checked(any(call.startswith("issue create --title ITI published a root that is not pinned") for call in gh_calls()), "an issue asks for a reviewed commit")
    checked(not any(call.startswith("pr ") for call in gh_calls() if "list" not in call), "no pull request is made for an unpinned root")
    checked(json.loads((repository / "data/pins.json").read_text())["roots"][0]["sha256"] == pin, "the job never writes a pin")

    log.unlink()
    (stubs / "existing-issue").write_text("9\n")
    job()
    checked(not any(call.startswith("issue create") for call in gh_calls()), "an open issue is not repeated")

    log.unlink()
    publish([("AC_Certisign_A.crt", first)], digest="0" * 128)
    run, result = job()
    summary = Path("out/summary.md").read_text()
    checked(result == "failed" and "SHA-512" in summary and "Do not review it" in summary, "a wrong SHA-512 fails the job and tells the reviewer not to trust the file")
    checked(not gh_calls(), "a wrong SHA-512 raises no issue")
    server.shutdown()
    server.server_close()
print(f"{checks} checks passed", flush=True)
