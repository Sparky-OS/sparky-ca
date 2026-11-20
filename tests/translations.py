# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""A language ships only when every message is translated, and the catalogue matches the sources."""
from pathlib import Path
import ast
import gettext
import io
import re
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).resolve()
checks = 0


def checked(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1
    print(f"PASS {message}", flush=True)


def message_ids(text):
    ids = set()
    for entry in re.finditer(r'^msgid (".*")((?:\n".*")*)', text, re.M):
        message = ''.join(ast.literal_eval(part) for part in (entry[1], *entry[2].splitlines()) if part)
        if message:
            ids.add(message)
    return ids


def messages(path):
    text = subprocess.run(["msgattrib", "--no-obsolete", "--translated", "--no-fuzzy", "--no-wrap", str(path)], capture_output=True, text=True, check=True).stdout
    return message_ids(text)


languages = (source / "po/LINGUAS").read_text().split()
checked(languages == ["pt_BR", "pl", "fr", "de", "es", "ja", "ko", "zh_CN", "zh_TW"], "the shipped languages match the complete catalogues")
pot = subprocess.run(["msgattrib", "--no-wrap", str(source / "po/sparky-ca.pot")], capture_output=True, text=True, check=True).stdout
wanted = message_ids(pot)
for language in languages:
    path = source / f"po/{language}.po"
    result = subprocess.run(["msgfmt", "--check-format", "--check-header", "--statistics", "-o", "/dev/null", str(path)], capture_output=True, text=True)
    checked(result.returncode == 0 and "untranslated" not in result.stderr and "fuzzy" not in result.stderr, f"{language}: every message is translated and none is fuzzy ({result.stderr.strip().splitlines()[-1]})")
    translated = set(messages(path))
    checked(wanted <= translated, f"{language}: every message of the catalogue has a translation")
    compiled = subprocess.check_output(["msgfmt", "-o", "-", str(path)])
    catalogue = gettext.GNUTranslations(io.BytesIO(compiled))
    for message in wanted:
        if '\n' in message.rstrip('\n'):
            translation = catalogue.gettext(message)
            checked(translation != message and translation.count('\n') == message.count('\n'),
                    f"{language}: multiline message keeps its line count and is translated")
            checked(sorted(re.findall(r"%\d+", message)) == sorted(re.findall(r"%\d+", translation)),
                    f"{language}: multiline message keeps its placeholders")
    identical = subprocess.run(["msgattrib", "--no-wrap", "--translated", str(path)], capture_output=True, text=True, check=True).stdout
    pairs = re.findall(r'^msgid "(.+)"\nmsgstr "(.*)"$', identical, re.M)
    copies = [m for m, t in pairs if m == t and len(m) > 40 and not m.startswith(("©", "list [installed], groups, install <group>,"))]
    checked(not copies, f"{language}: no long message is left as its English source")
    for message, translation in re.findall(r'^msgid "(.+)"\nmsgstr "(.+)"$', identical, re.M):
        if sorted(re.findall(r"%\d", message)) != sorted(re.findall(r"%\d", translation)):
            raise AssertionError(f"{language}: placeholders differ: {message}")
    checked(True, f"{language}: every translation keeps its placeholders")
ed521 = (source / "po/ed521/LINGUAS").read_text().split()
checked(sorted(ed521) == sorted(["pt_BR", "pl", "de", "es", "fr", "ja", "ko", "zh_CN", "zh_TW"]), "the Ed521 message ships in the edition's ten languages (English and nine translations)")
ed521_wanted = set(re.findall(r'^msgid "(.+)"$', subprocess.run(["msgattrib", "--no-wrap", str(source / "po/ed521/sparky-ca-ed521.pot")], capture_output=True, text=True, check=True).stdout, re.M))
for language in ed521:
    path = source / f"po/ed521/{language}.po"
    result = subprocess.run(["msgfmt", "--check-format", "--check-header", "--statistics", "-o", "/dev/null", str(path)], capture_output=True, text=True)
    checked(result.returncode == 0 and "untranslated" not in result.stderr and "fuzzy" not in result.stderr, f"ed521 {language}: every message is translated and none is fuzzy ({result.stderr.strip().splitlines()[-1]})")
    checked(ed521_wanted <= set(messages(path)), f"ed521 {language}: every message of the Ed521 catalogue has a translation")
    text = subprocess.run(["msgattrib", "--no-wrap", "--translated", str(path)], capture_output=True, text=True, check=True).stdout
    pairs = re.findall(r'^msgid "(.+)"\nmsgstr "(.*)"$', text, re.M)
    checked(not [m for m, t in pairs if m == t], f"ed521 {language}: no message is left as its English source")
    checked(all("openssl-provider-ed521" in t for m, t in pairs if "openssl-provider-ed521" in m), f"ed521 {language}: the package name stays as it is")
with tempfile.TemporaryDirectory() as temporary:
    copy = Path(temporary) / "source"
    subprocess.run(["cp", "-r", str(source), str(copy)], check=True)
    subprocess.run(["sh", str(copy / "tools/update-translations.sh")], check=True)
    fresh = message_ids(subprocess.run(["msgattrib", "--no-wrap", str(copy / "po/sparky-ca.pot")], capture_output=True, text=True, check=True).stdout)
    checked(fresh == wanted, "the catalogue matches the strings in the sources")
    fresh_ed521 = set(re.findall(r'^msgid "(.+)"$', subprocess.run(["msgattrib", "--no-wrap", str(copy / "po/ed521/sparky-ca-ed521.pot")], capture_output=True, text=True, check=True).stdout, re.M))
    checked(fresh_ed521 == ed521_wanted and len(ed521_wanted) == 9, "the Ed521 catalogue matches the strings in the sources")
print(f"{checks} checks passed", flush=True)
