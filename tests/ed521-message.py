# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""The Ed521 message: accurate for each state, gone when nothing is missing, closable, in nine languages.

ed521-message.py CHECK KCM SOURCE BUILD [PROVIDER]
The KCM part needs the installed data (/usr/share/sparky-ca), which the KCM reads;
with PROVIDER it points OPENSSL_CONF at that module, without it the system
configuration decides.  Screenshots go to $ED521_EVIDENCE when it is set.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

check_program, kcm, source, build = (str(Path(value).resolve()) for value in sys.argv[1:5])
provider = str(Path(sys.argv[5]).resolve()) if len(sys.argv) > 5 and sys.argv[5] else ''
evidence = os.environ.get('ED521_EVIDENCE')
checks = 0

OPENSSL_OK = 'ICP-Brasil v7 (Ed521) certificates validate on this computer in the command line and in programs that use OpenSSL.'
INSTALLED_UNUSED = 'ICP-Brasil v7 (Ed521) certificates do not validate on this computer: the package openssl-provider-ed521 is installed, but OpenSSL does not use it. The command /usr/libexec/openssl-provider-ed521/system-config status shows why.'
INSTALL = 'ICP-Brasil v7 (Ed521) certificates do not validate on this computer yet. Install the package openssl-provider-ed521 to validate them in the command line and in programs that use OpenSSL.'
NSS_YES = 'Firefox, Waterfox and Okular validate them through NSS.'
NSS_NO = 'Firefox, Waterfox and Okular check certificates with NSS, which cannot validate Ed521 yet.'
GNUPG_YES = 'Kleopatra and KMail validate them through GnuPG.'
GNUPG_NO = 'Kleopatra and KMail check certificates with GnuPG, which cannot validate Ed521 yet.'
CHROMIUM = 'Chromium checks certificates with its own BoringSSL, which cannot validate Ed521.'
TAIL = 'Certificates with RSA and ECDSA keys work in all of them.'
LOCALES = {'pt_BR': 'pt_BR', 'pl': 'pl_PL', 'de': 'de_DE', 'fr': 'fr_FR', 'ja': 'ja_JP', 'ko': 'ko_KR', 'zh_CN': 'zh_CN', 'zh_TW': 'zh_TW'}


def check(condition, message):
    global checks
    assert condition, message
    checks += 1
    print('PASS', message, flush=True)


def environment(**extra):
    env = dict(os.environ, XDG_DATA_DIRS=f'{build}:/usr/local/share:/usr/share', QT_QPA_PLATFORM='offscreen', QT_QUICK_BACKEND='software')
    env.update(extra)
    return env


def message(states, **extra):
    result = subprocess.run([check_program, 'message', *states], env=environment(**extra), capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def translations(language):
    text = subprocess.run(['msgattrib', '--no-wrap', '--translated', f'{source}/po/ed521/{language}.po'], capture_output=True, text=True, check=True).stdout
    return dict(re.findall(r'^msgid "(.+)"\nmsgstr "(.+)"$', text, re.M))


cases = [
    (('1', '1', '0', '0', '0'), [OPENSSL_OK, NSS_NO, GNUPG_NO, TAIL], 'OpenSSL validates, NSS and GnuPG cannot (today, with the provider)'),
    (('0', '0', '0', '0', '0'), [INSTALL, NSS_NO, GNUPG_NO, TAIL], 'the provider is missing: the message names the package'),
    (('0', '1', '0', '0', '0'), [INSTALLED_UNUSED, NSS_NO, GNUPG_NO, TAIL], 'the provider is installed but OpenSSL does not use it: the message says how to see why'),
    (('1', '1', '1', '0', '0'), [OPENSSL_OK, NSS_YES, GNUPG_NO, TAIL], 'NSS gains Ed521, GnuPG not yet'),
    (('1', '1', '0', '-', '0'), [OPENSSL_OK, NSS_NO, TAIL], 'without gpgsm the message does not mention GnuPG'),
    (('1', '1', '1', '1', '1'), [OPENSSL_OK, NSS_YES, GNUPG_YES, CHROMIUM, TAIL], 'Chromium installed: its BoringSSL is named'),
]
for states, parts, label in cases:
    result = message(states)
    check(not result['complete'] and result['message'] == ' '.join(parts), f'{label}: "{result["message"][:90]}..."')
for states, label in ((('1', '1', '1', '1', '0'), 'OpenSSL, NSS and GnuPG all validate'),
                      (('1', '1', '-', '-', '0'), 'OpenSSL validates and neither NSS tools nor gpgsm are installed')):
    result = message(states)
    check(result['complete'] and result['message'] == '', f'{label}: no message at all')

for language, locale in LOCALES.items():
    table = translations(language)
    expected = ' '.join(table[part] for part in (OPENSSL_OK, NSS_NO, GNUPG_NO, TAIL))
    result = message(('1', '1', '0', '0', '0'), LANGUAGE=language, LANG=f'{locale}.UTF-8', LC_ALL=f'{locale}.UTF-8')
    check(result['message'] == expected, f'{language}: the message comes from its catalogue: {result["message"][:60]}...')

if not Path('/usr/share/sparky-ca/roots/ICP-Brasilv7.crt').exists():
    print(f'SKIP the KCM part: it reads /usr/share/sparky-ca, which only the installed package provides')
    print(f'{checks} Ed521 message checks passed')
    sys.exit(0)
with tempfile.TemporaryDirectory(prefix='ed521-kcm-') as temporary:
    home = Path(temporary) / 'home'
    home.mkdir()
    shots = Path(evidence) if evidence else Path(temporary)
    shots.mkdir(parents=True, exist_ok=True)
    configured = {}
    if provider:
        config = Path(temporary) / 'openssl.cnf'
        template = Path(source) / 'ed521-provider/openssl-ed521.cnf'
        config.write_text(template.read_text().replace('[ed521_sect]\n', f'[ed521_sect]\nmodule = {provider}\n'))
        configured = {'OPENSSL_CONF': str(config)}

    def kcm_run(prefix, close=False, language=None, **extra):
        env = environment(**{'HOME': str(home), **extra})
        if language:
            env.update(LANGUAGE=language, LANG=f'{LOCALES[language]}.UTF-8', LC_ALL=f'{LOCALES[language]}.UTF-8')
        args = ['dbus-run-session', '--', check_program, 'kcm', f'{source}/data', kcm, str(shots / prefix)] + (['close'] if close else [])
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, (result.returncode, result.stderr[-2000:])
        return json.loads(result.stdout.strip().splitlines()[-1])

    if provider or Path('/usr/share/openssl-provider-ed521/openssl.cnf').exists():
        shown = kcm_run('kcm-ed521-en', close=True, **configured)
        expected = ' '.join([OPENSSL_OK, NSS_NO, GNUPG_NO, TAIL]) if shutil.which('gpgsm') else ' '.join([OPENSSL_OK, NSS_NO, TAIL])
        check(shown['itemFound'] and shown['itemVisible'] and shown['itemText'] == shown['message'] == expected and not shown['warning'],
              'the KCM shows the accurate message with the provider configured: ' + shown['message'][:70] + '...')
        check(shown['closeFound'] and shown['dismissedAfterClose'] and not shown['itemVisibleAfterClose'], 'its close action hides the message')
        again = kcm_run('kcm-ed521-reopened', **configured)
        check(again['dismissed'] and not again['itemVisible'], 'reopened, the message stays closed while nothing changed')
        for language in LOCALES:
            translated = kcm_run(f'kcm-ed521-{language}', language=language, HOME=str(Path(temporary) / language), **configured)
            check(translated['itemVisible'] and translated['itemText'] != expected and translated['itemText'] == translated['message'],
                  f'{language}: the KCM shows the translated message')
    changed = kcm_run('kcm-ed521-no-provider', OPENSSL_CONF='/dev/null')
    missing = INSTALLED_UNUSED if Path('/usr/share/openssl-provider-ed521/openssl.cnf').exists() else INSTALL
    check(changed['itemVisible'] and changed['warning'] and changed['itemText'].startswith(missing), 'when OpenSSL lacks Ed521 the message returns, as a warning that names the package: ' + changed['itemText'][:80] + '...')
print(f'{checks} Ed521 message checks passed')
