#!/bin/sh
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
# Rebuild po/sparky-ca.pot from the sources and merge it into every po/<language>.po;
# the same for the Ed521 message's own domain, po/ed521/sparky-ca-ed521.pot (i18nd only).
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
KDE='-kde -ci18n -ki18n:1 -ki18nc:1c,2 -ki18np:1,2 -ki18ncp:1c,2,3'
xgettext --from-code=UTF-8 -L C++ $KDE -o "$tmp/code.pot" src/*/*.cpp src/*/*.h
xgettext --from-code=UTF-8 -L JavaScript $KDE -o "$tmp/qml.pot" qml/*.qml
xgettext --from-code=UTF-8 -L Desktop -o "$tmp/desktop.pot" share/sparky-ca.desktop.in share/kservices/sparky-ca-preview.desktop.in
xgettext --from-code=UTF-8 --its=/usr/share/gettext/its/metainfo.its -o "$tmp/metainfo.pot" share/org.sparkylinux.sparkyca.metainfo.xml.in
msgcat --use-first --sort-by-file "$tmp/code.pot" "$tmp/qml.pot" "$tmp/desktop.pot" "$tmp/metainfo.pot" \
    | sed -e 's/^"Project-Id-Version: .*\\n"$/"Project-Id-Version: sparky-ca 2.0.1\\n"/' > po/sparky-ca.pot
for file in po/*.po; do
    [ -e "$file" ] || continue
    msgmerge --quiet --update --backup=none --no-fuzzy-matching "$file" po/sparky-ca.pot
    msgattrib --no-obsolete --output-file="$file" "$file"
done
xgettext --from-code=UTF-8 -L C++ -k -ki18nd:2 -o "$tmp/ed521-code.pot" src/core/ed521.cpp
xgettext --from-code=UTF-8 -L JavaScript -k -ki18nd:2 -o "$tmp/ed521-qml.pot" qml/CertificatePage.qml
# xgettext writes no file when a source has no such string.
msgcat --use-first --sort-by-file "$tmp/ed521-code.pot" $(ls "$tmp/ed521-qml.pot" 2>/dev/null) \
    | sed -e 's/^"Project-Id-Version: .*\\n"$/"Project-Id-Version: sparky-ca 2.0.3\\n"/' > po/ed521/sparky-ca-ed521.pot
for file in po/ed521/*.po; do
    [ -e "$file" ] || continue
    msgmerge --quiet --update --backup=none --no-fuzzy-matching "$file" po/ed521/sparky-ca-ed521.pot
    msgattrib --no-obsolete --output-file="$file" "$file"
done
