#!/bin/sh
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
# Rebuild po/sparky-ca.pot from the sources and merge it into every po/<language>.po.
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
    | sed -e 's/^"Project-Id-Version: .*\\n"$/"Project-Id-Version: sparky-ca 2.0.0\\n"/' > po/sparky-ca.pot
for file in po/*.po; do
    [ -e "$file" ] || continue
    msgmerge --quiet --update --backup=none --no-fuzzy-matching "$file" po/sparky-ca.pot
done
