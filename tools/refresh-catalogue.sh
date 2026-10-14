#!/bin/sh
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
# Fetch ITI's bundle, verify it and compare it with data/catalogue.json.
# usage: tools/refresh-catalogue.sh <sparky-ca binary> <output directory>
# The output directory receives result (current, changed, unpinned or failed), summary.md and,
# when changed, catalogue.json. REFRESH_ARGS passes extra options to the binary (a fixture
# server in tests). This script holds no credentials and runs no git or gh command.
set -eu
binary=$1
out=$2
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
rm -rf "$out"
mkdir -p "$out" "$out/download"
finish() {
    printf '%s\n' "$1" > "$out/result"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then printf 'result=%s\n' "$1" >> "$GITHUB_OUTPUT"; fi
    cat "$out/summary.md"
    rm -rf "$out/download"
    exit 0
}
# shellcheck disable=SC2086
if ! "$binary" --data data update --output "$out/catalogue.json" --download-dir "$out/download" ${REFRESH_ARGS:-} 2> "$out/error.txt"; then
    rm -f "$out/catalogue.json"
    set +e
    python3 -I tools/new-roots.py data/pins.json "$out/download" > "$out/roots.md"
    roots=$?
    set -e
    {
        echo "## The catalogue refresh failed"
        echo
        echo '```'
        cat "$out/error.txt"
        echo '```'
        echo
        cat "$out/roots.md"
    } > "$out/summary.md"
    rm -f "$out/error.txt" "$out/roots.md"
    if [ "$roots" -eq 3 ]; then finish unpinned; fi
    finish failed
fi
rm -f "$out/error.txt"
if cmp -s "$out/catalogue.json" data/catalogue.json; then
    rm -f "$out/catalogue.json"
    echo "The catalogue is current: ITI's bundle verified and nothing changed." > "$out/summary.md"
    finish current
fi
python3 -I tools/catalogue-diff.py data/catalogue.json "$out/catalogue.json" > "$out/summary.md"
finish changed
