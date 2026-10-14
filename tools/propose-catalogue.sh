#!/bin/sh
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
# Turn the result of tools/refresh-catalogue.sh into a pull request or an issue.
# usage: tools/propose-catalogue.sh <directory with result, summary.md and catalogue.json>
# DRY_RUN=1 prints what would happen and runs no git or gh command.
set -eu
out=$1
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
branch=catalogue-refresh
result=$(cat "$out/result")
case "$result" in
changed)
    if [ -n "${DRY_RUN:-}" ]; then echo "DRY_RUN: a pull request from $branch would carry the new catalogue."; exit 0; fi
    if [ -n "${GITHUB_ACTIONS:-}" ]; then git config --global --add safe.directory "$root"; fi
    git config user.name "sparky-ca catalogue refresh"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
    git checkout -B "$branch"
    cp "$out/catalogue.json" data/catalogue.json
    git add data/catalogue.json
    git commit -q -m "Refresh the ICP-Brasil catalogue from ITI's verified bundle" -m "$(cat "$out/summary.md")"
    git push --force origin "$branch"
    if [ -n "$(gh pr list --head "$branch" --state open --json number --jq '.[].number')" ]; then
        gh pr edit "$branch" --body-file "$out/summary.md"
    else
        gh pr create --head "$branch" --title "Refresh the ICP-Brasil catalogue" --body-file "$out/summary.md"
    fi
    ;;
unpinned)
    title="ITI published a root that is not pinned"
    if [ -n "${DRY_RUN:-}" ]; then echo "DRY_RUN: an issue titled '$title' would be opened."; exit 0; fi
    if [ -z "$(gh issue list --state open --search "$title in:title" --json number --jq '.[].number')" ]; then
        gh issue create --title "$title" --body-file "$out/summary.md"
    fi
    ;;
*)
    echo "Nothing to propose for result: $result"
    ;;
esac
