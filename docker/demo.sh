#!/usr/bin/env bash
#
# The demo run: audit the insecure container, harden it without asking
# (--yes - fine here, never do that on a real server without reading the plan
# first), and audit again. Reports go to /reports if it is mounted.
set -uo pipefail

tool=/opt/harden-audit/harden-audit.sh
out=/reports
[[ -d $out && -w $out ]] || out=/tmp/reports
mkdir -p "$out"

banner() { printf '\n\033[1m######## %s ########\033[0m\n\n' "$1"; }

banner "1/3  Audit the deliberately insecure container"
"$tool" audit --report "$out/before.html"

banner "2/3  Harden it (--yes: no questions, demo only)"
"$tool" harden --yes --report "$out/after.md"

banner "3/3  Audit again"
"$tool" audit --quiet --report "$out/after.html"

printf '\nReports written to %s:\n' "$out"
printf '  %s\n' "$out"/*.html "$out"/*.md
