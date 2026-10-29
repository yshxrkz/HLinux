#!/usr/bin/env bash
#
# Smoke test of the RHEL-family code paths: audit and harden a throwaway
# Rocky Linux 9 container with the repository mounted read-only. The
# container does not run systemd, so fixes that need it (firewalld, the
# dnf-automatic timer) must stop as "manual" without changing anything.
#
# Usage: tests/rocky-smoke.sh
# Extra docker run arguments can be passed in ROCKY_DOCKER_ARGS (for example
# to mount a CA bundle when a TLS-intercepting proxy is in the way).

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${ROCKY_IMAGE:-rockylinux:9}
read -r -a extra <<< "${ROCKY_DOCKER_ARGS:-}"

docker run --rm "${extra[@]}" --volume "$root:/opt/harden-audit:ro" "$image" bash -c '
set -uo pipefail
command -v update-ca-trust >/dev/null && update-ca-trust
dnf -y -q install openssh-server openssh-clients passwd sudo >/dev/null 2>&1
ssh-keygen -A >/dev/null
mkdir -p /run/sshd
chmod 644 /etc/shadow
useradd -m -G wheel admin
ssh-keygen -q -t ed25519 -N "" -f /root/key
install -d -m 700 -o admin -g admin /home/admin/.ssh
install -m 600 -o admin -g admin /root/key.pub /home/admin/.ssh/authorized_keys

tool=/opt/harden-audit/harden-audit.sh
failed=0
ok()   { printf "  ok    %s\n" "$1"; }
fail() { printf "  FAIL  %s\n" "$1"; failed=1; }

$tool audit --no-color --report /tmp/before.json >/dev/null
for id in SSH-1 SSH-2 AUTH-1 FILE-2 AUD-2; do
    if grep -q "\"id\": \"$id\".*\"status\": \"FAIL\"" /tmp/before.json; then ok "$id fails before"; else fail "$id fails before"; fi
done
$tool harden --yes --no-color > /tmp/harden.txt
$tool audit --no-color --report /tmp/after.json >/dev/null
for id in SSH-1 SSH-2 SSH-4 SSH-5 AUTH-1 AUTH-3 FILE-2 AUD-2; do
    if grep -q "\"id\": \"$id\".*\"status\": \"PASS\"" /tmp/after.json; then ok "$id passes after"; else fail "$id passes after"; fi
done
[[ $(stat -c "%a %U:%G" /etc/shadow) == "0 root:root" ]] && ok "/etc/shadow is 0000 root:root (RHEL style)" || fail "/etc/shadow is 0000 root:root"
sshd -t && ok "sshd -t accepts the result" || fail "sshd -t accepts the result"
grep -q "firewalld is managed by systemd" /tmp/harden.txt && ok "FW-1 stops as manual without systemd" || fail "FW-1 stops as manual without systemd"
rpm -q --quiet dnf-automatic && fail "dnf-automatic was installed although it cannot be enabled" || ok "UPD-1 changed nothing without systemd"
exit $failed
'
