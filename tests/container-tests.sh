#!/usr/bin/env bash
#
# End-to-end tests for harden-audit.sh, run INSIDE the deliberately insecure
# demo container (see Dockerfile). They audit it, check that a dry run and
# every refusal change nothing, harden it, and then prove the result from the
# outside: real SSH logins, file modes, services, packages and backups.
#
# Run from the host with tests/docker-test.sh, never on a real machine:
# this script hardens (changes) the system it runs on.

set -u
export LC_ALL=C

if [[ ! -e /usr/local/sbin/make-insecure ]]; then
    echo "Refusing to run: this is not the harden-audit demo container." >&2
    exit 2
fi

TOOL=/opt/harden-audit/harden-audit.sh
REPORTS=${REPORTS:-/reports}
[[ -d $REPORTS && -w $REPORTS ]] || REPORTS=/tmp/reports
mkdir -p "$REPORTS"
KEY=/root/demo-admin-key
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)
PASSED=0
FAILED=0

ok()   { PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else fail "$1"; fi; }
expect() {
    if grep -Eq -- "$3" <<<"$2"; then ok "$1"; else fail "$1 (no line matching: $3)"; fi
}
status_of() { jq -r --arg id "$2" '.controls[] | select(.id == $id) | .status' "$1"; }

# A fingerprint of everything harden could touch.
fingerprint() {
    {
        find /etc -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null
        stat -c '%n %a %U:%G' /etc/passwd /etc/shadow /etc/group /etc/gshadow
        pgrep -x vsftpd >/dev/null && echo "vsftpd running"
        ls /var/backups/harden-audit 2>/dev/null
    } | sha256sum
}

ssh_key_login()      { ssh "${SSH_OPTS[@]}" -i "$KEY" "$1@127.0.0.1" true 2>&1; }
ssh_password_login() { ssh "${SSH_OPTS[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive "$1@127.0.0.1" true 2>&1; }

echo "1. Baseline: the container is insecure"
"$TOOL" audit --no-color --report "$REPORTS/before.json" >/dev/null 2>&1
rc=$?
check "audit exits 1 when controls fail" "(($rc == 1))"
check "JSON report is valid" "jq -e . '$REPORTS/before.json' >/dev/null"
for id in SSH-1 SSH-2 SSH-3 SSH-4 SSH-5 AUTH-1 AUTH-2 AUTH-3 FW-1 SVC-1 FILE-2 FILE-4 UPD-1 AUD-2; do
    check "$id fails" "[[ \$(status_of '$REPORTS/before.json' $id) == FAIL ]]"
done
check "AUD-1 is skipped inside a container" "[[ \$(status_of '$REPORTS/before.json' AUD-1) == SKIP ]]"
score_before=$(jq '.score' "$REPORTS/before.json")
check "score is low (got $score_before)" "(($score_before < 30))"
check "SSH accepts a password before hardening" "! ssh_password_login admin | grep -q 'Permission denied (publickey)'"
"$TOOL" audit --quiet --report "$REPORTS/before.html" >/dev/null 2>&1

echo "2. Nothing changes without consent"
before=$(fingerprint)
out=$("$TOOL" harden --dry-run --no-color 2>&1)
rc=$?
check "dry run exits 0" "(($rc == 0))"
expect "dry run shows the planned commands" "$out" '\[plan\] +chmod 0640 /etc/shadow'
expect "dry run shows settings it would change" "$out" "\\[plan\\] +set 'PermitRootLogin no' in /etc/ssh/sshd_config.d/00-hardening.conf"
expect "dry run shows the content of new files" "$out" '\| -w /etc/shadow -p wa -k identity'
check "dry run changed nothing" "[[ \$(fingerprint) == '$before' ]]"
out=$("$TOOL" harden --no-color < /dev/null 2>&1)
rc=$?
check "harden without a terminal or --yes is refused (exit 2)" "(($rc == 2))"
check "...and changed nothing" "[[ \$(fingerprint) == '$before' ]]"
out=$(printf 'n\nn\nq\n' | script -qec "$TOOL harden --no-color --only AUTH-1,FILE-2" /dev/null 2>&1)
expect "the prompt asks before each fix" "$out" 'Apply this fix\? \[y\]es / \[n\]o / \[a\]ll remaining / \[q\]uit'
check "answering 'n' changed nothing" "[[ \$(fingerprint) == '$before' ]]"

echo "3. Lock-out guards"
mv /home/admin/.ssh/authorized_keys /root/authorized_keys.away
out=$("$TOOL" harden --yes --no-color --only SSH-2 2>&1)
expect "disabling passwords is refused when nobody has an SSH key" "$out" '\[refuse\] no non-root user has an SSH key'
check "...and sshd still accepts passwords" "sshd -T | grep -qx 'passwordauthentication yes'"
mv /root/authorized_keys.away /home/admin/.ssh/authorized_keys
out=$(SSH_CONNECTION="192.0.2.10 50000 192.0.2.1 22" SUDO_USER=deploy "$TOOL" harden --yes --no-color --only SSH-2 2>&1)
expect "refused when the user running it over SSH has no key" "$out" "logged in over SSH as 'deploy'"
check "nothing was changed by the refusals" "[[ \$(fingerprint) == '$before' ]]"

echo "4. Harden everything"
# Two quick runs first: back-to-back runs must get separate backup directories.
"$TOOL" harden --yes --no-color --only FILE-2 >/dev/null 2>&1
out=$("$TOOL" harden --yes --no-color --only FILE-4 2>&1)
expect "a second run right after the first still works" "$out" '^  FILE-4  FAIL -> PASS$'
check "each run has its own backup directory" "[[ \$(find /var/backups/harden-audit -mindepth 1 -maxdepth 1 -type d | wc -l) == 2 ]]"

out=$("$TOOL" harden --yes --no-color --report "$REPORTS/harden.json" 2>&1)
rc=$?
printf '%s\n' "$out" > "$REPORTS/harden-output.txt"
check "harden exits 0 (no FAIL left)" "(($rc == 0))"
check "every fix was applied" "[[ \$(jq '[.hardening[] | select(.outcome != \"applied\")] | length' '$REPORTS/harden.json') == 0 ]]"
check "the other 12 fixes were applied" "[[ \$(jq '.hardening | length' '$REPORTS/harden.json') == 12 ]]"
check "the report has the score before (low) and after (100)" \
    "[[ \$(jq '.score_before < 30 and .score == 100' '$REPORTS/harden.json') == true ]]"
expect "the output shows before -> after" "$out" 'Hardening score: [0-9]+/100 \(grade F\) -> 100/100 \(grade A\)'

echo "5. The result, checked from the outside"
check "sshd -t accepts the configuration" "sshd -t"
check "admin can still log in with the SSH key" "ssh_key_login admin >/dev/null"
expect "password logins are rejected" "$(ssh_password_login admin)" 'Permission denied \(publickey\)'
mkdir -p /root/.ssh && cp "$KEY.pub" /root/.ssh/authorized_keys
expect "root logins are rejected, even with a valid key" "$(ssh_key_login root)" 'Permission denied'
check "the empty-password account is locked" "[[ \$(getent shadow deploy | cut -d: -f2) == '!'* ]]"
check "/etc/shadow is 640 root:shadow" "[[ \$(stat -c '%a %U:%G' /etc/shadow) == '640 root:shadow' ]]"
check "login.defs has PASS_MAX_DAYS 365" "grep -Eq '^PASS_MAX_DAYS[[:space:]]+365$' /etc/login.defs"
check "pam_pwquality is in the PAM password stack" "grep -q pam_pwquality /etc/pam.d/common-password"
check "minlen = 14 is configured" "grep -qx 'minlen = 14' /etc/security/pwquality.conf.d/50-hardening.conf"
check "ufw is active" "ufw status | grep -qx 'Status: active'"
check "ufw allows SSH" "ufw status | grep -Eq '^22/tcp +ALLOW'"
check "vsftpd is no longer running" "! pgrep -x vsftpd >/dev/null"
check "unattended-upgrades is installed" "dpkg-query -W -f='\${Status}' unattended-upgrades | grep -q 'install ok installed'"
check "automatic upgrades are switched on" "apt-config dump | grep -q 'APT::Periodic::Unattended-Upgrade \"1\"'"
check "audit rules watch /etc/shadow" "grep -qx -- '-w /etc/shadow -p wa -k identity' /etc/audit/rules.d/50-hardening.rules"

echo "6. Backups"
# The full run is the one that backed up login.defs (AUTH-1).
backup=$(find /var/backups/harden-audit -path '*/etc/login.defs' -print -quit)
backup=${backup%/etc/login.defs}
check "the full run created a third backup directory" "[[ \$(find /var/backups/harden-audit -mindepth 1 -maxdepth 1 -type d | wc -l) == 3 ]]"
check "the backup directory is private (700)" "[[ \$(stat -c %a '$backup') == 700 ]]"
check "the original login.defs was backed up" "grep -Eq '^PASS_MAX_DAYS[[:space:]]+99999$' '$backup/etc/login.defs'"
check "new files are listed for rollback" "grep -qx /etc/ssh/sshd_config.d/00-hardening.conf '$backup/created-files.txt'"
check "the command log exists" "grep -q 'ufw --force enable' '$backup/harden.log'"

echo "7. Idempotent"
after=$(fingerprint)
out=$("$TOOL" harden --yes --no-color 2>&1)
rc=$?
check "a second run exits 0" "(($rc == 0))"
expect "a second run has nothing to fix" "$out" '^Nothing to fix\.$'
check "a second run changes nothing" "[[ \$(fingerprint) == '$after' ]]"
"$TOOL" audit --no-color --report "$REPORTS/after.html" >/dev/null 2>&1
rc=$?
check "the final audit passes (exit 0)" "(($rc == 0))"
"$TOOL" audit --quiet --no-color --report "$REPORTS/after.md" >/dev/null 2>&1

echo
echo "$PASSED passed, $FAILED failed"
((FAILED == 0))
