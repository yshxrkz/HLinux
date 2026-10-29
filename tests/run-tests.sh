#!/usr/bin/env bash
#
# Scenario tests for harden-audit.sh.
#
# The real system is never modified: each scenario runs the audit inside a
# private mount namespace (unshare -m) where fixture files from a temporary
# directory are bind-mounted over /etc/ssh/sshd_config, /etc/shadow, etc.
# The bind mounts disappear when the namespace exits.
#
# Requirements: root, util-linux (unshare, mount), and optionally strace for
# the read-only verification test.
#
# Usage: sudo tests/run-tests.sh

set -u
export LC_ALL=C

AUDIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/harden-audit.sh"
PASSED=0
FAILED=0

if [[ $EUID -ne 0 ]]; then
    echo "These tests need root (for unshare -m and bind mounts)." >&2
    exit 2
fi
if ! unshare -m true 2>/dev/null; then
    echo "unshare -m is not available here; cannot run scenario tests." >&2
    exit 2
fi

FIX=$(mktemp -d)
chmod 755 "$FIX"
trap 'rm -rf "$FIX"' EXIT

ok()   { PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$1"; }

# expect NAME OUTPUT REGEX - assert that OUTPUT contains a line matching REGEX
expect() {
    if grep -Eq -- "$3" <<<"$2"; then ok "$1"; else fail "$1 (no line matching: $3)"; fi
}

# run_in_ns "SRC:DEST ..." [USER] - run the audit with fixtures bind-mounted.
# Prints the audit output followed by a final line "EXIT=<code>".
run_in_ns() {
    local mounts=$1 user=${2:-root}
    # The inner script is expanded by the inner bash:
    # shellcheck disable=SC2016
    unshare -m bash -c '
        set -e
        mount --make-rprivate /
        for m in '"$mounts"'; do
            mount --bind "${m%%:*}" "${m#*:}"
        done
        set +e
        if [[ '"$user"' == root ]]; then
            "'"$AUDIT"'" --no-color
        else
            su -s /bin/bash '"$user"' -c "\"'"$AUDIT"'\" --no-color"
        fi
        echo "EXIT=$?"
    ' 2>&1
}

# --- fixtures ---------------------------------------------------------------

mkdir -p "$FIX/secure/sshd_config.d" "$FIX/insecure/sshd_config.d" "$FIX/match/sshd_config.d"

# Secure SSH: settings in a drop-in that is included before the main body.
cat > "$FIX/secure/sshd_config" <<'EOF'
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin yes
PasswordAuthentication yes
UsePAM yes
EOF
cat > "$FIX/secure/sshd_config.d/00-hardening.conf" <<'EOF'
# drop-in wins because it is read first
PermitRootLogin=no
  passwordauthentication   "no"
KbdInteractiveAuthentication no
MaxAuthTries 3
X11Forwarding no
EOF

# Insecure SSH
cat > "$FIX/insecure/sshd_config" <<'EOF'
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin yes
UsePAM yes
PermitEmptyPasswords yes
MaxAuthTries 10
X11Forwarding yes
EOF

# Secure globally, but a Match block re-enables root and password logins
cat > "$FIX/match/sshd_config" <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
Match Address 10.0.0.0/8
    PermitRootLogin yes
    PasswordAuthentication yes
    X11Forwarding yes
EOF

printf 'PASS_MAX_DAYS\t365\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t7\n' > "$FIX/login.defs.good"
printf 'PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\n' > "$FIX/login.defs.bad"

printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' \
    'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin' \
    'legacy:abc123hash:1001:1001::/home/legacy:/bin/sh' > "$FIX/passwd.bad"
printf '%s\n' 'root:!:19000:0:99999:7:::' 'nopass::19000:0:99999:7:::' > "$FIX/shadow.bad"
chmod 644 "$FIX/passwd.bad" "$FIX/shadow.bad"     # shadow world-readable = bad
cp /etc/group "$FIX/group.bad"
chmod 666 "$FIX/group.bad"                        # world-writable = bad
chown nobody "$FIX/group.bad"

printf 'password requisite pam_pwquality.so retry=3 minlen=14\npassword [success=1 default=ignore] pam_unix.so obscure use_authtok yescrypt\n' > "$FIX/common-password.good"
printf 'password requisite pam_pwquality.so retry=3\npassword [success=1 default=ignore] pam_unix.so obscure yescrypt\n' > "$FIX/common-password.weak"

printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "0";\n' > "$FIX/20auto-upgrades.off"
printf 'ENABLED=yes\n' > "$FIX/ufw.conf.enabled"

# --- scenarios --------------------------------------------------------------

echo "Scenario: secure SSH config (drop-in overrides main file)"
if [[ -e /etc/ssh/sshd_config ]]; then
    out=$(run_in_ns "$FIX/secure/sshd_config:/etc/ssh/sshd_config $FIX/secure/sshd_config.d:/etc/ssh/sshd_config.d $FIX/login.defs.good:/etc/login.defs $FIX/common-password.good:/etc/pam.d/common-password")
    expect "SSH-1 passes"  "$out" '^\[PASS\] SSH-1 '
    expect "SSH-2 passes"  "$out" '^\[PASS\] SSH-2 '
    expect "SSH-3 passes"  "$out" '^\[PASS\] SSH-3 '
    expect "SSH-4 passes"  "$out" '^\[PASS\] SSH-4 '
    expect "SSH-5 passes"  "$out" '^\[PASS\] SSH-5 '
    expect "AUTH-1 passes" "$out" '^\[PASS\] AUTH-1 '
    expect "AUTH-3 passes with minlen=14 on the PAM line" "$out" '^\[PASS\] AUTH-3 '
else
    echo "  (skipped: OpenSSH server not installed, nothing to bind-mount over)"
fi

echo "Scenario: insecure system"
mounts="$FIX/login.defs.bad:/etc/login.defs $FIX/passwd.bad:/etc/passwd $FIX/shadow.bad:/etc/shadow $FIX/group.bad:/etc/group"
if [[ -e /etc/ssh/sshd_config ]]; then
    mounts+=" $FIX/insecure/sshd_config:/etc/ssh/sshd_config $FIX/insecure/sshd_config.d:/etc/ssh/sshd_config.d"
fi
[[ -e /etc/apt/apt.conf.d/20auto-upgrades ]] && mounts+=" $FIX/20auto-upgrades.off:/etc/apt/apt.conf.d/20auto-upgrades"
[[ -e /etc/pam.d/common-password ]] && mounts+=" $FIX/common-password.weak:/etc/pam.d/common-password"
out=$(run_in_ns "$mounts")
if [[ -e /etc/ssh/sshd_config ]]; then
    expect "SSH-1 fails on PermitRootLogin yes"        "$out" '^\[FAIL\] SSH-1 '
    expect "SSH-2 fails on default PasswordAuth"       "$out" '^\[FAIL\] SSH-2 '
    expect "SSH-2 explains PAM keyboard-interactive"   "$out" 'KbdInteractiveAuthentication is .yes. with UsePAM'
    expect "SSH-3 fails on PermitEmptyPasswords yes"   "$out" '^\[FAIL\] SSH-3 '
    expect "SSH-4 fails on MaxAuthTries 10"            "$out" "MaxAuthTries is '10'"
    expect "SSH-5 fails on X11Forwarding yes"          "$out" '^\[FAIL\] SSH-5 '
fi
expect "AUTH-1 fails on PASS_MAX_DAYS 99999"       "$out" "PASS_MAX_DAYS is '99999'"
expect "AUTH-1 reports missing PASS_WARN_AGE"      "$out" "PASS_WARN_AGE is 'unset'"
[[ -e /etc/pam.d/common-password ]] && \
    expect "AUTH-3 fails on default minlen"        "$out" 'minlen is 8 \(from the libpwquality default\)'
expect "AUTH-2 finds empty password"               "$out" 'EMPTY password.*nopass'
expect "AUTH-2 finds unshadowed password"          "$out" 'world-readable /etc/passwd.*legacy'
expect "FILE-2 fails on world-readable shadow"     "$out" '^\[FAIL\] FILE-2 '
expect "FILE-3 reports wrong owner"                "$out" "owner is 'nobody'"
expect "FILE-3 reports excess mode"                "$out" 'mode is 666, which grants more than 644'
[[ -e /etc/apt/apt.conf.d/20auto-upgrades ]] && \
    expect "UPD-1 fails when Unattended-Upgrade is 0" "$out" "Unattended-Upgrade is '0'"
expect "AUD-1 and AUD-2 are evaluated"            "$(grep -cE '^\[(PASS|FAIL)\] AUD-[12] ' <<<"$out")" '^2$'
expect "exit code is 1 when a check fails"         "$out" '^EXIT=1$'
expect "every FAIL has a Fix line" \
    "$(awk '/^\[FAIL\]/{f=1; next} f && /Fix:/{f=0} /^\[/{ if (f) print "MISSING"; f=0 } END { if (f) print "MISSING"; else print "all-good" }' <<<"$out")" '^all-good$'

if [[ -e /etc/ssh/sshd_config ]]; then
    echo "Scenario: Match block re-enables root/password login"
    out=$(run_in_ns "$FIX/match/sshd_config:/etc/ssh/sshd_config $FIX/match/sshd_config.d:/etc/ssh/sshd_config.d")
    expect "SSH-1 fails because of Match block" "$out" 'Match Address 10.0.0.0/8" sets PermitRootLogin yes'
    expect "SSH-2 fails because of Match block" "$out" 'Match Address 10.0.0.0/8" sets PasswordAuthentication yes'
    expect "SSH-5 fails because of Match block" "$out" 'Match Address 10.0.0.0/8" sets X11Forwarding yes'
fi

echo "Scenario: insecure service running (fake 'vsftpd' process)"
if [[ -d /run/systemd/system ]]; then
    echo "  (skipped: systemd is in use, so the audit checks units, not process names)"
else
    cp /bin/sleep "$FIX/vsftpd"
    "$FIX/vsftpd" 30 &
    fake_pid=$!
    out=$("$AUDIT" --no-color 2>&1)
    kill "$fake_pid" 2>/dev/null
    wait "$fake_pid" 2>/dev/null
    expect "SVC-1 detects vsftpd" "$out" 'FTP server .*process vsftpd'
fi

echo "Scenario: non-root user"
mounts=""
[[ -e /etc/ufw/ufw.conf ]] && mounts="$FIX/ufw.conf.enabled:/etc/ufw/ufw.conf"
out=$(run_in_ns "$mounts" nobody)
expect "header warns about non-root"    "$out" 'not root: some checks will be SKIPPED'
expect "AUTH-2 skipped without shadow"  "$out" '^\[SKIP\] AUTH-2 '
if [[ -n $mounts ]] && command -v ufw >/dev/null; then
    expect "FW-1 passes from ufw.conf"  "$out" '^\[PASS\] FW-1 .*'
    expect "FW-1 explains ufw.conf"     "$out" 'ENABLED=yes in /etc/ufw/ufw.conf'
fi

echo "Scenario: command-line handling"
if "$AUDIT" --help >/dev/null 2>&1; then ok "--help exits 0"; else fail "--help exits 0"; fi
"$AUDIT" --bogus >/dev/null 2>&1
rc=$?
if ((rc == 2)); then ok "unknown option exits 2"; else fail "unknown option exits 2 (got $rc)"; fi
out=$("$AUDIT" --quiet --no-color 2>&1)
if grep -q '^\[PASS\]' <<<"$out"; then fail "--quiet hides PASS lines"; else ok "--quiet hides PASS lines"; fi
if grep -q $'\e\[' <<<"$out"; then fail "--no-color has no escape codes"; else ok "--no-color has no escape codes"; fi

# mutating_syscalls ALLOWED_DIR CMD... - run CMD under strace and print every
# open-for-write or other mutating syscall, ignoring /dev/null, the terminal,
# failed calls and (if not empty) anything under ALLOWED_DIR.
mutating_syscalls() {
    local allowed=$1 trace
    shift
    trace=$(strace -f -qq -e trace=open,openat,openat2,creat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,truncate,ftruncate,link,linkat,symlink,symlinkat,mknod,mknodat,utimensat,init_module,finit_module,delete_module,reboot,mount,umount2 \
        "$@" 2>&1 >/dev/null)
    grep -E 'O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|(^|[] ])(creat|unlink|unlinkat|rename|renameat2?|mkdir|mkdirat|rmdir|f?chmod|fchmodat|[fl]?chown|fchownat|f?truncate|linkat|link|symlinkat|symlink|mknodat|mknod|utimensat|f?init_module|delete_module|reboot|mount|umount2)\(' <<<"$trace" \
        | grep -Ev '"/dev/(null|tty|pts/[0-9]+)"' \
        | grep -Ev '= -1 E' \
        | { if [[ -n $allowed ]]; then grep -Fv "\"$allowed/"; else cat; fi; } || true
}

echo "Scenario: reports"
mkdir -p "$FIX/reports"
for ext in md html json; do
    "$AUDIT" --quiet --no-color --report "$FIX/reports/r.$ext" >/dev/null 2>&1
    if [[ -s $FIX/reports/r.$ext ]]; then ok "$ext report written"; else fail "$ext report written"; fi
    if [[ $(stat -c %a "$FIX/reports/r.$ext") == 600 ]]; then ok "$ext report is mode 600"; else fail "$ext report is mode 600"; fi
done
expect "Markdown report has the score heading" "$(cat "$FIX/reports/r.md")" '^## Hardening score: [0-9]+/100 \(grade [A-F]\)'
expect "Markdown report lists every control" "$(grep -cE '^\| (✅|❌|⚪)' "$FIX/reports/r.md")" "^$("$AUDIT" list | tail -n +2 | wc -l)\$"
if python3 -m json.tool "$FIX/reports/r.json" >/dev/null 2>&1; then ok "JSON report is valid JSON"; else fail "JSON report is valid JSON"; fi
expect "JSON report has a numeric score" "$(cat "$FIX/reports/r.json")" '"score": [0-9]+,'
html_check=$(python3 - "$FIX/reports/r.html" <<'PY'
import html.parser, sys
class P(html.parser.HTMLParser):
    void = {"meta", "br", "link", "img", "input", "hr"}
    def __init__(self):
        super().__init__(); self.stack = []; self.errors = []
    def handle_starttag(self, tag, attrs):
        if tag not in self.void: self.stack.append(tag)
    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag: self.stack.pop()
        else: self.errors.append(tag)
p = P(); p.feed(open(sys.argv[1], encoding="utf-8").read())
print("balanced" if not p.errors and not p.stack else f"errors={p.errors} unclosed={p.stack}")
PY
)
expect "HTML report tags are balanced (text is escaped)" "$html_check" '^balanced$'
"$AUDIT" --report "$FIX/reports/r.txt" >/dev/null 2>&1
rc=$?
if ((rc == 2)); then ok "unknown report extension exits 2"; else fail "unknown report extension exits 2 (got $rc)"; fi
echo "do not overwrite" > "$FIX/reports/victim"
ln -s "$FIX/reports/victim" "$FIX/reports/link.md"
"$AUDIT" --quiet --report "$FIX/reports/link.md" >/dev/null 2>&1
if [[ $(cat "$FIX/reports/victim") == "do not overwrite" && -f $FIX/reports/link.md && ! -L $FIX/reports/link.md ]]; then
    ok "a symlink at the report path is replaced, not followed"
else
    fail "a symlink at the report path is replaced, not followed"
fi

echo "Scenario: read-only guarantee (strace)"
if command -v strace >/dev/null; then
    bad=$(mutating_syscalls "" "$AUDIT" --no-color)
    if [[ -z $bad ]]; then
        ok "audit: no file writes or mutating syscalls"
    else
        fail "audit: mutating syscalls found:"
        printf '        %s\n' "$bad" | head -20
    fi
    bad=$(mutating_syscalls "$FIX/reports" "$AUDIT" --no-color --report "$FIX/reports/traced.html")
    if [[ -z $bad ]]; then
        ok "audit --report: writes only inside the report directory"
    else
        fail "audit --report: writes outside the report directory:"
        printf '        %s\n' "$bad" | head -20
    fi
else
    echo "  (skipped: strace not installed)"
fi

echo
echo "$PASSED passed, $FAILED failed"
((FAILED == 0))
