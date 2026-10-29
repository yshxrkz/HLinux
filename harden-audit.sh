#!/usr/bin/env bash
#
# harden-audit.sh - Linux hardening audit, loosely based on CIS benchmarks.
#
# Checks SSH root login, password authentication settings, the host firewall,
# unnecessary network services, permissions on account files and automatic
# security updates. Every check prints PASS, FAIL or SKIP with an explanation,
# and every FAIL includes a suggested fix.
#
# READ-ONLY GUARANTEE: the audit never changes the system. It only reads
# files and runs inspection commands (stat, sshd -T, systemctl is-active,
# nft list ruleset, apt-config dump, ...). It writes nothing to disk - it even
# avoids bash here-strings/here-docs, which can create temp files - and it
# never runs package managers, service managers in a mutating mode, or
# anything that could load kernel modules.
#
# Usage: sudo ./harden-audit.sh [--quiet] [--no-color] [--help] [--version]
#
# Exit status: 0 = no FAIL results, 1 = at least one FAIL, 2 = usage error.

set -u
export LC_ALL=C
# Make sure admin tools in sbin directories are found when run as a normal user.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

readonly VERSION="1.0.0"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"

# Resolve the real location (works through symlinks, e.g. /usr/local/bin).
HLINUX_ROOT=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
readonly HLINUX_LIB="$HLINUX_ROOT/lib"

# shellcheck source=lib/common.sh
source "$HLINUX_LIB/common.sh"
# shellcheck source=lib/controls/ssh.sh
source "$HLINUX_LIB/controls/ssh.sh"
# shellcheck source=lib/controls/auth.sh
source "$HLINUX_LIB/controls/auth.sh"
# shellcheck source=lib/controls/firewall.sh
source "$HLINUX_LIB/controls/firewall.sh"
# shellcheck source=lib/controls/services.sh
source "$HLINUX_LIB/controls/services.sh"
# shellcheck source=lib/controls/files.sh
source "$HLINUX_LIB/controls/files.sh"
# shellcheck source=lib/controls/updates.sh
source "$HLINUX_LIB/controls/updates.sh"

usage() {
    printf '%s\n' \
        "Usage: harden-audit.sh [OPTIONS]" \
        "" \
        "Read-only audit of basic Linux hardening settings (loosely based on CIS)." \
        "Run as root for complete results; some checks are skipped otherwise." \
        "" \
        "Options:" \
        "  -q, --quiet      Only print FAIL and SKIP results (plus the summary)" \
        "      --no-color   Disable coloured output (also honours NO_COLOR)" \
        "  -h, --help       Show this help and exit" \
        "  -V, --version    Show version and exit" \
        "" \
        "Exit status: 0 if nothing failed, 1 if any check failed, 2 on usage error."
}

while (($#)); do
    case $1 in
        -q|--quiet)    QUIET=1 ;;
        --no-color)    USE_COLOR=0 ;;
        -h|--help)     usage; exit 0 ;;
        -V|--version)  echo "harden-audit.sh $VERSION"; exit 0 ;;
        *)             echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

setup_colors

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    detect_os
    printf '%sLinux hardening audit%s (harden-audit.sh %s, read-only)\n' "$C_BOLD" "$C_OFF" "$VERSION"
    printf 'Host:   %s\n' "$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)"
    printf 'OS:     %s (kernel %s)\n' "$OS_NAME" "$(uname -r)"
    printf 'Date:   %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    if is_root; then
        printf 'User:   root\n'
    else
        printf 'User:   %s %s(not root: some checks will be SKIPPED - run with sudo for a full audit)%s\n' \
            "$(id -un)" "$C_SKIP" "$C_OFF"
    fi

    check_ssh
    check_password_policy
    check_firewall
    check_services
    check_file_permissions
    check_updates

    printf '\n%s== Summary ==%s\n' "$C_BOLD" "$C_OFF"
    printf '%s%d passed%s, %s%d failed%s, %s%d skipped%s (%d checks)\n' \
        "$C_PASS" "$N_PASS" "$C_OFF" "$C_FAIL" "$N_FAIL" "$C_OFF" "$C_SKIP" "$N_SKIP" "$C_OFF" \
        $((N_PASS + N_FAIL + N_SKIP))
    ((N_FAIL == 0))
}

main
exit $?
