#!/usr/bin/env bash
#
# harden-audit.sh - audit (and optionally harden) a Linux host against a set
# of CIS-benchmark-style controls.
#
#   audit   (default) Check every control and print PASS / FAIL / SKIP with an
#           explanation and a suggested fix, plus a weighted hardening score.
#   list    Show the controls, their severity and category.
#
# READ-ONLY GUARANTEE (audit, list): the audit never changes the system. It
# only reads files and runs inspection commands (stat, sshd -T, systemctl
# is-active, nft list ruleset, apt-config dump, ...). It writes nothing to
# disk except the report you ask for with --report - it even avoids bash
# here-strings/here-docs, which can create temp files - and it never runs
# package managers, service managers in a mutating mode, or anything that
# could load kernel modules.
#
# Usage: sudo ./harden-audit.sh [audit] [--quiet] [--no-color] [--report FILE]
#        ./harden-audit.sh list
#
# Exit status: 0 = no FAIL results, 1 = at least one FAIL, 2 = usage error.

set -u
export LC_ALL=C
# Make sure admin tools in sbin directories are found when run as a normal user.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

readonly VERSION="2.0.0"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"

# Resolve the real location (works through symlinks, e.g. /usr/local/bin).
HLINUX_ROOT=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
readonly HLINUX_LIB="$HLINUX_ROOT/lib"

# shellcheck source=lib/common.sh
source "$HLINUX_LIB/common.sh"
# shellcheck source=lib/report.sh
source "$HLINUX_LIB/report.sh"
# Controls register themselves in the order they are sourced, which is also
# the order they are audited, listed and hardened in.
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
# shellcheck source=lib/controls/auditd.sh
source "$HLINUX_LIB/controls/auditd.sh"

usage() {
    printf '%s\n' \
        "Usage: harden-audit.sh [COMMAND] [OPTIONS]" \
        "" \
        "Audit a Linux host against CIS-benchmark-style hardening controls." \
        "" \
        "Commands:" \
        "  audit            Check every control and report PASS/FAIL/SKIP (default)." \
        "                   Read-only: never changes the system." \
        "  list             List the controls with their severity and category." \
        "" \
        "Options:" \
        "  -q, --quiet      Only print FAIL and SKIP results (plus the summary)" \
        "  -r, --report FILE  Also write a report; format from the extension" \
        "                   (.md, .html or .json) unless --format is given" \
        "      --format FMT Report format: md, html or json" \
        "      --no-color   Disable coloured output (also honours NO_COLOR)" \
        "  -h, --help       Show this help and exit" \
        "  -V, --version    Show version and exit" \
        "" \
        "Run as root for complete results; some checks are skipped otherwise." \
        "Exit status: 0 if nothing failed, 1 if any check failed, 2 on usage error."
}

# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

# run_audit - run every check, recording results (and printing them unless
# SILENT=1). Safe to call more than once.
run_audit() {
    reset_results
    check_ssh
    check_password_policy
    check_firewall
    check_services
    check_file_permissions
    check_updates
    check_auditd
    compute_score
}

print_header() {
    printf '%s%s%s (harden-audit.sh %s)\n' "$C_BOLD" "$1" "$C_OFF" "$VERSION"
    printf 'Host:   %s\n' "$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)"
    printf 'OS:     %s (kernel %s)\n' "$OS_NAME" "$(uname -r)"
    printf 'Date:   %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    if is_root; then
        printf 'User:   root\n'
    else
        printf 'User:   %s %s(not root: some checks will be SKIPPED - run with sudo for a full audit)%s\n' \
            "$(id -un)" "$C_SKIP" "$C_OFF"
    fi
}

print_summary() {
    printf '\n%s== Summary ==%s\n' "$C_BOLD" "$C_OFF"
    printf '%s%d passed%s, %s%d failed%s, %s%d skipped%s (%d checks)\n' \
        "$C_PASS" "$N_PASS" "$C_OFF" "$C_FAIL" "$N_FAIL" "$C_OFF" "$C_SKIP" "$N_SKIP" "$C_OFF" \
        $((N_PASS + N_FAIL + N_SKIP))
    if [[ -n $SCORE ]]; then
        printf 'Hardening score: %s%d/100 (grade %s)%s %s\n' \
            "$(score_color "$SCORE")" "$SCORE" "$GRADE" "$C_OFF" "$(score_bar "$SCORE")"
    else
        printf 'Hardening score: n/a (no checks could be evaluated)\n'
    fi
}

# save_report - write the report requested with --report, if any.
save_report() {
    [[ -n $REPORT_FILE ]] || return 0
    REPORT_HOST=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)
    REPORT_DATE=$(date '+%Y-%m-%d %H:%M:%S %Z')
    REPORT_DATE_ISO=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    REPORT_USER=$(id -un)
    if write_report "$REPORT_FILE" "$REPORT_FORMAT"; then
        printf 'Report written to %s (%s)\n' "$REPORT_FILE" "$REPORT_FORMAT"
    else
        return 1
    fi
}

cmd_audit() {
    print_header "Linux hardening audit"
    run_audit
    print_summary
    save_report || return 2
    ((N_FAIL == 0))
}

cmd_list() {
    local id fix
    printf '%-7s %-8s %-17s %-6s %s\n' ID SEVERITY CATEGORY FIX TITLE
    for id in "${CONTROL_IDS[@]}"; do
        fix=manual
        [[ -n ${CTL_FIXFN[$id]} ]] && declare -F "${CTL_FIXFN[$id]}" >/dev/null && fix=auto
        printf '%-7s %-8s %-17s %-6s %s\n' "$id" "${CTL_SEV[$id]}" "${CTL_CAT[$id]}" "$fix" "${CTL_TITLE[$id]}"
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

REPORT_FILE=""
REPORT_FORMAT=""

main() {
    local cmd=audit
    case ${1:-} in
        audit|list) cmd=$1; shift ;;
        help)       usage; return 0 ;;
    esac
    while (($#)); do
        case $1 in
            -q|--quiet)    QUIET=1 ;;
            --no-color)    USE_COLOR=0 ;;
            -r|--report)
                [[ -n ${2:-} ]] || { echo "$1 needs a file name" >&2; return 2; }
                REPORT_FILE=$2; shift ;;
            --report=*)    REPORT_FILE=${1#*=} ;;
            --format)
                [[ -n ${2:-} ]] || { echo "$1 needs md, html or json" >&2; return 2; }
                REPORT_FORMAT=$2; shift ;;
            --format=*)    REPORT_FORMAT=${1#*=} ;;
            -h|--help)     usage; return 0 ;;
            -V|--version)  echo "harden-audit.sh $VERSION"; return 0 ;;
            *)             echo "Unknown option: $1" >&2; usage >&2; return 2 ;;
        esac
        shift
    done

    if [[ -n $REPORT_FILE ]]; then
        REPORT_FORMAT=$(report_format_for "$REPORT_FILE" "$REPORT_FORMAT") || {
            echo "Unknown report format for '$REPORT_FILE': use a .md, .html or .json file name, or --format md|html|json" >&2
            return 2
        }
    elif [[ -n $REPORT_FORMAT ]]; then
        echo "--format needs --report FILE" >&2
        return 2
    fi

    setup_colors
    detect_os
    case $cmd in
        audit) cmd_audit ;;
        list)  cmd_list ;;
    esac
}

main "$@"
exit $?
