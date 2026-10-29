# shellcheck shell=bash
#
# common.sh - shared helpers: output, result recording, OS detection.
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.
# Globals defined here are used by the other modules:
# shellcheck disable=SC2034

QUIET=0
USE_COLOR=1
N_PASS=0
N_FAIL=0
N_SKIP=0

# setup_colors - decide whether to colour output (TTY, NO_COLOR, TERM=dumb).
setup_colors() {
    if [[ ! -t 1 || -n ${NO_COLOR:-} || ${TERM:-dumb} == dumb ]]; then
        USE_COLOR=0
    fi
    if ((USE_COLOR)); then
        C_PASS=$'\e[32m' C_FAIL=$'\e[31m' C_SKIP=$'\e[33m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_OFF=$'\e[0m'
    else
        C_PASS='' C_FAIL='' C_SKIP='' C_BOLD='' C_DIM='' C_OFF=''
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

is_root() { [[ $EUID -eq 0 ]]; }

# True when systemd is the running init system (same test as sd_booted(3)).
has_systemd() { [[ -d /run/systemd/system ]] && have systemctl; }

trim() {
    local s=$1
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    printf '%s' "$s"
}

# join SEPARATOR ITEM... - print the items joined by SEPARATOR
join() {
    local sep=$1 out=""
    shift
    for item in "$@"; do out+=${out:+$sep}$item; done
    printf '%s' "$out"
}

section() {
    ((QUIET)) && return 0
    printf '\n%s== %s ==%s\n' "$C_BOLD" "$1" "$C_OFF"
}

# report STATUS ID TITLE DETAIL [FIX]
# FIX may contain several lines separated by newlines.
report() {
    local status=$1 id=$2 title=$3 detail=$4 fix=${5-} color indent='                '
    case $status in
        PASS) N_PASS=$((N_PASS + 1)); color=$C_PASS ;;
        FAIL) N_FAIL=$((N_FAIL + 1)); color=$C_FAIL ;;
        *)    N_SKIP=$((N_SKIP + 1)); color=$C_SKIP ;;
    esac
    ((QUIET)) && [[ $status == PASS ]] && return 0

    printf '%s[%s]%s %-7s %s\n' "$color" "$status" "$C_OFF" "$id" "$title"
    printf '%s%sDetail:%s %s\n' "${indent:0:8}" "$C_DIM" "$C_OFF" "${detail//$'\n'/$'\n'$indent}"
    if [[ -n $fix && $status != PASS ]]; then
        printf '%s%sFix:%s    %s\n' "${indent:0:8}" "$C_DIM" "$C_OFF" "${fix//$'\n'/$'\n'$indent}"
    fi
}

# ---------------------------------------------------------------------------
# Distribution detection (parses /etc/os-release without sourcing it)
# ---------------------------------------------------------------------------

OS_NAME="unknown Linux"
OS_FAMILY="other"   # debian | rhel | suse | arch | other

detect_os() {
    local line key val id="" id_like=""
    [[ -r /etc/os-release ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ ^([A-Z_]+)=(.*)$ ]] || continue
        key=${BASH_REMATCH[1]}
        val=${BASH_REMATCH[2]}
        val=${val#[\"\']}
        val=${val%[\"\']}
        case $key in
            PRETTY_NAME) OS_NAME=$val ;;
            ID)          id=$val ;;
            ID_LIKE)     id_like=$val ;;
        esac
    done < /etc/os-release

    case " $id $id_like " in
        *" debian "*|*" ubuntu "*)                                     OS_FAMILY=debian ;;
        *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*) OS_FAMILY=rhel ;;
        *" suse "*|*" opensuse "*|*" sles "*)                          OS_FAMILY=suse ;;
        *" arch "*)                                                     OS_FAMILY=arch ;;
    esac
}
