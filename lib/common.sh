# shellcheck shell=bash
#
# common.sh - shared helpers: output, result recording, OS detection.
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.
# Globals defined here are used by the other modules:
# shellcheck disable=SC2034

QUIET=0     # 1 = print only FAIL/SKIP results
SILENT=0    # 1 = print no results at all (harden mode re-runs the audit silently)
USE_COLOR=1
N_PASS=0
N_FAIL=0
N_SKIP=0

# ---------------------------------------------------------------------------
# Control registry
# ---------------------------------------------------------------------------
# Every control registers itself once with its severity (used for the score),
# its category, the name of the function that fixes it in harden mode (may be
# empty), a short title and a "why it matters" explanation.

CONTROL_IDS=()
declare -A CTL_SEV=() CTL_CAT=() CTL_FIXFN=() CTL_TITLE=() CTL_WHY=()

# register_control ID SEVERITY CATEGORY FIX_FUNCTION TITLE WHY
register_control() {
    CONTROL_IDS+=("$1")
    CTL_SEV[$1]=$2
    CTL_CAT[$1]=$3
    CTL_FIXFN[$1]=$4
    CTL_TITLE[$1]=$5
    CTL_WHY[$1]=$6
}

# severity_weight SEVERITY - points a control is worth in the hardening score.
severity_weight() {
    case $1 in
        high)   echo 3 ;;
        medium) echo 2 ;;
        *)      echo 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Results of the most recent audit run
# ---------------------------------------------------------------------------

R_IDS=()
declare -A R_STATUS=() R_TITLE=() R_DETAIL=() R_FIX=()

reset_results() {
    R_IDS=()
    R_STATUS=() R_TITLE=() R_DETAIL=() R_FIX=()
    N_PASS=0 N_FAIL=0 N_SKIP=0
}

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

# pkg_install_hint PACKAGE... - the install command for this distribution.
pkg_install_hint() {
    case $OS_FAMILY in
        debian) echo "sudo apt install $*" ;;
        rhel)   echo "sudo dnf install $*" ;;
        suse)   echo "sudo zypper install $*" ;;
        arch)   echo "sudo pacman -S $*" ;;
        *)      echo "Install the package(s): $*" ;;
    esac
}

# service_enable_hint UNIT - the command that enables and starts a service.
service_enable_hint() {
    echo "sudo systemctl enable --now $1"
}

section() {
    ((QUIET || SILENT)) && return 0
    printf '\n%s== %s ==%s\n' "$C_BOLD" "$1" "$C_OFF"
}

# report STATUS ID TITLE DETAIL [FIX]
# Records a result and prints it. FIX may contain several lines separated
# by newlines.
report() {
    local status=$1 id=$2 title=$3 detail=$4 fix=${5-} color indent='                '
    case $status in
        PASS) N_PASS=$((N_PASS + 1)); color=$C_PASS ;;
        FAIL) N_FAIL=$((N_FAIL + 1)); color=$C_FAIL ;;
        *)    N_SKIP=$((N_SKIP + 1)); color=$C_SKIP ;;
    esac
    R_IDS+=("$id")
    R_STATUS[$id]=$status
    R_TITLE[$id]=$title
    R_DETAIL[$id]=$detail
    R_FIX[$id]=$fix
    ((SILENT)) && return 0
    ((QUIET)) && [[ $status == PASS ]] && return 0

    printf '%s[%s]%s %-7s %s\n' "$color" "$status" "$C_OFF" "$id" "$title"
    printf '%s%sDetail:%s %s\n' "${indent:0:8}" "$C_DIM" "$C_OFF" "${detail//$'\n'/$'\n'$indent}"
    if [[ -n $fix && $status != PASS ]]; then
        printf '%s%sFix:%s    %s\n' "${indent:0:8}" "$C_DIM" "$C_OFF" "${fix//$'\n'/$'\n'$indent}"
    fi
}

# ---------------------------------------------------------------------------
# Hardening score
# ---------------------------------------------------------------------------
# score = weight of passed controls / weight of evaluated controls * 100,
# where high = 3, medium = 2 and low = 1 point. SKIPs are left out, so a
# non-root run is not punished for checks it could not perform.

SCORE=""
GRADE=""

compute_score() {
    local id w passed=0 total=0
    for id in "${R_IDS[@]}"; do
        [[ ${R_STATUS[$id]} == SKIP ]] && continue
        w=$(severity_weight "${CTL_SEV[$id]:-low}")
        total=$((total + w))
        [[ ${R_STATUS[$id]} == PASS ]] && passed=$((passed + w))
    done
    if ((total == 0)); then
        SCORE="" GRADE="n/a"
        return
    fi
    SCORE=$(((passed * 100 + total / 2) / total))
    if ((SCORE >= 90)); then GRADE=A
    elif ((SCORE >= 80)); then GRADE=B
    elif ((SCORE >= 70)); then GRADE=C
    elif ((SCORE >= 60)); then GRADE=D
    else GRADE=F
    fi
}

# score_bar SCORE - a 20-character bar such as [##############------]
score_bar() {
    local filled=$(($1 / 5)) bar=""
    while ((${#bar} < filled)); do bar+="#"; done
    while ((${#bar} < 20)); do bar+="-"; done
    printf '[%s]' "$bar"
}

# score_color SCORE - colour for the score: green >= 80, yellow >= 60, else red.
score_color() {
    if (($1 >= 80)); then printf '%s' "$C_PASS"
    elif (($1 >= 60)); then printf '%s' "$C_SKIP"
    else printf '%s' "$C_FAIL"
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
