# shellcheck shell=bash
#
# harden.sh - the harden command: apply fixes for failing controls, but only
# after confirmation, with a dry-run mode that changes nothing.
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.
# Globals defined here are also used by the control modules:
# shellcheck disable=SC2034
#
# Every fix function is written once, in terms of the act_* helpers below.
# It is called twice per control: first with APPLY=0, when the helpers only
# print what they would do (this is the plan shown before asking, and the
# whole of --dry-run), then with APPLY=1 after the user said yes.
#
# Fix functions take the control ID and return:
#   0  done (or, with APPLY=0, planned)
#   1  a step failed
#   2  cannot be fixed automatically; the reason has been printed
#   3  refused by a safety check (e.g. it would lock you out); see --force

HARDEN_DRY_RUN=0
HARDEN_YES=0
HARDEN_FORCE=0
HARDEN_ONLY=""          # comma-separated control IDs
HARDEN_SKIP=""
APPLY=0

BACKUP_ROOT="${HARDEN_AUDIT_BACKUP_ROOT:-/var/backups/harden-audit}"
BACKUP_DIR=""           # created on first use in apply mode
HARDEN_LOGFILE=""       # command output of the run, inside BACKUP_DIR
APT_UPDATED=0
declare -A BACKED_UP=()
HARDEN_LOG=()           # "ID|outcome|message" for the report

readonly RC_OK=0 RC_FAILED=1 RC_MANUAL=2 RC_REFUSED=3

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

# step TAG TEXT - one indented line of a plan or of the actions taken.
step() {
    local tag=$1 color=""
    shift
    case $tag in
        ok)          color=$C_PASS ;;
        fail|refuse) color=$C_FAIL ;;
        manual|plan) color=$C_SKIP ;;
    esac
    printf '    %s%-7s%s %s\n' "$color" "[$tag]" "$C_OFF" "$*"
}

# quote_cmd ARG... - the command as a copy-pasteable string.
quote_cmd() {
    local a out=""
    for a in "$@"; do
        if [[ $a =~ ^[A-Za-z0-9_./:=@%+,-]+$ ]]; then
            out+=" $a"
        else
            out+=" $(printf '%q' "$a")"
        fi
    done
    printf '%s' "${out# }"
}

# ---------------------------------------------------------------------------
# Backups and the run log
# ---------------------------------------------------------------------------

ensure_backup_dir() {
    [[ -n $BACKUP_DIR ]] && return 0
    BACKUP_DIR="$BACKUP_ROOT/$(date '+%Y%m%d-%H%M%S')"
    if ! mkdir -p "$BACKUP_ROOT" || ! chmod 700 "$BACKUP_ROOT" || ! mkdir -m 700 "$BACKUP_DIR"; then
        echo "Cannot create backup directory $BACKUP_DIR - refusing to change anything." >&2
        exit 2
    fi
    HARDEN_LOGFILE="$BACKUP_DIR/harden.log"
    : > "$HARDEN_LOGFILE"
}

# backup_file PATH - copy PATH into the backup directory (once per run). A
# file that does not exist yet is listed in created-files.txt instead, so a
# rollback knows to delete it.
backup_file() {
    local path=$1
    [[ -n ${BACKED_UP[$path]+set} ]] && return 0
    ensure_backup_dir
    if [[ -e $path ]]; then
        cp -a --parents -- "$path" "$BACKUP_DIR" || return 1
        BACKED_UP[$path]=copied
    else
        printf '%s\n' "$path" >> "$BACKUP_DIR/created-files.txt"
        BACKED_UP[$path]=created
    fi
}

# restore_file PATH - undo this run's changes to PATH (used when a change
# fails validation, e.g. sshd -t rejects the new SSH configuration).
restore_file() {
    local path=$1
    case ${BACKED_UP[$path]:-} in
        copied)  cp -a -- "$BACKUP_DIR$path" "$path" ;;
        created) rm -f -- "$path" ;;
    esac
}

# ---------------------------------------------------------------------------
# Actions: print with APPLY=0, print and execute with APPLY=1
# ---------------------------------------------------------------------------

# act_note TEXT - informational line; during apply it also goes into the run
# log, so e.g. the original permissions are on record for a rollback.
act_note() {
    step note "$*"
    if ((APPLY)) && [[ -n $HARDEN_LOGFILE ]]; then
        printf '# %s\n' "$*" >> "$HARDEN_LOGFILE"
    fi
}

# act_run CMD ARG... - run a command; its output goes to the run log.
act_run() {
    local cmd rc
    cmd=$(quote_cmd "$@")
    if ((!APPLY)); then
        step plan "$cmd"
        return 0
    fi
    ensure_backup_dir
    printf '\n$ %s\n' "$cmd" >> "$HARDEN_LOGFILE"
    "$@" >> "$HARDEN_LOGFILE" 2>&1 < /dev/null
    rc=$?
    if ((rc == 0)); then
        step ok "$cmd"
    else
        step fail "$cmd (exit $rc)"
        tail -n 5 "$HARDEN_LOGFILE" | sed 's/^/              /'
    fi
    return "$rc"
}

# act_write_file PATH MODE CONTENT - replace PATH atomically with CONTENT.
# Owner, group and mode of an existing file are kept; new files get MODE
# and root:root.
act_write_file() {
    local path=$1 mode=$2 content=$3 dir tmp
    [[ $content == *$'\n' ]] || content+=$'\n'
    if ((!APPLY)); then
        if [[ -e $path ]]; then step plan "rewrite $path:"; else step plan "create $path:"; fi
        printf '%s' "$content" | sed 's/^/              | /'
        return 0
    fi
    dir=$(dirname -- "$path")
    if [[ ! -d $dir ]]; then
        act_run mkdir -p -m 755 "$dir" || return 1
    fi
    backup_file "$path" || { step fail "could not back up $path"; return 1; }
    tmp=$(mktemp "$dir/.harden-audit.XXXXXX") || { step fail "cannot create a file in $dir"; return 1; }
    if ! printf '%s' "$content" > "$tmp"; then
        rm -f -- "$tmp"
        step fail "could not write $path"
        return 1
    fi
    if [[ -e $path ]]; then
        chown --reference="$path" "$tmp" && chmod --reference="$path" "$tmp"
    else
        chown root:root "$tmp" && chmod "$mode" "$tmp"
    fi
    if ! mv -f -- "$tmp" "$path"; then
        rm -f -- "$tmp"
        step fail "could not replace $path"
        return 1
    fi
    # Give the new file the right SELinux label (RHEL family).
    have restorecon && restorecon -- "$path" 2>/dev/null
    step ok "wrote $path"
}

# config_with_option FILE KEY VALUE SEP - FILE's content with every active
# (uncommented) KEY line replaced by "KEY<SEP>VALUE", or the line appended
# if there was none. Keys match case-insensitively.
config_with_option() {
    local file=$1 key=$2 value=$3 sep=$4 line out="" found=0
    if [[ -r $file ]]; then
        while IFS= read -r line || [[ -n $line ]]; do
            if [[ ${line,,} =~ ^[[:space:]]*${key,,}([[:space:]=]|$) ]]; then
                ((found)) || out+="$key$sep$value"$'\n'
                found=1
            else
                out+="$line"$'\n'
            fi
        done < "$file"
    fi
    ((found)) || out+="$key$sep$value"$'\n'
    printf '%s' "$out"
}

# current_option FILE KEY - the first active "KEY value" line, or "unset".
current_option() {
    local line
    if [[ -r $1 ]]; then
        while IFS= read -r line || [[ -n $line ]]; do
            if [[ ${line,,} =~ ^[[:space:]]*${2,,}([[:space:]=]|$) ]]; then
                trim "$line"
                return 0
            fi
        done < "$1"
    fi
    printf 'unset'
}

# act_set_option FILE KEY VALUE [SEP] [MODE] - set one option in a
# "key value" (or "key = value") style configuration file.
act_set_option() {
    local file=$1 key=$2 value=$3 sep=${4:- } mode=${5:-644} content
    if ((!APPLY)); then
        local shown
        shown=$(current_option "$file" "$key")
        step plan "set '$key${sep//$'\t'/ }$value' in $file (currently: ${shown//$'\t'/ })"
        return 0
    fi
    content=$(config_with_option "$file" "$key" "$value" "$sep")
    if [[ -e $file && "$content"$'\n' == "$(cat -- "$file")"$'\n' ]]; then
        step ok "$file already has '$key${sep//$'\t'/ }$value'"
        return 0
    fi
    act_write_file "$file" "$mode" "$content" >/dev/null || { step fail "could not update $file"; return 1; }
    step ok "set '$key${sep//$'\t'/ }$value' in $file"
}

package_installed() {
    case $OS_FAMILY in
        debian) [[ $(dpkg-query -W -f='${Status}' "$1" 2>/dev/null) == "install ok installed" ]] ;;
        rhel|suse) rpm -q --quiet "$1" 2>/dev/null ;;
        *) return 1 ;;
    esac
}

# act_pkg_install PACKAGE... - install the packages that are missing.
act_pkg_install() {
    local p missing=()
    for p in "$@"; do
        package_installed "$p" || missing+=("$p")
    done
    if ((${#missing[@]} == 0)); then
        step note "already installed: $*"
        return 0
    fi
    case $OS_FAMILY in
        debian)
            if ((!APT_UPDATED)); then
                act_run apt-get update || return 1
                ((APPLY)) && APT_UPDATED=1
            fi
            act_run env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
            ;;
        rhel) act_run dnf install -y "${missing[@]}" ;;
        suse) act_run zypper --non-interactive install "${missing[@]}" ;;
        *)
            step manual "install ${missing[*]} with your package manager"
            return "$RC_MANUAL"
            ;;
    esac
}

# act_service_enable UNIT - enable at boot and start now.
act_service_enable() {
    local unit=$1
    if has_systemd; then
        act_run systemctl enable --now "$unit"
    elif [[ -x /etc/init.d/$unit ]]; then
        if have update-rc.d; then act_run update-rc.d "$unit" enable || return 1; fi
        act_run service "$unit" start
    else
        step manual "start $unit with your init system (no systemd and no /etc/init.d/$unit)"
        return "$RC_MANUAL"
    fi
}

# act_service_disable UNIT - stop now and disable at boot.
act_service_disable() {
    local unit=$1 name=${1%.service}
    if has_systemd; then
        act_run systemctl disable --now "$unit"
    elif [[ -x /etc/init.d/$name ]]; then
        act_run service "$name" stop || return 1
        if have update-rc.d; then act_run update-rc.d "$name" disable; fi
    else
        step manual "stop $name with your init system (no systemd and no /etc/init.d/$name)"
        return "$RC_MANUAL"
    fi
}

# ---------------------------------------------------------------------------
# The harden command
# ---------------------------------------------------------------------------

# id_in_list ID "A,B,C"
id_in_list() { [[ ",${2^^}," == *",${1^^},"* ]]; }

# validate_id_list "A,B" - every ID must be a registered control.
validate_id_list() {
    local id ids
    IFS=, read -r -a ids < <(printf '%s\n' "$1")
    for id in "${ids[@]}"; do
        [[ -n ${CTL_SEV[${id^^}]+set} ]] || { echo "Unknown control ID: $id (see: harden-audit.sh list)" >&2; return 1; }
    done
}

# confirm - ask whether to apply the fix just shown. Returns 0 = yes,
# 1 = no, 2 = quit.
confirm() {
    local answer
    ((HARDEN_YES)) && return 0
    while true; do
        printf '  %sApply this fix?%s [y]es / [n]o / [a]ll remaining / [q]uit: ' "$C_BOLD" "$C_OFF"
        if ! read -r answer; then
            echo
            return 2
        fi
        case ${answer,,} in
            y|yes) return 0 ;;
            n|no|"") return 1 ;;
            a|all) HARDEN_YES=1; return 0 ;;
            q|quit) return 2 ;;
        esac
    done
}

log_outcome() { HARDEN_LOG+=("$1|$2|$3"); }

cmd_harden() {
    local id fn rc title plan candidates=() attempted=() fixed=0 failed=0 manual=0 declined=0
    declare -A before=()

    if ((!HARDEN_DRY_RUN)) && ! is_root; then
        echo "harden needs root. Preview the changes without root using: harden-audit.sh harden --dry-run" >&2
        return 2
    fi
    if ((!HARDEN_DRY_RUN && !HARDEN_YES)) && [[ ! -t 0 ]]; then
        echo "harden asks before every change, but stdin is not a terminal. Run it interactively, or pass --yes to apply every fix without asking." >&2
        return 2
    fi

    if ((HARDEN_DRY_RUN)); then
        print_header "Linux hardening - DRY RUN (nothing will be changed)"
    else
        print_header "Linux hardening"
        printf '\n%sWARNING:%s this changes system configuration. Test on a VM or snapshot first.\n' "$C_FAIL" "$C_OFF"
        printf 'Every changed file is backed up under %s first.\n' "$BACKUP_ROOT"
    fi

    SILENT=1 run_audit
    SCORE_BEFORE=$SCORE GRADE_BEFORE=$GRADE
    for id in "${R_IDS[@]}"; do
        before[$id]=${R_STATUS[$id]}
        [[ ${R_STATUS[$id]} == FAIL ]] || continue
        [[ -n $HARDEN_ONLY ]] && ! id_in_list "$id" "$HARDEN_ONLY" && continue
        [[ -n $HARDEN_SKIP ]] && id_in_list "$id" "$HARDEN_SKIP" && continue
        candidates+=("$id")
    done

    printf '\nCurrent score: %s. %d of %d controls fail' "$(score_text)" "$N_FAIL" $((N_PASS + N_FAIL + N_SKIP))
    if [[ -n $HARDEN_ONLY || -n $HARDEN_SKIP ]]; then
        printf ' (%d selected)' "${#candidates[@]}"
    fi
    printf '.\n'
    if ((${#candidates[@]} == 0)); then
        printf 'Nothing to fix.\n'
        save_report || return 2
        ((N_FAIL == 0))
        return
    fi

    for id in "${candidates[@]}"; do
        fn=${CTL_FIXFN[$id]}
        title=${CTL_TITLE[$id]}
        printf '\n%s%s%s %s (%s)\n' "$C_BOLD" "$id" "$C_OFF" "$title" "${CTL_SEV[$id]}"
        printf '%s\n' "${R_DETAIL[$id]}" | sed 's/^/  /'

        if [[ -z $fn ]] || ! declare -F "$fn" >/dev/null; then
            step manual "no automatic fix; suggested manual fix:"
            printf '%s\n' "${R_FIX[$id]}" | sed 's/^/              /'
            log_outcome "$id" manual "No automatic fix available."
            manual=$((manual + 1))
            continue
        fi

        # 1. Work out the plan. It is shown for a dry run and before asking;
        # with --yes only the actions themselves are printed. (Planning runs
        # in a subshell; with APPLY=0 the act_* helpers change nothing.)
        plan=$(APPLY=0 "$fn" "$id")
        rc=$?
        if ((HARDEN_DRY_RUN || !HARDEN_YES || rc == RC_MANUAL || rc == RC_REFUSED)); then
            printf '%s\n' "$plan"
        fi
        if ((rc == RC_MANUAL)); then
            log_outcome "$id" manual "Needs a manual fix (see the audit finding)."
            manual=$((manual + 1))
            continue
        elif ((rc == RC_REFUSED)); then
            log_outcome "$id" refused "Refused by a safety check; re-run with --force to override."
            manual=$((manual + 1))
            continue
        fi
        if ((HARDEN_DRY_RUN)); then
            log_outcome "$id" planned "Would be fixed (dry run)."
            continue
        fi

        # 2. Ask, then apply.
        confirm
        rc=$?
        if ((rc == 2)); then
            printf '  Stopping; no further changes.\n'
            log_outcome "$id" declined "Not applied (quit)."
            declined=$((declined + 1))
            break
        elif ((rc == 1)); then
            step skip "not applied"
            log_outcome "$id" declined "Not applied (declined)."
            declined=$((declined + 1))
            continue
        fi
        attempted+=("$id")
        APPLY=1 "$fn" "$id"
        rc=$?
        if ((rc == RC_OK)); then
            log_outcome "$id" applied "Fix applied."
            fixed=$((fixed + 1))
        else
            log_outcome "$id" failed "The fix did not complete; see ${HARDEN_LOGFILE:-the output above}."
            failed=$((failed + 1))
        fi
    done

    printf '\n%s== Result ==%s\n' "$C_BOLD" "$C_OFF"
    if ((HARDEN_DRY_RUN)); then
        printf 'Dry run: nothing was changed. %d fix(es) planned, %d need manual work.\n' \
            $((${#candidates[@]} - manual)) "$manual"
        printf 'Apply them with: sudo %s harden\n' "$0"
        save_report || return 2
        return 0
    fi

    SILENT=1 run_audit
    for id in "${attempted[@]}"; do
        printf '  %-7s %s -> %s\n' "$id" "${before[$id]}" "${R_STATUS[$id]}"
    done
    printf 'Applied %d, failed %d, declined %d, manual %d.\n' "$fixed" "$failed" "$declined" "$manual"
    printf 'Hardening score: %s/100 (grade %s) -> %s%s%s\n' "${SCORE_BEFORE:-n/a}" "$GRADE_BEFORE" \
        "$(score_color "${SCORE:-0}")" "$(score_text)" "$C_OFF"
    if [[ -n $BACKUP_DIR ]]; then
        printf 'Backups and command log: %s\n' "$BACKUP_DIR"
    fi
    REPORT_MODE=harden
    save_report || return 2
    ((N_FAIL == 0))
}
