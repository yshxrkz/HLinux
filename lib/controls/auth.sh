# shellcheck shell=bash
#
# auth.sh - local password policy controls (AUTH-*).
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.

# ---------------------------------------------------------------------------
# 2. Local password policy
# ---------------------------------------------------------------------------

login_defs_value() {
    local key=$1 line
    [[ -r /etc/login.defs ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line =~ ^[[:space:]]*${key}[[:space:]]+([^[:space:]]+) ]]; then
            printf '%s' "${BASH_REMATCH[1]}"
            return 0
        fi
    done < /etc/login.defs
}

check_password_policy() {
    section "2. Password policy"
    local max min warn problems=()

    # AUTH-1: password ageing defaults (CIS: max <= 365, min >= 1, warn >= 7)
    if [[ ! -r /etc/login.defs ]]; then
        report SKIP AUTH-1 "Password ageing policy is set" "/etc/login.defs is missing or unreadable." \
            "Check your distribution's documentation for where password ageing defaults are configured."
    else
        max=$(login_defs_value PASS_MAX_DAYS)
        min=$(login_defs_value PASS_MIN_DAYS)
        warn=$(login_defs_value PASS_WARN_AGE)
        [[ $max =~ ^[0-9]+$ ]] && ((max <= 365)) || problems+=("PASS_MAX_DAYS is '${max:-unset}' (should be 365 or less)")
        [[ $min =~ ^[0-9]+$ ]] && ((min >= 1))   || problems+=("PASS_MIN_DAYS is '${min:-unset}' (should be 1 or more)")
        [[ $warn =~ ^[0-9]+$ ]] && ((warn >= 7)) || problems+=("PASS_WARN_AGE is '${warn:-unset}' (should be 7 or more)")
        if ((${#problems[@]} == 0)); then
            report PASS AUTH-1 "Password ageing policy is set" \
                "/etc/login.defs: PASS_MAX_DAYS=$max, PASS_MIN_DAYS=$min, PASS_WARN_AGE=$warn."
        else
            local detail fix
            detail=$(printf '%s\n' "${problems[@]}")
            fix="Edit /etc/login.defs and set: PASS_MAX_DAYS 365, PASS_MIN_DAYS 1, PASS_WARN_AGE 7.
This only affects NEW accounts. For existing ones run, per user: sudo chage --maxdays 365 --mindays 1 --warndays 7 <user>"
            report FAIL AUTH-1 "Password ageing policy is set" "$detail" "$fix"
        fi
    fi

    # AUTH-2: no account may have an empty or non-shadowed password
    local unshadowed empty="" file_note=""
    # In /etc/passwd the field should be "x" (see /etc/shadow). An empty field
    # means no password at all; anything else that is not a lock marker
    # ("*", "!") is a password hash readable by every user.
    empty=$(awk -F: 'NF > 1 && $2 == "" { printf "%s ", $1 }' /etc/passwd 2>/dev/null)
    unshadowed=$(awk -F: '$2 != "" && $2 != "x" && $2 !~ /^[*!]/ { printf "%s ", $1 }' /etc/passwd 2>/dev/null)
    if [[ -r /etc/shadow ]]; then
        empty+=$(awk -F: 'NF > 1 && $2 == "" { printf "%s ", $1 }' /etc/shadow 2>/dev/null)
    else
        file_note=" (/etc/shadow not readable as $(id -un); only /etc/passwd was checked)"
    fi
    unshadowed=$(trim "$unshadowed")
    empty=$(trim "$(printf '%s' "$empty" | tr -s ' ' '\n' | sort -u | tr '\n' ' ')")
    if [[ -n $empty || -n $unshadowed ]]; then
        local detail="" fix=""
        [[ -n $empty ]] && detail+="Accounts with an EMPTY password: $empty. Anyone can log in as them without a password."$'\n'
        [[ -n $unshadowed ]] && detail+="Accounts whose password is stored in world-readable /etc/passwd instead of /etc/shadow: $unshadowed."$'\n'
        detail=${detail%$'\n'}
        [[ -n $empty ]] && fix+="Lock each empty account (sudo passwd -l <user>) or set a password (sudo passwd <user>)."$'\n'
        [[ -n $unshadowed ]] && fix+="Move passwords into /etc/shadow with: sudo pwconv"$'\n'
        report FAIL AUTH-2 "No accounts have empty or unshadowed passwords" "$detail" "${fix%$'\n'}"
    elif [[ -n $file_note ]]; then
        report SKIP AUTH-2 "No accounts have empty or unshadowed passwords" \
            "All /etc/passwd entries use shadowed passwords$file_note." "Re-run this audit as root (sudo) to check /etc/shadow too."
    else
        report PASS AUTH-2 "No accounts have empty or unshadowed passwords" \
            "Every account uses /etc/shadow and none has an empty password field."
    fi
}
