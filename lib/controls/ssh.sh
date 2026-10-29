# shellcheck shell=bash
#
# ssh.sh - SSH server controls (SSH-*).
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.

# ---------------------------------------------------------------------------
# 1. SSH server configuration
# ---------------------------------------------------------------------------

register_control SSH-1 high SSH fix_ssh_root_login \
    "SSH root login is disabled" \
    "Root is the one account every attacker knows exists, and it has unlimited power. Making admins log in as themselves and use sudo leaves an audit trail of who did what, and a leaked root key or password is no longer enough on its own."
register_control SSH-2 high SSH fix_ssh_password_auth \
    "SSH password authentication is disabled" \
    "Internet-facing SSH servers see constant password-guessing attacks. Key-based logins cannot realistically be brute-forced and are not affected by password reuse from other breaches."
register_control SSH-3 high SSH fix_ssh_empty_passwords \
    "SSH does not allow empty passwords" \
    "With PermitEmptyPasswords enabled, any account without a password is a remote shell for anyone who guesses the user name."
register_control SSH-4 medium SSH fix_ssh_max_auth_tries \
    "SSH limits authentication attempts (MaxAuthTries <= 4)" \
    "MaxAuthTries caps how many passwords or keys a client may try per connection. A low limit slows brute-force attacks and makes them stand out in the logs."
register_control SSH-5 low SSH fix_ssh_x11_forwarding \
    "SSH X11 forwarding is disabled" \
    "X11 forwarding lets the server reach back into the admin's graphical desktop. A compromised server could then log keystrokes or take screenshots on the admin's machine. Servers almost never need it."

declare -A SSHD=()
SSHD_SOURCE=""

# Parse an sshd_config file the way sshd does for the global section:
# keywords are case-insensitive, the FIRST value seen wins, Include files are
# read in place, and a Match block ends the global section of that file.
parse_sshd_file() {
    local file=$1 depth=$2 line key val pattern inc
    ((depth > 8)) && return 0
    [[ -r $file ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%%#*}
        [[ $line =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*[=[:space:]][[:space:]]*(.*)$ ]] || continue
        key=${BASH_REMATCH[1],,}
        val=$(trim "${BASH_REMATCH[2]}")
        val=${val#\"}
        val=${val%\"}
        case $key in
            match)
                break
                ;;
            include)
                for pattern in $val; do
                    [[ $pattern == /* ]] || pattern="/etc/ssh/$pattern"
                    for inc in $pattern; do
                        [[ -f $inc ]] && parse_sshd_file "$inc" $((depth + 1))
                    done
                done
                ;;
            *)
                [[ -z ${SSHD[$key]+set} ]] && SSHD[$key]=${val,,}
                ;;
        esac
    done < "$file"
}

# Returns 0 = config loaded, 1 = no SSH server installed, 2 = config unreadable.
load_sshd_config() {
    local out line
    if ! have sshd && [[ ! -e $SSHD_CONFIG ]]; then
        return 1
    fi
    # Prefer the effective configuration as computed by sshd itself.
    if is_root && have sshd && out=$(sshd -T 2>/dev/null) && [[ -n $out ]]; then
        while IFS= read -r line; do
            [[ $line =~ ^([^[:space:]]+)[[:space:]]+(.*)$ ]] || continue
            SSHD[${BASH_REMATCH[1],,}]=${BASH_REMATCH[2],,}
        done < <(printf '%s\n' "$out")
        SSHD_SOURCE="effective config from 'sshd -T'"
        return 0
    fi
    if [[ -r $SSHD_CONFIG ]]; then
        shopt -s nullglob
        parse_sshd_file "$SSHD_CONFIG" 0
        shopt -u nullglob
        SSHD_SOURCE="parsed $SSHD_CONFIG and its Include files; unset options use OpenSSH defaults"
        return 0
    fi
    return 2
}

# Where a sysadmin should put an override so that it actually wins.
ssh_fix_location() {
    if [[ -r $SSHD_CONFIG ]] && grep -Eiq '^[[:space:]]*Include[[:space:]=].*sshd_config\.d' "$SSHD_CONFIG"; then
        echo "/etc/ssh/sshd_config.d/00-hardening.conf (drop-ins are read first, and sshd uses the FIRST value it finds)"
    else
        echo "$SSHD_CONFIG, above any Match blocks (sshd uses the FIRST value it finds)"
    fi
}

ssh_reload_cmd() {
    local unit=sshd
    [[ $OS_FAMILY == debian ]] && unit=ssh
    echo "sudo sshd -t && sudo systemctl reload $unit"
}

# ssh_match_overrides KEY SAFE_VALUE
# Prints one line per Match block that sets KEY to something other than
# SAFE_VALUE. The global checks below cannot see these: e.g.
# "Match Address 10.0.0.0/8 / PermitRootLogin yes" re-enables root logins.
ssh_match_overrides() {
    local key=$1 safe=$2 f files=()
    shopt -s nullglob
    for f in "$SSHD_CONFIG" /etc/ssh/sshd_config.d/*.conf; do
        [[ -r $f ]] && files+=("$f")
    done
    shopt -u nullglob
    ((${#files[@]})) || return 0
    awk -v key="$key" -v safe="$safe" '
        FNR == 1 { hdr = "" }
        {
            line = $0
            sub(/#.*/, "", line)
            sub(/^[ \t]+/, "", line)
            sub(/[ \t]+$/, "", line)
            if (split(line, w, /[ \t=]+/) < 2) next
            gsub(/"/, "", w[2])
        }
        tolower(w[1]) == "match" { hdr = line; next }
        hdr != "" && tolower(w[1]) == key && tolower(w[2]) != safe {
            printf "%s: \"%s\" sets %s %s\n", FILENAME, hdr, w[1], w[2]
        }
    ' "${files[@]}" 2>/dev/null
}

check_ssh() {
    section "1. SSH server"
    local rc id where reload val pa kbd pam overrides reasons=()
    load_sshd_config
    rc=$?
    if ((rc == 1)); then
        for id in SSH-1 SSH-2 SSH-3 SSH-4 SSH-5; do
            report PASS "$id" "${CTL_TITLE[$id]}" "No OpenSSH server is installed, so remote SSH logins are not possible."
        done
        return
    elif ((rc == 2)); then
        local msg
        msg="Cannot read $SSHD_CONFIG as $(id -un)."
        for id in SSH-1 SSH-2 SSH-3 SSH-4 SSH-5; do
            report SKIP "$id" "${CTL_TITLE[$id]}" "$msg" "Re-run this audit as root (sudo)."
        done
        return
    fi
    where=$(ssh_fix_location)
    reload=$(ssh_reload_cmd)

    # SSH-1: PermitRootLogin (CIS: "Ensure sshd PermitRootLogin is disabled")
    val=${SSHD[permitrootlogin]:-prohibit-password}
    overrides=$(ssh_match_overrides permitrootlogin no)
    if [[ $val == no && -z $overrides ]]; then
        report PASS SSH-1 "SSH root login is disabled" "PermitRootLogin is '$val' ($SSHD_SOURCE)."
    elif [[ $val == no ]]; then
        report FAIL SSH-1 "SSH root login is disabled" \
            "PermitRootLogin is 'no' globally, but a Match block re-enables it for some connections:"$'\n'"$overrides" \
            "Remove the PermitRootLogin line from those Match blocks (or set it to 'no'). Then: $reload"
    else
        local why="PermitRootLogin is '$val' ($SSHD_SOURCE)."
        case $val in
            prohibit-password|without-password) why+=" Root can still log in with an SSH key." ;;
            forced-commands-only)               why+=" Root can still log in with a key that has a forced command." ;;
            yes)                                why+=" Root can log in directly, including with a password." ;;
        esac
        report FAIL SSH-1 "SSH root login is disabled" "$why" \
"Add 'PermitRootLogin no' to $where.
Log in as a normal user and use sudo instead. Then: $reload"
    fi

    # SSH-2: password-based logins (PasswordAuthentication, and keyboard-interactive via PAM)
    pa=${SSHD[passwordauthentication]:-yes}
    kbd=${SSHD[kbdinteractiveauthentication]:-${SSHD[challengeresponseauthentication]:-yes}}
    pam=${SSHD[usepam]:-no}
    [[ $pa == yes ]] && reasons+=("PasswordAuthentication is 'yes'")
    [[ $kbd == yes && $pam == yes ]] && reasons+=("KbdInteractiveAuthentication is 'yes' with UsePAM 'yes', which also allows password prompts")
    overrides=$(ssh_match_overrides passwordauthentication no)
    if ((${#reasons[@]} == 0)) && [[ -z $overrides ]]; then
        report PASS SSH-2 "SSH password authentication is disabled" \
            "PasswordAuthentication is '$pa', KbdInteractiveAuthentication is '$kbd' ($SSHD_SOURCE). Only key-based logins are accepted."
    else
        local detail
        if ((${#reasons[@]})); then
            detail="$(join '; ' "${reasons[@]}") ($SSHD_SOURCE)."
        else
            detail="PasswordAuthentication is 'no' globally ($SSHD_SOURCE)."
        fi
        [[ -n $overrides ]] && detail+=$'\n'"A Match block re-enables passwords for some connections:"$'\n'"$overrides"
        detail+=$'\n'"Passwords can be brute-forced; SSH keys cannot realistically be guessed."
        local fix="First make sure every admin can log in with an SSH key (ssh-copy-id user@host)!"
        ((${#reasons[@]})) && fix+=$'\n'"Then add 'PasswordAuthentication no' and 'KbdInteractiveAuthentication no' to $where."
        [[ -n $overrides ]] && fix+=$'\n'"Remove 'PasswordAuthentication yes' from the Match blocks listed above."
        fix+=$'\n'"Then: $reload"
        report FAIL SSH-2 "SSH password authentication is disabled" "$detail" "$fix"
    fi

    # SSH-3: PermitEmptyPasswords (CIS: "Ensure sshd PermitEmptyPasswords is disabled")
    val=${SSHD[permitemptypasswords]:-no}
    if [[ $val == no ]]; then
        report PASS SSH-3 "SSH does not allow empty passwords" "PermitEmptyPasswords is '$val' ($SSHD_SOURCE)."
    else
        report FAIL SSH-3 "SSH does not allow empty passwords" \
            "PermitEmptyPasswords is '$val' ($SSHD_SOURCE). Accounts without a password can log in remotely." \
            "Add 'PermitEmptyPasswords no' to $where. Then: $reload"
    fi

    # SSH-4: MaxAuthTries (CIS: "Ensure sshd MaxAuthTries is set to 4 or less")
    val=${SSHD[maxauthtries]:-6}
    if [[ $val =~ ^[0-9]+$ ]] && ((val <= 4)); then
        report PASS SSH-4 "${CTL_TITLE[SSH-4]}" "MaxAuthTries is $val ($SSHD_SOURCE)."
    else
        report FAIL SSH-4 "${CTL_TITLE[SSH-4]}" \
            "MaxAuthTries is '$val' ($SSHD_SOURCE). Each connection may try that many passwords or keys before being dropped." \
            "Add 'MaxAuthTries 4' to $where. Then: $reload"
    fi

    # SSH-5: X11Forwarding (CIS: "Ensure sshd X11Forwarding is disabled")
    val=${SSHD[x11forwarding]:-no}
    overrides=$(ssh_match_overrides x11forwarding no)
    if [[ $val == no && -z $overrides ]]; then
        report PASS SSH-5 "${CTL_TITLE[SSH-5]}" "X11Forwarding is '$val' ($SSHD_SOURCE)."
    elif [[ $val == no ]]; then
        report FAIL SSH-5 "${CTL_TITLE[SSH-5]}" \
            "X11Forwarding is 'no' globally, but a Match block enables it for some connections:"$'\n'"$overrides" \
            "Remove 'X11Forwarding yes' from those Match blocks. Then: $reload"
    else
        local note=""
        [[ $OS_FAMILY == debian ]] && note=" Debian and Ubuntu enable it in their default sshd_config."
        report FAIL SSH-5 "${CTL_TITLE[SSH-5]}" \
            "X11Forwarding is '$val' ($SSHD_SOURCE).$note" \
            "Add 'X11Forwarding no' to $where. Then: $reload"
    fi
}
