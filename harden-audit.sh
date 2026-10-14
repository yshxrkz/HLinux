#!/usr/bin/env bash
#
# harden-audit.sh - read-only Linux hardening audit, loosely based on CIS benchmarks.
#
# Checks SSH root login, password authentication settings, the host firewall,
# unnecessary network services, permissions on account files and automatic
# security updates. Every check prints PASS, FAIL or SKIP with an explanation,
# and every FAIL includes a suggested fix.
#
# READ-ONLY GUARANTEE: this script never changes the system. It only reads
# files and runs inspection commands (stat, sshd -T, systemctl is-active,
# ufw status, nft list ruleset, apt-config dump, ...). It writes nothing to
# disk - it even avoids bash here-strings/here-docs, which can create temp
# files - and it never runs package managers, service managers in a mutating
# mode, or anything that could load kernel modules.
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

QUIET=0
USE_COLOR=1
N_PASS=0
N_FAIL=0
N_SKIP=0

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

if [[ ! -t 1 || -n ${NO_COLOR:-} || ${TERM:-dumb} == dumb ]]; then
    USE_COLOR=0
fi
if ((USE_COLOR)); then
    C_PASS=$'\e[32m' C_FAIL=$'\e[31m' C_SKIP=$'\e[33m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_OFF=$'\e[0m'
else
    C_PASS='' C_FAIL='' C_SKIP='' C_BOLD='' C_DIM='' C_OFF=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# 1. SSH server configuration
# ---------------------------------------------------------------------------

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
    local rc where reload val pa kbd pam overrides reasons=()
    load_sshd_config
    rc=$?
    if ((rc == 1)); then
        report PASS SSH-1 "SSH root login is disabled" "No OpenSSH server is installed, so remote SSH logins are not possible."
        report PASS SSH-2 "SSH password authentication is disabled" "No OpenSSH server is installed."
        report PASS SSH-3 "SSH does not allow empty passwords" "No OpenSSH server is installed."
        return
    elif ((rc == 2)); then
        local msg
        msg="Cannot read $SSHD_CONFIG as $(id -un)."
        report SKIP SSH-1 "SSH root login is disabled" "$msg" "Re-run this audit as root (sudo)."
        report SKIP SSH-2 "SSH password authentication is disabled" "$msg" "Re-run this audit as root (sudo)."
        report SKIP SSH-3 "SSH does not allow empty passwords" "$msg" "Re-run this audit as root (sudo)."
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
}

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

# ---------------------------------------------------------------------------
# 3. Host firewall
# ---------------------------------------------------------------------------

check_firewall() {
    section "3. Firewall"
    local found=() notes=() out cmd

    # ufw (Debian/Ubuntu). 'ufw status' is deliberately NOT used: it writes a
    # lock file (/run/ufw.lock). The persistent ENABLED flag is read instead,
    # and the live rules are confirmed by the nftables/iptables checks below.
    if have ufw; then
        if [[ -r /etc/ufw/ufw.conf ]] && grep -Eq '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes' /etc/ufw/ufw.conf; then
            if has_systemd && ! systemctl is-active --quiet ufw 2>/dev/null; then
                notes+=("ufw is enabled in /etc/ufw/ufw.conf but the ufw service is not active")
            else
                found+=("ufw is enabled (ENABLED=yes in /etc/ufw/ufw.conf)")
            fi
        else
            notes+=("ufw is installed but not enabled")
        fi
    fi

    # firewalld (RHEL/Fedora/SUSE)
    if have firewall-cmd || [[ -e /usr/lib/systemd/system/firewalld.service ]]; then
        if has_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
            found+=("firewalld is running")
        else
            notes+=("firewalld is installed but not running")
        fi
    fi

    # Raw nftables rules. Only queried when the nf_tables module is already
    # loaded, so the audit can never trigger a kernel module load.
    if is_root && have nft && [[ -d /sys/module/nf_tables ]]; then
        if out=$(nft list ruleset 2>/dev/null) && [[ $out == *"hook input"* ]]; then
            # Heuristic: an input hook plus a drop policy or any drop/reject rule.
            if [[ $out == *"policy drop"* || $out == *" drop"* || $out == *" reject"* ]]; then
                found+=("nftables has an input chain that drops/rejects traffic")
            else
                notes+=("nftables has an input chain, but it accepts everything")
            fi
        fi
    fi

    # Legacy iptables rules, again only if the module is already loaded.
    if is_root && [[ -r /proc/net/ip_tables_names ]] && grep -qx filter /proc/net/ip_tables_names; then
        cmd=iptables
        have iptables-legacy && cmd=iptables-legacy
        if have "$cmd" && out=$("$cmd" -S INPUT 2>/dev/null); then
            if [[ $out == *"-P INPUT DROP"* || $out == *"-j DROP"* || $out == *"-j REJECT"* ]]; then
                found+=("iptables INPUT chain drops/rejects traffic")
            fi
        fi
    fi

    local fix
    case $OS_FAMILY in
        debian) fix="sudo ufw allow OpenSSH && sudo ufw default deny incoming && sudo ufw enable
(install first with 'sudo apt install ufw' if needed; allow SSH BEFORE enabling or you may lock yourself out)" ;;
        rhel|suse) fix="sudo systemctl enable --now firewalld && sudo firewall-cmd --list-all
(install first with 'sudo dnf install firewalld' / 'sudo zypper install firewalld' if needed)" ;;
        *) fix="Enable a host firewall (ufw, firewalld or an nftables ruleset) that denies incoming traffic by default
and only allows the services you need (e.g. SSH)." ;;
    esac

    if ((${#found[@]})); then
        report PASS FW-1 "A host firewall is active" "$(join '; ' "${found[@]}")."
    elif ! is_root; then
        report SKIP FW-1 "A host firewall is active" \
            "No ufw/firewalld firewall detected, but nftables/iptables rules can only be inspected as root.${notes[0]:+ Notes: $(join '; ' "${notes[@]}").}" \
            "Re-run this audit as root (sudo)."
    else
        local detail="No active firewall found (checked ufw, firewalld, nftables and iptables)."
        ((${#notes[@]})) && detail+=" Notes: $(join '; ' "${notes[@]}")."
        report FAIL FW-1 "A host firewall is active" "$detail Every listening service is reachable from the network." "$fix"
    fi
}

# ---------------------------------------------------------------------------
# 4. Unnecessary / insecure services
# ---------------------------------------------------------------------------

# Format: "description|systemd units|process names (fallback without systemd)"
readonly SERVICES=(
    "Telnet server (cleartext logins)|telnet.socket telnetd.service inetutils-telnetd.service|telnetd in.telnetd"
    "rsh/rlogin/rexec (cleartext r-services)|rsh.socket rlogin.socket rexec.socket|in.rshd in.rlogind in.rexecd"
    "TFTP server (no authentication)|tftp.socket tftp.service tftpd-hpa.service|in.tftpd tftpd"
    "FTP server (cleartext passwords)|vsftpd.service proftpd.service pure-ftpd.service|vsftpd proftpd pure-ftpd"
    "inetd/xinetd super-server|xinetd.service inetd.service openbsd-inetd.service inetutils-inetd.service|xinetd inetd"
    "talk server|talk.socket ntalk.socket|in.talkd in.ntalkd"
    "NIS (ypserv/ypbind)|ypserv.service ypbind.service|ypserv ypbind"
    "Avahi mDNS/zeroconf daemon|avahi-daemon.service avahi-daemon.socket|avahi-daemon"
    "CUPS print server|cups.service cups.socket|cupsd"
    "RPC portmapper (rpcbind)|rpcbind.service rpcbind.socket|rpcbind"
    "NFS server|nfs-server.service nfs-kernel-server.service|nfsd"
    "Samba file sharing|smb.service smbd.service nmb.service nmbd.service|smbd nmbd"
    "SNMP daemon|snmpd.service|snmpd"
    "LDAP server (slapd)|slapd.service|slapd"
    "DHCP server|isc-dhcp-server.service dhcpd.service kea-dhcp4-server.service|dhcpd kea-dhcp4"
    "DNS server (BIND)|named.service bind9.service|named"
    "IMAP/POP3 server (Dovecot)|dovecot.service|dovecot"
    "HTTP proxy (Squid)|squid.service|squid"
    "rsync daemon|rsync.service rsyncd.service|"
)

check_services() {
    section "4. Unnecessary services"
    local active_units="" running_procs="" entry desc units procs u p hits=() fixes=() method
    if has_systemd; then
        method="active systemd units"
        active_units=" $(systemctl list-units --type=service,socket --state=active --plain --no-legend --no-pager 2>/dev/null \
                          | awk '{ printf "%s ", $1 }') "
    else
        method="running processes, as systemd is not in use"
        running_procs=" $(cat /proc/[0-9]*/comm 2>/dev/null | sort -u | tr '\n' ' ') "
    fi

    for entry in "${SERVICES[@]}"; do
        desc=${entry%%|*}
        units=${entry#*|}; units=${units%%|*}
        procs=${entry##*|}
        if [[ -n $active_units ]]; then
            for u in $units; do
                if [[ $active_units == *" $u "* ]]; then
                    hits+=("$desc [$u]")
                    fixes+=("$u")
                fi
            done
        else
            for p in $procs; do
                if [[ $running_procs == *" $p "* ]]; then
                    hits+=("$desc [process $p]")
                    break
                fi
            done
        fi
    done

    if ((${#hits[@]} == 0)); then
        report PASS SVC-1 "No unnecessary or insecure services are running" \
            "None of ${#SERVICES[@]} commonly unneeded services (telnet, FTP, TFTP, rsh, NIS, Avahi, CUPS, rpcbind, Samba, SNMP, ...) are active (checked $method)."
    else
        local detail fix
        detail="Active services that are insecure or rarely needed on a server (checked $method):"
        detail+=$(printf '\n  - %s' "${hits[@]}")
        detail+=$'\n'"Each one is extra attack surface; disable the ones you do not need."
        if ((${#fixes[@]})); then
            fix="For each service you do not need: sudo systemctl disable --now <unit>  (e.g. sudo systemctl disable --now ${fixes[0]})
Better still, uninstall the package that provides it. Keep a service only if this host is meant to provide it."
        else
            fix="Stop the listed daemons and remove the packages that provide them (or disable them in your init system)."
        fi
        report FAIL SVC-1 "No unnecessary or insecure services are running" "$detail" "$fix"
    fi
}

# ---------------------------------------------------------------------------
# 5. Permissions on account files
# ---------------------------------------------------------------------------

# check_file_perms ID PATH MAX_MODE OWNER ALLOWED_GROUPS FIX_GROUP FIX_MODE WHY
check_file_perms() {
    local id=$1 path=$2 max=$3 owner=$4 groups=$5 fix_group=$6 fix_mode=$7 why=$8
    local title="$path permissions are $max or stricter, owned by $owner:${groups// //}"
    local st mode f_owner f_group problems=()
    if [[ ! -e $path ]]; then
        report SKIP "$id" "$title" "$path does not exist on this system." ""
        return
    fi
    st=$(stat -Lc '%a %U %G' "$path" 2>/dev/null) || {
        report SKIP "$id" "$title" "Could not stat $path." "Re-run this audit as root (sudo)."
        return
    }
    read -r mode f_owner f_group < <(printf '%s\n' "$st")
    if (( (8#$mode) & ~(8#$max) )); then
        problems+=("mode is $mode, which grants more than $max")
    fi
    [[ $f_owner == "$owner" ]] || problems+=("owner is '$f_owner', expected '$owner'")
    [[ " $groups " == *" $f_group "* ]] || problems+=("group is '$f_group', expected '${groups// /\' or \'}'")
    if ((${#problems[@]} == 0)); then
        report PASS "$id" "$title" "$path is mode $mode, owned by $f_owner:$f_group."
    else
        report FAIL "$id" "$title" "$(join '; ' "${problems[@]}"). $why" \
            "sudo chown $owner:$fix_group $path && sudo chmod $fix_mode $path"
    fi
}

check_file_permissions() {
    section "5. Account file permissions"
    # Debian-style systems use group "shadow" (0640); RHEL-style use root (0000).
    local shadow_group=root shadow_mode=0000
    if getent group shadow >/dev/null 2>&1; then
        shadow_group=shadow shadow_mode=0640
    fi
    check_file_perms FILE-1 /etc/passwd  644 root "root"        root          0644 \
        "Only root should be able to modify the list of accounts."
    check_file_perms FILE-2 /etc/shadow  640 root "root shadow" "$shadow_group" "$shadow_mode" \
        "/etc/shadow contains password hashes; if other users can read it they can crack them offline."
    check_file_perms FILE-3 /etc/group   644 root "root"        root          0644 \
        "Only root should be able to modify group membership (e.g. add someone to sudo/wheel)."
    check_file_perms FILE-4 /etc/gshadow 640 root "root shadow" "$shadow_group" "$shadow_mode" \
        "/etc/gshadow contains group password hashes and administrator lists."
}

# ---------------------------------------------------------------------------
# 6. Automatic security updates
# ---------------------------------------------------------------------------

apt_periodic() {
    apt-config dump 2>/dev/null | sed -n "s/^APT::Periodic::$1 \"\(.*\)\";\$/\1/p" | tail -n 1
}

check_updates_debian() {
    local problems=() installed upd ua timer
    installed=$(dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null)
    [[ $installed == "install ok installed" ]] || problems+=("the unattended-upgrades package is not installed")
    if have apt-config; then
        upd=$(apt_periodic Update-Package-Lists)
        ua=$(apt_periodic Unattended-Upgrade)
        [[ -n $upd && $upd != 0 ]] || problems+=("APT::Periodic::Update-Package-Lists is '${upd:-unset}'")
        [[ -n $ua && $ua != 0 ]]   || problems+=("APT::Periodic::Unattended-Upgrade is '${ua:-unset}'")
    fi
    if has_systemd; then
        timer=$(systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null)
        [[ $timer == enabled || $timer == static ]] || problems+=("apt-daily-upgrade.timer is '${timer:-not found}'")
    fi
    if ((${#problems[@]} == 0)); then
        report PASS UPD-1 "Automatic security updates are enabled" \
            "unattended-upgrades is installed; APT::Periodic::Update-Package-Lists=$upd, Unattended-Upgrade=$ua."
    else
        report FAIL UPD-1 "Automatic security updates are enabled" \
            "$(join $'\n' "${problems[@]}")" \
"sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
(this writes /etc/apt/apt.conf.d/20auto-upgrades with Update-Package-Lists \"1\" and Unattended-Upgrade \"1\")"
    fi
}

check_updates_rhel() {
    local timer t state conf apply="" detail
    if has_systemd; then
        for t in dnf-automatic-install.timer dnf-automatic.timer dnf5-automatic.timer yum-cron.service; do
            state=$(systemctl is-enabled "$t" 2>/dev/null)
            if [[ $state == enabled ]]; then
                timer=$t
                break
            fi
        done
    fi
    if [[ -z ${timer:-} ]]; then
        report FAIL UPD-1 "Automatic security updates are enabled" \
            "No automatic update timer is enabled (looked for dnf-automatic, dnf-automatic-install and yum-cron)." \
"sudo dnf install dnf-automatic
Set 'apply_updates = yes' (and optionally 'upgrade_type = security') in /etc/dnf/automatic.conf
sudo systemctl enable --now dnf-automatic.timer"
        return
    fi
    if [[ $timer == dnf-automatic-install.timer ]]; then
        report PASS UPD-1 "Automatic security updates are enabled" "$timer is enabled (downloads AND installs updates)."
        return
    fi
    for conf in /etc/dnf/dnf5-plugins/automatic.conf /etc/dnf/automatic.conf /etc/yum/yum-cron.conf; do
        if [[ -r $conf ]] && grep -Eiq '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*(yes|true|1)[[:space:]]*$' "$conf"; then
            apply=$conf
            break
        fi
    done
    if [[ -n $apply ]]; then
        report PASS UPD-1 "Automatic security updates are enabled" "$timer is enabled and apply_updates = yes in $apply."
    else
        detail="$timer is enabled, but apply_updates is not 'yes', so updates are only downloaded/announced, never installed."
        report FAIL UPD-1 "Automatic security updates are enabled" "$detail" \
            "Set 'apply_updates = yes' in the [commands] section of /etc/dnf/automatic.conf (or /etc/yum/yum-cron.conf on EL7)."
    fi
}

check_updates() {
    section "6. Automatic updates"
    case $OS_FAMILY in
        debian) check_updates_debian ;;
        rhel)   check_updates_rhel ;;
        *)
            report SKIP UPD-1 "Automatic security updates are enabled" \
                "Automatic update detection is not implemented for '$OS_NAME'." \
                "Check manually: SUSE uses 'zypper patch' via a systemd timer or yast2-online-update-configuration; Arch has no supported unattended mechanism - update regularly with 'pacman -Syu'."
            ;;
    esac
}

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
