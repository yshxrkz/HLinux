# shellcheck shell=bash
#
# services.sh - unnecessary/insecure services control (SVC-*).
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.

# ---------------------------------------------------------------------------
# 4. Unnecessary / insecure services
# ---------------------------------------------------------------------------

register_control SVC-1 medium Services fix_services \
    "No unnecessary or insecure services are running" \
    "Every listening daemon is attack surface. Legacy protocols such as telnet, FTP and rsh also send credentials in cleartext, and services like Avahi or CUPS are rarely needed on a server."

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

# Units the last audit found running, for the fix: systemd units, or (without
# systemd) the SysV init scripts that belong to the processes found.
SVC_TO_DISABLE=()

check_services() {
    section "4. Unnecessary services"
    local active_units="" running_procs="" entry desc units procs u p hits=() fixes=() method
    SVC_TO_DISABLE=()
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
                    SVC_TO_DISABLE+=("$u")
                fi
            done
        else
            for p in $procs; do
                if [[ $running_procs == *" $p "* ]]; then
                    hits+=("$desc [process $p]")
                    for u in $units; do
                        if [[ -x /etc/init.d/${u%.*} ]]; then
                            SVC_TO_DISABLE+=("${u%.*}")
                            break
                        fi
                    done
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

# fix_services - stop and disable what the audit found. There is no way to
# know whether this host is *meant* to run, say, a DNS server, so the plan
# says so; decline the fix (or use --skip SVC-1) to keep them.
fix_services() {
    local unit
    if ((${#SVC_TO_DISABLE[@]} == 0)); then
        step manual "no service unit or init script found for the processes listed; stop them and remove their packages by hand"
        return "$RC_MANUAL"
    fi
    act_note "keep any service this host is supposed to provide: answer 'n' (or use --skip SVC-1) and remove the rest by hand"
    for unit in "${SVC_TO_DISABLE[@]}"; do
        act_service_disable "$unit" || return
    done
}
