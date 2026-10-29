# shellcheck shell=bash
#
# firewall.sh - host firewall control (FW-*).
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.

# ---------------------------------------------------------------------------
# 3. Host firewall
# ---------------------------------------------------------------------------

register_control FW-1 high Firewall fix_firewall \
    "A host firewall is active" \
    "A default-deny firewall means a service that is installed or misconfigured later is not automatically reachable from the network. It is a second line of defence behind 'only run what you need'."

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
