# shellcheck shell=bash
#
# updates.sh - automatic security update control (UPD-*).
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.

# ---------------------------------------------------------------------------
# 6. Automatic security updates
# ---------------------------------------------------------------------------

register_control UPD-1 high Updates fix_auto_updates \
    "Automatic security updates are enabled" \
    "Most real-world compromises exploit vulnerabilities that already have a patch. Unattended security updates close that window within a day instead of whenever someone remembers to log in."

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
