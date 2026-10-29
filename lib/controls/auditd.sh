# shellcheck shell=bash
#
# auditd.sh - Linux audit daemon controls (AUD-*).
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.

register_control AUD-1 medium Auditing fix_auditd_service \
    "auditd is installed and running" \
    "auditd records security-relevant kernel events - logins, privilege changes, edits to key files - in a log that ordinary users cannot alter. Without it, incident response has very little to go on."
register_control AUD-2 medium Auditing fix_audit_rules \
    "Audit rules watch account, sudo and SSH configuration files" \
    "auditd with no rules records almost nothing. Watching the account databases, sudoers and sshd_config shows who changed them and when - the first questions after a suspected compromise."

# Files that must be watched for writes/attribute changes (-w PATH -p wa).
# Optional files are only required when they exist on this host.
readonly AUDIT_REQUIRED_WATCHES=(/etc/passwd /etc/shadow /etc/group /etc/gshadow)
readonly AUDIT_OPTIONAL_WATCHES=(/etc/sudoers /etc/sudoers.d /etc/ssh/sshd_config)

auditd_installed() { have auditd || [[ -x /sbin/auditd ]]; }

auditd_running() {
    if has_systemd; then
        systemctl is-active --quiet auditd 2>/dev/null
    else
        grep -qx auditd /proc/[0-9]*/comm 2>/dev/null
    fi
}

audit_package_name() {
    case $OS_FAMILY in
        rhel|suse) echo audit ;;
        *)         echo auditd ;;
    esac
}

check_auditd() {
    section "7. Auditing (auditd)"
    local pkg enabled=""
    pkg=$(audit_package_name)

    # AUD-1: auditd installed, running (and enabled at boot under systemd)
    if ! auditd_installed; then
        report FAIL AUD-1 "${CTL_TITLE[AUD-1]}" \
            "The audit daemon is not installed, so no security events are being recorded." \
            "$(pkg_install_hint "$pkg")"$'\n'"$(service_enable_hint auditd)"
    elif ! auditd_running; then
        report FAIL AUD-1 "${CTL_TITLE[AUD-1]}" \
            "auditd is installed but not running, so no security events are being recorded." \
            "$(service_enable_hint auditd)"
    elif has_systemd && enabled=$(systemctl is-enabled auditd 2>/dev/null) && [[ $enabled != enabled && $enabled != static ]]; then
        report FAIL AUD-1 "${CTL_TITLE[AUD-1]}" \
            "auditd is running now, but is '$enabled' at boot, so it will not come back after a reboot." \
            "sudo systemctl enable auditd"
    else
        report PASS AUD-1 "${CTL_TITLE[AUD-1]}" "auditd is installed and running."
    fi

    # AUD-2: watch rules for the account databases, sudoers and sshd_config.
    # Prefer the rules loaded in the kernel; fall back to the rules files.
    local rules="" source="" detail f path missing=() wanted=("${AUDIT_REQUIRED_WATCHES[@]}")
    for path in "${AUDIT_OPTIONAL_WATCHES[@]}"; do
        [[ -e $path ]] && wanted+=("$path")
    done
    if is_root && have auditctl && auditd_running && rules=$(auditctl -l 2>/dev/null); then
        source="rules loaded in the kernel (auditctl -l)"
    else
        shopt -s nullglob
        for f in /etc/audit/rules.d/*.rules /etc/audit/audit.rules; do
            [[ -r $f ]] && rules+=$(cat "$f")$'\n'
        done
        shopt -u nullglob
        source="rules files in /etc/audit/rules.d"
    fi
    for path in "${wanted[@]}"; do
        # A watch looks like: -w /etc/passwd -p wa -k identity
        [[ $rules =~ (^|$'\n')[[:space:]]*-w[[:space:]]+"$path"[[:space:]] ]] || missing+=("$path")
    done
    if ((${#missing[@]} == 0)); then
        report PASS AUD-2 "${CTL_TITLE[AUD-2]}" "All of $(join ', ' "${wanted[@]}") are watched ($source)."
    else
        detail="Not watched ($source): $(join ', ' "${missing[@]}")."
        auditd_installed || detail+=" auditd is not installed (see AUD-1)."
        report FAIL AUD-2 "${CTL_TITLE[AUD-2]}" "$detail" \
"Create /etc/audit/rules.d/50-hardening.rules with one line per file, e.g.
  -w /etc/passwd -p wa -k identity
  -w /etc/sudoers -p wa -k scope
Then load the rules: sudo augenrules --load"
    fi
}
