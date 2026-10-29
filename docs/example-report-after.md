# Linux hardening report: web01

| | |
|---|---|
| **Host** | web01 |
| **OS** | Ubuntu 24.04.5 LTS (kernel 6.18.44-fc-v185) |
| **Date** | 2026-10-29 23:15:43 UTC |
| **Run as** | root |
| **Tool** | harden-audit.sh 2.0.0 (harden mode) |

## Hardening score: 100/100 (grade A)

`[####################]` 100/100

Before hardening: **13/100 (grade F)** → after: **100/100 (grade A)**

**16 passed**, **0 failed**, **1 skipped** out of 17 controls. The score weights each control by severity (high = 3, medium = 2, low = 1) and leaves skipped controls out.

## Hardening actions

| Control | Outcome | Note |
|---|---|---|
| SSH-1 | applied | Fix applied. |
| SSH-2 | applied | Fix applied. |
| SSH-3 | applied | Fix applied. |
| SSH-4 | applied | Fix applied. |
| SSH-5 | applied | Fix applied. |
| AUTH-1 | applied | Fix applied. |
| AUTH-2 | applied | Fix applied. |
| AUTH-3 | applied | Fix applied. |
| FW-1 | applied | Fix applied. |
| SVC-1 | applied | Fix applied. |
| FILE-2 | applied | Fix applied. |
| FILE-4 | applied | Fix applied. |
| UPD-1 | applied | Fix applied. |
| AUD-2 | applied | Fix applied. |

## Results by category

| Category | Passed | Failed | Skipped |
|---|---:|---:|---:|
| SSH | 5 | 0 | 0 |
| Password policy | 3 | 0 | 0 |
| Firewall | 1 | 0 | 0 |
| Services | 1 | 0 | 0 |
| File permissions | 4 | 0 | 0 |
| Updates | 1 | 0 | 0 |
| Auditing | 1 | 0 | 1 |

## All controls

| Status | ID | Severity | Control |
|---|---|---|---|
| ✅ PASS | SSH-1 | high | SSH root login is disabled |
| ✅ PASS | SSH-2 | high | SSH password authentication is disabled |
| ✅ PASS | SSH-3 | high | SSH does not allow empty passwords |
| ✅ PASS | SSH-4 | medium | SSH limits authentication attempts (MaxAuthTries <= 4) |
| ✅ PASS | SSH-5 | low | SSH X11 forwarding is disabled |
| ✅ PASS | AUTH-1 | medium | Password ageing policy is set |
| ✅ PASS | AUTH-2 | high | No accounts have empty or unshadowed passwords |
| ✅ PASS | AUTH-3 | medium | Password quality is enforced (pam_pwquality, minlen >= 14) |
| ✅ PASS | FW-1 | high | A host firewall is active |
| ✅ PASS | SVC-1 | medium | No unnecessary or insecure services are running |
| ✅ PASS | FILE-1 | high | /etc/passwd permissions are 644 or stricter, owned by root:root |
| ✅ PASS | FILE-2 | high | /etc/shadow permissions are 640 or stricter, owned by root:root/shadow |
| ✅ PASS | FILE-3 | medium | /etc/group permissions are 644 or stricter, owned by root:root |
| ✅ PASS | FILE-4 | medium | /etc/gshadow permissions are 640 or stricter, owned by root:root/shadow |
| ✅ PASS | UPD-1 | high | Automatic security updates are enabled |
| ⚪ SKIP | AUD-1 | medium | auditd is installed and running |
| ✅ PASS | AUD-2 | medium | Audit rules watch account, sudo and SSH configuration files |

## Skipped

- **AUD-1** auditd is installed and running: This is a container. auditd needs the host kernel's audit subsystem and cannot run inside a container; the host should run it.

## Passed

- ✅ **SSH-1** SSH root login is disabled: PermitRootLogin is 'no' (effective config from 'sshd -T').
- ✅ **SSH-2** SSH password authentication is disabled: PasswordAuthentication is 'no', KbdInteractiveAuthentication is 'no' (effective config from 'sshd -T'). Only key-based logins are accepted.
- ✅ **SSH-3** SSH does not allow empty passwords: PermitEmptyPasswords is 'no' (effective config from 'sshd -T').
- ✅ **SSH-4** SSH limits authentication attempts (MaxAuthTries <= 4): MaxAuthTries is 4 (effective config from 'sshd -T').
- ✅ **SSH-5** SSH X11 forwarding is disabled: X11Forwarding is 'no' (effective config from 'sshd -T').
- ✅ **AUTH-1** Password ageing policy is set: /etc/login.defs: PASS_MAX_DAYS=365, PASS_MIN_DAYS=1, PASS_WARN_AGE=7.
- ✅ **AUTH-2** No accounts have empty or unshadowed passwords: Every account uses /etc/shadow and none has an empty password field.
- ✅ **AUTH-3** Password quality is enforced (pam_pwquality, minlen >= 14): pam_pwquality is enabled in /etc/pam.d/common-password with minlen = 14 (from /etc/security/pwquality.conf.d/50-hardening.conf).
- ✅ **FW-1** A host firewall is active: ufw is enabled (ENABLED=yes in /etc/ufw/ufw.conf).
- ✅ **SVC-1** No unnecessary or insecure services are running: None of 19 commonly unneeded services (telnet, FTP, TFTP, rsh, NIS, Avahi, CUPS, rpcbind, Samba, SNMP, ...) are active (checked running processes, as systemd is not in use).
- ✅ **FILE-1** /etc/passwd permissions are 644 or stricter, owned by root:root: /etc/passwd is mode 644, owned by root:root.
- ✅ **FILE-2** /etc/shadow permissions are 640 or stricter, owned by root:root/shadow: /etc/shadow is mode 640, owned by root:shadow.
- ✅ **FILE-3** /etc/group permissions are 644 or stricter, owned by root:root: /etc/group is mode 644, owned by root:root.
- ✅ **FILE-4** /etc/gshadow permissions are 640 or stricter, owned by root:root/shadow: /etc/gshadow is mode 640, owned by root:shadow.
- ✅ **UPD-1** Automatic security updates are enabled: unattended-upgrades is installed; APT::Periodic::Update-Package-Lists=1, Unattended-Upgrade=1.
- ✅ **AUD-2** Audit rules watch account, sudo and SSH configuration files: All of /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow, /etc/sudoers, /etc/sudoers.d, /etc/ssh/sshd_config are watched (rules files in /etc/audit/rules.d).

---

*Generated by harden-audit.sh 2.0.0. Controls are loosely based on the CIS Benchmarks; this is not a full CIS assessment.*
