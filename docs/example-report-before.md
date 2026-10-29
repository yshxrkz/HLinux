# Linux hardening report: web01

| | |
|---|---|
| **Host** | web01 |
| **OS** | Ubuntu 24.04.5 LTS (kernel 6.18.44-fc-v185) |
| **Date** | 2026-10-29 23:15:23 UTC |
| **Run as** | root |
| **Tool** | harden-audit.sh 2.0.0 (audit mode) |

## Hardening score: 13/100 (grade F)

`[##------------------]` 13/100

**2 passed**, **14 failed**, **1 skipped** out of 17 controls. The score weights each control by severity (high = 3, medium = 2, low = 1) and leaves skipped controls out.

## Results by category

| Category | Passed | Failed | Skipped |
|---|---:|---:|---:|
| SSH | 0 | 5 | 0 |
| Password policy | 0 | 3 | 0 |
| Firewall | 0 | 1 | 0 |
| Services | 0 | 1 | 0 |
| File permissions | 2 | 2 | 0 |
| Updates | 0 | 1 | 0 |
| Auditing | 0 | 1 | 1 |

## All controls

| Status | ID | Severity | Control |
|---|---|---|---|
| ❌ FAIL | SSH-1 | high | SSH root login is disabled |
| ❌ FAIL | SSH-2 | high | SSH password authentication is disabled |
| ❌ FAIL | SSH-3 | high | SSH does not allow empty passwords |
| ❌ FAIL | SSH-4 | medium | SSH limits authentication attempts (MaxAuthTries <= 4) |
| ❌ FAIL | SSH-5 | low | SSH X11 forwarding is disabled |
| ❌ FAIL | AUTH-1 | medium | Password ageing policy is set |
| ❌ FAIL | AUTH-2 | high | No accounts have empty or unshadowed passwords |
| ❌ FAIL | AUTH-3 | medium | Password quality is enforced (pam_pwquality, minlen >= 14) |
| ❌ FAIL | FW-1 | high | A host firewall is active |
| ❌ FAIL | SVC-1 | medium | No unnecessary or insecure services are running |
| ✅ PASS | FILE-1 | high | /etc/passwd permissions are 644 or stricter, owned by root:root |
| ❌ FAIL | FILE-2 | high | /etc/shadow permissions are 640 or stricter, owned by root:root/shadow |
| ✅ PASS | FILE-3 | medium | /etc/group permissions are 644 or stricter, owned by root:root |
| ❌ FAIL | FILE-4 | medium | /etc/gshadow permissions are 640 or stricter, owned by root:root/shadow |
| ❌ FAIL | UPD-1 | high | Automatic security updates are enabled |
| ⚪ SKIP | AUD-1 | medium | auditd is installed and running |
| ❌ FAIL | AUD-2 | medium | Audit rules watch account, sudo and SSH configuration files |

## Findings

### ❌ SSH-1: SSH root login is disabled

*Severity: high · Category: SSH*

**What was found**

```text
PermitRootLogin is 'yes' (effective config from 'sshd -T'). Root can log in directly, including with a password.
```

**Why it matters:** Root is the one account every attacker knows exists, and it has unlimited power. Making admins log in as themselves and use sudo leaves an audit trail of who did what, and a leaked root key or password is no longer enough on its own.

**How to fix**

```text
Add 'PermitRootLogin no' to /etc/ssh/sshd_config.d/00-hardening.conf (drop-ins are read first, and sshd uses the FIRST value it finds).
Log in as a normal user and use sudo instead. Then: sudo sshd -t && sudo systemctl reload ssh
```

### ❌ SSH-2: SSH password authentication is disabled

*Severity: high · Category: SSH*

**What was found**

```text
PasswordAuthentication is 'yes' (effective config from 'sshd -T').
Passwords can be brute-forced; SSH keys cannot realistically be guessed.
```

**Why it matters:** Internet-facing SSH servers see constant password-guessing attacks. Key-based logins cannot realistically be brute-forced and are not affected by password reuse from other breaches.

**How to fix**

```text
First make sure every admin can log in with an SSH key (ssh-copy-id user@host)!
Then add 'PasswordAuthentication no' and 'KbdInteractiveAuthentication no' to /etc/ssh/sshd_config.d/00-hardening.conf (drop-ins are read first, and sshd uses the FIRST value it finds).
Then: sudo sshd -t && sudo systemctl reload ssh
```

### ❌ SSH-3: SSH does not allow empty passwords

*Severity: high · Category: SSH*

**What was found**

```text
PermitEmptyPasswords is 'yes' (effective config from 'sshd -T'). Accounts without a password can log in remotely.
```

**Why it matters:** With PermitEmptyPasswords enabled, any account without a password is a remote shell for anyone who guesses the user name.

**How to fix**

```text
Add 'PermitEmptyPasswords no' to /etc/ssh/sshd_config.d/00-hardening.conf (drop-ins are read first, and sshd uses the FIRST value it finds). Then: sudo sshd -t && sudo systemctl reload ssh
```

### ❌ SSH-4: SSH limits authentication attempts (MaxAuthTries <= 4)

*Severity: medium · Category: SSH*

**What was found**

```text
MaxAuthTries is '10' (effective config from 'sshd -T'). Each connection may try that many passwords or keys before being dropped.
```

**Why it matters:** MaxAuthTries caps how many passwords or keys a client may try per connection. A low limit slows brute-force attacks and makes them stand out in the logs.

**How to fix**

```text
Add 'MaxAuthTries 4' to /etc/ssh/sshd_config.d/00-hardening.conf (drop-ins are read first, and sshd uses the FIRST value it finds). Then: sudo sshd -t && sudo systemctl reload ssh
```

### ❌ SSH-5: SSH X11 forwarding is disabled

*Severity: low · Category: SSH*

**What was found**

```text
X11Forwarding is 'yes' (effective config from 'sshd -T'). Debian and Ubuntu enable it in their default sshd_config.
```

**Why it matters:** X11 forwarding lets the server reach back into the admin's graphical desktop. A compromised server could then log keystrokes or take screenshots on the admin's machine. Servers almost never need it.

**How to fix**

```text
Add 'X11Forwarding no' to /etc/ssh/sshd_config.d/00-hardening.conf (drop-ins are read first, and sshd uses the FIRST value it finds). Then: sudo sshd -t && sudo systemctl reload ssh
```

### ❌ AUTH-1: Password ageing policy is set

*Severity: medium · Category: Password policy*

**What was found**

```text
PASS_MAX_DAYS is '99999' (should be 365 or less)
PASS_MIN_DAYS is '0' (should be 1 or more)
```

**Why it matters:** A maximum age limits how long a stolen password stays useful; a minimum age stops users from cycling straight back to their old password; a warning period avoids surprise lockouts.

**How to fix**

```text
Edit /etc/login.defs and set: PASS_MAX_DAYS 365, PASS_MIN_DAYS 1, PASS_WARN_AGE 7.
This only affects NEW accounts. For existing ones run, per user: sudo chage --maxdays 365 --mindays 1 --warndays 7 <user>
```

### ❌ AUTH-2: No accounts have empty or unshadowed passwords

*Severity: high · Category: Password policy*

**What was found**

```text
Accounts with an EMPTY password: deploy. Anyone can log in as them without a password.
```

**Why it matters:** An account with an empty password can be used by anyone with console or local access. A password hash left in world-readable /etc/passwd can be copied by any user and cracked offline.

**How to fix**

```text
Lock each empty account (sudo passwd -l <user>) or set a password (sudo passwd <user>).
```

### ❌ AUTH-3: Password quality is enforced (pam_pwquality, minlen >= 14)

*Severity: medium · Category: Password policy*

**What was found**

```text
pam_pwquality is not enabled in the PAM password stack (looked in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth), so only pam_unix's basic length check applies.
```

**Why it matters:** Short passwords fall quickly to offline cracking. pam_pwquality rejects weak passwords at the moment they are set, which is the only point where the plaintext is available to check.

**How to fix**

```text
sudo apt install libpam-pwquality   (it adds pam_pwquality to /etc/pam.d/common-password)
Then set 'minlen = 14' in /etc/security/pwquality.conf.d/50-hardening.conf.
```

### ❌ FW-1: A host firewall is active

*Severity: high · Category: Firewall*

**What was found**

```text
No active firewall found (checked ufw, firewalld, nftables and iptables). Notes: ufw is installed but not enabled. Every listening service is reachable from the network.
```

**Why it matters:** A default-deny firewall means a service that is installed or misconfigured later is not automatically reachable from the network. It is a second line of defence behind 'only run what you need'.

**How to fix**

```text
sudo ufw allow OpenSSH && sudo ufw default deny incoming && sudo ufw enable
(install first with 'sudo apt install ufw' if needed; allow SSH BEFORE enabling or you may lock yourself out)
```

### ❌ SVC-1: No unnecessary or insecure services are running

*Severity: medium · Category: Services*

**What was found**

```text
Active services that are insecure or rarely needed on a server (checked running processes, as systemd is not in use):
  - FTP server (cleartext passwords) [process vsftpd]
Each one is extra attack surface; disable the ones you do not need.
```

**Why it matters:** Every listening daemon is attack surface. Legacy protocols such as telnet, FTP and rsh also send credentials in cleartext, and services like Avahi or CUPS are rarely needed on a server.

**How to fix**

```text
Stop the listed daemons and remove the packages that provide them (or disable them in your init system).
```

### ❌ FILE-2: /etc/shadow permissions are 640 or stricter, owned by root:root/shadow

*Severity: high · Category: File permissions*

**What was found**

```text
mode is 644, which grants more than 640. /etc/shadow contains password hashes; if other users can read it they can crack them offline.
```

**Why it matters:** /etc/shadow holds every password hash. If ordinary users can read it, they can crack the hashes offline at their leisure.

**How to fix**

```text
sudo chown root:shadow /etc/shadow && sudo chmod 0640 /etc/shadow
```

### ❌ FILE-4: /etc/gshadow permissions are 640 or stricter, owned by root:root/shadow

*Severity: medium · Category: File permissions*

**What was found**

```text
mode is 644, which grants more than 640. /etc/gshadow contains group password hashes and administrator lists.
```

**Why it matters:** /etc/gshadow holds group password hashes and group administrator lists; it should be as protected as /etc/shadow.

**How to fix**

```text
sudo chown root:shadow /etc/gshadow && sudo chmod 0640 /etc/gshadow
```

### ❌ UPD-1: Automatic security updates are enabled

*Severity: high · Category: Updates*

**What was found**

```text
the unattended-upgrades package is not installed
APT::Periodic::Update-Package-Lists is 'unset'
APT::Periodic::Unattended-Upgrade is 'unset'
```

**Why it matters:** Most real-world compromises exploit vulnerabilities that already have a patch. Unattended security updates close that window within a day instead of whenever someone remembers to log in.

**How to fix**

```text
sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
(this writes /etc/apt/apt.conf.d/20auto-upgrades with Update-Package-Lists "1" and Unattended-Upgrade "1")
```

### ❌ AUD-2: Audit rules watch account, sudo and SSH configuration files

*Severity: medium · Category: Auditing*

**What was found**

```text
Not watched (rules files in /etc/audit/rules.d): /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow, /etc/sudoers, /etc/sudoers.d, /etc/ssh/sshd_config. auditd is not installed (see AUD-1).
```

**Why it matters:** auditd with no rules records almost nothing. Watching the account databases, sudoers and sshd_config shows who changed them and when - the first questions after a suspected compromise.

**How to fix**

```text
Create /etc/audit/rules.d/50-hardening.rules with one line per file, e.g.
  -w /etc/passwd -p wa -k identity
  -w /etc/sudoers -p wa -k scope
Then load the rules: sudo augenrules --load
```

## Skipped

- **AUD-1** auditd is installed and running: This is a container. auditd needs the host kernel's audit subsystem and cannot run inside a container; the host should run it.

## Passed

- ✅ **FILE-1** /etc/passwd permissions are 644 or stricter, owned by root:root: /etc/passwd is mode 644, owned by root:root.
- ✅ **FILE-3** /etc/group permissions are 644 or stricter, owned by root:root: /etc/group is mode 644, owned by root:root.

---

*Generated by harden-audit.sh 2.0.0. Controls are loosely based on the CIS Benchmarks; this is not a full CIS assessment.*
