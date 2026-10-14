# HLinux

Linux hardening audit script.

`harden-audit.sh` checks a Linux host against a small hardening checklist,
loosely based on the CIS Benchmarks. Each check prints **PASS** or **FAIL**
with an explanation, and every FAIL comes with a suggested fix.

The script is **strictly read-only**: it only inspects. It never changes the
system. All fixes are printed for you to review and apply yourself.

## Quick start

```bash
sudo ./harden-audit.sh            # full audit
sudo ./harden-audit.sh --quiet    # only show FAIL/SKIP results and the summary
./harden-audit.sh                 # works without root too, but some checks are SKIPPED
```

| Option            | Meaning                                                     |
|-------------------|-------------------------------------------------------------|
| `-q`, `--quiet`   | Print only FAIL and SKIP results (plus the summary)         |
| `--no-color`      | Disable coloured output (`NO_COLOR=1` also works)           |
| `-h`, `--help`    | Show help                                                   |
| `-V`, `--version` | Show version                                                |

**Exit status:** `0` = no check failed, `1` = at least one check failed,
`2` = invalid option. You can use it in cron jobs, CI or configuration
management, e.g. `sudo ./harden-audit.sh --quiet || alert-admins`.

**Requirements:** bash 4+, coreutils, awk, grep, sed. Optional tools are used
when present: `sshd`, `systemctl`, `nft`, `iptables`, `ufw`, `apt-config`,
`dpkg-query`.

## What is checked

| ID     | Check | Passes when | CIS topic |
|--------|-------|-------------|-----------|
| SSH-1  | SSH root login disabled | `PermitRootLogin no`, and no `Match` block turns it back on | SSH server configuration |
| SSH-2  | SSH password authentication disabled | `PasswordAuthentication no`, keyboard-interactive is not a password backdoor via PAM, and no `Match` block re-enables passwords | SSH server configuration |
| SSH-3  | SSH does not allow empty passwords | `PermitEmptyPasswords no` | SSH server configuration |
| AUTH-1 | Password ageing policy | `/etc/login.defs`: `PASS_MAX_DAYS` ≤ 365, `PASS_MIN_DAYS` ≥ 1, `PASS_WARN_AGE` ≥ 7 | Shadow password suite parameters |
| AUTH-2 | No empty or unshadowed passwords | No empty password field in `/etc/passwd` or `/etc/shadow`, and no hashes in `/etc/passwd` | Local user and group settings |
| FW-1   | Host firewall active | ufw enabled, firewalld running, or an nftables/iptables input chain that drops/rejects traffic | Host based firewall |
| SVC-1  | No unnecessary services running | None of 19 legacy or rarely needed services is active: telnet, rsh/rlogin/rexec, TFTP, FTP, (x)inetd, talk, NIS, Avahi, CUPS, rpcbind, NFS, Samba, SNMP, LDAP, DHCP, DNS, Dovecot, Squid, rsyncd | Special purpose services |
| FILE-1 | `/etc/passwd` permissions | mode 644 or stricter, `root:root` | System file permissions |
| FILE-2 | `/etc/shadow` permissions | mode 640 or stricter, `root:root` or `root:shadow` | System file permissions |
| FILE-3 | `/etc/group` permissions | mode 644 or stricter, `root:root` | System file permissions |
| FILE-4 | `/etc/gshadow` permissions | mode 640 or stricter, `root:root` or `root:shadow` | System file permissions |
| UPD-1  | Automatic security updates | **Debian/Ubuntu:** `unattended-upgrades` installed, `APT::Periodic::Update-Package-Lists` and `Unattended-Upgrade` enabled, and `apt-daily-upgrade.timer` enabled. **RHEL/Fedora/Rocky/Alma:** `dnf-automatic-install.timer` enabled, or `dnf-automatic`/`yum-cron` enabled with `apply_updates = yes` | Software updates |

Each result is one of:

- **PASS**: the setting matches the checklist.
- **FAIL**: it does not. The `Detail:` line says what was found and why it
  matters, and the `Fix:` line gives commands to fix it.
- **SKIP**: the check could not be evaluated. This usually means the script is
  not running as root, or the distribution is not supported for that check.
  SKIPs do not change the exit status.

The fix commands match your distribution family. For example, they suggest
`ufw` on Debian/Ubuntu and `firewalld` on RHEL-likes, `systemctl reload ssh`
or `sshd`, and `root:shadow 0640` or `root:root 0000` for `/etc/shadow`.

### How the SSH checks work

As root, the script asks `sshd -T` for sshd's **effective** configuration,
with all `Include` files and defaults applied. If that's not possible (when
running as non-root, or when sshd refuses to start its config test), it falls
back to its own parser. The parser mimics sshd: keywords are case-insensitive,
`Include` globs are expanded in place, and the **first** value it finds wins.
Options left unset take OpenSSH's defaults. For example, an unset
`PermitRootLogin` means `prohibit-password`, which is a FAIL.

The script also scans `Match` blocks separately. A block such as
`Match Address 10.0.0.0/8` followed by `PermitRootLogin yes` makes SSH-1 fail
even when the global setting is `no`.

## Read-only guarantee

The script is written so that it cannot modify the host:

- It only reads files (`stat`, `awk`, `grep`) and runs inspection commands:
  `sshd -T`, `systemctl is-active`/`is-enabled`/`list-units`,
  `nft list ruleset`, `iptables -S`, `apt-config dump`, `dpkg-query -W`.
- It writes **no files at all**, not even temp files. Bash here-strings
  (`<<<`) and here-docs can create temp files, so the audit code doesn't use
  them.
- It does **not** call `ufw status`, because that command writes
  `/run/ufw.lock`. It reads `/etc/ufw/ufw.conf` instead.
- It only queries netfilter (`nft`, `iptables`) when the matching kernel
  module is already loaded, so the audit can never load a kernel module.
- It never runs package managers or `systemctl start/stop/enable`, and it
  never uses `sudo` itself.
- It reads `/etc/shadow` only to look for **empty** password fields. It never
  prints password hashes.

The test suite verifies this: it runs the audit under `strace` and fails on
any open-for-write or other mutating syscall (see [Testing](#testing)).

## Sample output

This is real output, captured on an Ubuntu 24.04 test machine with some
deliberate problems. The machine runs without systemd, so the service check
falls back to looking at running processes. With systemd, it reports unit
names (e.g. `cups.service`), and the fix suggests
`sudo systemctl disable --now <unit>`.

```text
$ sudo ./harden-audit.sh
Linux hardening audit (harden-audit.sh 1.0.0, read-only)
Host:   web01
OS:     Ubuntu 24.04.5 LTS (kernel 6.18.44-fc-v114)
Date:   2026-10-14 02:58:51 UTC
User:   root

== 1. SSH server ==
[FAIL] SSH-1   SSH root login is disabled
        Detail: PermitRootLogin is 'without-password' (effective config from 'sshd -T'). Root can still log in with an SSH key.
        Fix:    Add 'PermitRootLogin no' to /etc/ssh/sshd_config.d/00-hardening.conf (drop-ins are read first, and sshd uses the FIRST value it finds).
                Log in as a normal user and use sudo instead. Then: sudo sshd -t && sudo systemctl reload ssh
[FAIL] SSH-2   SSH password authentication is disabled
        Detail: PasswordAuthentication is 'yes' (effective config from 'sshd -T').
                Passwords can be brute-forced; SSH keys cannot realistically be guessed.
        Fix:    First make sure every admin can log in with an SSH key (ssh-copy-id user@host)!
                Then add 'PasswordAuthentication no' and 'KbdInteractiveAuthentication no' to /etc/ssh/sshd_config.d/00-hardening.conf (drop-ins are read first, and sshd uses the FIRST value it finds).
                Then: sudo sshd -t && sudo systemctl reload ssh
[PASS] SSH-3   SSH does not allow empty passwords
        Detail: PermitEmptyPasswords is 'no' (effective config from 'sshd -T').

== 2. Password policy ==
[FAIL] AUTH-1  Password ageing policy is set
        Detail: PASS_MAX_DAYS is '99999' (should be 365 or less)
                PASS_MIN_DAYS is '0' (should be 1 or more)
        Fix:    Edit /etc/login.defs and set: PASS_MAX_DAYS 365, PASS_MIN_DAYS 1, PASS_WARN_AGE 7.
                This only affects NEW accounts. For existing ones run, per user: sudo chage --maxdays 365 --mindays 1 --warndays 7 <user>
[FAIL] AUTH-2  No accounts have empty or unshadowed passwords
        Detail: Accounts with an EMPTY password: deploy. Anyone can log in as them without a password.
        Fix:    Lock each empty account (sudo passwd -l <user>) or set a password (sudo passwd <user>).

== 3. Firewall ==
[FAIL] FW-1    A host firewall is active
        Detail: No active firewall found (checked ufw, firewalld, nftables and iptables). Notes: ufw is installed but not enabled. Every listening service is reachable from the network.
        Fix:    sudo ufw allow OpenSSH && sudo ufw default deny incoming && sudo ufw enable
                (install first with 'sudo apt install ufw' if needed; allow SSH BEFORE enabling or you may lock yourself out)

== 4. Unnecessary services ==
[FAIL] SVC-1   No unnecessary or insecure services are running
        Detail: Active services that are insecure or rarely needed on a server (checked running processes, as systemd is not in use):
                  - Avahi mDNS/zeroconf daemon [process avahi-daemon]
                  - CUPS print server [process cupsd]
                Each one is extra attack surface; disable the ones you do not need.
        Fix:    Stop the listed daemons and remove the packages that provide them (or disable them in your init system).

== 5. Account file permissions ==
[PASS] FILE-1  /etc/passwd permissions are 644 or stricter, owned by root:root
        Detail: /etc/passwd is mode 644, owned by root:root.
[FAIL] FILE-2  /etc/shadow permissions are 640 or stricter, owned by root:root/shadow
        Detail: mode is 644, which grants more than 640. /etc/shadow contains password hashes; if other users can read it they can crack them offline.
        Fix:    sudo chown root:shadow /etc/shadow && sudo chmod 0640 /etc/shadow
[PASS] FILE-3  /etc/group permissions are 644 or stricter, owned by root:root
        Detail: /etc/group is mode 644, owned by root:root.
[PASS] FILE-4  /etc/gshadow permissions are 640 or stricter, owned by root:root/shadow
        Detail: /etc/gshadow is mode 640, owned by root:shadow.

== 6. Automatic updates ==
[PASS] UPD-1   Automatic security updates are enabled
        Detail: unattended-upgrades is installed; APT::Periodic::Update-Package-Lists=1, Unattended-Upgrade=1.

== Summary ==
5 passed, 7 failed, 0 skipped (12 checks)
$ echo $?
1
```

The same host after the fixes, in quiet mode:

```text
$ sudo ./harden-audit.sh --quiet
Linux hardening audit (harden-audit.sh 1.0.0, read-only)
Host:   web02
OS:     Ubuntu 24.04.5 LTS (kernel 6.18.44-fc-v114)
Date:   2026-10-14 02:59:04 UTC
User:   root

== Summary ==
12 passed, 0 failed, 0 skipped (12 checks)
$ echo $?
0
```

When it is run without root, checks that need privileged access are marked
SKIP instead of guessing:

```text
[SKIP] AUTH-2  No accounts have empty or unshadowed passwords
        Detail: All /etc/passwd entries use shadowed passwords (/etc/shadow not readable as nobody; only /etc/passwd was checked).
        Fix:    Re-run this audit as root (sudo) to check /etc/shadow too.
```

## Testing

```bash
sudo tests/run-tests.sh
```

The tests run the audit against good and bad scenarios: insecure SSH config,
`Match` overrides, empty passwords, a world-readable shadow file, a
world-writable group file, auto-updates turned off, a fake `vsftpd` process,
a non-root user, and the CLI options. They also check the read-only guarantee
with `strace`.

The tests never touch the real system files. Each scenario runs inside a
private mount namespace (`unshare -m`), where fixture files from a temp
directory are bind-mounted over paths like `/etc/shadow`. The bind mounts
disappear when the scenario ends. You need root, `unshare`, and optionally
`strace`. The script is also clean under `shellcheck`.

## Limitations

- This is a **basic** checklist covering a few high-value controls. It is not
  a full CIS assessment. For a complete audit, use a dedicated tool such as
  OpenSCAP, CIS-CAT or Lynis.
- Firewall detection is heuristic. It confirms that a firewall is active and
  drops some traffic, not that the rules make sense. Review them with
  `sudo ufw status verbose`, `sudo firewall-cmd --list-all` or
  `sudo nft list ruleset`.
- The "unnecessary services" list includes services that some hosts are
  *meant* to run, such as a DNS or NFS server. A FAIL there means "confirm
  this host should provide it", not "always remove it".
- Automatic update detection supports the Debian and RHEL families. It
  reports SKIP on other distributions (SUSE, Arch, ...).
- Password ageing (AUTH-1) follows the classic CIS recommendation. Some
  current guidance, such as NIST SP 800-63B, advises against forced
  periodic password changes. Adjust to your organisation's policy.
- Always test SSH changes from a second session before logging out, and allow
  SSH in the firewall *before* enabling it. Otherwise you can lock yourself
  out.
