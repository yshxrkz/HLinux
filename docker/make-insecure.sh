#!/usr/bin/env bash
#
# Turn a fresh Ubuntu container into a badly configured "server" so that
# harden-audit.sh has something to find and fix. Run once at image build time.
# Every weakness here is deliberate - never do this on a real machine.
set -euo pipefail

# SSH: root may log in with a password, passwords and empty passwords are
# allowed, many attempts per connection. (Ubuntu's default sshd_config already
# enables X11Forwarding.) A drop-in is how a real admin might have done it.
cat > /etc/ssh/sshd_config.d/50-insecure-demo.conf <<'CONF'
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
CONF
echo 'root:toor' | chpasswd

# An admin account in the sudo group with an SSH key - so hardening can
# safely switch SSH to keys only. The private key stays in the image for the
# tests (/root/demo-admin-key); it is generated per build and is worthless
# outside this container.
useradd --create-home --shell /bin/bash --groups sudo admin
echo 'admin:Demo-Passw0rd!' | chpasswd
ssh-keygen -q -t ed25519 -N '' -C 'harden-audit demo admin' -f /root/demo-admin-key
install -d -m 700 -o admin -g admin /home/admin/.ssh
install -m 600 -o admin -g admin /root/demo-admin-key.pub /home/admin/.ssh/authorized_keys

# A service account nobody set a password for.
useradd --create-home --shell /bin/bash deploy
passwd -d deploy >/dev/null

# Cleartext FTP. Listen on IPv4 only: containers usually have no IPv6, and
# vsftpd's default (listen_ipv6=YES) then fails to start.
sed -i 's/^listen=NO/listen=YES/; s/^listen_ipv6=YES/listen_ipv6=NO/' /etc/vsftpd.conf

# Password hashes readable by every user.
chmod 644 /etc/shadow /etc/gshadow

# Nothing else to do: login.defs keeps Ubuntu's PASS_MAX_DAYS 99999, ufw is
# installed but inactive, vsftpd (cleartext FTP) is started by the entry
# point, and unattended-upgrades, auditd and libpam-pwquality are not
# installed at all.
