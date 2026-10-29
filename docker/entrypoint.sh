#!/usr/bin/env bash
#
# Entry point of the demo container: start the services a typical (badly
# configured) server would run, then run the demo, a harden-audit command, or
# whatever command was given.
set -euo pipefail

mkdir -p /run/sshd
/usr/sbin/sshd
service vsftpd start >/dev/null

case ${1:-demo} in
    demo)              exec /opt/harden-audit/docker/demo.sh ;;
    audit|harden|list) exec /opt/harden-audit/harden-audit.sh "$@" ;;
    *)                 exec "$@" ;;
esac
