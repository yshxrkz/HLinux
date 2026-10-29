#!/usr/bin/env bash
#
# Build the demo image and run the end-to-end tests inside it.
#
# The container is deliberately insecure (root password, cleartext FTP), so it
# runs on Docker's default bridge network with no published ports. It needs
# NET_ADMIN so that ufw can load firewall rules in its own network namespace.
#
# Usage: tests/docker-test.sh [REPORT_DIR]     (default: ./reports)

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${IMAGE:-harden-audit-demo}
reports=${1:-$root/reports}

mkdir -p "$reports"

echo "Building $image ..."
docker build --quiet --tag "$image" "$root" >/dev/null

# Reports are written by the container's root with mode 600. Give them back
# to whoever ran this script, even if the tests fail.
give_back_reports() {
    docker run --rm --volume "$reports:/reports" --entrypoint chown "$image" \
        -R "$(id -u):$(id -g)" /reports
}
trap give_back_reports EXIT

echo "Running the end-to-end tests in a fresh container ..."
docker run --rm --cap-add NET_ADMIN --volume "$reports:/reports" "$image" \
    /opt/harden-audit/tests/container-tests.sh

echo "Reports: $reports"
