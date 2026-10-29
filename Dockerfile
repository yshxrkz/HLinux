# Demo and test target for harden-audit.sh: an Ubuntu 24.04 "server" that is
# deliberately badly configured (see docker/make-insecure.sh).
#
#   docker build -t harden-audit-demo .
#   docker run --rm -it --cap-add NET_ADMIN harden-audit-demo          # audit -> harden -> audit
#   docker run --rm -it --cap-add NET_ADMIN harden-audit-demo bash     # explore by hand
#
# It is insecure on purpose (root login with a known password, an account
# without a password, an FTP server). Never publish its ports or run it on a
# network you care about.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server openssh-client vsftpd ufw sudo jq procps \
    && rm -rf /var/lib/apt/lists/*

COPY docker/make-insecure.sh /usr/local/sbin/make-insecure
RUN /usr/local/sbin/make-insecure

COPY . /opt/harden-audit
RUN ln -s /opt/harden-audit/harden-audit.sh /usr/local/bin/harden-audit

ENTRYPOINT ["/opt/harden-audit/docker/entrypoint.sh"]
CMD ["demo"]
