FROM debian:bookworm-slim
ENV container=docker
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    openssh-server openssh-client sshpass python3 systemd systemd-sysv dbus \
    && rm -rf /var/lib/apt/lists/* \
    && touch /etc/sshpasswdtool-integration-container
COPY . /opt/ssh-password
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
