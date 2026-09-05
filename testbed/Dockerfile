# strongSwan peer for the Stage 0 testbed, plus the traffic generators that
# ride the tunnel. One image serves both peers; role is decided by the mounted
# swanctl.conf.
FROM debian:bookworm-slim

# The plugin packages are not optional: plain `strongswan` ships no crypto
# backend at all, and every connection fails to load with
# "invalid value for: auth".
RUN apt-get update && apt-get install -y --no-install-recommends \
        strongswan strongswan-swanctl charon-systemd \
        libstrongswan-standard-plugins libstrongswan-extra-plugins \
        libcharon-extra-plugins \
        iproute2 iputils-ping tcpdump procps \
        curl nginx ffmpeg sip-tester postfix swaks python3 \
    && rm -rf /var/lib/apt/lists/*

COPY generators /opt/generators
CMD ["sleep", "infinity"]
