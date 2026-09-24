#!/bin/sh
set -eu

umask 027

# Named volumes and tmpfs mounts are initially root-owned. Limit ownership
# changes to the two writable Suricata paths, then let Suricata open capture
# descriptors as root and drop to the image's unprivileged suricata account.
mkdir -p /var/log/suricata /var/run/suricata
chown suricata:suricata /var/log/suricata /var/run/suricata

exec /usr/bin/suricata \
    -c /etc/suricata/suricata.yaml \
    --user suricata \
    --group suricata \
    --pidfile /var/run/suricata/suricata.pid \
    "$@"
