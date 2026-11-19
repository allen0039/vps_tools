#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/legacy-realm.toml"
if [[ -f /etc/default/liqun-lab-net ]]; then
    # shellcheck disable=SC1091
    source /etc/default/liqun-lab-net
    VPS_9929_IP="${VPS_9929_IP:-10.7.0.146}"
    HK_IP="${HK_IP:-198.51.100.10}"
    if [[ "${VPS_9929_IP}" != "10.7.0.146" || "${HK_IP}" != "198.51.100.10" ]]; then
        CONF="/run/legacy-realm.toml"
        cat > "${CONF}" <<EOF
[log]
level = "warn"
output = "stdout"

[network]
no_tcp = false
use_udp = false

[[endpoints]]
listen = "${VPS_9929_IP}:19999"
remote = "${HK_IP}:54848"
through = "${VPS_9929_IP}"
EOF
    fi
fi

exec /usr/local/bin/realm -c "${CONF}"
