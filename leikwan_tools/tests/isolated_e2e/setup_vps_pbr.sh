#!/usr/bin/env bash
set -euo pipefail

# Deterministic NIC naming & pre-existing source policy routing for Debian 12 VPS lab container.
if [[ -f /etc/default/liqun-lab-net ]]; then
    # shellcheck disable=SC1091
    source /etc/default/liqun-lab-net
fi

VPS_9929_IP="${VPS_9929_IP:-10.7.0.146}"
GW_9929="${GW_9929:-10.7.0.1}"
SUB_9929="${SUB_9929:-10.7.0.0/24}"

VPS_CN2_IP="${VPS_CN2_IP:-10.8.0.146}"
GW_CN2="${GW_CN2:-10.8.0.1}"
SUB_CN2="${SUB_CN2:-10.8.0.0/24}"

find_iface_by_ip() {
    local target_ip="$1"
    ip -4 -o addr show | awk -v ip="${target_ip}/" '$4 ~ "^"ip {print $2; exit}'
}

IF_9929="$(find_iface_by_ip "${VPS_9929_IP}")"
IF_CN2="$(find_iface_by_ip "${VPS_CN2_IP}")"

if [[ -z "${IF_9929}" || -z "${IF_CN2}" ]]; then
    echo "Missing expected VPS interfaces (${VPS_9929_IP} / ${VPS_CN2_IP})" >&2
    ip -4 -o addr show >&2
    exit 1
fi

if [[ "${IF_9929}" != "eth0" || "${IF_CN2}" != "eth1" ]]; then
    ip link set "${IF_9929}" down
    ip link set "${IF_CN2}" down
    ip link set "${IF_9929}" name tmp_9929
    ip link set "${IF_CN2}" name tmp_cn2
    ip link set tmp_9929 name eth0
    ip link set tmp_cn2 name eth1
    ip link set eth0 up
    ip link set eth1 up
fi

# Reconcile main route via GW_9929 (replacing Docker's .254 default gw).
ip -4 route replace default via "${GW_9929}" dev eth0

if [[ -f /etc/liqun-lab-main-only ]]; then
    exit 0
fi

# Optional simulated boot delay BEFORE policy routing rules/tables are installed (for R1 reboot race testing).
if [[ -f /etc/liqun-lab-delay-pbr ]]; then
    DELAY_SEC="$(cat /etc/liqun-lab-delay-pbr | tr -d '[:space:]')"
    if [[ -n "${DELAY_SEC}" && "${DELAY_SEC}" -gt 0 ]]; then
        sleep "${DELAY_SEC}"
    fi
fi

# Reconcile source policy routing tables 101 (9929) and 102 (cn2).
ip -4 route replace "${SUB_9929}" dev eth0 proto kernel scope link src "${VPS_9929_IP}" table 101
ip -4 route replace default via "${GW_9929}" dev eth0 table 101

ip -4 route replace "${SUB_CN2}" dev eth1 proto kernel scope link src "${VPS_CN2_IP}" table 102
ip -4 route replace default via "${GW_CN2}" dev eth1 table 102

while ip -4 rule del from "${VPS_9929_IP}" >/dev/null 2>&1; do :; done
while ip -4 rule del from "${VPS_CN2_IP}" >/dev/null 2>&1; do :; done
ip -4 rule add from "${VPS_9929_IP}" lookup 101 pref 101
ip -4 rule add from "${VPS_CN2_IP}" lookup 102 pref 102
ip -4 route flush cache
