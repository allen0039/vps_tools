#!/usr/bin/env bash
set -euo pipefail

if [[ -f /etc/default/liqun-lab-net ]]; then
    # shellcheck disable=SC1091
    source /etc/default/liqun-lab-net
fi

GW_9929="${GW_9929:-10.7.0.1}"
GW_CN2="${GW_CN2:-10.8.0.1}"
GW_PUB="${GW_PUB:-203.0.113.1}"
GW_JP="${GW_JP:-192.0.2.1}"
GW_HK="${GW_HK:-198.51.100.1}"
VPS_9929_IP="${VPS_9929_IP:-10.7.0.146}"
PUB_10="${PUB_10:-203.0.113.10}"
PUB_11="${PUB_11:-203.0.113.11}"
PUB_12="${PUB_12:-203.0.113.12}"
PUB_13="${PUB_13:-203.0.113.13}"
JP_IP="${JP_IP:-192.0.2.10}"
HK_IP="${HK_IP:-198.51.100.10}"

find_iface_by_ip() {
    local target_ip="$1"
    ip -4 -o addr show | awk -v ip="${target_ip}/" '$4 ~ "^"ip {print $2; exit}'
}

IF_9929="$(find_iface_by_ip "${GW_9929}")"
IF_CN2="$(find_iface_by_ip "${GW_CN2}")"
IF_PUB="$(find_iface_by_ip "${GW_PUB}")"
IF_JP="$(find_iface_by_ip "${GW_JP}")"
IF_HK="$(find_iface_by_ip "${GW_HK}")"

echo "Router interfaces: 9929=${IF_9929} cn2=${IF_CN2} pub=${IF_PUB} jp=${IF_JP} hk=${IF_HK}"

for pub_ip in "${PUB_10}" "${PUB_11}" "${PUB_12}" "${PUB_13}"; do
    ip addr replace "${pub_ip}/24" dev "${IF_PUB}"
done

if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
fi

iptables -t nat -F
iptables -t mangle -F
iptables -F

iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_10}" -p tcp --dport 54141 -j DNAT --to-destination "${VPS_9929_IP}:10001"
iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_11}" -p tcp --dport 54141 -j DNAT --to-destination "${VPS_9929_IP}:10001"
iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_10}" -p tcp --dport 54848 -j DNAT --to-destination "${VPS_9929_IP}:10003"
iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_10}" -p tcp --dport 54999 -j DNAT --to-destination "${VPS_9929_IP}:10009"
iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_10}" -p tcp --dport 54443 -j DNAT --to-destination "${VPS_9929_IP}:10010"
iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_10}" -p tcp --dport 54444 -j DNAT --to-destination "${VPS_9929_IP}:10011"
iptables -t nat -A POSTROUTING -o "${IF_9929}" -d "${VPS_9929_IP}" -j MASQUERADE

iptables -t mangle -A PREROUTING -i "${IF_9929}" -p tcp --syn -d "${JP_IP}" -m comment --comment "EGRESS_9929_JP"
iptables -t mangle -A PREROUTING -i "${IF_CN2}"  -p tcp --syn -d "${JP_IP}" -m comment --comment "EGRESS_CN2_JP"
iptables -t mangle -A PREROUTING -i "${IF_9929}" -p tcp --syn -d "${HK_IP}" -m comment --comment "EGRESS_9929_HK"
iptables -t mangle -A PREROUTING -i "${IF_CN2}"  -p tcp --syn -d "${HK_IP}" -m comment --comment "EGRESS_CN2_HK"

cat > /tmp/dns_records.json <<EOF
{
  "paid-v4.bgp1.leikwanhost.com": [
    "${PUB_10}",
    "${PUB_11}",
    "${PUB_12}",
    "${PUB_13}"
  ]
}
EOF

nohup python3 /opt/lab/mock_dns.py --listen "${GW_PUB}" --port 53 --records-file /tmp/dns_records.json >/tmp/dns.log 2>&1 &
nohup python3 /opt/lab/mock_landing.py --id wrong-decoy-node --listen "${PUB_12}" --port 54141 >/tmp/decoy.log 2>&1 &

echo "Router setup complete."
sleep infinity
