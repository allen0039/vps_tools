#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
E2E_DIR="${SCRIPT_DIR}/isolated_e2e"
OUT_DIR="${LIQUN_TEST_OUT_DIR:-${PROJECT_DIR}/test-results-ipv6}"
mkdir -p "${OUT_DIR}"

LOG_FILE="${OUT_DIR}/ipv6-egress-e2e-output.txt"
exec > >(tee "${LOG_FILE}") 2>&1

# shellcheck disable=SC1091
source "${E2E_DIR}/lab_common.sh"
lab_init_vars "v6e2e"
trap lab_cleanup EXIT

fail() {
    echo "FAILED: $*" >&2
    exit 1
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local label="${3:-assertion}"
    if ! grep -Fq -- "${needle}" <<< "${haystack}"; then
        fail "${label}: expected '${needle}' in output:\n${haystack}"
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local label="${3:-assertion}"
    if grep -Fq -- "${needle}" <<< "${haystack}"; then
        fail "${label}: did NOT expect '${needle}' in output:\n${haystack}"
    fi
}

client_probe() {
    local host="$1"
    local port="$2"
    local payload="${3:-PING}"
    docker exec -i "${C_CLIENT}" python3 - "${host}" "${port}" "${payload}" <<'PY'
import socket, sys
host, port, payload = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), timeout=5)
s.settimeout(5)
s.sendall((payload + "\n").encode("utf-8"))
data = s.recv(4096).decode("utf-8", errors="replace").strip()
s.close()
print(data)
PY
}

get_v4_mangle_pkts() {
    local comment="$1"
    docker exec "${C_ROUTER}" iptables -t mangle -L PREROUTING -v -n -x | awk -v c="${comment}" '$0 ~ c {print $1; exit}'
}

get_v6_mangle_pkts() {
    local comment="$1"
    docker exec "${C_ROUTER}" ip6tables -t mangle -L PREROUTING -v -n -x | awk -v c="${comment}" '$0 ~ c {print $1; exit}'
}

lab_build_images "${E2E_DIR}"

# Allocate non-overlapping IPv4 + IPv6 dual-stack isolated Docker networks
LAB_NET_ENV_FILE="$(mktemp -t liqun-v6lab-net)"
alloc_log="$(mktemp -t liqun-v6lab-alloc)"
if python3 - "${NET_9929}" "${NET_CN2}" "${NET_PUB}" "${NET_JP}" >"${alloc_log}" <<'PY'
import fcntl, ipaddress, json, os, subprocess, sys

net_names = sys.argv[1:5]
lock_path = "/tmp/liqun-e2e-alloc.lock"
fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
try:
    fcntl.flock(fd, fcntl.LOCK_EX)
    ids = subprocess.check_output(["docker", "network", "ls", "-q"], text=True).split()
    used_nets = []
    for nid in ids:
        proc = subprocess.run(["docker", "network", "inspect", nid], capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            continue
        for item in json.loads(proc.stdout):
            for cfg in (item.get("IPAM") or {}).get("Config") or []:
                sub = cfg.get("Subnet")
                if sub:
                    try:
                        used_nets.append(ipaddress.ip_network(sub, strict=False))
                    except ValueError:
                        pass

    def free_block(subnets):
        objs = [ipaddress.ip_network(s, strict=False) for s in subnets]
        for cand in objs:
            for existing in used_nets:
                if cand.version == existing.version and cand.overlaps(existing):
                    return False
        return True

    chosen = None
    for s in range(30, 220):
        hx = f"{s:x}"
        subs4 = [f"10.{s}.7.0/24", f"10.{s}.8.0/24", f"10.{s}.113.0/24", f"10.{s}.201.0/24"]
        subs6 = [
            f"240e:fe00:{hx}::/64",
            f"2408:fe00:{hx}::/64",
            f"2001:db8:fe00:{hx}::/64",
            f"2001:db8:fe01:{hx}::/64",
        ]
        if free_block(subs4 + subs6):
            chosen = {
                "SUB_9929": subs4[0], "GW_DOCKER_9929": f"10.{s}.7.254", "GW_9929": f"10.{s}.7.1", "VPS_9929_IP": f"10.{s}.7.146",
                "SUB_CN2": subs4[1],  "GW_DOCKER_CN2": f"10.{s}.8.254",  "GW_CN2": f"10.{s}.8.1",  "VPS_CN2_IP": f"10.{s}.8.146",
                "SUB_PUB": subs4[2],  "GW_DOCKER_PUB": f"10.{s}.113.254", "GW_PUB": f"10.{s}.113.1",
                "CLIENT_IP": f"10.{s}.113.50", "PUB_10": f"10.{s}.113.10",
                "SUB_JP": subs4[3],   "GW_DOCKER_JP": f"10.{s}.201.254",  "GW_JP": f"10.{s}.201.1", "JP_IP": f"10.{s}.201.10",
                "SUB_CT_V6": subs6[0], "GW_DOCKER_CT_V6": f"240e:fe00:{hx}::fffe", "GW_CT_V6": f"240e:fe00:{hx}::1", "VPS_CT_V6": f"240e:fe00:{hx}::146",
                "SUB_CU_V6": subs6[1], "GW_DOCKER_CU_V6": f"2408:fe00:{hx}::fffe", "GW_CU_V6": f"2408:fe00:{hx}::1", "VPS_CU_V6": f"2408:fe00:{hx}::146",
                "SUB_PUB_V6": subs6[2], "GW_DOCKER_PUB_V6": f"2001:db8:fe00:{hx}::fffe", "GW_PUB_V6": f"2001:db8:fe00:{hx}::1", "CLIENT_V6": f"2001:db8:fe00:{hx}::50",
                "SUB_JP_V6": subs6[3],  "GW_DOCKER_JP_V6": f"2001:db8:fe01:{hx}::fffe",  "GW_JP_V6": f"2001:db8:fe01:{hx}::1",  "JP_V6": f"2001:db8:fe01:{hx}::10",
            }
            break
    if not chosen:
        raise RuntimeError("No free dual-stack IPv4/IPv6 subnet block found")

    specs = [
        (net_names[0], chosen["SUB_9929"], chosen["GW_DOCKER_9929"], chosen["SUB_CT_V6"], chosen["GW_DOCKER_CT_V6"]),
        (net_names[1], chosen["SUB_CN2"],  chosen["GW_DOCKER_CN2"],  chosen["SUB_CU_V6"], chosen["GW_DOCKER_CU_V6"]),
        (net_names[2], chosen["SUB_PUB"],  chosen["GW_DOCKER_PUB"],  chosen["SUB_PUB_V6"], chosen["GW_DOCKER_PUB_V6"]),
        (net_names[3], chosen["SUB_JP"],   chosen["GW_DOCKER_JP"],   chosen["SUB_JP_V6"], chosen["GW_DOCKER_JP_V6"]),
    ]
    for nname, s4, g4, s6, g6 in specs:
        subprocess.check_call(
            [
                "docker", "network", "create", "--internal", "--ipv6",
                f"--subnet={s4}", f"--gateway={g4}",
                f"--subnet={s6}", f"--gateway={g6}",
                nname,
            ],
            stdout=subprocess.DEVNULL,
        )
        print(f"CREATED_NETWORK={nname}", flush=True)

    for k, v in chosen.items():
        print(f"{k}={v}")
finally:
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
PY
then
    alloc_rc=0
else
    alloc_rc=$?
fi

while IFS= read -r alloc_line; do
    if [[ "${alloc_line}" == CREATED_NETWORK=* ]]; then
        CREATED_NETWORKS+=("${alloc_line#CREATED_NETWORK=}")
    elif [[ -n "${alloc_line}" ]]; then
        printf '%s\n' "${alloc_line}" >> "${LAB_NET_ENV_FILE}"
    fi
done < "${alloc_log}"
rm -f "${alloc_log}" || true
[[ ${alloc_rc} -eq 0 ]] || exit "${alloc_rc}"

# shellcheck disable=SC1090
source "${LAB_NET_ENV_FILE}"
echo "=== [Setup] Dual-stack isolated topology (RUN_ID=${RUN_ID}) ==="
echo "  9929/CT : v4=${SUB_9929} (VPS=${VPS_9929_IP}, GW=${GW_9929}) | v6=${SUB_CT_V6} (VPS=${VPS_CT_V6}, GW=${GW_CT_V6})"
echo "  CN2/CU  : v4=${SUB_CN2} (VPS=${VPS_CN2_IP}, GW=${GW_CN2}) | v6=${SUB_CU_V6} (VPS=${VPS_CU_V6}, GW=${GW_CU_V6})"
echo "  PUB     : v4=${SUB_PUB} (CLIENT=${CLIENT_IP}, BGP=${PUB_10}) | v6=${SUB_PUB_V6} (CLIENT=${CLIENT_V6})"
echo "  JP      : v4=${SUB_JP} (JP_V4=${JP_IP}) | v6=${SUB_JP_V6} (JP_V6=${JP_V6})"

# Start Router
docker create --name "${C_ROUTER}" --cap-add=NET_ADMIN \
    --sysctl net.ipv4.ip_forward=1 \
    --sysctl net.ipv6.conf.all.forwarding=1 \
    --network "${NET_9929}" --ip "${GW_9929}" --ip6 "${GW_CT_V6}" \
    "${IMG_NETNODE}" bash -c '
set -euo pipefail
source /etc/default/liqun-lab-net
find_iface_by_ip() {
    local target_ip="$1"
    ip -4 -o addr show | awk -v ip="${target_ip}/" "\$4 ~ \"^\"ip {print \$2; exit}"
}
IF_9929="$(find_iface_by_ip "${GW_9929}")"
IF_CN2="$(find_iface_by_ip "${GW_CN2}")"
IF_PUB="$(find_iface_by_ip "${GW_PUB}")"
IF_JP="$(find_iface_by_ip "${GW_JP}")"

ip addr replace "${PUB_10}/24" dev "${IF_PUB}"
ip -6 addr replace "${GW_CT_V6}/64" dev "${IF_9929}" nodad
ip -6 addr replace "${GW_CU_V6}/64" dev "${IF_CN2}" nodad
ip -6 addr replace "${GW_PUB_V6}/64" dev "${IF_PUB}" nodad
ip -6 addr replace "${GW_JP_V6}/64" dev "${IF_JP}" nodad
if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
fi
if [[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0)" != "1" ]]; then
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
fi

iptables -t nat -F
iptables -t mangle -F
ip6tables -t mangle -F

# Simulate LeiKwan Official IPv4 BGP port mappings onto VPS eth0 (9929 NIC)
iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_10}" -p tcp --dport 54141 -j DNAT --to-destination "${VPS_9929_IP}:10001"
iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_10}" -p tcp --dport 54204 -j DNAT --to-destination "${VPS_9929_IP}:10014"
iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_10}" -p tcp --dport 54205 -j DNAT --to-destination "${VPS_9929_IP}:10015"
iptables -t nat -A PREROUTING -i "${IF_PUB}" -d "${PUB_10}" -p tcp --dport 54206 -j DNAT --to-destination "${VPS_9929_IP}:10016"
iptables -t nat -A POSTROUTING -o "${IF_9929}" -d "${VPS_9929_IP}" -j MASQUERADE

# Egress SYN counters on both CT (IF_9929) and CU (IF_CN2) links toward JP
iptables -t mangle -A PREROUTING -i "${IF_9929}" -p tcp --syn -d "${JP_IP}" -m comment --comment "EGRESS_9929_JP"
iptables -t mangle -A PREROUTING -i "${IF_CN2}"  -p tcp --syn -d "${JP_IP}" -m comment --comment "EGRESS_CN2_JP"
ip6tables -t mangle -A PREROUTING -i "${IF_9929}" -p tcp --syn -d "${JP_V6}" -m comment --comment "EGRESS_CT_V6_JP"
ip6tables -t mangle -A PREROUTING -i "${IF_CN2}"  -p tcp --syn -d "${JP_V6}" -m comment --comment "EGRESS_CU_V6_JP"

echo "V6 Router ready: 9929=${IF_9929} cn2=${IF_CN2} pub=${IF_PUB} jp=${IF_JP}"
sleep infinity
' >/dev/null
CREATED_CONTAINERS+=("${C_ROUTER}")
docker network connect --ip "${GW_CN2}" --ip6 "${GW_CU_V6}" "${NET_CN2}" "${C_ROUTER}"
docker network connect --ip "${GW_PUB}" --ip6 "${GW_PUB_V6}" "${NET_PUB}" "${C_ROUTER}"
docker network connect --ip "${GW_JP}"  --ip6 "${GW_JP_V6}"  "${NET_JP}"  "${C_ROUTER}"
docker cp "${LAB_NET_ENV_FILE}" "${C_ROUTER}:/etc/default/liqun-lab-net"
docker start "${C_ROUTER}" >/dev/null

# Start dual-stack JP Landing
docker run -d --name "${C_JP}" --cap-add=NET_ADMIN \
    --network "${NET_JP}" --ip "${JP_IP}" --ip6 "${JP_V6}" \
    "${IMG_NETNODE}" bash -c "
set -euo pipefail
ip -6 addr replace ${JP_V6}/64 dev eth0 nodad
ip -4 route replace default via ${GW_JP}
ip -6 route replace default via ${GW_JP_V6}
python3 /opt/lab/mock_landing.py --id zouter-jp-v4 --listen ${JP_IP} --port 54141 &
python3 /opt/lab/mock_landing.py --id zouter-jp-v6 --listen ${JP_V6} --port 54141 &
wait
" >/dev/null
CREATED_CONTAINERS+=("${C_JP}")

# Start dual-stack Client
docker run -d --name "${C_CLIENT}" --cap-add=NET_ADMIN \
    --network "${NET_PUB}" --ip "${CLIENT_IP}" --ip6 "${CLIENT_V6}" \
    "${IMG_NETNODE}" bash -c "
set -euo pipefail
ip -6 addr replace ${CLIENT_V6}/64 dev eth0 nodad
ip -4 route replace default via ${GW_PUB}
ip -6 route replace default via ${GW_PUB_V6}
exec sleep infinity
" >/dev/null
CREATED_CONTAINERS+=("${C_CLIENT}")

# Start Debian 12 + systemd VPS
docker create --name "${C_VPS}" \
    --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    --network "${NET_9929}" --ip "${VPS_9929_IP}" --ip6 "${VPS_CT_V6}" \
    "${IMG_VPS}" >/dev/null
CREATED_CONTAINERS+=("${C_VPS}")
docker network connect --ip "${VPS_CN2_IP}" --ip6 "${VPS_CU_V6}" "${NET_CN2}" "${C_VPS}"
docker cp "${LAB_NET_ENV_FILE}" "${C_VPS}:/etc/default/liqun-lab-net"
docker start "${C_VPS}" >/dev/null

echo "=== [Setup] Waiting for Debian 12 systemd & router readiness ==="
for _ in $(seq 1 40); do
    st="$(docker exec "${C_VPS}" systemctl is-system-running 2>/dev/null || true)"
    if [[ "${st}" == "running" || "${st}" == "degraded" ]]; then
        break
    fi
    sleep 1
done
for _ in $(seq 1 20); do
    if docker exec "${C_ROUTER}" ip6tables -t mangle -L PREROUTING -n 2>/dev/null | grep -q "EGRESS_CU_V6_JP"; then
        break
    fi
    sleep 0.5
done
if ! docker exec "${C_ROUTER}" ip6tables -t mangle -L PREROUTING -n 2>/dev/null | grep -q "EGRESS_CU_V6_JP"; then
    docker logs "${C_ROUTER}" >&2 || true
    fail "Router container failed readiness check"
fi
for _ in $(seq 1 20); do
    jp_ss="$(docker exec "${C_JP}" ss -H -ltn 2>/dev/null || true)"
    if grep -qF "${JP_IP}:54141" <<< "${jp_ss}" && grep -qF "${JP_V6}" <<< "${jp_ss}"; then
        break
    fi
    sleep 0.5
done
jp_ss="$(docker exec "${C_JP}" ss -H -ltn 2>/dev/null || true)"
if ! grep -qF "${JP_IP}:54141" <<< "${jp_ss}" || ! grep -qF "${JP_V6}" <<< "${jp_ss}"; then
    docker logs "${C_JP}" >&2 || true
    fail "JP landing container failed readiness check"
fi
if [[ "$(docker inspect -f '{{.State.Running}}' "${C_CLIENT}" 2>/dev/null || true)" != "true" ]]; then
    docker logs "${C_CLIENT}" >&2 || true
    fail "Client container failed readiness check"
fi

# Copy local source into VPS & install
docker exec "${C_VPS}" mkdir -p /opt/src/leikwan_tools /opt/v6-rules
docker cp "${PROJECT_DIR}/." "${C_VPS}:/opt/src/leikwan_tools/"

echo "=== [V1] Realm v2.9.6 verification, installation & check-prereqs (IPv4 + IPv6 lines) ==="
REALM_VER="$(docker exec "${C_VPS}" /usr/local/bin/realm --version)"
echo "Realm version in container: ${REALM_VER}"
assert_contains "${REALM_VER}" "2.9.6" "V1 realm version"

docker exec "${C_VPS}" bash -lc 'cd /opt/src/leikwan_tools && bash install.sh --realm-tarball /opt/cache/realm-v2.9.6.tar.gz'

docker exec -i "${C_VPS}" python3 - "${GW_PUB}" "${VPS_9929_IP}" "${GW_9929}" "${VPS_CN2_IP}" "${GW_CN2}" "${VPS_CT_V6}" "${GW_CT_V6}" "${VPS_CU_V6}" "${GW_CU_V6}" <<'PY'
import sys
gw_pub, vps_9929, gw_9929, vps_cn2, gw_cn2, ct_v6, gw_ct6, cu_v6, gw_cu6 = sys.argv[1:10]
p = "/etc/leikwan_tools/config.toml"
txt = open(p, encoding="utf-8").read()
txt = txt.replace('dns_server = ""', f'dns_server = "{gw_pub}"', 1)
txt = txt.replace('10.7.0.146', vps_9929).replace('10.7.0.1', gw_9929)
txt = txt.replace('10.8.0.146', vps_cn2).replace('10.8.0.1', gw_cn2)
txt += f"""
[lines.ct_v6]
family = "ipv6"
interface = "eth0"
source_ip = "{ct_v6}"
gateway = "{gw_ct6}"
description = "电信 IPv6 出口"

[lines.cu_v6]
family = "ipv6"
interface = "eth1"
source_ip = "{cu_v6}"
gateway = "{gw_cu6}"
description = "联通 IPv6 出口"
"""
open(p, "w", encoding="utf-8").write(txt)
PY

echo "--- VPS IPv6 addresses & routes ---"
docker exec "${C_VPS}" ip -6 -o addr show scope global
docker exec "${C_VPS}" ip -6 route show

PREREQ_V6="$(docker exec "${C_VPS}" leikwan_tools check-prereqs --probe-remote "${JP_IP}" --probe-remote-v6 "${JP_V6}")"
echo "${PREREQ_V6}"
assert_contains "${PREREQ_V6}" "线路 9929 [通过]" "V1 prereq 9929"
assert_contains "${PREREQ_V6}" "线路 cn2 [通过]" "V1 prereq cn2"
assert_contains "${PREREQ_V6}" "线路 ct_v6 [通过]" "V1 prereq ct_v6"
assert_contains "${PREREQ_V6}" "线路 cu_v6 [通过]" "V1 prereq cu_v6"
assert_contains "${PREREQ_V6}" "不代表远端落地 TCP 端口可达" "V1 kernel vs tcp note"

echo "=== [V2] Verifying all 4 ingress/egress/landing combinations with real Realm v2.9.6 ==="

# Combo 1: IPv6 direct -> IPv4 egress (cn2) -> IPv4 landing
docker exec -i "${C_VPS}" tee /opt/v6-rules/combo1.toml >/dev/null <<EOF
[rule]
name = "combo1-v6-to-v4"
description = "组合1: 公网IPv6直连 -> cn2(IPv4) -> IPv4落地"
line = "cn2"
[ingress]
public_port = 54201
[forward]
listen_ip = "${VPS_CT_V6}"
listen_port = 54201
remote_ip = "${JP_IP}"
remote_port = 54141
EOF

# Combo 2: IPv6 direct -> IPv6 egress (cu_v6) -> IPv6 landing
docker exec -i "${C_VPS}" tee /opt/v6-rules/combo2.toml >/dev/null <<EOF
[rule]
name = "combo2-v6-to-v6"
description = "组合2: 公网IPv6直连 -> cu_v6(IPv6) -> IPv6落地"
line = "cu_v6"
[ingress]
public_port = 54202
[forward]
listen_ip = "${VPS_CT_V6}"
listen_port = 54202
remote_ip = "${JP_V6}"
remote_port = 54141
EOF

# Combo 3: Simulated Official IPv4 BGP -> IPv4 egress (cn2) -> IPv4 landing
docker exec -i "${C_VPS}" tee /opt/v6-rules/combo3.toml >/dev/null <<EOF
[rule]
name = "combo3-bgp-to-v4"
description = "组合3: 官方IPv4 BGP入口 -> cn2(IPv4) -> IPv4落地"
line = "cn2"
[ingress]
domain = "paid-v4.bgp1.leikwanhost.com"
public_port = 54141
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10001
remote_ip = "${JP_IP}"
remote_port = 54141
EOF

# Combo 4: Simulated Official IPv4 BGP -> IPv6 egress (cu_v6) -> IPv6 landing
docker exec -i "${C_VPS}" tee /opt/v6-rules/combo4.toml >/dev/null <<EOF
[rule]
name = "combo4-bgp-to-v6"
description = "组合4: 官方IPv4 BGP入口 -> cu_v6(IPv6) -> IPv6落地"
line = "cu_v6"
[ingress]
domain = "paid-v4.bgp1.leikwanhost.com"
public_port = 54204
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10014
remote_ip = "${JP_V6}"
remote_port = 54141
EOF

for f in combo1.toml combo2.toml combo3.toml combo4.toml; do
    echo "--- Applying ${f} ---"
    docker exec "${C_VPS}" leikwan_tools apply "/opt/v6-rules/${f}"
done

# Verify generated Realm TOMLs
C2_TOML="$(docker exec "${C_VPS}" cat /var/lib/leikwan_tools/realm/combo2-v6-to-v6.toml)"
C4_TOML="$(docker exec "${C_VPS}" cat /var/lib/leikwan_tools/realm/combo4-bgp-to-v6.toml)"
assert_contains "${C2_TOML}" 'mode = "ipv6_only"' "Combo2 dns mode"
assert_contains "${C2_TOML}" "remote = \"[${JP_V6}]:54141\"" "Combo2 remote bracketed"
assert_contains "${C2_TOML}" "through = \"[${VPS_CU_V6}]\"" "Combo2 through"
assert_contains "${C2_TOML}" 'interface = "eth1"' "Combo2 interface"
assert_not_contains "${C2_TOML}" 'listen_interface' "Combo2 no listen_interface"

assert_contains "${C4_TOML}" 'listen_interface = "eth0"' "Combo4 BGP listen_interface"
assert_contains "${C4_TOML}" "remote = \"[${JP_V6}]:54141\"" "Combo4 remote bracketed"
assert_contains "${C4_TOML}" "through = \"[${VPS_CU_V6}]\"" "Combo4 through"
assert_contains "${C4_TOML}" 'interface = "eth1"' "Combo4 interface"
assert_contains "$(docker exec "${C_VPS}" ss -H -ltn4 'sport = :10014')" "${VPS_9929_IP}%eth0:10014" "Combo4 BGP ss listen_interface"

# Live traffic probes for Combos 1-4 with router SYN counter verification
V4_9929_0="$(get_v4_mangle_pkts EGRESS_9929_JP)"
V4_CN2_0="$(get_v4_mangle_pkts EGRESS_CN2_JP)"
RESP1="$(client_probe "${VPS_CT_V6}" 54201 "COMBO1_PROBE")"
V4_9929_1="$(get_v4_mangle_pkts EGRESS_9929_JP)"
V4_CN2_1="$(get_v4_mangle_pkts EGRESS_CN2_JP)"
echo "Combo 1 reply: ${RESP1} | v4 SYN 9929=${V4_9929_0}->${V4_9929_1}, cn2=${V4_CN2_0}->${V4_CN2_1}"
assert_contains "${RESP1}" "LANDING=zouter-jp-v4 SRC=${VPS_CN2_IP}" "Combo1 reply"
assert_contains "${RESP1}" "ECHO=COMBO1_PROBE" "Combo1 echo"
[[ "${V4_CN2_1}" -gt "${V4_CN2_0}" && "${V4_9929_1}" -eq "${V4_9929_0}" ]] || fail "Combo1 SYN counters mismatch"

V6_CT_0="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
V6_CU_0="$(get_v6_mangle_pkts EGRESS_CU_V6_JP)"
RESP2="$(client_probe "${VPS_CT_V6}" 54202 "COMBO2_PROBE")"
V6_CT_1="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
V6_CU_1="$(get_v6_mangle_pkts EGRESS_CU_V6_JP)"
echo "Combo 2 reply: ${RESP2} | v6 SYN ct=${V6_CT_0}->${V6_CT_1}, cu=${V6_CU_0}->${V6_CU_1}"
assert_contains "${RESP2}" "LANDING=zouter-jp-v6 SRC=${VPS_CU_V6}" "Combo2 reply"
assert_contains "${RESP2}" "ECHO=COMBO2_PROBE" "Combo2 echo"
[[ "${V6_CU_1}" -gt "${V6_CU_0}" && "${V6_CT_1}" -eq "${V6_CT_0}" ]] || fail "Combo2 SYN counters mismatch"

RESP3="$(client_probe "${PUB_10}" 54141 "COMBO3_PROBE")"
V4_9929_2="$(get_v4_mangle_pkts EGRESS_9929_JP)"
V4_CN2_2="$(get_v4_mangle_pkts EGRESS_CN2_JP)"
echo "Combo 3 reply: ${RESP3} | v4 SYN 9929=${V4_9929_1}->${V4_9929_2}, cn2=${V4_CN2_1}->${V4_CN2_2}"
assert_contains "${RESP3}" "LANDING=zouter-jp-v4 SRC=${VPS_CN2_IP}" "Combo3 reply"
assert_contains "${RESP3}" "ECHO=COMBO3_PROBE" "Combo3 echo"
[[ "${V4_CN2_2}" -gt "${V4_CN2_1}" && "${V4_9929_2}" -eq "${V4_9929_1}" ]] || fail "Combo3 SYN counters mismatch"

RESP4="$(client_probe "${PUB_10}" 54204 "COMBO4_PROBE")"
V6_CT_2="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
V6_CU_2="$(get_v6_mangle_pkts EGRESS_CU_V6_JP)"
echo "Combo 4 reply: ${RESP4} | v6 SYN ct=${V6_CT_1}->${V6_CT_2}, cu=${V6_CU_1}->${V6_CU_2}"
assert_contains "${RESP4}" "LANDING=zouter-jp-v6 SRC=${VPS_CU_V6}" "Combo4 reply"
assert_contains "${RESP4}" "ECHO=COMBO4_PROBE" "Combo4 echo"
[[ "${V6_CU_2}" -gt "${V6_CU_1}" && "${V6_CT_2}" -eq "${V6_CT_1}" ]] || fail "Combo4 SYN counters mismatch"

STATUS_OUT="$(docker exec "${C_VPS}" leikwan_tools status)"
echo "--- leikwan_tools status ---"
echo "${STATUS_OUT}"
assert_contains "${STATUS_OUT}" "[${VPS_CT_V6}]:54202" "Status combo2 ingress/listen"
assert_contains "${STATUS_OUT}" "[${VPS_JP_V6:-$JP_V6}]:54141" "Status IPv6 remote"
assert_contains "${STATUS_OUT}" "(入口网卡=eth0)" "Status BGP listen_interface"
assert_contains "${STATUS_OUT}" "(${VPS_CU_V6}@eth1)" "Status CU through@iface"
assert_contains "${STATUS_OUT}" "仅内核查路，不代表落地 TCP 可达" "Status kernel route note"

echo "=== [V3] Dual rules targeting SAME IPv6 [${JP_V6}]:54141 (CT vs CU), outage isolation & recovery ==="
docker exec -i "${C_VPS}" tee /opt/v6-rules/dual-ct.toml >/dev/null <<EOF
[rule]
name = "dual-v6-ct"
description = "同落地IPv6-电信出口"
line = "ct_v6"
[ingress]
public_port = 54205
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10015
remote_ip = "${JP_V6}"
remote_port = 54141
EOF

docker exec -i "${C_VPS}" tee /opt/v6-rules/dual-cu.toml >/dev/null <<EOF
[rule]
name = "dual-v6-cu"
description = "同落地IPv6-联通出口"
line = "cu_v6"
[ingress]
public_port = 54206
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10016
remote_ip = "${JP_V6}"
remote_port = 54141
EOF

docker exec "${C_VPS}" leikwan_tools apply /opt/v6-rules/dual-ct.toml
docker exec "${C_VPS}" leikwan_tools apply /opt/v6-rules/dual-cu.toml

# Confirm BOTH reach [JP_V6]:54141 via their respective links before withdrawal
DUAL_CT_OK="$(client_probe "${PUB_10}" 54205 "DUAL_CT_BEFORE")"
DUAL_CU_OK="$(client_probe "${PUB_10}" 54206 "DUAL_CU_BEFORE")"
echo "Dual BEFORE: CT=[${DUAL_CT_OK}] | CU=[${DUAL_CU_OK}]"
assert_contains "${DUAL_CT_OK}" "LANDING=zouter-jp-v6 SRC=${VPS_CT_V6}" "Dual CT before"
assert_contains "${DUAL_CU_OK}" "LANDING=zouter-jp-v6 SRC=${VPS_CU_V6}" "Dual CU before"

echo "--- Withdrawing cu_v6 default route on eth1 (while ct_v6 backup link on eth0 remains healthy!) ---"
docker exec "${C_VPS}" ip -6 route del default via "${GW_CU_V6}" dev eth1 metric 200
docker exec "${C_VPS}" ip -6 route flush cache

ST_CU_DOWN="$(docker exec "${C_VPS}" leikwan_tools status dual-v6-cu)"
echo "${ST_CU_DOWN}"
assert_contains "${ST_CU_DOWN}" "出口路由   : 异常" "V3 status route abnormal"

set +e
PLAN_CU_DOWN="$(docker exec "${C_VPS}" leikwan_tools plan /opt/v6-rules/dual-cu.toml 2>&1)"
PLAN_CU_RC=$?
VS_CU_DOWN="$(docker exec "${C_VPS}" leikwan_tools _verify-startup dual-v6-cu --wait-timeout 0 2>&1)"
VS_CU_RC=$?
set -e
[[ ${PLAN_CU_RC} -ne 0 && ${VS_CU_RC} -ne 0 ]] || fail "V3: plan or _verify-startup unexpectedly succeeded without CU route"
assert_contains "${PLAN_CU_DOWN}" "严禁静默切到其他线路" "V3 plan blocks silent fallback"
assert_contains "${VS_CU_DOWN}" "严禁静默切到其他线路" "V3 startup blocks silent fallback"

CT_D0="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
CU_D0="$(get_v6_mangle_pkts EGRESS_CU_V6_JP)"

OUTAGE_RES="$(docker exec -i "${C_CLIENT}" python3 - "${PUB_10}" <<'PY'
import socket, sys
pub = sys.argv[1]
results = []
for idx in range(1, 6):
    try:
        s = socket.create_connection((pub, 54206), timeout=2)
        s.settimeout(2)
        s.sendall(f"DUAL_CU_OUTAGE_{idx}\n".encode())
        data = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()
        if not data:
            results.append(("FAIL", "EOF: Realm closed connection without landing reply"))
        else:
            results.append(("OK", data))
    except Exception as exc:
        results.append(("FAIL", f"{type(exc).__name__}: {exc}"))
print(results)
assert all(r[0] == "FAIL" for r in results), f"CU rule unexpectedly succeeded during outage: {results}"
PY
)"
echo "Outage 5 probes to dual-v6-cu: ${OUTAGE_RES}"

CT_D1="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
CU_D1="$(get_v6_mangle_pkts EGRESS_CU_V6_JP)"
echo "Router v6 SYN counters during dual-v6-cu outage: CT=${CT_D0}->${CT_D1} (delta=$((CT_D1-CT_D0))), CU=${CU_D0}->${CU_D1} (delta=$((CU_D1-CU_D0)))"
[[ "${CT_D1}" -eq "${CT_D0}" ]] || fail "V3: dual-v6-cu leaked $((CT_D1-CT_D0)) SYNs onto backup CT link!"
[[ "${CU_D1}" -eq "${CU_D0}" ]] || fail "V3: CU SYN counter changed unexpectedly during outage"

JP_LOGS_OUTAGE="$(docker logs "${C_JP}" 2>&1 || true)"
assert_not_contains "${JP_LOGS_OUTAGE}" "DUAL_CU_OUTAGE_" "V3 landing observed leaked outage payload"

# Verify backup CT rule dual-v6-ct STILL works during CU outage
DUAL_CT_DURING="$(client_probe "${PUB_10}" 54205 "DUAL_CT_DURING")"
CT_D2="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
echo "Backup CT probe during CU outage: ${DUAL_CT_DURING} | CT SYN=${CT_D1}->${CT_D2}"
assert_contains "${DUAL_CT_DURING}" "LANDING=zouter-jp-v6 SRC=${VPS_CT_V6}" "V3 CT still works"
[[ "${CT_D2}" -gt "${CT_D1}" ]] || fail "V3: CT SYN counter did not increment for dual-v6-ct"

echo "--- Realm dual-v6-cu journal during outage ---"
docker exec "${C_VPS}" journalctl -u leikwan_tools-realm@dual-v6-cu.service -n 8 --no-pager

echo "--- Restoring cu_v6 route WITHOUT restarting Realm ---"
CU_PID_BEFORE="$(docker exec "${C_VPS}" systemctl show -p MainPID --value leikwan_tools-realm@dual-v6-cu.service)"
docker exec "${C_VPS}" ip -6 route replace default via "${GW_CU_V6}" dev eth1 metric 200
docker exec "${C_VPS}" ip -6 route flush cache
DUAL_CU_RECOVERED="$(client_probe "${PUB_10}" 54206 "DUAL_CU_RECOVERED")"
CU_PID_AFTER="$(docker exec "${C_VPS}" systemctl show -p MainPID --value leikwan_tools-realm@dual-v6-cu.service)"
echo "Recovered CU probe (PID ${CU_PID_BEFORE}->${CU_PID_AFTER}): ${DUAL_CU_RECOVERED}"
assert_contains "${DUAL_CU_RECOVERED}" "LANDING=zouter-jp-v6 SRC=${VPS_CU_V6}" "V3 CU recovered"
[[ "${CU_PID_BEFORE}" == "${CU_PID_AFTER}" ]] || fail "V3: Realm PID changed across route restore"

echo "--- Testing IPv6 source policy table (ip -6 rule table 202) mode ---"
POLICY_GW="${GW_CU_V6%:*}:73"
POLICY_ROUTER_IF="$(docker exec "${C_ROUTER}" ip -6 -o addr show | awk -v address="${GW_CU_V6}/64" '$4 == address {print $2; exit}')"
[[ -n "${POLICY_ROUTER_IF}" ]] || fail "V3: missing CU router interface"
docker exec "${C_ROUTER}" ip -6 addr add "${POLICY_GW}/64" dev "${POLICY_ROUTER_IF}" nodad
docker exec "${C_VPS}" cp /etc/leikwan_tools/config.toml /tmp/config-main-v6.toml
docker exec -i "${C_VPS}" python3 - "${GW_CU_V6}" "${POLICY_GW}" <<'PY'
from pathlib import Path
import sys

config = Path("/etc/leikwan_tools/config.toml")
old_gateway, policy_gateway = sys.argv[1:]
base, section = config.read_text().split("\n[lines.cu_v6]\n", 1)
assert f'gateway = "{old_gateway}"' in section
section = section.replace(f'gateway = "{old_gateway}"', f'gateway = "{policy_gateway}"', 1)
config.write_text(base + "\n[lines.cu_v6]\ntable = 202\n" + section)
PY
docker exec "${C_VPS}" ip -6 route replace default via "${POLICY_GW}" dev eth1 table 202
docker exec "${C_VPS}" ip -6 rule add from "${VPS_CU_V6}/128" lookup 202 pref 202
if NO_GUARD_OUT="$(docker exec "${C_VPS}" leikwan_tools plan /opt/v6-rules/dual-cu.toml 2>&1)"; then
    fail "V3: plan accepted an unguarded IPv6 routing table"
fi
assert_contains "${NO_GUARD_OUT}" "unreachable" "V3 policy guard required"
docker exec "${C_VPS}" ip -6 rule add unreachable from "${VPS_CU_V6}/128" pref 203
docker exec "${C_VPS}" leikwan_tools check-prereqs --probe-remote "${JP_IP}" --probe-remote-v6 "${JP_V6}"
POLICY_APPLY="$(docker exec "${C_VPS}" leikwan_tools apply /opt/v6-rules/dual-cu.toml)"
assert_contains "${POLICY_APPLY}" "元数据" "V3 policy-only configuration change is persisted"
assert_contains "$(client_probe "${PUB_10}" 54206 "V3_POLICY_202_OK")" "LANDING=zouter-jp-v6 SRC=${VPS_CU_V6}" "V3 policy table 202 ok"

docker exec "${C_VPS}" ip -6 route del default via "${POLICY_GW}" dev eth1 table 202
assert_contains "$(docker exec "${C_VPS}" ip -6 route get "${JP_V6}" oif eth1)" "via ${GW_CU_V6}" "V3 alternate gateway still present"
if POL_FAIL_OUT="$(docker exec "${C_VPS}" leikwan_tools plan /opt/v6-rules/dual-cu.toml 2>&1)"; then
    fail "V3: plan accepted missing policy route"
fi
assert_contains "${POL_FAIL_OUT}" "IPv6 路由探测失败" "V3 policy table rejects main fallback"
POL_CT_BEFORE="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
POL_CU_BEFORE="$(get_v6_mangle_pkts EGRESS_CU_V6_JP)"
if client_probe "${PUB_10}" 54206 "V3_POLICY_OUTAGE" >/dev/null 2>&1; then
    fail "V3: rule fell back to the alternate gateway on the same interface"
fi
POL_CT_AFTER="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
POL_CU_AFTER="$(get_v6_mangle_pkts EGRESS_CU_V6_JP)"
echo "Policy outage SYN counters with same-NIC backup gateway: CT=${POL_CT_BEFORE}->${POL_CT_AFTER}, CU=${POL_CU_BEFORE}->${POL_CU_AFTER}"
[[ "${POL_CT_BEFORE}" == "${POL_CT_AFTER}" && "${POL_CU_BEFORE}" == "${POL_CU_AFTER}" ]] || fail "V3: SYN leaked during policy outage"
docker exec "${C_VPS}" ip -6 route replace default via "${POLICY_GW}" dev eth1 table 202
assert_contains "$(client_probe "${PUB_10}" 54206 "V3_POLICY_RECOVERED")" "ECHO=V3_POLICY_RECOVERED" "V3 policy route restored"

# Restore main-table config for V4/V5
docker exec "${C_VPS}" ip -6 rule del from "${VPS_CU_V6}/128" lookup 202
docker exec "${C_VPS}" ip -6 rule del unreachable from "${VPS_CU_V6}/128" pref 203
docker exec "${C_VPS}" ip -6 route flush table 202
docker exec "${C_VPS}" mv /tmp/config-main-v6.toml /etc/leikwan_tools/config.toml
docker exec "${C_VPS}" leikwan_tools apply /opt/v6-rules/dual-cu.toml
docker exec "${C_ROUTER}" ip -6 addr del "${POLICY_GW}/64" dev "${POLICY_ROUTER_IF}"

echo "--- Testing pending IPv6 source, rollback, and re-apply ---"
NEW_CU_SOURCE="${VPS_CU_V6%:*}:147"
docker exec "${C_VPS}" ip -6 addr add "${NEW_CU_SOURCE}/64" dev eth1 nodad
docker exec "${C_VPS}" cp /etc/leikwan_tools/config.toml /tmp/config-main-v6.toml
docker exec -i "${C_VPS}" python3 - "${VPS_CU_V6}" "${NEW_CU_SOURCE}" <<'PY'
from pathlib import Path
import sys

config = Path("/etc/leikwan_tools/config.toml")
old_source, new_source = sys.argv[1:]
contents = config.read_text()
assert contents.count(old_source) == 1
config.write_text(contents.replace(old_source, new_source, 1))
PY
PENDING_STATUS="$(docker exec "${C_VPS}" leikwan_tools status dual-v6-cu)"
assert_contains "${PENDING_STATUS}" "(${VPS_CU_V6}@eth1)" "V3 status reports applied source"
assert_contains "${PENDING_STATUS}" "待应用出口 : ${NEW_CU_SOURCE}@eth1" "V3 status reports pending source"
ROLLBACK_OUT="$(docker exec -i "${C_VPS}" env PYTHONPATH=/usr/local/lib/leikwan_tools python3 - <<'PY'
from unittest.mock import patch

from leikwan_tools import manager
from leikwan_tools.config import load_global_config

verify_service = manager._verify_unit_running_and_listening
verification_calls = 0

def inject_failure(*args, **kwargs):
    global verification_calls
    verification_calls += 1
    if verification_calls == 1:
        raise manager.ApplyError("IPv6 source change: injected service verification failure")
    return verify_service(*args, **kwargs)

cfg = load_global_config("/etc/leikwan_tools/config.toml")
with patch.object(manager, "_verify_unit_running_and_listening", side_effect=inject_failure):
    try:
        manager.apply_rule(cfg, "/opt/v6-rules/dual-cu.toml")
    except manager.ApplyError as exc:
        print(exc)
    else:
        raise AssertionError("Expected service verification failure")
assert verification_calls == 2
PY
)"
assert_contains "${ROLLBACK_OUT}" "已恢复原有规则配置、启用状态并重新拉起原运行实例" "V3 rollback restored active service"
ROLLED_BACK_REPLY="$(client_probe "${PUB_10}" 54206 "V3_SOURCE_ROLLBACK")"
echo "Rollback reply: ${ROLLED_BACK_REPLY}"
assert_contains "${ROLLED_BACK_REPLY}" "SRC=${VPS_CU_V6}" "V3 rollback restored old source on the wire"
docker exec "${C_VPS}" leikwan_tools apply /opt/v6-rules/dual-cu.toml
REAPPLIED_REPLY="$(client_probe "${PUB_10}" 54206 "V3_SOURCE_REAPPLIED")"
echo "Re-applied reply: ${REAPPLIED_REPLY}"
assert_contains "${REAPPLIED_REPLY}" "SRC=${NEW_CU_SOURCE}" "V3 apply switched to the new source"
assert_not_contains "$(docker exec "${C_VPS}" leikwan_tools status dual-v6-cu)" "待应用出口" "V3 status agrees with re-applied source"
docker exec "${C_VPS}" mv /tmp/config-main-v6.toml /etc/leikwan_tools/config.toml
docker exec "${C_VPS}" leikwan_tools apply /opt/v6-rules/dual-cu.toml
docker exec "${C_VPS}" ip -6 addr del "${NEW_CU_SOURCE}/64" dev eth1

echo "=== [V4] Negative validations (missing IPv6, wrong NIC, deprecated, family mismatch) & Menu ==="
docker exec -i "${C_VPS}" python3 - "${VPS_CT_V6}" "${VPS_CU_V6}" "${JP_IP}" "${JP_V6}" "${VPS_9929_IP}" <<'PY'
import subprocess, sys
ct_v6, cu_v6, jp_v4, jp_v6, vps_9929 = sys.argv[1:6]
cfg = open("/etc/leikwan_tools/config.toml", encoding="utf-8").read()

# 1) Wrong NIC: cu_v6 IP configured on eth0 instead of eth1
open("/tmp/cfg-wrong-nic.toml", "w").write(cfg.replace(f'interface = "eth1"\nsource_ip = "{cu_v6}"', f'interface = "eth0"\nsource_ip = "{cu_v6}"'))
p1 = subprocess.run(["leikwan_tools", "--config", "/tmp/cfg-wrong-nic.toml", "plan", "/opt/v6-rules/dual-cu.toml"], capture_output=True, text=True)
assert p1.returncode != 0 and "不在指定网卡 eth0 上" in (p1.stdout + p1.stderr) and "eth1" in (p1.stdout + p1.stderr), p1.stdout + p1.stderr

# 2) Missing IPv6 source
open("/tmp/cfg-missing-v6.toml", "w").write(cfg.replace(cu_v6, "2408:fe00:dead::999"))
p2 = subprocess.run(["leikwan_tools", "--config", "/tmp/cfg-missing-v6.toml", "plan", "/opt/v6-rules/dual-cu.toml"], capture_output=True, text=True)
assert p2.returncode != 0 and "缺少源 IPv6" in (p2.stdout + p2.stderr), p2.stdout + p2.stderr

# 3) Deprecated (preferred_lft 0) IPv6 source
dep_ip = cu_v6.rsplit("::", 1)[0] + "::deaf"
subprocess.run(["ip", "-6", "addr", "add", f"{dep_ip}/64", "dev", "eth1", "preferred_lft", "0", "nodad"], check=True)
try:
    open("/tmp/cfg-dep-v6.toml", "w").write(cfg.replace(cu_v6, dep_ip))
    p3 = subprocess.run(["leikwan_tools", "--config", "/tmp/cfg-dep-v6.toml", "plan", "/opt/v6-rules/dual-cu.toml"], capture_output=True, text=True)
    assert p3.returncode != 0 and ("deprecated" in (p3.stdout + p3.stderr) or "preferred_lft=0" in (p3.stdout + p3.stderr)), p3.stdout + p3.stderr
finally:
    subprocess.run(["ip", "-6", "addr", "del", f"{dep_ip}/64", "dev", "eth1"], check=False)

# 4) Family mismatches: IPv6 remote + IPv4 line; IPv4 remote + IPv6 line
open("/tmp/rule-v6-on-v4line.toml", "w").write(f'[rule]\nname = "bad1"\nline = "cn2"\n[ingress]\npublic_port = 54210\n[forward]\nlisten_ip = "{vps_9929}"\nlisten_port = 10020\nremote_ip = "{jp_v6}"\nremote_port = 54141\n')
p4 = subprocess.run(["leikwan_tools", "plan", "/tmp/rule-v6-on-v4line.toml"], capture_output=True, text=True)
assert p4.returncode != 0 and "地址族" in (p4.stdout + p4.stderr), p4.stdout + p4.stderr

open("/tmp/rule-v4-on-v6line.toml", "w").write(f'[rule]\nname = "bad2"\nline = "cu_v6"\n[ingress]\npublic_port = 54211\n[forward]\nlisten_ip = "{vps_9929}"\nlisten_port = 10021\nremote_ip = "{jp_v4}"\nremote_port = 54141\n')
p5 = subprocess.run(["leikwan_tools", "plan", "/tmp/rule-v4-on-v6line.toml"], capture_output=True, text=True)
assert p5.returncode != 0 and "地址族" in (p5.stdout + p5.stderr), p5.stdout + p5.stderr
print("All 5 negative validation assertions passed.")
PY

# Interactive menu 2 -> 2 create rule with IPv6 landing filtering lines to IPv6 only
MENU_V6_OUT="$(printf '2\n2\nmenu-v6\n%s\n54209\n%s\n54141\ncu_v6\ny\n0\n0\n' "${VPS_CT_V6}" "${JP_V6}" | docker exec -i "${C_VPS}" lqtool menu)"
echo "${MENU_V6_OUT}"
assert_contains "${MENU_V6_OUT}" "cu_v6（IPV6" "V4 menu shows cu_v6"
assert_contains "${MENU_V6_OUT}" "ct_v6（IPV6" "V4 menu shows ct_v6"
assert_not_contains "${MENU_V6_OUT}" "9929（IPV4" "V4 menu hides IPv4 9929"
assert_not_contains "${MENU_V6_OUT}" "cn2（IPV4" "V4 menu hides IPv4 cn2"
assert_contains "$(client_probe "${VPS_CT_V6}" 54209 "MENU_V6_OK")" "LANDING=zouter-jp-v6 SRC=${VPS_CU_V6}" "V4 menu rule live probe"
docker exec "${C_VPS}" leikwan_tools delete menu-v6

echo "=== [V5] IPv6 Boot Delay Race (5s delay) & docker restart full recovery ==="
docker exec "${C_VPS}" mkdir -p /etc/systemd/system/mock-leikwan-pbr.service.d
docker exec -i "${C_VPS}" tee /etc/systemd/system/mock-leikwan-pbr.service.d/delay.conf >/dev/null <<'EOF'
[Unit]
DefaultDependencies=yes
After=network-online.target
Before=
[Service]
TimeoutStartSec=30
EOF
docker exec "${C_VPS}" bash -lc 'echo 5 > /etc/liqun-lab-delay-v6 && systemctl daemon-reload'

CT_BOOT0="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
CU_BOOT0="$(get_v6_mangle_pkts EGRESS_CU_V6_JP)"
docker restart "${C_VPS}" >/dev/null
sleep 2
BOOT_SNAP="$(docker exec "${C_VPS}" bash -lc 'echo "pbr=$(systemctl is-active mock-leikwan-pbr.service || true) c2_active=$(systemctl is-active leikwan_tools-realm@combo2-v6-to-v6.service || true) c2_sub=$(systemctl show -p SubState --value leikwan_tools-realm@combo2-v6-to-v6.service)"' || true)"
echo "Mid-boot snapshot during 5s IPv6 delay: ${BOOT_SNAP}"

ALL_UNITS=(
    leikwan_tools-realm@combo1-v6-to-v4.service
    leikwan_tools-realm@combo2-v6-to-v6.service
    leikwan_tools-realm@combo3-bgp-to-v4.service
    leikwan_tools-realm@combo4-bgp-to-v6.service
    leikwan_tools-realm@dual-v6-ct.service
    leikwan_tools-realm@dual-v6-cu.service
)
for _ in $(seq 1 40); do
    pbr_st="$(docker exec "${C_VPS}" systemctl is-active mock-leikwan-pbr.service 2>/dev/null || true)"
    all_up=1
    for u in "${ALL_UNITS[@]}"; do
        if ! docker exec "${C_VPS}" systemctl is-active --quiet "${u}" 2>/dev/null; then
            all_up=0
            break
        fi
    done
    if [[ "${pbr_st}" == "active" && "${all_up}" -eq 1 ]]; then
        break
    fi
    sleep 1
done

for u in "${ALL_UNITS[@]}"; do
    docker exec "${C_VPS}" systemctl is-active --quiet "${u}" || fail "V5: ${u} failed to auto-recover after reboot"
done

CT_BOOT1="$(get_v6_mangle_pkts EGRESS_CT_V6_JP)"
CU_BOOT1="$(get_v6_mangle_pkts EGRESS_CU_V6_JP)"
[[ "${CT_BOOT1}" -eq "${CT_BOOT0}" && "${CU_BOOT1}" -eq "${CU_BOOT0}" ]] || fail "V5: leaked SYNs during boot wait"

assert_contains "$(client_probe "${VPS_CT_V6}" 54201 "BOOT_C1")" "LANDING=zouter-jp-v4 SRC=${VPS_CN2_IP}" "V5 boot combo1"
assert_contains "$(client_probe "${VPS_CT_V6}" 54202 "BOOT_C2")" "LANDING=zouter-jp-v6 SRC=${VPS_CU_V6}" "V5 boot combo2"
assert_contains "$(client_probe "${PUB_10}" 54141 "BOOT_C3")" "LANDING=zouter-jp-v4 SRC=${VPS_CN2_IP}" "V5 boot combo3"
assert_contains "$(client_probe "${PUB_10}" 54204 "BOOT_C4")" "LANDING=zouter-jp-v6 SRC=${VPS_CU_V6}" "V5 boot combo4"
assert_contains "$(client_probe "${PUB_10}" 54205 "BOOT_DUAL_CT")" "LANDING=zouter-jp-v6 SRC=${VPS_CT_V6}" "V5 boot dual-ct"
assert_contains "$(client_probe "${PUB_10}" 54206 "BOOT_DUAL_CU")" "LANDING=zouter-jp-v6 SRC=${VPS_CU_V6}" "V5 boot dual-cu"
echo "Post-boot all 6 live probes succeeded!"

echo "=== [V6] Cleanup boot delay drop-in, purge uninstall & verify legacy sentinels ==="
docker exec "${C_VPS}" rm -rf /etc/systemd/system/mock-leikwan-pbr.service.d /etc/liqun-lab-delay-v6
docker exec "${C_VPS}" systemctl daemon-reload
SENTINEL_BEFORE="$(docker exec "${C_VPS}" sha256sum /usr/local/bin/Toolkit /usr/local/bin/LeiKwanManager /root/v6-mng.sh /usr/local/bin/realm /etc/legacy-realm.toml)"
docker exec "${C_VPS}" bash -lc 'cd /opt/src/leikwan_tools && bash uninstall.sh --purge'
SENTINEL_AFTER="$(docker exec "${C_VPS}" sha256sum /usr/local/bin/Toolkit /usr/local/bin/LeiKwanManager /root/v6-mng.sh /usr/local/bin/realm /etc/legacy-realm.toml)"
[[ "${SENTINEL_BEFORE}" == "${SENTINEL_AFTER}" ]] || fail "V6: sentinel checksums changed!"
docker exec "${C_VPS}" systemctl is-active --quiet legacy-realm.service || fail "V6: legacy-realm stopped"

echo ""
echo "========================================================================"
echo "ALL ISOLATED DEBIAN 12 + SYSTEMD IPv6 LANDING & EGRESS TESTS PASSED (V1 - V6)"
echo "========================================================================"
