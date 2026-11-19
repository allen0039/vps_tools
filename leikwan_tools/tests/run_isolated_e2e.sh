#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
E2E_DIR="${SCRIPT_DIR}/isolated_e2e"
OUT_DIR="${LIQUN_TEST_OUT_DIR:-${PROJECT_DIR}/test-results-r2}"
mkdir -p "${OUT_DIR}"

LOG_FILE="${OUT_DIR}/isolated-e2e-output.txt"
exec > >(tee "${LOG_FILE}") 2>&1

# shellcheck disable=SC1091
source "${E2E_DIR}/lab_common.sh"
lab_init_vars "e2e"
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
        fail "${label}: expected to find '${needle}' in output:\n${haystack}"
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local label="${3:-assertion}"
    if grep -Fq -- "${needle}" <<< "${haystack}"; then
        fail "${label}: did NOT expect to find '${needle}' in output:\n${haystack}"
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

get_mangle_pkts() {
    local comment="$1"
    docker exec "${C_ROUTER}" iptables -t mangle -L PREROUTING -v -n -x | awk -v c="${comment}" '$0 ~ c {print $1; exit}'
}

lab_build_images "${E2E_DIR}"
lab_create_networks_and_env
lab_start_containers

echo "=== [T1] Checking Debian 12 systemd baseline ==="
SYS_STATE="$(docker exec "${C_VPS}" systemctl is-system-running || true)"
echo "systemd state: ${SYS_STATE}"
[[ "${SYS_STATE}" == "running" ]] || fail "T1: expected systemd state=running, got ${SYS_STATE}"

docker exec "${C_VPS}" systemctl is-active --quiet mock-leikwan-pbr.service || fail "T1: mock-leikwan-pbr inactive"
docker exec "${C_VPS}" systemctl is-active --quiet legacy-realm.service || fail "T1: legacy-realm inactive"

SENTINEL_BEFORE="$(docker exec "${C_VPS}" sha256sum /usr/local/bin/Toolkit /usr/local/bin/LeiKwanManager /root/v6-mng.sh /usr/local/bin/realm /etc/legacy-realm.toml)"
RULES_BEFORE="$(docker exec "${C_VPS}" ip -4 rule show)"
MAIN_ROUTE_BEFORE="$(docker exec "${C_VPS}" ip -4 route show table main | sort)"
T101_BEFORE="$(docker exec "${C_VPS}" ip -4 route show table 101 | sort)"
T102_BEFORE="$(docker exec "${C_VPS}" ip -4 route show table 102 | sort)"
IPTABLES_BEFORE="$(docker exec "${C_VPS}" iptables-save | grep -v '^#' | grep -v 'DOCKER_' | sed -E 's/\[[0-9]+:[0-9]+\]/[0:0]/g' || true)"
echo "Baseline sentinels:"
echo "${SENTINEL_BEFORE}"

echo "=== [Setup] Copying local leikwan_tools source into VPS and client (no internet access needed) ==="
docker exec "${C_VPS}" mkdir -p /opt/src/leikwan_tools
docker cp "${PROJECT_DIR}/." "${C_VPS}:/opt/src/leikwan_tools/"
docker exec "${C_CLIENT}" mkdir -p /usr/local/lib/leikwan_tools
docker cp "${PROJECT_DIR}/leikwan_tools" "${C_CLIENT}:/usr/local/lib/leikwan_tools/leikwan_tools"
docker cp "${PROJECT_DIR}/bin/leikwan_tools" "${C_CLIENT}:/usr/local/bin/leikwan_tools"
docker exec "${C_CLIENT}" chmod +x /usr/local/bin/leikwan_tools

echo "=== [T2] Realm SHA-256 verification, reuse mode, tarball install, zero default rules ==="
set +e
BAD_TAR_OUT="$(docker exec "${C_VPS}" bash -lc 'cd /opt/src/leikwan_tools && python3 -c "from leikwan_tools.realm import install_realm_binary; install_realm_binary(target_path=\"/tmp/r\", tarball_path=\"/opt/cache/bad-realm.tar.gz\", state_dir=\"/tmp\")"' 2>&1)"
BAD_TAR_RC=$?
set -e
echo "Tampered tarball output: ${BAD_TAR_OUT}"
[[ ${BAD_TAR_RC} -ne 0 ]] || fail "T2: tampered realm tarball unexpectedly succeeded"
assert_contains "${BAD_TAR_OUT}" "SHA-256 校验失败" "T2 tampered sha256"

# First verify auto-reuse of existing /usr/local/bin/realm via install.sh (no flags), then uninstall and install managed tarball.
REUSE_OUT="$(docker exec "${C_VPS}" bash -lc 'cd /opt/src/leikwan_tools && bash install.sh')"
echo "${REUSE_OUT}"
assert_contains "${REUSE_OUT}" "发现并复用已有兼容 Realm: /usr/local/bin/realm" "T2 reuse install"
docker exec "${C_VPS}" bash -lc 'cd /opt/src/leikwan_tools && bash uninstall.sh --purge'

INSTALL_OUT="$(docker exec "${C_VPS}" bash -lc 'cd /opt/src/leikwan_tools && bash install.sh --realm-tarball /opt/cache/realm-v2.9.6.tar.gz')"
echo "${INSTALL_OUT}"
assert_contains "${INSTALL_OUT}" "Realm 已安装" "T2 tarball install"
docker exec "${C_VPS}" test -x /usr/local/lib/leikwan_tools/bin/realm || fail "T2: managed realm binary missing"
docker exec "${C_VPS}" cat /var/lib/leikwan_tools/realm-source.json

STATUS_EMPTY="$(docker exec "${C_VPS}" leikwan_tools status)"
echo "Initial status: ${STATUS_EMPTY}"
assert_contains "${STATUS_EMPTY}" "当前没有已部署的托管规则" "T2 zero default rules"

# Update /etc/leikwan_tools/config.toml to match allocated subnet variables + mock DNS server.
docker exec -i "${C_VPS}" python3 - "${GW_PUB}" "${VPS_9929_IP}" "${GW_9929}" "${VPS_CN2_IP}" "${GW_CN2}" <<'PY'
import sys
gw_pub, vps_9929, gw_9929, vps_cn2, gw_cn2 = sys.argv[1:6]
p = "/etc/leikwan_tools/config.toml"
txt = open(p, encoding="utf-8").read()
txt = txt.replace('dns_server = ""', f'dns_server = "{gw_pub}"', 1)
txt = txt.replace('10.7.0.146', vps_9929).replace('10.7.0.1', gw_9929)
txt = txt.replace('10.8.0.146', vps_cn2).replace('10.8.0.1', gw_cn2)
open(p, "w", encoding="utf-8").write(txt)
PY

PREREQ_OUT="$(docker exec "${C_VPS}" leikwan_tools check-prereqs --probe-remote "${JP_IP}")"
echo "${PREREQ_OUT}"
assert_contains "${PREREQ_OUT}" "线路 9929 [通过]" "T2 prereq 9929"
assert_contains "${PREREQ_OUT}" "线路 cn2 [通过]" "T2 prereq cn2"

echo "=== [T3] Same inbound mapping (${VPS_9929_IP}:10001) routed via 9929 then switched to CN2 ==="
docker exec -i "${C_VPS}" tee /tmp/rule-zouter-9929.toml >/dev/null <<EOF
[rule]
name = "zouter-jp"
description = "Zouter JP rule via 9929"
line = "9929"

[ingress]
domain = "paid-v4.bgp1.leikwanhost.com"
fixed_ip = ""
public_port = 54141

[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10001
remote_ip = "${JP_IP}"
remote_port = 54141

[realm]
log_level = "warn"
EOF

PLAN_OUT="$(docker exec "${C_VPS}" leikwan_tools plan /tmp/rule-zouter-9929.toml)"
echo "${PLAN_OUT}"
assert_contains "${PLAN_OUT}" "[CREATE]" "T3 plan"
assert_contains "${PLAN_OUT}" "through = \"${VPS_9929_IP}\"" "T3 plan through"
assert_contains "${PLAN_OUT}" 'interface = "eth0"' "T3 plan interface"
docker exec "${C_VPS}" test ! -e /etc/leikwan_tools/rules.d/zouter-jp.toml || fail "T3: plan wrote rule file"

APPLY_9929="$(docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-zouter-9929.toml)"
echo "${APPLY_9929}"
assert_contains "${APPLY_9929}" "已创建并启用" "T3 apply 9929"

PKT_9929_BEFORE="$(get_mangle_pkts EGRESS_9929_JP)"
PKT_CN2_BEFORE="$(get_mangle_pkts EGRESS_CN2_JP)"
RESP_9929="$(client_probe "${PUB_10}" 54141 TEST_9929)"
PKT_9929_AFTER="$(get_mangle_pkts EGRESS_9929_JP)"
PKT_CN2_AFTER="$(get_mangle_pkts EGRESS_CN2_JP)"
echo "Client probe (9929): ${RESP_9929} | mangle 9929: ${PKT_9929_BEFORE}->${PKT_9929_AFTER}, cn2: ${PKT_CN2_BEFORE}->${PKT_CN2_AFTER}"
assert_contains "${RESP_9929}" "LANDING=zouter-jp-mock SRC=${VPS_9929_IP}" "T3 9929 client reply"
assert_contains "${RESP_9929}" "ECHO=TEST_9929" "T3 9929 echo"
[[ "${PKT_9929_AFTER}" -gt "${PKT_9929_BEFORE}" && "${PKT_CN2_AFTER}" -eq "${PKT_CN2_BEFORE}" ]] || fail "T3: 9929 mangle counter mismatch"

docker exec -i "${C_VPS}" tee /tmp/rule-zouter-cn2.toml >/dev/null <<EOF
[rule]
name = "zouter-jp"
description = "Zouter JP rule switched to CN2"
line = "cn2"

[ingress]
domain = "paid-v4.bgp1.leikwanhost.com"
fixed_ip = ""
public_port = 54141

[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10001
remote_ip = "${JP_IP}"
remote_port = 54141

[realm]
log_level = "warn"
EOF

APPLY_CN2="$(docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-zouter-cn2.toml)"
echo "${APPLY_CN2}"
assert_contains "${APPLY_CN2}" "已更新并重启" "T3 apply cn2"

PKT_9929_BEFORE2="$(get_mangle_pkts EGRESS_9929_JP)"
PKT_CN2_BEFORE2="$(get_mangle_pkts EGRESS_CN2_JP)"
RESP_CN2="$(client_probe "${PUB_10}" 54141 TEST_CN2)"
PKT_9929_AFTER2="$(get_mangle_pkts EGRESS_9929_JP)"
PKT_CN2_AFTER2="$(get_mangle_pkts EGRESS_CN2_JP)"
echo "Client probe (CN2): ${RESP_CN2} | mangle 9929: ${PKT_9929_BEFORE2}->${PKT_9929_AFTER2}, cn2: ${PKT_CN2_BEFORE2}->${PKT_CN2_AFTER2}"
assert_contains "${RESP_CN2}" "LANDING=zouter-jp-mock SRC=${VPS_CN2_IP}" "T3 CN2 client reply"
assert_contains "${RESP_CN2}" "ECHO=TEST_CN2" "T3 CN2 echo"
[[ "${PKT_CN2_AFTER2}" -gt "${PKT_CN2_BEFORE2}" && "${PKT_9929_AFTER2}" -eq "${PKT_9929_BEFORE2}" ]] || fail "T3: CN2 mangle counter mismatch"

echo "=== [T4] Multi-rule coexistence, distinct 3 ports, & isolated update ==="
docker exec -i "${C_VPS}" tee /tmp/rule-rfc-hk.toml >/dev/null <<EOF
[rule]
name = "rfc-hk"
description = "RFC HK rule via 9929"
line = "9929"

[ingress]
domain = "paid-v4.bgp1.leikwanhost.com"
fixed_ip = ""
public_port = 54848

[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10003
remote_ip = "${HK_IP}"
remote_port = 54848

[realm]
log_level = "warn"
EOF

APPLY_HK="$(docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-rfc-hk.toml)"
echo "${APPLY_HK}"
HK_PID_BEFORE="$(docker exec "${C_VPS}" systemctl show -p MainPID --value leikwan_tools-realm@rfc-hk.service)"
RESP_HK_1="$(client_probe "${PUB_10}" 54848 HK_BEFORE)"
echo "HK probe before updating JP: ${RESP_HK_1} (MainPID=${HK_PID_BEFORE})"
assert_contains "${RESP_HK_1}" "LANDING=rfc-hk-mock SRC=${VPS_9929_IP}" "T4 HK before"

docker exec "${C_VPS}" python3 -c 'open("/tmp/rule-zouter-cn2.toml", "a").write("tcp_timeout = 6\n")'
APPLY_JP_UPDATE="$(docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-zouter-cn2.toml)"
echo "${APPLY_JP_UPDATE}"
HK_PID_AFTER="$(docker exec "${C_VPS}" systemctl show -p MainPID --value leikwan_tools-realm@rfc-hk.service)"
[[ "${HK_PID_BEFORE}" == "${HK_PID_AFTER}" && -n "${HK_PID_AFTER}" ]] || fail "T4: rfc-hk MainPID changed (${HK_PID_BEFORE} -> ${HK_PID_AFTER})"
RESP_HK_2="$(client_probe "${PUB_10}" 54848 HK_AFTER)"
assert_contains "${RESP_HK_2}" "LANDING=rfc-hk-mock SRC=${VPS_9929_IP}" "T4 HK after"

docker exec -i "${C_VPS}" tee /tmp/rule-three-ports.toml >/dev/null <<EOF
[rule]
name = "three-ports"
description = "Independent public/listen/remote ports via CN2"
line = "cn2"
[ingress]
public_port = 54999
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10009
remote_ip = "${HK_IP}"
remote_port = 54848
EOF
docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-three-ports.toml
RESP_3P="$(client_probe "${PUB_10}" 54999 THREE_PORTS)"
echo "3-distinct-ports probe (54999->10009->54848 via CN2): ${RESP_3P}"
assert_contains "${RESP_3P}" "LANDING=rfc-hk-mock SRC=${VPS_CN2_IP}" "T4 3 distinct ports src"
assert_contains "${RESP_3P}" "ECHO=THREE_PORTS" "T4 3 distinct ports echo"
docker exec "${C_VPS}" leikwan_tools delete three-ports

BIDIR_OUT="$(docker exec -i "${C_CLIENT}" python3 - "${PUB_10}" <<'PY'
import socket, sys
s = socket.create_connection((sys.argv[1], 54141), timeout=5)
f = s.makefile("rw", encoding="utf-8", newline="\n")
f.write("BIDIR_MSG_1\n")
f.flush()
r1 = f.readline().strip()
f.write("BIDIR_MSG_2\n")
f.flush()
r2 = f.readline().strip()
f.close()
s.close()
print(r1 + " | " + r2)
PY
)"
echo "Bidirectional multi-turn probe: ${BIDIR_OUT}"
assert_contains "${BIDIR_OUT}" "ECHO=BIDIR_MSG_1" "T4 bidir 1"
assert_contains "${BIDIR_OUT}" "ECHO=BIDIR_MSG_2" "T4 bidir 2"

echo "=== [T5] Idempotent re-apply & concurrent lock contention ==="
JP_PID_1="$(docker exec "${C_VPS}" systemctl show -p MainPID --value leikwan_tools-realm@zouter-jp.service)"
NOOP_OUT="$(docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-zouter-cn2.toml)"
echo "${NOOP_OUT}"
assert_contains "${NOOP_OUT}" "幂等跳过" "T5 idempotent noop"
JP_PID_2="$(docker exec "${C_VPS}" systemctl show -p MainPID --value leikwan_tools-realm@zouter-jp.service)"
[[ "${JP_PID_1}" == "${JP_PID_2}" ]] || fail "T5: idempotent apply restarted service (${JP_PID_1} -> ${JP_PID_2})"

LOCK_TEST_OUT="$(docker exec "${C_VPS}" env PYTHONPATH=/usr/local/lib/leikwan_tools python3 -c '
import subprocess
from leikwan_tools.system import FileLock
with FileLock("/run/leikwan_tools.lock", timeout=2.0):
    res = subprocess.run(["leikwan_tools", "apply", "/tmp/rule-zouter-cn2.toml", "--lock-timeout", "0.3"], capture_output=True, text=True)
    print("rc=", res.returncode)
    print(res.stdout + res.stderr)
')"
echo "${LOCK_TEST_OUT}"
assert_contains "${LOCK_TEST_OUT}" "rc= 1" "T5 lock rc"
assert_contains "${LOCK_TEST_OUT}" "获取并发写锁超时" "T5 lock msg"

echo "=== [T6] Exact and wildcard port conflicts (without killing occupying processes) ==="
docker exec -d "${C_VPS}" python3 -c "import socket, time; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', 10005)); s.listen(5); time.sleep(60)"
docker exec -d "${C_VPS}" python3 -c "import socket, time; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('${VPS_9929_IP}', 10006)); s.listen(5); time.sleep(60)"
sleep 0.5
CONFLICT_PIDS_BEFORE="$(docker exec "${C_VPS}" ss -H -ltnp '( sport = :10005 or sport = :10006 )')"
echo "Pre-existing listeners:"
echo "${CONFLICT_PIDS_BEFORE}"

docker exec -i "${C_VPS}" tee /tmp/rule-conflict-wild.toml >/dev/null <<EOF
[rule]
name = "conflict-wild"
line = "9929"
[ingress]
public_port = 54105
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10005
remote_ip = "${JP_IP}"
remote_port = 54141
EOF

docker exec -i "${C_VPS}" tee /tmp/rule-conflict-exact.toml >/dev/null <<EOF
[rule]
name = "conflict-exact"
line = "9929"
[ingress]
public_port = 54106
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10006
remote_ip = "${JP_IP}"
remote_port = 54141
EOF

set +e
WILD_OUT="$(docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-conflict-wild.toml 2>&1)"
WILD_RC=$?
EXACT_OUT="$(docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-conflict-exact.toml 2>&1)"
EXACT_RC=$?
set -e
echo "Wildcard conflict: ${WILD_OUT}"
echo "Exact conflict: ${EXACT_OUT}"
[[ ${WILD_RC} -ne 0 && ${EXACT_RC} -ne 0 ]] || fail "T6: conflict should fail"
assert_contains "${WILD_OUT}" "通配端口冲突" "T6 wildcard type"
assert_contains "${EXACT_OUT}" "精确地址冲突" "T6 exact type"

CONFLICT_PIDS_AFTER="$(docker exec "${C_VPS}" ss -H -ltnp '( sport = :10005 or sport = :10006 )')"
[[ "${CONFLICT_PIDS_BEFORE}" == "${CONFLICT_PIDS_AFTER}" ]] || fail "T6: occupying processes were killed or altered!"
docker exec "${C_VPS}" test ! -e /etc/leikwan_tools/rules.d/conflict-wild.toml || fail "T6: stray rule created"

echo "=== [T7] Route mismatch / missing policy rule must fail loudly without silent line switch ==="
docker exec "${C_VPS}" ip -4 rule del from "${VPS_CN2_IP}" lookup 102
set +e
MISSING_RULE_OUT="$(docker exec "${C_VPS}" leikwan_tools plan /tmp/rule-zouter-cn2.toml 2>&1)"
MISSING_RULE_RC=$?
set -e
echo "${MISSING_RULE_OUT}"
[[ ${MISSING_RULE_RC} -ne 0 ]] || fail "T7: missing table 102 rule should fail"
assert_contains "${MISSING_RULE_OUT}" "严禁静默切到其他线路" "T7 no silent fallback"

docker exec "${C_VPS}" ip -4 rule add from "${VPS_CN2_IP}" lookup 102 pref 102

docker exec "${C_VPS}" bash -lc 'sed "s/line = \"cn2\"/line = \"nonexistent\"/" /tmp/rule-zouter-cn2.toml > /tmp/rule-bad-line.toml'
set +e
BAD_LINE_OUT="$(docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-bad-line.toml 2>&1)"
BAD_LINE_RC=$?
set -e
[[ ${BAD_LINE_RC} -ne 0 ]] || fail "T7: unknown line should fail"
assert_contains "${BAD_LINE_OUT}" "不存在" "T7 unknown line"

echo "=== [T8] Failure rollback (first create cleanup + existing active rule restore + disabled rule restore) ==="
docker exec -i "${C_VPS}" tee /opt/failing-realm.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    --version) echo "realm 2.9.6"; exit 0 ;;
    --help) echo "Usage: realm -c --config -x --through -i --interface"; exit 0 ;;
    *) echo "simulated realm crash on start" >&2; exit 42 ;;
esac
EOF
docker exec "${C_VPS}" chmod +x /opt/failing-realm.sh
docker exec "${C_VPS}" bash -lc 'sed "s|realm_bin = \"\"|realm_bin = \"/opt/failing-realm.sh\"|" /etc/leikwan_tools/config.toml > /tmp/config-failing.toml'

docker exec -i "${C_VPS}" tee /tmp/rule-fail-new.toml >/dev/null <<EOF
[rule]
name = "fail-new"
line = "9929"
[ingress]
public_port = 54199
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10099
remote_ip = "${JP_IP}"
remote_port = 54141
EOF

set +e
RB_NEW_OUT="$(docker exec "${C_VPS}" leikwan_tools --config /tmp/config-failing.toml apply /tmp/rule-fail-new.toml 2>&1)"
RB_NEW_RC=$?
set -e
echo "8a rollback output:"
echo "${RB_NEW_OUT}"
[[ ${RB_NEW_RC} -ne 0 ]] || fail "T8a: expected failure"
assert_contains "${RB_NEW_OUT}" "首次创建失败，已停用单元并清理本次生成的规则与运行文件" "T8a cleanup msg"
docker exec "${C_VPS}" test ! -e /etc/leikwan_tools/rules.d/fail-new.toml || fail "T8a: rule file leaked"
docker exec "${C_VPS}" test ! -e /var/lib/leikwan_tools/realm/fail-new.toml || fail "T8a: realm toml leaked"
docker exec "${C_VPS}" test ! -e /var/lib/leikwan_tools/state/fail-new.json || fail "T8a: state json leaked"

JP_RULE_BEFORE="$(docker exec "${C_VPS}" cat /etc/leikwan_tools/rules.d/zouter-jp.toml)"
JP_REALM_BEFORE="$(docker exec "${C_VPS}" cat /var/lib/leikwan_tools/realm/zouter-jp.toml)"
docker exec "${C_VPS}" bash -lc 'sed "s/tcp_timeout = 6/tcp_timeout = 9/" /tmp/rule-zouter-cn2.toml > /tmp/rule-zouter-fail-upd.toml'
set +e
RB_UPD_OUT="$(docker exec "${C_VPS}" leikwan_tools --config /tmp/config-failing.toml apply /tmp/rule-zouter-fail-upd.toml 2>&1)"
RB_UPD_RC=$?
set -e
echo "8b rollback output:"
echo "${RB_UPD_OUT}"
[[ ${RB_UPD_RC} -ne 0 ]] || fail "T8b: expected update failure"
assert_contains "${RB_UPD_OUT}" "已恢复原有规则配置、启用状态并重新拉起原运行实例" "T8b rollback msg"
JP_RULE_AFTER="$(docker exec "${C_VPS}" cat /etc/leikwan_tools/rules.d/zouter-jp.toml)"
JP_REALM_AFTER="$(docker exec "${C_VPS}" cat /var/lib/leikwan_tools/realm/zouter-jp.toml)"
[[ "${JP_RULE_BEFORE}" == "${JP_RULE_AFTER}" && "${JP_REALM_BEFORE}" == "${JP_REALM_AFTER}" ]] || fail "T8b: rule files not restored"
docker exec "${C_VPS}" systemctl is-active --quiet leikwan_tools-realm@zouter-jp.service || fail "T8b: zouter-jp not active after rollback"
RESP_AFTER_RB="$(client_probe "${PUB_10}" 54141 AFTER_ROLLBACK)"
assert_contains "${RESP_AFTER_RB}" "LANDING=zouter-jp-mock SRC=${VPS_CN2_IP}" "T8b live forwarding after rollback"

docker exec -i "${C_VPS}" tee /tmp/rule-stay-disabled.toml >/dev/null <<EOF
[rule]
name = "stay-disabled"
description = "Rule that stays disabled across failed update and reboot"
line = "9929"
[ingress]
public_port = 54188
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10088
remote_ip = "${JP_IP}"
remote_port = 54141
EOF
docker exec "${C_VPS}" leikwan_tools apply /tmp/rule-stay-disabled.toml
docker exec "${C_VPS}" leikwan_tools disable stay-disabled
docker exec "${C_VPS}" bash -lc 'sed "s/remote_port = 54141/remote_port = 54142/" /tmp/rule-stay-disabled.toml > /tmp/rule-stay-disabled-bad.toml'
set +e
RB_DIS_OUT="$(docker exec "${C_VPS}" leikwan_tools --config /tmp/config-failing.toml apply /tmp/rule-stay-disabled-bad.toml 2>&1)"
RB_DIS_RC=$?
set -e
[[ ${RB_DIS_RC} -ne 0 ]] || fail "T8c: expected failure"
assert_contains "${RB_DIS_OUT}" "已恢复原有规则配置与停用状态" "T8c disabled rollback"
! docker exec "${C_VPS}" systemctl is-enabled --quiet leikwan_tools-realm@stay-disabled.service || fail "T8c: rule re-enabled!"
! docker exec "${C_VPS}" systemctl is-active --quiet leikwan_tools-realm@stay-disabled.service || fail "T8c: rule active!"
docker exec "${C_VPS}" rm -f /opt/failing-realm.sh /tmp/config-failing.toml

echo "=== [T9] Real container reboot recovery (docker restart ${C_VPS}) ==="
docker restart "${C_VPS}" >/dev/null
for _ in $(seq 1 40); do
    STATE="$(docker exec "${C_VPS}" systemctl is-system-running 2>/dev/null || true)"
    if [[ "${STATE}" == "running" || "${STATE}" == "degraded" ]]; then
        break
    fi
    sleep 1
done
docker exec "${C_VPS}" systemctl is-active --quiet leikwan_tools-realm@zouter-jp.service || fail "T9: zouter-jp did not auto-recover on reboot"
docker exec "${C_VPS}" systemctl is-active --quiet leikwan_tools-realm@rfc-hk.service || fail "T9: rfc-hk did not auto-recover on reboot"
docker exec "${C_VPS}" systemctl is-active --quiet legacy-realm.service || fail "T9: legacy-realm did not recover"
! docker exec "${C_VPS}" systemctl is-active --quiet leikwan_tools-realm@stay-disabled.service || fail "T9: disabled rule started on reboot"

RESP_REBOOT_JP="$(client_probe "${PUB_10}" 54141 REBOOT_JP)"
RESP_REBOOT_HK="$(client_probe "${PUB_10}" 54848 REBOOT_HK)"
echo "Post-reboot probes: JP=[${RESP_REBOOT_JP}] HK=[${RESP_REBOOT_HK}]"
assert_contains "${RESP_REBOOT_JP}" "LANDING=zouter-jp-mock SRC=${VPS_CN2_IP}" "T9 reboot JP"
assert_contains "${RESP_REBOOT_HK}" "LANDING=rfc-hk-mock SRC=${VPS_9929_IP}" "T9 reboot HK"

echo "=== [T10] Public ingress query, 3-tier classification, selection, client verify, DNS disappearance ==="
CLIENT_Q_TCP="$(docker exec "${C_CLIENT}" leikwan_tools ingress query --domain paid-v4.bgp1.leikwanhost.com --port 54141)"
echo "${CLIENT_Q_TCP}"
assert_contains "${CLIENT_Q_TCP}" "查询时间" "T10 timestamp"
assert_contains "${CLIENT_Q_TCP}" "${PUB_10}:54141  [TCP 端口可达]" "T10 .10 tcp"
assert_contains "${CLIENT_Q_TCP}" "${PUB_12}:54141  [TCP 端口可达]" "T10 .12 decoy tcp"
assert_contains "${CLIENT_Q_TCP}" "${PUB_13}:54141  [DNS 候选]" "T10 .13 closed"

CLIENT_Q_LANDING="$(docker exec "${C_CLIENT}" leikwan_tools ingress query --domain paid-v4.bgp1.leikwanhost.com --port 54141 --verify-send 'PING\n' --verify-expect 'LANDING=zouter-jp-mock')"
echo "${CLIENT_Q_LANDING}"
assert_contains "${CLIENT_Q_LANDING}" "${PUB_10}:54141  [已验证到达指定落地]" "T10 .10 verified"
assert_contains "${CLIENT_Q_LANDING}" "${PUB_11}:54141  [已验证到达指定落地]" "T10 .11 verified"
assert_contains "${CLIENT_Q_LANDING}" "${PUB_12}:54141  [TCP 端口可达]" "T10 .12 decoy unverified"
assert_contains "${CLIENT_Q_LANDING}" "${PUB_13}:54141  [DNS 候选]" "T10 .13 unreachable"

JP_PID_BEFORE_SEL="$(docker exec "${C_VPS}" systemctl show -p MainPID --value leikwan_tools-realm@zouter-jp.service)"
SEL_OUT="$(docker exec "${C_VPS}" leikwan_tools ingress select --rule zouter-jp --ip "${PUB_11}")"
echo "${SEL_OUT}"
assert_contains "${SEL_OUT}" "客户端拨号地址/端口: ${PUB_11}:54141" "T10 dial addr"
assert_contains "${SEL_OUT}" "保持不变，未重启 Realm" "T10 realm untouched"
assert_contains "${SEL_OUT}" "禁止把 TLS SNI / Host 改成拨号 IP" "T10 protocol note"
JP_PID_AFTER_SEL="$(docker exec "${C_VPS}" systemctl show -p MainPID --value leikwan_tools-realm@zouter-jp.service)"
[[ "${JP_PID_BEFORE_SEL}" == "${JP_PID_AFTER_SEL}" ]] || fail "T10: ingress select restarted Realm"

CLIENT_VER_OUT="$(docker exec "${C_CLIENT}" leikwan_tools ingress verify --host "${PUB_11}" --port 54141 --send 'PING\n' --expect 'LANDING=zouter-jp-mock')"
echo "${CLIENT_VER_OUT}"
assert_contains "${CLIENT_VER_OUT}" "[已验证到达指定落地]" "T10 client verify"

docker exec -i "${C_ROUTER}" tee /tmp/dns_records.json >/dev/null <<EOF
{
  "paid-v4.bgp1.leikwanhost.com": [
    "${PUB_10}",
    "${PUB_12}",
    "${PUB_13}"
  ]
}
EOF

QUERY_STALE_OUT="$(docker exec "${C_VPS}" leikwan_tools ingress query --rule zouter-jp)"
echo "${QUERY_STALE_OUT}"
assert_contains "${QUERY_STALE_OUT}" "固定公网 IP ${PUB_11} 已从 paid-v4.bgp1.leikwanhost.com 当前 DNS A 记录中消失" "T10 query stale warning"
assert_contains "${QUERY_STALE_OUT}" "当前固定IP : ${PUB_11}" "T10 query fixed ip preserved"

STALE_OUT="$(docker exec "${C_VPS}" leikwan_tools status zouter-jp --check-dns)"
echo "${STALE_OUT}"
assert_contains "${STALE_OUT}" "固定公网 IP ${PUB_11} 已从 paid-v4.bgp1.leikwanhost.com 当前 DNS A 记录中消失" "T10 stale warning"
assert_contains "${STALE_OUT}" "固定公网IP : ${PUB_11}" "T10 fixed ip preserved"

echo "=== [T11] Disable, delete, uninstall & non-interference verification ==="
docker exec "${C_VPS}" leikwan_tools delete stay-disabled
docker exec "${C_VPS}" leikwan_tools disable rfc-hk
! docker exec "${C_VPS}" systemctl is-active --quiet leikwan_tools-realm@rfc-hk.service || fail "T11: rfc-hk still active after disable"
docker exec "${C_VPS}" test -f /etc/leikwan_tools/rules.d/rfc-hk.toml || fail "T11: disable removed rule config"

docker exec "${C_VPS}" leikwan_tools delete rfc-hk
docker exec "${C_VPS}" test ! -e /etc/leikwan_tools/rules.d/rfc-hk.toml || fail "T11: delete left rule config"
docker exec "${C_VPS}" systemctl is-active --quiet leikwan_tools-realm@zouter-jp.service || fail "T11: deleting rfc-hk impacted zouter-jp"

UNINSTALL_OUT="$(docker exec "${C_VPS}" bash -lc 'cd /opt/src/leikwan_tools && bash uninstall.sh --purge')"
echo "${UNINSTALL_OUT}"
docker exec "${C_VPS}" test ! -e /usr/local/bin/leikwan_tools || fail "T11: binary still exists"
docker exec "${C_VPS}" test ! -e /usr/local/lib/leikwan_tools || fail "T11: lib dir still exists"
docker exec "${C_VPS}" test ! -e /var/lib/leikwan_tools || fail "T11: state dir still exists"
docker exec "${C_VPS}" test ! -e /etc/leikwan_tools || fail "T11: config dir still exists"
docker exec "${C_VPS}" test ! -e /etc/systemd/system/leikwan_tools-realm@.service || fail "T11: systemd unit still exists"

docker exec "${C_VPS}" systemctl is-active --quiet legacy-realm.service || fail "T11: legacy-realm stopped!"
LEGACY_WAIT="$(docker exec -i "${C_VPS}" python3 - "${VPS_9929_IP}" <<'PY'
import socket, sys
s = socket.create_connection((sys.argv[1], 19999), 3)
s.sendall(b"LEGACY\n")
print(s.recv(4096).decode())
s.close()
PY
)"
echo "Legacy Realm forwarding probe after uninstall: ${LEGACY_WAIT}"
assert_contains "${LEGACY_WAIT}" "LANDING=rfc-hk-mock SRC=${VPS_9929_IP}" "T11 legacy realm alive"
assert_contains "${LEGACY_WAIT}" "ECHO=LEGACY" "T11 legacy realm echo"

SENTINEL_AFTER="$(docker exec "${C_VPS}" sha256sum /usr/local/bin/Toolkit /usr/local/bin/LeiKwanManager /root/v6-mng.sh /usr/local/bin/realm /etc/legacy-realm.toml)"
RULES_AFTER="$(docker exec "${C_VPS}" ip -4 rule show)"
MAIN_ROUTE_AFTER="$(docker exec "${C_VPS}" ip -4 route show table main | sort)"
T101_AFTER="$(docker exec "${C_VPS}" ip -4 route show table 101 | sort)"
T102_AFTER="$(docker exec "${C_VPS}" ip -4 route show table 102 | sort)"
IPTABLES_AFTER="$(docker exec "${C_VPS}" iptables-save | grep -v '^#' | grep -v 'DOCKER_' | sed -E 's/\[[0-9]+:[0-9]+\]/[0:0]/g' || true)"

[[ "${SENTINEL_BEFORE}" == "${SENTINEL_AFTER}" ]] || fail "T11: sentinel checksums changed!\nBEFORE:\n${SENTINEL_BEFORE}\nAFTER:\n${SENTINEL_AFTER}"
[[ "${RULES_BEFORE}" == "${RULES_AFTER}" ]] || fail "T11: ip rules changed!"
[[ "${MAIN_ROUTE_BEFORE}" == "${MAIN_ROUTE_AFTER}" ]] || fail "T11: main route changed!"
[[ "${T101_BEFORE}" == "${T101_AFTER}" ]] || fail "T11: table 101 changed!"
[[ "${T102_BEFORE}" == "${T102_AFTER}" ]] || fail "T11: table 102 changed!"
[[ "${IPTABLES_BEFORE}" == "${IPTABLES_AFTER}" ]] || fail "T11: iptables changed!\nBEFORE:\n${IPTABLES_BEFORE}\nAFTER:\n${IPTABLES_AFTER}"

echo ""
echo "========================================================================"
echo "ALL ISOLATED DEBIAN 12 + SYSTEMD E2E TESTS (T1 - T11) PASSED SUCCESSFULLY"
echo "========================================================================"
