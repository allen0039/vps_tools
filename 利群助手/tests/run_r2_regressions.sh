#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
E2E_DIR="${SCRIPT_DIR}/isolated_e2e"
OUT_DIR="${LIQUN_TEST_OUT_DIR:-${PROJECT_DIR}/test-results-r2}"
mkdir -p "${OUT_DIR}"

LOG_FILE="${OUT_DIR}/regression-r2-output.txt"
exec > >(tee "${LOG_FILE}") 2>&1

# shellcheck disable=SC1091
source "${E2E_DIR}/lab_common.sh"
lab_init_vars "r2reg"
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

client_probe() {
    local host="$1"
    local port="$2"
    local payload="${3:-PING}"
    docker exec -i "${C_CLIENT}" python3 - "${host}" "${port}" "${payload}" <<'PY'
import socket, sys
host, port, payload = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), timeout=4)
s.settimeout(4)
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

install_helper_on_vps() {
    local extra_args="$*"
    docker exec "${C_VPS}" bash -lc "cd /opt/src/liqun-helper && bash install.sh --realm-tarball /opt/cache/realm-v2.9.6.tar.gz ${extra_args}"
}

patch_vps_config_for_lab() {
    local cfg_file="$1"
    docker exec -i "${C_VPS}" python3 - "${cfg_file}" "${GW_PUB}" "${VPS_9929_IP}" "${GW_9929}" "${VPS_CN2_IP}" "${GW_CN2}" <<'PY'
import sys
cfg_file, gw_pub, vps_9929, gw_9929, vps_cn2, gw_cn2 = sys.argv[1:7]
txt = open(cfg_file, encoding="utf-8").read()
txt = txt.replace('dns_server = ""', f'dns_server = "{gw_pub}"', 1)
txt = txt.replace('10.7.0.146', vps_9929).replace('10.7.0.1', gw_9929)
txt = txt.replace('10.8.0.146', vps_cn2).replace('10.8.0.1', gw_cn2)
open(cfg_file, "w", encoding="utf-8").write(txt)
PY
}

lab_build_images "${E2E_DIR}"
lab_create_networks_and_env
lab_start_containers

docker exec "${C_VPS}" mkdir -p /opt/src/liqun-helper /opt/test-rules
docker cp "${PROJECT_DIR}/." "${C_VPS}:/opt/src/liqun-helper/"
docker exec "${C_CLIENT}" mkdir -p /usr/local/lib/liqun-helper
docker cp "${PROJECT_DIR}/liqun_helper" "${C_CLIENT}:/usr/local/lib/liqun-helper/liqun_helper"
docker cp "${PROJECT_DIR}/bin/liqun-helper" "${C_CLIENT}:/usr/local/bin/liqun-helper"
docker exec "${C_CLIENT}" chmod +x /usr/local/bin/liqun-helper

# ==============================================================================
# R1: Live route withdrawal zero-cross-line leak + delayed boot route race
# ==============================================================================
echo "=== [R1] Zero-leak runtime route loss & delayed boot PBR race ==="
install_helper_on_vps
patch_vps_config_for_lab "/etc/liqun-helper/config.toml"

docker exec -i "${C_VPS}" tee /opt/test-rules/r1-jp-cn2.toml >/dev/null <<EOF
[rule]
name = "zouter-jp"
line = "cn2"
[ingress]
public_port = 54141
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10001
remote_ip = "${JP_IP}"
remote_port = 54141
EOF

docker exec -i "${C_VPS}" tee /opt/test-rules/r1-hk-9929.toml >/dev/null <<EOF
[rule]
name = "rfc-hk"
line = "9929"
[ingress]
public_port = 54848
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10003
remote_ip = "${HK_IP}"
remote_port = 54848
EOF

docker exec "${C_VPS}" liqun-helper apply /opt/test-rules/r1-jp-cn2.toml
docker exec "${C_VPS}" liqun-helper apply /opt/test-rules/r1-hk-9929.toml

echo "--- [R1 Phase 1-3: Initial connection + continuous stream across CN2 policy rule withdrawal & recovery] ---"
R1_INIT_RES="$(client_probe "${PUB_10}" 54141 "R1_INIT")"
echo "Initial normal probe: ${R1_INIT_RES}"
assert_contains "${R1_INIT_RES}" "LANDING=zouter-jp-mock SRC=${VPS_CN2_IP}" "R1 init"

R1_STREAM_RES="$(python3 - "${C_CLIENT}" "${C_VPS}" "${C_ROUTER}" "${C_JP}" "${PUB_10}" "${VPS_CN2_IP}" "${VPS_9929_IP}" <<'PY'
import re
import subprocess
import sys
import threading
import time

c_client, c_vps, c_router, c_jp, pub10, vps_cn2, vps_9929 = sys.argv[1:8]

def get_syn_counters():
    out = subprocess.check_output(
        ["docker", "exec", c_router, "iptables", "-t", "mangle", "-L", "PREROUTING", "-v", "-n", "-x"],
        text=True,
    )
    c9929 = ccn2 = None
    for line in out.splitlines():
        fields = line.split()
        if not fields:
            continue
        if "EGRESS_9929_JP" in line:
            c9929 = int(fields[0])
        elif "EGRESS_CN2_JP" in line:
            ccn2 = int(fields[0])
    assert c9929 is not None and ccn2 is not None, f"Missing mangle counters in:\n{out}"
    return c9929, ccn2

worker_code = f"""
import socket, sys, threading, time
t0 = time.monotonic()
stop_evt = threading.Event()
def watch_stdin():
    for _ in sys.stdin:
        pass
    stop_evt.set()
threading.Thread(target=watch_stdin, daemon=True).start()
seq = 0
while not stop_evt.is_set():
    seq += 1
    payload = f"R1_STREAM_{{seq:04d}}"
    st_ts = time.monotonic() - t0
    try:
        s = socket.create_connection(({pub10!r}, 54141), timeout=1.2)
        s.settimeout(1.2)
        s.sendall((payload + "\\n").encode("utf-8"))
        data = s.recv(4096).decode("utf-8", errors="replace").strip()
        s.close()
        en_ts = time.monotonic() - t0
        if f"ECHO={{payload}}" in data:
            print(f"{{seq}}|OK|{{st_ts:.3f}}|{{en_ts:.3f}}|{{data}}", flush=True)
        else:
            print(f"{{seq}}|ERR|{{st_ts:.3f}}|{{en_ts:.3f}}|unexpected={{data!r}}", flush=True)
    except Exception as exc:
        en_ts = time.monotonic() - t0
        print(f"{{seq}}|ERR|{{st_ts:.3f}}|{{en_ts:.3f}}|{{type(exc).__name__}}: {{exc}}", flush=True)
    time.sleep(0.15)
"""

records = []
rec_lock = threading.Lock()
host_t0 = time.monotonic()
proc = subprocess.Popen(
    ["docker", "exec", "-i", c_client, "python3", "-u", "-c", worker_code],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

def reader():
    for line in proc.stdout:
        line = line.strip()
        parts = line.split("|", 4)
        if len(parts) == 5 and parts[0].isdigit():
            with rec_lock:
                records.append((int(parts[0]), parts[1], float(parts[2]), float(parts[3]), parts[4], round(time.monotonic() - host_t0, 3)))

t_read = threading.Thread(target=reader, daemon=True)
t_read.start()

try:
    syn_t0 = get_syn_counters()

    # Wait for >= 5 BEFORE stream connections
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        with rec_lock:
            before_cnt = len(records)
        if before_cnt >= 5:
            break
        time.sleep(0.1)
    with rec_lock:
        before_end_seq = records[-1][0] if records else 0
    syn_t1 = get_syn_counters()

    # Withdraw CN2 policy rule mid-stream while main table default remains 9929 (eth0)
    subprocess.run(
        ["docker", "exec", c_vps, "sh", "-c", f"ip -4 rule del from {vps_cn2} lookup 102 && ip -4 route flush cache"],
        check=True,
    )
    t_del_done = round(time.monotonic() - host_t0, 3)
    time.sleep(1.5)
    with rec_lock:
        outage_start_seq = (records[-1][0] + 1) if records else (before_end_seq + 1)
    syn_d0 = get_syn_counters()

    # Keep stream firing during outage + verify healthy 9929 rule rfc-hk
    hk_probe = subprocess.check_output(
        [
            "docker", "exec", "-i", c_client, "python3", "-c",
            f"import socket; s=socket.create_connection(({pub10!r},54848),timeout=3); "
            f"s.sendall(b'R1_HK_DURING\\n'); print(s.recv(4096).decode().strip()); s.close()",
        ],
        text=True,
    ).strip()
    assert f"LANDING=rfc-hk-mock SRC={vps_9929}" in hk_probe, f"9929 healthy probe failed: {hk_probe}"

    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        with rec_lock:
            dur_cnt = sum(1 for r in records if r[0] >= outage_start_seq)
        if dur_cnt >= 6:
            break
        time.sleep(0.1)
    time.sleep(0.3)
    with rec_lock:
        outage_end_seq = records[-1][0]
    syn_d1 = get_syn_counters()

    # Restore CN2 policy rule mid-stream
    subprocess.run(
        ["docker", "exec", c_vps, "sh", "-c", f"ip -4 rule add from {vps_cn2} lookup 102 pref 102 && ip -4 route flush cache"],
        check=True,
    )
    t_add_done = round(time.monotonic() - host_t0, 3)
    time.sleep(1.5)
    with rec_lock:
        after_start_seq = records[-1][0] + 1
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        with rec_lock:
            after_ok = sum(1 for r in records if r[0] >= after_start_seq and r[1] == "OK")
        if after_ok >= 4:
            break
        time.sleep(0.1)
    syn_t3 = get_syn_counters()
finally:
    if proc.stdin:
        try:
            proc.stdin.close()
        except OSError:
            pass
    proc.wait(timeout=5)
    t_read.join(timeout=2)

before_recs = [r for r in records if r[0] <= before_end_seq]
during_recs = [r for r in records if outage_start_seq <= r[0] <= outage_end_seq]
after_recs = [r for r in records if r[0] >= after_start_seq]

before_ok = [r for r in before_recs if r[1] == "OK"]
before_err = [r for r in before_recs if r[1] != "OK"]
during_ok = [r for r in during_recs if r[1] == "OK"]
during_err = [r for r in during_recs if r[1] != "OK"]
after_ok = [r for r in after_recs if r[1] == "OK"]
after_err = [r for r in after_recs if r[1] != "OK"]

print(f"Timeline markers: t_del_done={t_del_done}s t_add_done={t_add_done}s before_end={before_end_seq} outage={outage_start_seq}..{outage_end_seq} after_start={after_start_seq}")
print(f"BEFORE (seq 1..{before_end_seq}): ok={len(before_ok)} fail={len(before_err)} sample={before_ok[0][4]}")
print(f"  Router SYN BEFORE : 9929={syn_t0[0]}->{syn_t1[0]} (delta={syn_t1[0]-syn_t0[0]}), cn2={syn_t0[1]}->{syn_t1[1]} (delta={syn_t1[1]-syn_t0[1]})")
print(f"DURING (seq {outage_start_seq}..{outage_end_seq}): ok={len(during_ok)} fail={len(during_err)} sample_err={during_err[0][4] if during_err else 'none'}")
print(f"  Healthy 9929 rule during CN2 outage: {hk_probe}")
print(f"  Router SYN DURING : 9929={syn_t1[0]}->{syn_d1[0]} (delta={syn_d1[0]-syn_t1[0]}), cn2_steady={syn_d0[1]}->{syn_d1[1]} (delta={syn_d1[1]-syn_d0[1]})")
print(f"AFTER  (seq {after_start_seq}..{records[-1][0]}): ok={len(after_ok)} fail={len(after_err)} sample={after_ok[0][4] if after_ok else 'none'}")
print(f"  Router SYN AFTER  : 9929={syn_d1[0]}->{syn_t3[0]} (delta={syn_t3[0]-syn_d1[0]}), cn2={syn_d1[1]}->{syn_t3[1]} (delta={syn_t3[1]-syn_d1[1]})")

try:
    assert len(before_ok) >= 5 and not before_err, f"BEFORE failed: {before_err}"
    assert all(f"SRC={vps_cn2}" in r[4] for r in before_ok)
    assert len(during_ok) == 0 and len(during_err) >= 5, f"DURING unexpectedly succeeded: {during_ok}"
    assert syn_t0[0] == syn_t1[0] == syn_d0[0] == syn_d1[0] == syn_t3[0], f"9929 leaked SYNs: {(syn_t0, syn_t1, syn_d0, syn_d1, syn_t3)}"
    assert syn_d0[1] == syn_d1[1], f"CN2 changed during steady outage: {syn_d0} -> {syn_d1}"
    assert len(after_ok) >= 4 and not after_err, f"AFTER recovery errors: {after_err}"
    assert all(f"SRC={vps_cn2}" in r[4] for r in after_ok)
    assert syn_t3[1] - syn_d1[1] >= 4
except AssertionError:
    sys.stderr.write(f"DEBUG R1 ALL RECORDS: {records}\n")
    raise

jp_logs = subprocess.check_output(["docker", "logs", c_jp], text=True)
obs_lines = [ln for ln in jp_logs.splitlines() if "[LANDING_OBS]" in ln]
obs_srcs = sorted({re.search(r"src=(\S+)", ln).group(1) for ln in obs_lines if "src=" in ln})
outage_obs = []
for ln in obs_lines:
    m = re.search(r"payload=R1_STREAM_(\d+)", ln)
    if m and outage_start_seq <= int(m.group(1)) <= outage_end_seq:
        outage_obs.append(ln)
print(f"Landing observation ({c_jp}): total_obs={len(obs_lines)}, observed_srcs={obs_srcs}, outage_window_obs={len(outage_obs)}")
assert obs_srcs == [vps_cn2], f"Landing observed unexpected src IP: {obs_srcs}"
assert not outage_obs, f"Landing observed probes during outage: {outage_obs}"
PY
)"
echo "${R1_STREAM_RES}"

echo "--- [R1 _verify-startup timeout failure when policy route missing] ---"
docker exec "${C_VPS}" ip -4 rule del from "${VPS_CN2_IP}" lookup 102
set +e
VS_TIMEOUT_OUT="$(docker exec "${C_VPS}" liqun-helper _verify-startup zouter-jp --wait-timeout 2 2>&1)"
VS_TIMEOUT_RC=$?
set -e
echo "_verify-startup missing route rc=${VS_TIMEOUT_RC}: ${VS_TIMEOUT_OUT}"
[[ ${VS_TIMEOUT_RC} -ne 0 ]] || fail "R1: _verify-startup unexpectedly succeeded when route was absent!"
docker exec "${C_VPS}" ip -4 rule add from "${VPS_CN2_IP}" lookup 102 pref 102
docker exec "${C_VPS}" ip -4 route flush cache

echo "--- [R1 Boot Race: mock-leikwan-pbr delayed 5s AFTER network-online.target] ---"
docker exec "${C_VPS}" mkdir -p /etc/systemd/system/mock-leikwan-pbr.service.d
docker exec -i "${C_VPS}" tee /etc/systemd/system/mock-leikwan-pbr.service.d/delay.conf >/dev/null <<'EOF'
[Unit]
DefaultDependencies=yes
After=network-online.target
Before=
[Service]
TimeoutStartSec=30
EOF
docker exec "${C_VPS}" bash -lc 'echo 5 > /etc/liqun-lab-delay-pbr && systemctl daemon-reload'

SYN_9929_BOOT0="$(get_mangle_pkts EGRESS_9929_JP)"
docker restart "${C_VPS}" >/dev/null
sleep 2
BOOT_SNAP="$(docker exec "${C_VPS}" bash -lc 'echo "pbr=$(systemctl is-active mock-leikwan-pbr.service || true) jp=$(systemctl is-active liqun-helper-realm@zouter-jp.service || true) jp_sub=$(systemctl show -p SubState --value liqun-helper-realm@zouter-jp.service)"' || true)"
echo "Mid-boot snapshot (during 5s PBR delay): ${BOOT_SNAP}"

for _ in $(seq 1 30); do
    st="$(docker exec "${C_VPS}" systemctl is-system-running 2>/dev/null || true)"
    pbr_st="$(docker exec "${C_VPS}" systemctl is-active mock-leikwan-pbr.service 2>/dev/null || true)"
    jp_st="$(docker exec "${C_VPS}" systemctl is-active liqun-helper-realm@zouter-jp.service 2>/dev/null || true)"
    if [[ "${pbr_st}" == "active" && "${jp_st}" == "active" && ( "${st}" == "running" || "${st}" == "degraded" ) ]]; then
        break
    fi
    sleep 1
done

docker exec "${C_VPS}" systemctl is-active --quiet liqun-helper-realm@zouter-jp.service || fail "R1 boot: zouter-jp not active after delayed PBR"
RESP_BOOT_RACE="$(client_probe "${PUB_10}" 54141 "R1_BOOT_RACE")"
SYN_9929_BOOT1="$(get_mangle_pkts EGRESS_9929_JP)"
echo "Post delayed-boot probe: ${RESP_BOOT_RACE} | 9929 SYN delta=${SYN_9929_BOOT1}-${SYN_9929_BOOT0}"
assert_contains "${RESP_BOOT_RACE}" "LANDING=zouter-jp-mock SRC=${VPS_CN2_IP}" "R1 boot race"
[[ "${SYN_9929_BOOT1}" -eq "${SYN_9929_BOOT0}" ]] || fail "R1 boot race leaked SYN onto 9929!"

# Restore normal PBR unit ordering
docker exec "${C_VPS}" rm -rf /etc/systemd/system/mock-leikwan-pbr.service.d /etc/liqun-lab-delay-pbr
docker exec "${C_VPS}" systemctl daemon-reload
docker exec "${C_VPS}" bash -lc 'cd /opt/src/liqun-helper && bash uninstall.sh --purge'

# ==============================================================================
# R2: Resource ownership, shared dirs, unmanaged service, existing Realm, concurrent lock
# ==============================================================================
echo "=== [R2] Ownership boundaries, shared directories, unmanaged unit, & concurrent lock ==="
docker exec "${C_VPS}" mkdir -p /tmp/r2-shared-cfg/rules.d /tmp/r2-shared-state
docker exec -i "${C_VPS}" tee /tmp/r2-shared-cfg/sentinel-cfg.txt >/dev/null <<< "cfg-sentinel-v1"
docker exec -i "${C_VPS}" tee /tmp/r2-shared-state/sentinel-state.txt >/dev/null <<< "state-sentinel-v1"
docker exec -i "${C_VPS}" tee /tmp/r2-shared-cfg/rules.d/foreign-rule.toml >/dev/null <<< "# unrelated foreign file"
docker exec -i "${C_VPS}" tee /etc/systemd/system/liqun-helper-realm@unmanaged.service >/dev/null <<'EOF'
[Unit]
Description=Foreign Unmanaged Service With Same Prefix
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
docker exec "${C_VPS}" systemctl daemon-reload
docker exec "${C_VPS}" systemctl start liqun-helper-realm@unmanaged.service

UNM_PID_BEFORE="$(docker exec "${C_VPS}" systemctl show -p MainPID --value liqun-helper-realm@unmanaged.service)"
UNM_ACT_BEFORE="$(docker exec "${C_VPS}" systemctl is-active liqun-helper-realm@unmanaged.service)"
R2_HASH_BEFORE="$(docker exec "${C_VPS}" sha256sum /tmp/r2-shared-cfg/sentinel-cfg.txt /tmp/r2-shared-state/sentinel-state.txt /tmp/r2-shared-cfg/rules.d/foreign-rule.toml /usr/local/bin/realm)"
echo "R2 BEFORE unmanaged: pid=${UNM_PID_BEFORE} active=${UNM_ACT_BEFORE}"
echo "R2 BEFORE hashes:"
echo "${R2_HASH_BEFORE}"

# Reject symlink config-dir target during install
docker exec "${C_VPS}" ln -s /tmp/r2-shared-cfg /tmp/r2-cfg-symlink
set +e
SYM_INST_OUT="$(docker exec "${C_VPS}" bash -lc 'cd /opt/src/liqun-helper && bash install.sh --config-dir /tmp/r2-cfg-symlink --state-dir /tmp/r2-shared-state' 2>&1)"
SYM_INST_RC=$?
set -e
docker exec "${C_VPS}" rm -f /tmp/r2-cfg-symlink
echo "Refused symlink install target (rc=${SYM_INST_RC}): ${SYM_INST_OUT}"
[[ ${SYM_INST_RC} -ne 0 ]] || fail "R2: install.sh accepted symlink --config-dir!"
assert_contains "${SYM_INST_OUT}" "拒绝安装到符号链接路径" "R2 symlink install msg"

# Install into shared dirs (auto-reusing /usr/local/bin/realm) + repeat install
docker exec "${C_VPS}" bash -lc 'cd /opt/src/liqun-helper && bash install.sh --config-dir /tmp/r2-shared-cfg --state-dir /tmp/r2-shared-state'
patch_vps_config_for_lab "/tmp/r2-shared-cfg/config.toml"
CFG_HASH_MID="$(docker exec "${C_VPS}" sha256sum /tmp/r2-shared-cfg/config.toml)"
docker exec "${C_VPS}" bash -lc 'cd /opt/src/liqun-helper && bash install.sh --config-dir /tmp/r2-shared-cfg --state-dir /tmp/r2-shared-state'
CFG_HASH_REPEAT="$(docker exec "${C_VPS}" sha256sum /tmp/r2-shared-cfg/config.toml)"
[[ "${CFG_HASH_MID}" == "${CFG_HASH_REPEAT}" ]] || fail "R2: repeat install overwrote config.toml!"

# Refuse install-realm over existing /usr/local/bin/realm
set +e
OVERWRITE_OUT="$(docker exec "${C_VPS}" liqun-helper install-realm --tarball /opt/cache/realm-v2.9.6.tar.gz --target /usr/local/bin/realm 2>&1)"
OVERWRITE_RC=$?
set -e
echo "Refused Realm overwrite: ${OVERWRITE_OUT}"
[[ ${OVERWRITE_RC} -ne 0 ]] || fail "R2: install-realm overwrote /usr/local/bin/realm"
assert_contains "${OVERWRITE_OUT}" "拒绝覆盖" "R2 overwrite msg"

# Refuse foreign systemd template in config
docker exec "${C_VPS}" bash -lc 'sed "s|systemd_unit_template = .*|systemd_unit_template = \"foreign@.service\"|" /tmp/r2-shared-cfg/config.toml > /tmp/r2-bad-tpl.toml'
set +e
BAD_TPL_OUT="$(docker exec "${C_VPS}" liqun-helper --config /tmp/r2-bad-tpl.toml plan /opt/test-rules/r1-jp-cn2.toml 2>&1)"
BAD_TPL_RC=$?
set -e
[[ ${BAD_TPL_RC} -ne 0 ]] || fail "R2: foreign systemd template accepted!"
assert_contains "${BAD_TPL_OUT}" "禁止修改受管 systemd 模板名" "R2 foreign tpl msg"

# Refuse apply/disable/delete against unmanaged service
docker exec "${C_VPS}" bash -lc 'sed "s/name = \"zouter-jp\"/name = \"unmanaged\"/" /opt/test-rules/r1-jp-cn2.toml > /tmp/r2-unmanaged-rule.toml'
set +e
UNM_APPLY_OUT="$(docker exec "${C_VPS}" liqun-helper apply /tmp/r2-unmanaged-rule.toml 2>&1)"
UNM_APPLY_RC=$?
UNM_DEL_OUT="$(docker exec "${C_VPS}" liqun-helper delete unmanaged 2>&1)"
UNM_DEL_RC=$?
set -e
[[ ${UNM_APPLY_RC} -ne 0 && ${UNM_DEL_RC} -ne 0 ]] || fail "R2: hijacked unmanaged service!"
assert_contains "${UNM_APPLY_OUT}" "拒绝" "R2 unmanaged apply"
assert_contains "${UNM_DEL_OUT}" "拒绝" "R2 unmanaged delete"

# Apply owned rule, verify single-rule delete keeps sentinels & unmanaged service, then re-apply & uninstall
docker exec "${C_VPS}" liqun-helper apply /opt/test-rules/r1-jp-cn2.toml
docker exec "${C_VPS}" liqun-helper delete zouter-jp
[[ "$(docker exec "${C_VPS}" sha256sum /tmp/r2-shared-cfg/sentinel-cfg.txt /tmp/r2-shared-state/sentinel-state.txt /tmp/r2-shared-cfg/rules.d/foreign-rule.toml /usr/local/bin/realm)" == "${R2_HASH_BEFORE}" ]] || fail "R2: single-rule delete modified sentinel files!"
docker exec "${C_VPS}" liqun-helper apply /opt/test-rules/r1-jp-cn2.toml
docker exec "${C_VPS}" bash -lc 'cd /opt/src/liqun-helper && bash uninstall.sh --purge --config-dir /tmp/r2-shared-cfg --state-dir /tmp/r2-shared-state'

UNM_PID_AFTER="$(docker exec "${C_VPS}" systemctl show -p MainPID --value liqun-helper-realm@unmanaged.service)"
UNM_ACT_AFTER="$(docker exec "${C_VPS}" systemctl is-active liqun-helper-realm@unmanaged.service)"
R2_HASH_AFTER="$(docker exec "${C_VPS}" sha256sum /tmp/r2-shared-cfg/sentinel-cfg.txt /tmp/r2-shared-state/sentinel-state.txt /tmp/r2-shared-cfg/rules.d/foreign-rule.toml /usr/local/bin/realm)"
echo "R2 AFTER unmanaged: pid=${UNM_PID_AFTER} active=${UNM_ACT_AFTER}"
echo "R2 AFTER hashes:"
echo "${R2_HASH_AFTER}"
[[ "${UNM_PID_BEFORE}" == "${UNM_PID_AFTER}" && -n "${UNM_PID_AFTER}" ]] || fail "R2: unmanaged service PID changed (${UNM_PID_BEFORE} -> ${UNM_PID_AFTER})"
[[ "${R2_HASH_BEFORE}" == "${R2_HASH_AFTER}" ]] || fail "R2: sentinel files or /usr/local/bin/realm modified!"
echo "R2 shared-dir sentinel hashes & unmanaged PID (${UNM_PID_AFTER}) verified intact."

# Legacy conservative uninstall (remove manifest & managed-rules.json, verify only proven legacy rule is removed while foreign file remains)
install_helper_on_vps --config-dir /tmp/r2-shared-cfg --state-dir /tmp/r2-shared-state
patch_vps_config_for_lab "/tmp/r2-shared-cfg/config.toml"
docker exec "${C_VPS}" liqun-helper apply /opt/test-rules/r1-jp-cn2.toml
docker exec "${C_VPS}" rm -f /usr/local/lib/liqun-helper/install-manifest.json /tmp/r2-shared-state/managed-rules.json
LEGACY_UN_OUT="$(docker exec "${C_VPS}" bash -lc 'cd /opt/src/liqun-helper && bash uninstall.sh --config-dir /tmp/r2-shared-cfg --state-dir /tmp/r2-shared-state')"
echo "${LEGACY_UN_OUT}"
assert_contains "${LEGACY_UN_OUT}" "卸载模式: legacy-conservative" "R2 legacy mode"
assert_contains "${LEGACY_UN_OUT}" "已清理规则: zouter-jp" "R2 legacy rule cleaned"
docker exec "${C_VPS}" test -f /tmp/r2-shared-cfg/rules.d/foreign-rule.toml || fail "R2 legacy: deleted unverified foreign-rule.toml!"
docker exec "${C_VPS}" test -f /tmp/r2-shared-state/sentinel-state.txt || fail "R2 legacy: deleted sentinel-state.txt!"

# Concurrent apply vs uninstall --purge under lock
install_helper_on_vps
patch_vps_config_for_lab "/etc/liqun-helper/config.toml"
CONC_OUT="$(docker exec "${C_VPS}" bash -lc '
cd /opt/src/liqun-helper
liqun-helper apply /opt/test-rules/r1-jp-cn2.toml >/tmp/c1.out 2>&1 &
p1=$!
bash uninstall.sh --purge >/tmp/c2.out 2>&1 &
p2=$!
wait $p1; rc1=$?
wait $p2; rc2=$?
echo "CONC_RC1=${rc1} CONC_RC2=${rc2}"
echo "--- apply out ---"; cat /tmp/c1.out
echo "--- uninstall out ---"; cat /tmp/c2.out
')"
echo "${CONC_OUT}"
# If uninstall ran second, nothing remains; if apply ran second after uninstall removed template/config, apply failed cleanly without writing orphan files!
if docker exec "${C_VPS}" test -e /etc/systemd/system/liqun-helper-realm@.service; then
    docker exec "${C_VPS}" bash -lc 'cd /opt/src/liqun-helper && bash uninstall.sh --purge'
fi
docker exec "${C_VPS}" test ! -e /etc/liqun-helper/rules.d/zouter-jp.toml || fail "R2 concurrent: stray rule left after uninstall"

# Clean up unmanaged test unit
docker exec "${C_VPS}" systemctl stop liqun-helper-realm@unmanaged.service
docker exec "${C_VPS}" rm -rf /etc/systemd/system/liqun-helper-realm@unmanaged.service /tmp/r2-shared-cfg /tmp/r2-shared-state
docker exec "${C_VPS}" systemctl daemon-reload

# ==============================================================================
# R3: Staged rollback fault injections + live long-lived TCP connection preservation
# ==============================================================================
echo "=== [R3] Staged rollback with real long-lived TCP connection preservation ==="
install_helper_on_vps
patch_vps_config_for_lab "/etc/liqun-helper/config.toml"
docker exec "${C_VPS}" liqun-helper apply /opt/test-rules/r1-jp-cn2.toml

docker exec -i "${C_VPS}" tee /tmp/r3-stay-disabled.toml >/dev/null <<EOF
[rule]
name = "stay-disabled"
line = "9929"
[ingress]
public_port = 54188
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10088
remote_ip = "${JP_IP}"
remote_port = 54141
EOF
docker exec "${C_VPS}" liqun-helper apply /tmp/r3-stay-disabled.toml
docker exec "${C_VPS}" liqun-helper disable stay-disabled

JP_PID_R3_BEFORE="$(docker exec "${C_VPS}" systemctl show -p MainPID --value liqun-helper-realm@zouter-jp.service)"
docker exec -i "${C_VPS}" tee /tmp/r1-jp-cn2-upd.toml >/dev/null <<EOF
[rule]
name = "zouter-jp"
line = "cn2"
[ingress]
public_port = 54141
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10001
remote_ip = "${JP_IP}"
remote_port = 54141
[realm]
log_level = "info"
tcp_timeout = 7
EOF

# Drive the long connection directly inside a host coordinator while injecting Stage 1 write faults inside C_VPS!
R3_LONG_RES="$(python3 - "${C_CLIENT}" "${C_VPS}" "${PUB_10}" <<'PY'
import subprocess, sys, time

c_client, c_vps, pub_ip = sys.argv[1:4]
client_code = f"""
import socket, sys
s = socket.create_connection(({pub_ip!r}, 54141), timeout=5)
f = s.makefile("rw", encoding="utf-8", newline="\\n")
for line in sys.stdin:
    tag = line.strip()
    if not tag:
        continue
    if tag == "QUIT":
        break
    f.write(tag + "\\n")
    f.flush()
    print(f.readline().strip(), flush=True)
"""
proc = subprocess.Popen(
    ["docker", "exec", "-i", c_client, "python3", "-c", client_code],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
try:
    proc.stdin.write("LONG_BEFORE\n"); proc.stdin.flush()
    print("LONG_0:", proc.stdout.readline().strip())

    # Inject FIRST write failure on VPS during update of active zouter-jp
    res1 = subprocess.run([
        "docker", "exec", c_vps, "env", "PYTHONPATH=/usr/local/lib/liqun-helper", "python3", "-c",
        """
from unittest.mock import patch
from liqun_helper.config import load_global_config
from liqun_helper.manager import apply_rule, ApplyError
cfg = load_global_config('/etc/liqun-helper/config.toml')
with patch('liqun_helper.manager.atomic_write_text', side_effect=OSError('injected-first-write-fail')):
    try:
        apply_rule(cfg, '/tmp/r1-jp-cn2-upd.toml')
    except ApplyError as e:
        print('FIRST_FAIL:', e)
"""
    ], capture_output=True, text=True, check=True)
    print(res1.stdout.strip())
    assert "首次写入即失败" in res1.stdout

    proc.stdin.write("LONG_AFTER_FIRST_FAIL\n"); proc.stdin.flush()
    r1 = proc.stdout.readline().strip()
    print("LONG_1:", r1)
    assert "ECHO=LONG_AFTER_FIRST_FAIL" in r1

    # Inject MID-WRITE failure (fail on 2nd atomic_write_text call)
    res2 = subprocess.run([
        "docker", "exec", c_vps, "env", "PYTHONPATH=/usr/local/lib/liqun-helper", "python3", "-c",
        """
from unittest.mock import patch
from liqun_helper.config import load_global_config
from liqun_helper.manager import apply_rule, ApplyError
from liqun_helper import system as sysmod
real_write = sysmod.atomic_write_text
cnt = [0]
def fail_on_second(*a, **kw):
    cnt[0] += 1
    if cnt[0] == 2:
        raise OSError('injected-mid-write-fail')
    return real_write(*a, **kw)
cfg = load_global_config('/etc/liqun-helper/config.toml')
with patch('liqun_helper.manager.atomic_write_text', side_effect=fail_on_second):
    try:
        apply_rule(cfg, '/tmp/r1-jp-cn2-upd.toml')
    except ApplyError as e:
        print('MID_FAIL:', e)
"""
    ], capture_output=True, text=True, check=True)
    print(res2.stdout.strip())
    assert "仅回滚已写入文件" in res2.stdout

    proc.stdin.write("LONG_AFTER_MID_FAIL\n"); proc.stdin.flush()
    r2 = proc.stdout.readline().strip()
    print("LONG_2:", r2)
    assert "ECHO=LONG_AFTER_MID_FAIL" in r2

    proc.stdin.write("QUIT\n"); proc.stdin.flush()
    proc.wait(timeout=5)
finally:
    if proc.poll() is None:
        proc.kill()
PY
)"
echo "${R3_LONG_RES}"
JP_PID_R3_AFTER="$(docker exec "${C_VPS}" systemctl show -p MainPID --value liqun-helper-realm@zouter-jp.service)"
echo "Long-conn Realm PID before/after write failures: ${JP_PID_R3_BEFORE} -> ${JP_PID_R3_AFTER}"
[[ "${JP_PID_R3_BEFORE}" == "${JP_PID_R3_AFTER}" ]] || fail "R3: write-stage failure restarted active Realm!"

# Also test Stage 1 & Stage 2 rollback across first creation (inactive vs still-running), active update, and disabled update!
R3_STAGE2_OUT="$(docker exec -i "${C_VPS}" env PYTHONPATH=/usr/local/lib/liqun-helper python3 - <<EOF
from pathlib import Path
from unittest.mock import patch
from liqun_helper.config import load_global_config
from liqun_helper.manager import apply_rule, delete_rule, ApplyError
from liqun_helper import system as sysmod
import liqun_helper.manager as mgr

cfg = load_global_config('/etc/liqun-helper/config.toml')

Path('/tmp/r3-fail-new.toml').write_text('''[rule]
name = "r3-fail-new"
line = "9929"
[ingress]
public_port = 54199
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10099
remote_ip = "${JP_IP}"
remote_port = 54141
''')

# 1) New rule Stage 1 FIRST-WRITE fail -> zero generated files
with patch.object(mgr, 'atomic_write_text', side_effect=OSError('new-first-write-fail')):
    try:
        apply_rule(cfg, '/tmp/r3-fail-new.toml')
    except ApplyError as e:
        print('NEW_FIRST_FAIL:', e)
        assert '首次写入即失败' in str(e)
        assert not Path('/etc/liqun-helper/rules.d/r3-fail-new.toml').exists()

# 2) New rule Stage 1 MID-WRITE fail -> rolled back all written files
real_write = sysmod.atomic_write_text
def make_nth_fail(n, err_msg):
    cnt = [0]
    def _fn(*a, **kw):
        cnt[0] += 1
        if cnt[0] == n:
            raise OSError(err_msg)
        return real_write(*a, **kw)
    return _fn

with patch.object(mgr, 'atomic_write_text', side_effect=make_nth_fail(2, 'new-mid-write-fail')):
    try:
        apply_rule(cfg, '/tmp/r3-fail-new.toml')
    except ApplyError as e:
        print('NEW_MID_FAIL:', e)
        assert '仅回滚已写入文件' in str(e)
        assert not Path('/etc/liqun-helper/rules.d/r3-fail-new.toml').exists()
        assert not Path('/var/lib/liqun-helper/realm/r3-fail-new.toml').exists()

# 3) New rule Stage 2 start fail + journalctl fail + stop fail (actually inactive) -> cleans all 4 files!
with patch.object(mgr, 'systemd_restart', side_effect=RuntimeError('injected-start-fail')), \
     patch.object(mgr, 'systemd_journal_tail', side_effect=RuntimeError('injected-journal-fail')), \
     patch.object(mgr, 'systemd_stop', side_effect=RuntimeError('injected-stop-fail')):
    try:
        apply_rule(cfg, '/tmp/r3-fail-new.toml')
    except ApplyError as e:
        txt = str(e)
        print('STAGE2_NEW_INACTIVE:', txt)
        assert '日志采集失败' in txt
        assert '已确认 liqun-helper-realm@r3-fail-new.service 未在运行；已清理文件' in txt
        assert not Path('/etc/liqun-helper/rules.d/r3-fail-new.toml').exists()
        assert not Path('/var/lib/liqun-helper/realm/r3-fail-new.toml').exists()
        assert not Path('/var/lib/liqun-helper/state/r3-fail-new.json').exists()

# 4) New rule Stage 2 stop fail while STILL active -> preserves runtime files & warns rollback incomplete!
with patch.object(mgr, 'systemd_restart', side_effect=RuntimeError('injected-start-fail')), \
     patch.object(mgr, 'systemd_journal_tail', return_value='mock-tail'), \
     patch.object(mgr, 'systemd_stop', side_effect=RuntimeError('stop-perm-denied')), \
     patch.object(mgr, 'systemd_is_active', return_value=True):
    try:
        apply_rule(cfg, '/tmp/r3-fail-new.toml')
    except ApplyError as e:
        txt = str(e)
        print('STAGE2_NEW_STILL_ACTIVE:', txt)
        assert '回滚未完全完成' in txt
        assert Path('/etc/liqun-helper/rules.d/r3-fail-new.toml').is_file()
        assert Path('/var/lib/liqun-helper/realm/r3-fail-new.toml').is_file()
delete_rule(cfg, 'r3-fail-new')

# 5) Active rule Stage 2 start fail + journalctl fail -> rolls back config & restarts previous online instance
orig_restart = sysmod.systemd_restart
s2_calls = [0]
def fail_then_restore_restart(unit):
    s2_calls[0] += 1
    if s2_calls[0] == 1:
        raise RuntimeError('injected-active-update-start-fail')
    return orig_restart(unit)

with patch.object(mgr, 'systemd_restart', side_effect=fail_then_restore_restart), \
     patch.object(mgr, 'systemd_journal_tail', side_effect=RuntimeError('injected-journal-fail')):
    try:
        apply_rule(cfg, '/tmp/r1-jp-cn2-upd.toml')
    except ApplyError as e:
        txt = str(e)
        print('STAGE2_ACTIVE_UPDATE:', txt)
        assert '日志采集失败' in txt
        assert '已恢复原有规则配置、启用状态并重新拉起原运行实例' in txt
        assert 'tcp_timeout = 5' in Path('/etc/liqun-helper/rules.d/zouter-jp.toml').read_text(encoding='utf-8')

# 6) Disabled rule Stage 1 first/mid write fail + Stage 2 start fail -> stays disabled & inactive & old config intact
Path('/tmp/r3-stay-disabled-bad.toml').write_text('''[rule]
name = "stay-disabled"
line = "9929"
[ingress]
public_port = 54188
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10088
remote_ip = "${JP_IP}"
remote_port = 54149
''')
with patch.object(mgr, 'atomic_write_text', side_effect=OSError('disabled-first-fail')):
    try:
        apply_rule(cfg, '/tmp/r3-stay-disabled-bad.toml')
    except ApplyError as e:
        print('DISABLED_FIRST_FAIL:', e)
        assert '首次写入即失败' in str(e)

with patch.object(mgr, 'atomic_write_text', side_effect=make_nth_fail(2, 'disabled-mid-fail')):
    try:
        apply_rule(cfg, '/tmp/r3-stay-disabled-bad.toml')
    except ApplyError as e:
        print('DISABLED_MID_FAIL:', e)
        assert '仅回滚已写入文件' in str(e)

with patch.object(mgr, 'systemd_restart', side_effect=RuntimeError('injected-start-fail')):
    try:
        apply_rule(cfg, '/tmp/r3-stay-disabled-bad.toml')
    except ApplyError as e:
        print('STAGE2_DISABLED:', e)
        assert '已恢复原有规则配置与停用状态' in str(e)
assert 'remote_port = 54141' in Path('/etc/liqun-helper/rules.d/stay-disabled.toml').read_text(encoding='utf-8')
EOF
)"
echo "${R3_STAGE2_OUT}"
R3_ACTIVE_PROBE="$(client_probe "${PUB_10}" 54141 "R3_ACTIVE_S2_RECOVER")"
echo "Active rule probe after Stage 2 rollback: ${R3_ACTIVE_PROBE}"
assert_contains "${R3_ACTIVE_PROBE}" "LANDING=zouter-jp-mock SRC=${VPS_CN2_IP}" "R3 active stage2 recover"
docker exec "${C_VPS}" systemctl is-enabled --quiet liqun-helper-realm@zouter-jp.service || fail "R3: zouter-jp disabled after rollback!"
docker exec "${C_VPS}" systemctl is-active --quiet liqun-helper-realm@zouter-jp.service || fail "R3: zouter-jp inactive after rollback!"
! docker exec "${C_VPS}" systemctl is-enabled --quiet liqun-helper-realm@stay-disabled.service || fail "R3: disabled rule re-enabled!"
! docker exec "${C_VPS}" systemctl is-active --quiet liqun-helper-realm@stay-disabled.service || fail "R3: disabled rule active!"
docker exec "${C_VPS}" bash -lc 'cd /opt/src/liqun-helper && bash uninstall.sh --purge'

# ==============================================================================
# R4: Custom directory matrix (default, config-only, state-only, both-custom)
# ==============================================================================
echo "=== [R4] Custom directory matrix (default, config-only, state-only, both-custom) ==="
for combo in "default::" "cfg-only:/opt/liqun-cfg-a:" "state-only::/var/lib/liqun-st-b" "both:/opt/liqun-cfg-c:/var/lib/liqun-st-c"; do
    IFS=':' read -r label cdir sdir <<< "${combo}"
    echo "--- Testing combo: ${label} (config=${cdir:-default}, state=${sdir:-default}) ---"
    inst_args=""
    un_args="--purge"
    effective_cfg="/etc/liqun-helper/config.toml"
    if [[ -n "${cdir}" ]]; then
        inst_args+=" --config-dir ${cdir}"
        un_args+=" --config-dir ${cdir}"
        effective_cfg="${cdir}/config.toml"
    fi
    if [[ -n "${sdir}" ]]; then
        inst_args+=" --state-dir ${sdir}"
        un_args+=" --state-dir ${sdir}"
    fi

    install_helper_on_vps "${inst_args}"
    patch_vps_config_for_lab "${effective_cfg}"
    # Apply WITHOUT passing --config! Must read install-manifest / install.env automatically!
    docker exec "${C_VPS}" liqun-helper apply /opt/test-rules/r1-jp-cn2.toml
    r_before="$(client_probe "${PUB_10}" 54141 "R4_${label}_BEFORE")"
    assert_contains "${r_before}" "LANDING=zouter-jp-mock SRC=${VPS_CN2_IP}" "R4 ${label} before reboot"

    docker restart "${C_VPS}" >/dev/null
    for _ in $(seq 1 30); do
        st="$(docker exec "${C_VPS}" systemctl is-system-running 2>/dev/null || true)"
        jp_st="$(docker exec "${C_VPS}" systemctl is-active liqun-helper-realm@zouter-jp.service 2>/dev/null || true)"
        if [[ "${jp_st}" == "active" && ( "${st}" == "running" || "${st}" == "degraded" ) ]]; then
            break
        fi
        sleep 1
    done
    r_after="$(client_probe "${PUB_10}" 54141 "R4_${label}_REBOOT")"
    echo "  ${label} post-reboot: ${r_after}"
    assert_contains "${r_after}" "LANDING=zouter-jp-mock SRC=${VPS_CN2_IP}" "R4 ${label} after reboot"

    docker exec "${C_VPS}" bash -lc "cd /opt/src/liqun-helper && bash uninstall.sh ${un_args}"
done

# ==============================================================================
# R5: TLS diagnostic exit codes & layered output (plain TCP, valid TLS, untrusted, bad host, bad app)
# ==============================================================================
echo "=== [R5] TLS diagnostics & layered status verification ==="
install_helper_on_vps
patch_vps_config_for_lab "/etc/liqun-helper/config.toml"

docker exec -i "${C_VPS}" tee /tmp/r5-tls-valid.toml >/dev/null <<EOF
[rule]
name = "r5-tls-valid"
line = "cn2"
[ingress]
public_port = 54443
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10010
remote_ip = "${JP_IP}"
remote_port = 54443
EOF
docker exec -i "${C_VPS}" tee /tmp/r5-tls-wronghost.toml >/dev/null <<EOF
[rule]
name = "r5-tls-wronghost"
line = "9929"
[ingress]
public_port = 54444
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10011
remote_ip = "${HK_IP}"
remote_port = 54444
EOF
docker exec "${C_VPS}" liqun-helper apply /opt/test-rules/r1-jp-cn2.toml
docker exec "${C_VPS}" liqun-helper apply /tmp/r5-tls-valid.toml
docker exec "${C_VPS}" liqun-helper apply /tmp/r5-tls-wronghost.toml

# Generate CA + valid leaf (SAN=tls-valid.example.com) + wrong-host leaf (SAN=wrong-host.example.com)
CERT_TMP="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=LiqunTestCA" \
    -keyout "${CERT_TMP}/ca.key" -out "${CERT_TMP}/ca.crt" 2>/dev/null
printf 'subjectAltName=DNS:tls-valid.example.com\n' > "${CERT_TMP}/ext_valid.cnf"
printf 'subjectAltName=DNS:wrong-host.example.com\n' > "${CERT_TMP}/ext_wrong.cnf"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=tls-valid.example.com" \
    -keyout "${CERT_TMP}/valid.key" -out "${CERT_TMP}/valid.csr" 2>/dev/null
openssl x509 -req -in "${CERT_TMP}/valid.csr" -CA "${CERT_TMP}/ca.crt" -CAkey "${CERT_TMP}/ca.key" -CAcreateserial \
    -out "${CERT_TMP}/valid.crt" -days 2 -extfile "${CERT_TMP}/ext_valid.cnf" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=wrong-host.example.com" \
    -keyout "${CERT_TMP}/wrong.key" -out "${CERT_TMP}/wrong.csr" 2>/dev/null
openssl x509 -req -in "${CERT_TMP}/wrong.csr" -CA "${CERT_TMP}/ca.crt" -CAkey "${CERT_TMP}/ca.key" -CAcreateserial \
    -out "${CERT_TMP}/wrong.crt" -days 2 -extfile "${CERT_TMP}/ext_wrong.cnf" 2>/dev/null

docker cp "${CERT_TMP}/valid.crt" "${C_JP}:/tmp/valid.crt"
docker cp "${CERT_TMP}/valid.key" "${C_JP}:/tmp/valid.key"
docker cp "${CERT_TMP}/wrong.crt" "${C_HK}:/tmp/wrong.crt"
docker cp "${CERT_TMP}/wrong.key" "${C_HK}:/tmp/wrong.key"
docker cp "${CERT_TMP}/ca.crt" "${C_CLIENT}:/tmp/ca.crt"
rm -rf "${CERT_TMP}"

docker exec -d "${C_JP}" python3 /opt/lab/mock_tls_landing.py --id tls-valid-jp --port 54443 --cert /tmp/valid.crt --key /tmp/valid.key
docker exec -d "${C_HK}" python3 /opt/lab/mock_tls_landing.py --id tls-wrong-hk --port 54444 --cert /tmp/wrong.crt --key /tmp/wrong.key
sleep 0.6

# 5.0 Pure TCP check (no --send, no --expect, no --tls) -> exit 0
R5_TCP_ONLY="$(docker exec "${C_CLIENT}" liqun-helper ingress verify --host "${PUB_10}" --port 54141)"
echo "5.0 pure TCP-only:"
echo "${R5_TCP_ONLY}"
assert_contains "${R5_TCP_ONLY}" "[TCP 端口可达]" "R5.0 stage"
assert_contains "${R5_TCP_ONLY}" "TLS=未启用" "R5.0 tls"

# 5.1 Plain TCP with --send/--expect without --tls -> exit 0
docker exec "${C_CLIENT}" liqun-helper ingress verify --host "${PUB_10}" --port 54141 --send 'PING\n' --expect 'LANDING=zouter-jp-mock'

# 5.2 Plain TCP WITH --tls-sni -> non-zero exit 3
set +e
R5_PLAIN_TLS="$(docker exec "${C_CLIENT}" liqun-helper ingress verify --host "${PUB_10}" --port 54141 --tls-sni tls-valid.example.com 2>&1)"
R5_PLAIN_RC=$?
set -e
echo "5.2 plain-with-tls rc=${R5_PLAIN_RC}:"
echo "${R5_PLAIN_TLS}"
[[ ${R5_PLAIN_RC} -eq 3 ]] || fail "R5.2: expected rc=3, got ${R5_PLAIN_RC}"

# 5.7 Plain TCP WITH bare --tls (no --tls-sni) -> non-zero exit 3
set +e
R5_BARE_TLS="$(docker exec "${C_CLIENT}" liqun-helper ingress verify --host "${PUB_10}" --port 54141 --tls 2>&1)"
R5_BARE_RC=$?
set -e
echo "5.7 bare --tls on plain TCP rc=${R5_BARE_RC}:"
echo "${R5_BARE_TLS}"
[[ ${R5_BARE_RC} -eq 3 ]] || fail "R5.7: expected rc=3, got ${R5_BARE_RC}"

# 5.3 Valid TLS + CA + SNI + matching app -> exit 0
R5_VALID_OUT="$(docker exec "${C_CLIENT}" liqun-helper ingress verify --host "${PUB_10}" --port 54443 --tls-sni tls-valid.example.com --tls-cafile /tmp/ca.crt --send 'PING\n' --expect 'LANDING=tls-valid-jp')"
echo "5.3 valid TLS:"
echo "${R5_VALID_OUT}"
assert_contains "${R5_VALID_OUT}" "[已验证到达指定落地]" "R5.3 stage"
assert_contains "${R5_VALID_OUT}" "TLS=握手成功" "R5.3 tls"
assert_contains "${R5_VALID_OUT}" "校验通过" "R5.3 cert"

# 5.4 Untrusted CA -> non-zero exit 4
set +e
R5_UNTRUST_OUT="$(docker exec "${C_CLIENT}" liqun-helper ingress verify --host "${PUB_10}" --port 54443 --tls-sni tls-valid.example.com 2>&1)"
R5_UNTRUST_RC=$?
set -e
echo "5.4 untrusted rc=${R5_UNTRUST_RC}:"
echo "${R5_UNTRUST_OUT}"
[[ ${R5_UNTRUST_RC} -eq 4 ]] || fail "R5.4: expected rc=4, got ${R5_UNTRUST_RC}"
assert_contains "${R5_UNTRUST_OUT}" "证书不受信任" "R5.4 untrusted"

# 5.5 Hostname mismatch -> non-zero exit 4
set +e
R5_HOST_OUT="$(docker exec "${C_CLIENT}" liqun-helper ingress verify --host "${PUB_10}" --port 54444 --tls-sni tls-valid.example.com --tls-cafile /tmp/ca.crt 2>&1)"
R5_HOST_RC=$?
set -e
echo "5.5 hostname mismatch rc=${R5_HOST_RC}:"
echo "${R5_HOST_OUT}"
[[ ${R5_HOST_RC} -eq 4 ]] || fail "R5.5: expected rc=4, got ${R5_HOST_RC}"
assert_contains "${R5_HOST_OUT}" "主机名不匹配" "R5.5 hostname"

# 5.6 Valid TLS + CA + SNI, app mismatch -> non-zero exit 2
set +e
R5_APP_OUT="$(docker exec "${C_CLIENT}" liqun-helper ingress verify --host "${PUB_10}" --port 54443 --tls-sni tls-valid.example.com --tls-cafile /tmp/ca.crt --send 'PING\n' --expect 'WRONG_ID' 2>&1)"
R5_APP_RC=$?
set -e
echo "5.6 app mismatch rc=${R5_APP_RC}:"
echo "${R5_APP_OUT}"
[[ ${R5_APP_RC} -eq 2 ]] || fail "R5.6: expected rc=2, got ${R5_APP_RC}"
assert_contains "${R5_APP_OUT}" "不匹配预期落地" "R5.6 app"

# ==============================================================================
# R6: Unified fixed IP validation + zero-restart on fixed_ip update
# ==============================================================================
echo "=== [R6] Unified fixed_ip validation across ingress select and TOML apply ==="
docker exec -i "${C_VPS}" tee /tmp/r6-bad-fixed.toml >/dev/null <<EOF
[rule]
name = "zouter-jp"
line = "cn2"
[ingress]
domain = "paid-v4.bgp1.leikwanhost.com"
fixed_ip = "203.0.113.250"
public_port = 54141
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10001
remote_ip = "${JP_IP}"
remote_port = 54141
EOF

set +e
R6_REJECT_OUT="$(docker exec "${C_VPS}" liqun-helper apply /tmp/r6-bad-fixed.toml 2>&1)"
R6_REJECT_RC=$?
R6_SEL_REJECT="$(docker exec "${C_VPS}" liqun-helper ingress select --rule zouter-jp --ip 203.0.113.250 2>&1)"
R6_SEL_REJECT_RC=$?
R6_SEL_DNSFAIL="$(docker exec "${C_VPS}" liqun-helper ingress select --rule zouter-jp --ip "${PUB_10}" --dns-server 127.0.0.1 2>&1)"
R6_SEL_DNSFAIL_RC=$?
set -e
echo "R6 non-DNS TOML reject: ${R6_REJECT_OUT}"
echo "R6 non-DNS select reject: ${R6_SEL_REJECT}"
echo "R6 DNS-fail new select reject: ${R6_SEL_DNSFAIL}"
[[ ${R6_REJECT_RC} -ne 0 && ${R6_SEL_REJECT_RC} -ne 0 && ${R6_SEL_DNSFAIL_RC} -ne 0 ]] || fail "R6: non-DNS or DNS-fail new fixed_ip should fail without --allow-non-dns"
assert_contains "${R6_REJECT_OUT}" "--allow-non-dns" "R6 reject msg"
assert_contains "${R6_SEL_REJECT}" "--allow-non-dns" "R6 select reject msg"
assert_contains "${R6_SEL_DNSFAIL}" "DNS 查询失败" "R6 select dnsfail msg"

# Also check DNS-fail on new fixed_ip via TOML apply
docker exec -i "${C_VPS}" tee /tmp/r6-new-dnsfail.toml >/dev/null <<EOF
[rule]
name = "zouter-jp"
line = "cn2"
[ingress]
domain = "paid-v4.bgp1.leikwanhost.com"
fixed_ip = "${PUB_10}"
public_port = 54141
[forward]
listen_ip = "${VPS_9929_IP}"
listen_port = 10001
remote_ip = "${JP_IP}"
remote_port = 54141
EOF
set +e
R6_TOML_DNSFAIL="$(docker exec "${C_VPS}" liqun-helper apply /tmp/r6-new-dnsfail.toml --dns-server 127.0.0.1 2>&1)"
R6_TOML_DNSFAIL_RC=$?
set -e
echo "R6 DNS-fail new TOML apply reject: ${R6_TOML_DNSFAIL}"
[[ ${R6_TOML_DNSFAIL_RC} -ne 0 ]] || fail "R6: new fixed_ip TOML apply during DNS failure should fail"
assert_contains "${R6_TOML_DNSFAIL}" "DNS 查询失败" "R6 toml dnsfail msg"

JP_PID_R6_BEFORE="$(docker exec "${C_VPS}" systemctl show -p MainPID --value liqun-helper-realm@zouter-jp.service)"
R6_SEL_FORCE_OUT="$(docker exec "${C_VPS}" liqun-helper ingress select --rule zouter-jp --ip 203.0.113.250 --allow-non-dns)"
echo "R6 forced override via ingress select:"
echo "${R6_SEL_FORCE_OUT}"
assert_contains "${R6_SEL_FORCE_OUT}" "--allow-non-dns" "R6 select override marker"

# Check status --check-dns against live DNS where 203.0.113.250 is missing -> preserves & warns disappearance
R6_STALE_OUT="$(docker exec "${C_VPS}" liqun-helper status zouter-jp --check-dns)"
echo "R6 status --check-dns with missing fixed_ip:"
echo "${R6_STALE_OUT}"
assert_contains "${R6_STALE_OUT}" "已从" "R6 stale warning"
assert_contains "${R6_STALE_OUT}" "203.0.113.250" "R6 stale preserved"

# Unselect first so TOML --allow-non-dns apply exercises full metadata-updated transition too
docker exec "${C_VPS}" liqun-helper ingress unselect --rule zouter-jp

# Check TOML forced override apply also keeps PID unchanged
R6_FORCE_OUT="$(docker exec "${C_VPS}" liqun-helper apply /tmp/r6-bad-fixed.toml --allow-non-dns)"
echo "R6 forced override apply: ${R6_FORCE_OUT}"
assert_contains "${R6_FORCE_OUT}" "已更新客户端入口元数据（未重启 Realm）" "R6 metadata-only"
assert_contains "${R6_FORCE_OUT}" "--allow-non-dns" "R6 override marker"
JP_PID_R6_AFTER="$(docker exec "${C_VPS}" systemctl show -p MainPID --value liqun-helper-realm@zouter-jp.service)"
[[ "${JP_PID_R6_BEFORE}" == "${JP_PID_R6_AFTER}" ]] || fail "R6: fixed_ip update restarted Realm!"

# Verify unchanged fixed_ip with DNS query failure preserves fixed_ip and warns separately
R6_DNSFAIL_OUT="$(docker exec "${C_VPS}" liqun-helper plan /tmp/r6-bad-fixed.toml --check-dns --dns-server 127.0.0.1)"
echo "R6 unchanged fixed_ip during DNS failure:"
echo "${R6_DNSFAIL_OUT}"
assert_contains "${R6_DNSFAIL_OUT}" "DNS 查询失败" "R6 dns failure warning"

# Verify established TCP connection stays alive across BOTH `ingress select` and TOML `fixed_ip` apply!
R6_LONG_RES="$(python3 - "${C_CLIENT}" "${C_VPS}" "${PUB_10}" "${PUB_11}" <<'PY'
import subprocess, sys
c_client, c_vps, pub10, pub11 = sys.argv[1:5]
client_code = f"""
import socket, sys
s = socket.create_connection(({pub10!r}, 54141), timeout=5)
f = s.makefile("rw", encoding="utf-8", newline="\\n")
for line in sys.stdin:
    tag = line.strip()
    if not tag:
        continue
    if tag == "QUIT":
        break
    f.write(tag + "\\n")
    f.flush()
    print(f.readline().strip(), flush=True)
"""
proc = subprocess.Popen(
    ["docker", "exec", "-i", c_client, "python3", "-c", client_code],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
)
try:
    proc.stdin.write("R6_BEFORE\n"); proc.stdin.flush()
    print("R6_LONG_0:", proc.stdout.readline().strip())
    subprocess.run(["docker", "exec", c_vps, "liqun-helper", "ingress", "select", "--rule", "zouter-jp", "--ip", pub11], check=True)
    proc.stdin.write("R6_AFTER_SELECT\n"); proc.stdin.flush()
    r1 = proc.stdout.readline().strip()
    print("R6_LONG_1:", r1)
    assert "ECHO=R6_AFTER_SELECT" in r1
    subprocess.run(["docker", "exec", c_vps, "liqun-helper", "apply", "/opt/test-rules/r1-jp-cn2.toml"], check=True)
    proc.stdin.write("R6_AFTER_TOML_UNSET\n"); proc.stdin.flush()
    r2 = proc.stdout.readline().strip()
    print("R6_LONG_2:", r2)
    assert "ECHO=R6_AFTER_TOML_UNSET" in r2
    proc.stdin.write("QUIT\n"); proc.stdin.flush()
    proc.wait(timeout=5)
finally:
    if proc.poll() is None:
        proc.kill()
PY
)"
echo "${R6_LONG_RES}"
JP_PID_R6_END="$(docker exec "${C_VPS}" systemctl show -p MainPID --value liqun-helper-realm@zouter-jp.service)"
[[ "${JP_PID_R6_BEFORE}" == "${JP_PID_R6_END}" ]] || fail "R6: fixed_ip changes modified Realm PID!"

docker exec "${C_VPS}" bash -lc 'cd /opt/src/liqun-helper && bash uninstall.sh --purge'

# ==============================================================================
# R7: Concurrent isolated Docker runs & sentinel resource protection
# ==============================================================================
echo "=== [R7] Concurrent isolated Docker labs & mid-setup failure isolation ==="
R7_ID="${RUN_ID}-r7"
SENTINEL_NET="liqun-sentinel-${R7_ID}-net"
SENTINEL_CONT="liqun-sentinel-${R7_ID}-box"
SENTINEL_IMG="liqun-sentinel-img:${R7_ID}"

docker network create --internal "${SENTINEL_NET}" >/dev/null
docker tag "${IMG_NETNODE}" "${SENTINEL_IMG}"
docker run -d --name "${SENTINEL_CONT}" --network "${SENTINEL_NET}" "${SENTINEL_IMG}" sleep infinity >/dev/null

r7_cleanup_sentinels() {
    docker rm -f "${SENTINEL_CONT}" >/dev/null 2>&1 || true
    docker network rm "${SENTINEL_NET}" >/dev/null 2>&1 || true
    docker rmi "${SENTINEL_IMG}" >/dev/null 2>&1 || true
}
trap 'r7_cleanup_sentinels; lab_cleanup' EXIT

PARENT_NETNODE_IMG="${IMG_NETNODE}"

# Run two concurrent isolated mini-labs (each with its own unique RUN_ID, image tag, networks, and container) + setup failures.
(
    export LIQUN_TEST_FORCE_DYNAMIC_SUBNET=1
    lab_init_vars "concA-${R7_ID}"
    trap lab_cleanup EXIT
    docker tag "${PARENT_NETNODE_IMG}" "${IMG_NETNODE}"
    CREATED_IMAGES+=("${IMG_NETNODE}")
    lab_create_networks_and_env
    docker run -d --name "${C_CLIENT}" --network "${NET_PUB}" --ip "${CLIENT_IP}" "${IMG_NETNODE}" sleep 10 >/dev/null
    CREATED_CONTAINERS+=("${C_CLIENT}")
    echo "Concurrent lab A (${RUN_ID}) allocated: ${SUB_9929} & started ${C_CLIENT} (${IMG_NETNODE})"
    sleep 2
) &
pid_a=$!

(
    export LIQUN_TEST_FORCE_DYNAMIC_SUBNET=1
    lab_init_vars "concB-${R7_ID}"
    trap lab_cleanup EXIT
    docker tag "${PARENT_NETNODE_IMG}" "${IMG_NETNODE}"
    CREATED_IMAGES+=("${IMG_NETNODE}")
    lab_create_networks_and_env
    docker run -d --name "${C_CLIENT}" --network "${NET_PUB}" --ip "${CLIENT_IP}" "${IMG_NETNODE}" sleep 10 >/dev/null
    CREATED_CONTAINERS+=("${C_CLIENT}")
    echo "Concurrent lab B (${RUN_ID}) allocated: ${SUB_9929} & started ${C_CLIENT} (${IMG_NETNODE})"
    sleep 2
) &
pid_b=$!

set +e
(
    export LIQUN_TEST_FORCE_DYNAMIC_SUBNET=1
    lab_init_vars "failMid-${R7_ID}"
    trap lab_cleanup EXIT
    docker tag "${PARENT_NETNODE_IMG}" "${IMG_NETNODE}"
    CREATED_IMAGES+=("${IMG_NETNODE}")
    lab_create_networks_and_env
    docker run -d --name "${C_CLIENT}" --network "${NET_PUB}" --ip "${CLIENT_IP}" "${IMG_NETNODE}" sleep 10 >/dev/null
    CREATED_CONTAINERS+=("${C_CLIENT}")
    exit 9
)
fail_mid_rc=$?
set -e
[[ ${fail_mid_rc} -eq 9 ]] || fail "R7: expected mid-fail rc=9"

wait "${pid_a}" || fail "R7: concA subshell failed"
wait "${pid_b}" || fail "R7: concB subshell failed"

# Exercise failures during creation of each network after the first one. Every successful network must be registered for cleanup.
for fail_at in 2 3 4 5; do
    (
        export LIQUN_TEST_FORCE_DYNAMIC_SUBNET=1
        export LIQUN_TEST_FAIL_NETWORK_CREATE_AT="${fail_at}"
        lab_init_vars "failNet${fail_at}-${R7_ID}"
        trap lab_cleanup EXIT
        docker tag "${PARENT_NETNODE_IMG}" "${IMG_NETNODE}"
        CREATED_IMAGES+=("${IMG_NETNODE}")
        set +e
        lab_create_networks_and_env
        fail_net_rc=$?
        set -e
        [[ ${fail_net_rc} -ne 0 ]] || exit 11
    ) || fail "R7: network creation failure at index ${fail_at} was not rejected"
done

# Assert sentinel container, network, and image tag STILL exist and zero leaked resources.
docker inspect "${SENTINEL_CONT}" >/dev/null || fail "R7: sentinel container missing!"
docker network inspect "${SENTINEL_NET}" >/dev/null || fail "R7: sentinel network missing!"
docker image inspect "${SENTINEL_IMG}" >/dev/null || fail "R7: sentinel image missing!"
LEFTOVERS="$(docker ps -a --format '{{.Names}}' | grep -E "liqun-lab-(concA|concB|failMid|failNet[2-5])-.*${R7_ID}" || true)"
[[ -z "${LEFTOVERS}" ]] || fail "R7: leaked containers: ${LEFTOVERS}"
LEFTOVER_NETS="$(docker network ls --format '{{.Name}}' | grep -E "liqun_((concA|concB|failMid|failNet[2-5])-.*${R7_ID})" || true)"
[[ -z "${LEFTOVER_NETS}" ]] || fail "R7: leaked networks: ${LEFTOVER_NETS}"
echo "R7 verified: sentinel container/network/image intact; concurrent, mid-fail, and per-network failures cleaned only own resources."

echo ""
echo "========================================================================"
echo "ALL ROUND 2 AUDIT REGRESSION TESTS (R1 - R7) PASSED SUCCESSFULLY"
echo "========================================================================"
