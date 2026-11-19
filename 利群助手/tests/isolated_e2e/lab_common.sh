#!/usr/bin/env bash
# Shared isolated Docker lab lifecycle helper (unique per-run containers, networks, image tags, and dynamic subnets).

lab_init_vars() {
    local prefix="${1:-r2}"
    local rand_part
    rand_part="$(python3 -c 'import os, time; print(f"{int(time.time())}-{os.getpid()}-{os.urandom(2).hex()}")')"
    RUN_ID="${LIQUN_TEST_RUN_ID:-${prefix}-${rand_part}}"

    NET_9929="liqun_${RUN_ID}_0_9929"
    NET_CN2="liqun_${RUN_ID}_1_cn2"
    NET_PUB="liqun_${RUN_ID}_2_pub"
    NET_JP="liqun_${RUN_ID}_3_jp"
    NET_HK="liqun_${RUN_ID}_4_hk"

    C_ROUTER="liqun-lab-${RUN_ID}-router"
    C_VPS="liqun-lab-${RUN_ID}-vps"
    C_JP="liqun-lab-${RUN_ID}-jp"
    C_HK="liqun-lab-${RUN_ID}-hk"
    C_CLIENT="liqun-lab-${RUN_ID}-client"

    IMG_VPS="liqun-lab-vps:${RUN_ID}"
    IMG_NETNODE="liqun-lab-netnode:${RUN_ID}"

    CREATED_CONTAINERS=()
    CREATED_NETWORKS=()
    CREATED_IMAGES=()
    LAB_NET_ENV_FILE=""
}

lab_cleanup() {
    echo ""
    echo "=== [Cleanup] Removing ONLY resources created by RUN_ID=${RUN_ID} ==="
    if [[ ${#CREATED_CONTAINERS[@]} -gt 0 ]]; then
        for resource in "${CREATED_CONTAINERS[@]}"; do
            docker rm -f "${resource}" >/dev/null 2>&1 || true
        done
    fi
    if [[ ${#CREATED_NETWORKS[@]} -gt 0 ]]; then
        for resource in "${CREATED_NETWORKS[@]}"; do
            docker network rm "${resource}" >/dev/null 2>&1 || true
        done
    fi
    if [[ ${#CREATED_IMAGES[@]} -gt 0 ]]; then
        for resource in "${CREATED_IMAGES[@]}"; do
            docker rmi "${resource}" >/dev/null 2>&1 || true
        done
    fi
    if [[ -n "${LAB_NET_ENV_FILE}" && -f "${LAB_NET_ENV_FILE}" ]]; then
        rm -f "${LAB_NET_ENV_FILE}" || true
    fi
}

lab_build_images() {
    local e2e_dir="$1"
    echo "=== [Setup] Building isolated images (${IMG_VPS}, ${IMG_NETNODE}) ==="
    docker build -t "${IMG_VPS}" -f "${e2e_dir}/Dockerfile.vps" "${e2e_dir}"
    CREATED_IMAGES+=("${IMG_VPS}")
    docker build -t "${IMG_NETNODE}" -f "${e2e_dir}/Dockerfile.netnode" "${e2e_dir}"
    CREATED_IMAGES+=("${IMG_NETNODE}")
}

lab_create_networks_and_env() {
    LAB_NET_ENV_FILE="$(mktemp -t liqun-lab-net)"
    local alloc_log alloc_rc
    alloc_log="$(mktemp -t liqun-lab-alloc)"
    if python3 - "${NET_9929}" "${NET_CN2}" "${NET_PUB}" "${NET_JP}" "${NET_HK}" "${LIQUN_TEST_FORCE_DYNAMIC_SUBNET:-0}" >"${alloc_log}" <<'PY'
import fcntl, ipaddress, json, os, subprocess, sys

net_names = sys.argv[1:6]
force_dyn = sys.argv[6] == "1"
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
        cand_objs = [ipaddress.ip_network(s) for s in subnets]
        return all(not any(c.overlaps(u) for u in used_nets) for c in cand_objs)

    classic = ["10.7.0.0/24", "10.8.0.0/24", "203.0.113.0/24", "192.0.2.0/24", "198.51.100.0/24"]
    chosen = None
    mode = "classic"
    if not force_dyn and free_block(classic):
        chosen = {
            "SUB_9929": "10.7.0.0/24", "GW_DOCKER_9929": "10.7.0.254", "GW_9929": "10.7.0.1", "VPS_9929_IP": "10.7.0.146",
            "SUB_CN2": "10.8.0.0/24",  "GW_DOCKER_CN2": "10.8.0.254",  "GW_CN2": "10.8.0.1",  "VPS_CN2_IP": "10.8.0.146",
            "SUB_PUB": "203.0.113.0/24", "GW_DOCKER_PUB": "203.0.113.254", "GW_PUB": "203.0.113.1",
            "CLIENT_IP": "203.0.113.50", "PUB_10": "203.0.113.10", "PUB_11": "203.0.113.11", "PUB_12": "203.0.113.12", "PUB_13": "203.0.113.13",
            "SUB_JP": "192.0.2.0/24", "GW_DOCKER_JP": "192.0.2.254", "GW_JP": "192.0.2.1", "JP_IP": "192.0.2.10",
            "SUB_HK": "198.51.100.0/24", "GW_DOCKER_HK": "198.51.100.254", "GW_HK": "198.51.100.1", "HK_IP": "198.51.100.10",
        }
    else:
        mode = "dynamic"
        for s in range(20, 220):
            subs = [f"10.{s}.7.0/24", f"10.{s}.8.0/24", f"10.{s}.113.0/24", f"10.{s}.201.0/24", f"10.{s}.202.0/24"]
            if free_block(subs):
                chosen = {
                    "SUB_9929": f"10.{s}.7.0/24",   "GW_DOCKER_9929": f"10.{s}.7.254",   "GW_9929": f"10.{s}.7.1",   "VPS_9929_IP": f"10.{s}.7.146",
                    "SUB_CN2": f"10.{s}.8.0/24",    "GW_DOCKER_CN2": f"10.{s}.8.254",    "GW_CN2": f"10.{s}.8.1",    "VPS_CN2_IP": f"10.{s}.8.146",
                    "SUB_PUB": f"10.{s}.113.0/24",  "GW_DOCKER_PUB": f"10.{s}.113.254",  "GW_PUB": f"10.{s}.113.1",
                    "CLIENT_IP": f"10.{s}.113.50", "PUB_10": f"10.{s}.113.10", "PUB_11": f"10.{s}.113.11", "PUB_12": f"10.{s}.113.12", "PUB_13": f"10.{s}.113.13",
                    "SUB_JP": f"10.{s}.201.0/24",   "GW_DOCKER_JP": f"10.{s}.201.254",   "GW_JP": f"10.{s}.201.1",   "JP_IP": f"10.{s}.201.10",
                    "SUB_HK": f"10.{s}.202.0/24",   "GW_DOCKER_HK": f"10.{s}.202.254",   "GW_HK": f"10.{s}.202.1",   "HK_IP": f"10.{s}.202.10",
                }
                break
    if not chosen:
        raise RuntimeError("No free /24 subnet block found for isolated lab")

    pairs = [
        (net_names[0], chosen["SUB_9929"], chosen["GW_DOCKER_9929"]),
        (net_names[1], chosen["SUB_CN2"],  chosen["GW_DOCKER_CN2"]),
        (net_names[2], chosen["SUB_PUB"],  chosen["GW_DOCKER_PUB"]),
        (net_names[3], chosen["SUB_JP"],   chosen["GW_DOCKER_JP"]),
        (net_names[4], chosen["SUB_HK"],   chosen["GW_DOCKER_HK"]),
    ]
    fail_at = int(os.environ.get("LIQUN_TEST_FAIL_NETWORK_CREATE_AT", "0") or "0")
    for index, (nname, sub, gw) in enumerate(pairs, start=1):
        if fail_at == index:
            raise RuntimeError(f"Injected network creation failure at index {index}")
        subprocess.check_call(["docker", "network", "create", "--internal", f"--subnet={sub}", f"--gateway={gw}", nname], stdout=subprocess.DEVNULL)
        print(f"CREATED_NETWORK={nname}", flush=True)

    print(f"ALLOC_MODE={mode}")
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

    if [[ ${alloc_rc} -ne 0 ]]; then
        return "${alloc_rc}"
    fi

    # shellcheck disable=SC1090
    source "${LAB_NET_ENV_FILE}"
    echo "=== [Setup] Allocated subnets (${ALLOC_MODE}): 9929=${SUB_9929}, cn2=${SUB_CN2}, pub=${SUB_PUB}, jp=${SUB_JP}, hk=${SUB_HK} ==="
}

lab_start_containers() {
    echo "=== [Setup] Starting isolated lab containers (RUN_ID=${RUN_ID}) ==="
    docker create --name "${C_ROUTER}" --cap-add=NET_ADMIN --sysctl net.ipv4.ip_forward=1 --network "${NET_9929}" --ip "${GW_9929}" \
        "${IMG_NETNODE}" /opt/lab/setup_router.sh >/dev/null
    CREATED_CONTAINERS+=("${C_ROUTER}")
    docker network connect --ip "${GW_CN2}" "${NET_CN2}" "${C_ROUTER}"
    docker network connect --ip "${GW_PUB}" "${NET_PUB}" "${C_ROUTER}"
    docker network connect --ip "${GW_JP}"  "${NET_JP}"  "${C_ROUTER}"
    docker network connect --ip "${GW_HK}"  "${NET_HK}"  "${C_ROUTER}"
    docker cp "${LAB_NET_ENV_FILE}" "${C_ROUTER}:/etc/default/liqun-lab-net"
    docker start "${C_ROUTER}" >/dev/null

    docker run -d --name "${C_JP}" --cap-add=NET_ADMIN --network "${NET_JP}" --ip "${JP_IP}" \
        "${IMG_NETNODE}" sh -c "ip route replace default via ${GW_JP} && exec python3 /opt/lab/mock_landing.py --id zouter-jp-mock --port 54141" >/dev/null
    CREATED_CONTAINERS+=("${C_JP}")

    docker run -d --name "${C_HK}" --cap-add=NET_ADMIN --network "${NET_HK}" --ip "${HK_IP}" \
        "${IMG_NETNODE}" sh -c "ip route replace default via ${GW_HK} && exec python3 /opt/lab/mock_landing.py --id rfc-hk-mock --port 54848" >/dev/null
    CREATED_CONTAINERS+=("${C_HK}")

    docker run -d --name "${C_CLIENT}" --cap-add=NET_ADMIN --network "${NET_PUB}" --ip "${CLIENT_IP}" \
        "${IMG_NETNODE}" sh -c "ip route replace default via ${GW_PUB} && printf 'nameserver ${GW_PUB}\n' > /etc/resolv.conf && exec sleep infinity" >/dev/null
    CREATED_CONTAINERS+=("${C_CLIENT}")

    docker create --name "${C_VPS}" \
        --privileged --cgroupns=private \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
        --network "${NET_9929}" --ip "${VPS_9929_IP}" \
        "${IMG_VPS}" >/dev/null
    CREATED_CONTAINERS+=("${C_VPS}")
    docker network connect --ip "${VPS_CN2_IP}" "${NET_CN2}" "${C_VPS}"
    docker cp "${LAB_NET_ENV_FILE}" "${C_VPS}:/etc/default/liqun-lab-net"
    docker start "${C_VPS}" >/dev/null

    echo "=== [Setup] Waiting for Debian 12 systemd & router readiness ==="
    for _ in $(seq 1 30); do
        if docker exec "${C_ROUTER}" ss -H -lun | grep -q ":53 "; then
            break
        fi
        sleep 0.5
    done
    for _ in $(seq 1 40); do
        local st
        st="$(docker exec "${C_VPS}" systemctl is-system-running 2>/dev/null || true)"
        if [[ "${st}" == "running" || "${st}" == "degraded" ]]; then
            break
        fi
        sleep 1
    done
}
