#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_LIB_DIR="/usr/local/lib/leikwan_tools"
BIN_PATH="/usr/local/bin/leikwan_tools"
SHORTCUT_PATH="/usr/local/bin/lqtool"
SYSTEMD_UNIT_PATH="/etc/systemd/system/leikwan_tools-realm@.service"
ROUTING_UNIT_PATH="/etc/systemd/system/leikwan_tools-routing.service"
ROUTING_UNIT_SOURCE="${SCRIPT_DIR}/leikwan_tools/leikwan_tools-routing.service"
DDNS_SERVICE_PATH="/etc/systemd/system/leikwan_tools-ddns.service"
DDNS_TIMER_PATH="/etc/systemd/system/leikwan_tools-ddns.timer"
DDNS_SERVICE_SOURCE="${SCRIPT_DIR}/systemd/leikwan_tools-ddns.service"
DDNS_TIMER_SOURCE="${SCRIPT_DIR}/systemd/leikwan_tools-ddns.timer"
CONFIG_DIR="/etc/leikwan_tools"
STATE_DIR="/var/lib/leikwan_tools"
LOCK_FILE="/run/leikwan_tools.lock"

REALM_BIN_ARG=""
REALM_TARBALL_ARG=""
SKIP_REALM_INSTALL=0
ORIG_ARGS=("$@")

usage() {
    cat <<'EOF'
用法: sudo bash install.sh [选项]

选项:
  --realm-bin <path>       指定要复用的已有 Realm 二进制路径（校验版本 >= 2.6.0 且主版本为 2）
  --realm-tarball <path>   指定离线 Realm v2.9.6 官方 .tar.gz 安装包路径（执行 SHA-256 校验）
  --skip-realm-install     若未找到已有 Realm，跳过下载安装（稍后需手动执行 install-realm）
  --config-dir <dir>       配置目录 (默认: /etc/leikwan_tools)
  --state-dir <dir>        状态与生成配置目录 (默认: /var/lib/leikwan_tools)
  -h, --help               显示帮助
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --realm-bin)
            REALM_BIN_ARG="${2:-}"
            shift 2
            ;;
        --realm-tarball)
            REALM_TARBALL_ARG="${2:-}"
            shift 2
            ;;
        --skip-realm-install)
            SKIP_REALM_INSTALL=1
            shift
            ;;
        --config-dir)
            CONFIG_DIR="${2:-}"
            shift 2
            ;;
        --state-dir)
            STATE_DIR="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "错误: 未知参数 $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    echo "错误: 请使用 root 或 sudo 运行 install.sh" >&2
    exit 1
fi

for cmd in python3 ip ss systemctl; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "错误: 缺少系统命令 ${cmd}" >&2
        exit 1
    fi
done

# Coordinate entire install lifecycle under the shared FileLock against concurrent uninstall/apply.
if [[ "${_LEIKWAN_TOOLS_INSTALL_LOCKED:-0}" != "1" ]]; then
    export PYTHONPATH="${SCRIPT_DIR}"
    exec env _LEIKWAN_TOOLS_INSTALL_LOCKED=1 python3 -m leikwan_tools.ownership with-lock \
        --lock-file "${LOCK_FILE}" --lock-timeout 20 -- \
        bash "${BASH_SOURCE[0]}" "${ORIG_ARGS[@]}"
fi

export PYTHONPATH="${SCRIPT_DIR}"
if ! python3 "${SCRIPT_DIR}/bin/leikwan_tools" --version >/dev/null; then
    echo "错误: 利群助手安装包不完整或入口无法加载；请重新下载统一安装器或使用利群助手的更新命令。" >&2
    exit 1
fi
python3 -m leikwan_tools.ownership check-install-targets \
    --config-dir "${CONFIG_DIR}" --state-dir "${STATE_DIR}" --lock-file "${LOCK_FILE}"

ROUTING_FRAGMENT="$(systemctl show -p FragmentPath --value leikwan_tools-routing.service || true)"
ROUTING_DROPINS="$(systemctl show -p DropInPaths --value leikwan_tools-routing.service || true)"
if [[ -L "${ROUTING_UNIT_PATH}" || -n "${ROUTING_DROPINS}" ||
      ( -n "${ROUTING_FRAGMENT}" && "${ROUTING_FRAGMENT}" != "${ROUTING_UNIT_PATH}" ) ]] ||
   { [[ -e "${ROUTING_UNIT_PATH}" ]] && ! cmp -s "${ROUTING_UNIT_PATH}" "${ROUTING_UNIT_SOURCE}" && ! grep -Fxq "# Managed-By: leikwan_tools" "${ROUTING_UNIT_PATH}"; }; then
    echo "错误: 拒绝覆盖非受管源策略路由服务 ${ROUTING_UNIT_PATH}" >&2
    exit 1
fi

for unit_name in leikwan_tools-ddns.service leikwan_tools-ddns.timer; do
    unit_path="/etc/systemd/system/${unit_name}"
    fragment="$(systemctl show -p FragmentPath --value "${unit_name}" || true)"
    dropins="$(systemctl show -p DropInPaths --value "${unit_name}" || true)"
    if [[ -n "${dropins}" || ( -n "${fragment}" && "${fragment}" != "${unit_path}" ) ]]; then
        echo "错误: 拒绝覆盖非本工具 DDNS 单元 ${unit_name} (${fragment})" >&2
        exit 1
    fi
done

echo "[1/5] 安装 leikwan_tools 程序文件到 ${INSTALL_LIB_DIR}..."
mkdir -p "${INSTALL_LIB_DIR}/bin"
rm -rf "${INSTALL_LIB_DIR}/leikwan_tools"
cp -R "${SCRIPT_DIR}/leikwan_tools" "${INSTALL_LIB_DIR}/leikwan_tools"
find "${INSTALL_LIB_DIR}/leikwan_tools" -type d -name "__pycache__" -exec rm -rf {} +

install -m 0755 "${SCRIPT_DIR}/bin/realm-exec.sh" "${INSTALL_LIB_DIR}/realm-exec.sh"
install -m 0755 "${SCRIPT_DIR}/bin/realm-preflight.sh" "${INSTALL_LIB_DIR}/realm-preflight.sh"
install -m 0755 "${SCRIPT_DIR}/bin/leikwan_tools" "${BIN_PATH}"
install -m 0755 "${SCRIPT_DIR}/bin/leikwan_tools" "${SHORTCUT_PATH}"

echo "[2/5] 安装 systemd 模板单元 ${SYSTEMD_UNIT_PATH}..."
install -m 0644 "${SCRIPT_DIR}/systemd/leikwan_tools-realm@.service" "${SYSTEMD_UNIT_PATH}"
install -m 0644 "${ROUTING_UNIT_SOURCE}" "${ROUTING_UNIT_PATH}"
install -m 0644 "${DDNS_SERVICE_SOURCE}" "${DDNS_SERVICE_PATH}"
systemctl daemon-reload
systemctl enable leikwan_tools-routing.service

echo "[3/5] 初始化配置目录 ${CONFIG_DIR} 与状态目录 ${STATE_DIR}（不启用任何示例规则）..."
ensure_dir() {
    local dir="$1"
    if [[ -L "${dir}" || ( -e "${dir}" && ! -d "${dir}" ) ]]; then
        echo "错误: 安装目标不是普通目录: ${dir}" >&2
        exit 1
    fi
    if [[ ! -e "${dir}" ]]; then
        mkdir -p "${dir}"
        chmod 0755 "${dir}"
    fi
}

# Preserve permissions on pre-existing shared directories. Only directories
# created by this installation receive the default mode.
ensure_dir "${CONFIG_DIR}"
ensure_dir "${CONFIG_DIR}/rules.d"
ensure_dir "${CONFIG_DIR}/examples"
ensure_dir "${STATE_DIR}"
ensure_dir "${STATE_DIR}/realm"
ensure_dir "${STATE_DIR}/state"

EXAMPLE_ARGS=()
for src_ex in "${SCRIPT_DIR}/examples/"*.toml; do
    base_ex="$(basename "${src_ex}")"
    dst_ex="${CONFIG_DIR}/examples/${base_ex}"
    if [[ -e "${dst_ex}" || -L "${dst_ex}" ]]; then
        if [[ -L "${dst_ex}" || ! -f "${dst_ex}" ]]; then
            echo "错误: 示例文件目标不是普通文件: ${dst_ex}" >&2
            exit 1
        fi
        echo "  保留已有示例文件: ${dst_ex}"
    else
        install -m 0644 "${src_ex}" "${dst_ex}"
        EXAMPLE_ARGS+=(--example-file "${dst_ex}")
    fi
done

CREATED_CONFIG=0
if [[ ! -f "${CONFIG_DIR}/config.toml" ]]; then
    cp "${SCRIPT_DIR}/examples/config.example.toml" "${CONFIG_DIR}/config.toml"
    python3 - "${CONFIG_DIR}/config.toml" "${REALM_BIN_ARG}" "${CONFIG_DIR}/rules.d" "${STATE_DIR}" "${LOCK_FILE}" <<'PY'
import os, pathlib, sys
cfg_path, rb, rules_dir, state_dir, lock_file = sys.argv[1:6]
p = pathlib.Path(cfg_path)
txt = p.read_text(encoding="utf-8")
if rb:
    txt = txt.replace('realm_bin = ""', f'realm_bin = "{rb}"', 1)
txt = txt.replace('rules_dir = "/etc/leikwan_tools/rules.d"', f'rules_dir = "{os.path.realpath(rules_dir)}"', 1)
txt = txt.replace('state_dir = "/var/lib/leikwan_tools"', f'state_dir = "{os.path.realpath(state_dir)}"', 1)
txt = txt.replace('lock_file = "/run/leikwan_tools.lock"', f'lock_file = "{lock_file}"', 1)
p.write_text(txt, encoding="utf-8")
PY
    chmod 0644 "${CONFIG_DIR}/config.toml"
    CREATED_CONFIG=1
    echo "  已生成初始主配置: ${CONFIG_DIR}/config.toml（请按本机参数核对后使用）"
else
    echo "  保留已有主配置: ${CONFIG_DIR}/config.toml"
fi

# Render the DDNS timer interval from the independent [ddns] configuration.
# A later config change takes effect after rerunning install.sh (or an update).
DDNS_INTERVAL_SECONDS="$(python3 - "${CONFIG_DIR}/config.toml" <<'PY'
from leikwan_tools.config import load_global_config
import sys
print(load_global_config(sys.argv[1]).ddns.interval_seconds)
PY
)"
python3 - "${CONFIG_DIR}/config.toml" "${DDNS_TIMER_SOURCE}" "${DDNS_TIMER_PATH}" "${DDNS_INTERVAL_SECONDS}" <<'PY'
import pathlib, re, sys

_, source_path, target_path, interval_text = sys.argv[1:5]
interval = int(interval_text)
text = pathlib.Path(source_path).read_text(encoding="utf-8")
text, count = re.subn(r"(?m)^OnUnitActiveSec=.*$", f"OnUnitActiveSec={interval}s", text, count=1)
if count != 1:
    raise SystemExit("DDNS timer 模板缺少 OnUnitActiveSec")
pathlib.Path(target_path).write_text(text, encoding="utf-8")
pathlib.Path(target_path).chmod(0o644)
print(f"  DDNS 自动更新周期: {interval}s")
PY
systemctl daemon-reload
systemctl enable --now leikwan_tools-ddns.timer

echo "[4/5] 检查并准备兼容的 Realm 二进制（保留系统已有二进制，不覆盖）..."
export PYTHONPATH="${INSTALL_LIB_DIR}"
REALM_META_FILE="$(mktemp)"
trap 'rm -f "${REALM_META_FILE}"' EXIT

REALM_OK=0
if [[ -n "${REALM_BIN_ARG}" ]]; then
    if python3 - "${REALM_BIN_ARG}" "${STATE_DIR}" "${REALM_META_FILE}" <<'PY'
import json, pathlib, sys
from leikwan_tools.realm import inspect_realm_binary
bin_arg, state_dir, meta_out = sys.argv[1], sys.argv[2], sys.argv[3]
info = inspect_realm_binary(bin_arg, origin="configured")
print(f"  复用指定 Realm: {info.path} (v{info.version_text}, sha256={info.sha256[:12]}...)")
sd = pathlib.Path(state_dir)
sd.mkdir(parents=True, exist_ok=True)
rec = sd / "realm-source.json"
if not rec.exists():
    rec.write_text(json.dumps({
        "mode": "reused-configured",
        "version": info.version_text,
        "binary_path": info.path,
        "binary_sha256": info.sha256,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
pathlib.Path(meta_out).write_text(json.dumps({"path": info.path, "managed": False}), encoding="utf-8")
PY
    then
        REALM_OK=1
    else
        echo "错误: 指定的 --realm-bin 不可用或不兼容: ${REALM_BIN_ARG}" >&2
        exit 1
    fi
elif [[ -z "${REALM_TARBALL_ARG}" ]]; then
    if python3 - "${STATE_DIR}" "${REALM_META_FILE}" <<'PY'
import json, os, pathlib, sys
from leikwan_tools import MANAGED_REALM_BIN
from leikwan_tools.realm import discover_realm_binary, RealmError
state_dir, meta_out = sys.argv[1], sys.argv[2]
try:
    info = discover_realm_binary()
    is_managed = (os.path.realpath(info.path) == os.path.realpath(MANAGED_REALM_BIN))
    print(f"  发现并复用已有兼容 Realm: {info.path} (v{info.version_text}, origin={info.origin}, sha256={info.sha256[:12]}...)")
    sd = pathlib.Path(state_dir)
    sd.mkdir(parents=True, exist_ok=True)
    rec = sd / "realm-source.json"
    if not rec.exists():
        rec.write_text(json.dumps({
            "mode": f"reused-{info.origin}",
            "version": info.version_text,
            "binary_path": info.path,
            "binary_sha256": info.sha256,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pathlib.Path(meta_out).write_text(json.dumps({"path": info.path, "managed": is_managed}), encoding="utf-8")
    raise SystemExit(0)
except RealmError:
    raise SystemExit(1)
PY
    then
        REALM_OK=1
    fi
fi

if [[ "${REALM_OK}" -eq 0 ]]; then
    if [[ "${SKIP_REALM_INSTALL}" -eq 1 ]]; then
        echo "  已跳过 Realm 安装；启用规则前请先运行: leikwan_tools install-realm"
        printf '{"path": "", "managed": false}' > "${REALM_META_FILE}"
    else
        if [[ -n "${REALM_TARBALL_ARG}" ]]; then
            "${BIN_PATH}" --config "${CONFIG_DIR}/config.toml" install-realm --tarball "${REALM_TARBALL_ARG}" --state-dir "${STATE_DIR}"
        else
            "${BIN_PATH}" --config "${CONFIG_DIR}/config.toml" install-realm --state-dir "${STATE_DIR}"
        fi
        printf '{"path": "/usr/local/lib/leikwan_tools/bin/realm", "managed": true}' > "${REALM_META_FILE}"
    fi
fi

REALM_USED_PATH="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["path"])' "${REALM_META_FILE}")"
REALM_MANAGED_FLAG="$(python3 -c 'import json,sys; print("1" if json.load(open(sys.argv[1]))["managed"] else "0")' "${REALM_META_FILE}")"

WRITE_ARGS=(
    --install-lib-dir "${INSTALL_LIB_DIR}"
    --config-dir "${CONFIG_DIR}"
    --state-dir "${STATE_DIR}"
    --config-file "${CONFIG_DIR}/config.toml"
    --lock-file "${LOCK_FILE}"
    --realm-bin "${REALM_USED_PATH}"
)
if [[ "${REALM_MANAGED_FLAG}" == "1" ]]; then
    WRITE_ARGS+=(--realm-managed)
fi
if [[ "${CREATED_CONFIG}" == "1" ]]; then
    WRITE_ARGS+=(--created-config)
fi
WRITE_ARGS+=("${EXAMPLE_ARGS[@]}")

# Note: lock already held by parent with-lock wrapper, call write_install_artifacts directly!
python3 - "${WRITE_ARGS[@]}" <<'PY'
import argparse
from leikwan_tools.ownership import write_install_artifacts

p = argparse.ArgumentParser()
p.add_argument("--install-lib-dir", required=True)
p.add_argument("--config-dir", required=True)
p.add_argument("--state-dir", required=True)
p.add_argument("--config-file", required=True)
p.add_argument("--lock-file", required=True)
p.add_argument("--realm-bin", default="")
p.add_argument("--realm-managed", action="store_true")
p.add_argument("--created-config", action="store_true")
p.add_argument("--example-file", action="append", default=[])
a = p.parse_args()

write_install_artifacts(
    install_lib_dir=a.install_lib_dir,
    config_dir=a.config_dir,
    state_dir=a.state_dir,
    config_file=a.config_file,
    lock_file=a.lock_file,
    realm_bin_path=a.realm_bin,
    realm_managed_install=a.realm_managed,
    example_files=a.example_file,
    created_config_file=a.created_config,
)
PY

echo "[5/5] 安装完成验证..."
"${BIN_PATH}" --version
echo "安装完成："
echo "  - 输入 lqtool 打开交互菜单。"
echo "  - 已写入资源归属清单: ${INSTALL_LIB_DIR}/install-manifest.json"
echo "  - 已启用独立 DDNS 定时器: leikwan_tools-ddns.timer（周期 ${DDNS_INTERVAL_SECONDS}s；未配置或 disabled 时自动跳过）"
echo "  - 未启用任何示例规则；未修改 Toolkit / LeiKwanManager / v6-mng.sh / 现有 Realm / 路由 / 防火墙。"
echo "  - 核对 ${CONFIG_DIR}/config.toml 后，用 lqtool routing plan 预览源策略路由，或从菜单进入「5. 初始化与环境排查 -> 1. 初始化双线出口路由」。"
