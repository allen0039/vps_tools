#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_LIB_DIR="/usr/local/lib/leikwan_tools"
CONFIG_DIR_ARG=""
STATE_DIR_ARG=""
PURGE=0
LOCK_TIMEOUT=15

usage() {
    cat <<'EOF'
用法: sudo bash uninstall.sh [选项]

选项:
  --purge              仅删除安装清单记录的本工具配置文件（不会误删共享目录中的无关文件）
  --config-dir <dir>   指定配置目录（有安装清单时须与安装记录一致）
  --state-dir <dir>    指定状态目录（有安装清单时须与安装记录一致）
  --lock-timeout <sec> 并发写锁等待秒数 (默认: 15)
  -h, --help           显示帮助

说明:
  依据安装清单与规则归属记录执行加锁清理，只删除 leikwan_tools 自身创建的资源；
  共享目录中的无关文件、复用的 Realm、非托管同名服务、Toolkit、LeiKwanManager、v6-mng.sh、路由和防火墙均保持原样。
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge)
            PURGE=1
            shift
            ;;
        --config-dir)
            CONFIG_DIR_ARG="${2:-}"
            shift 2
            ;;
        --state-dir)
            STATE_DIR_ARG="${2:-}"
            shift 2
            ;;
        --lock-timeout)
            LOCK_TIMEOUT="${2:-15}"
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
    echo "错误: 请使用 root 或 sudo 运行 uninstall.sh" >&2
    exit 1
fi

PY_ROOT=""
if [[ -f "${INSTALL_LIB_DIR}/leikwan_tools/ownership.py" ]]; then
    PY_ROOT="${INSTALL_LIB_DIR}"
elif [[ -f "${SCRIPT_DIR}/leikwan_tools/ownership.py" ]]; then
    PY_ROOT="${SCRIPT_DIR}"
else
    echo "错误: 未找到 leikwan_tools.ownership 模块，拒绝执行无清单清理" >&2
    exit 1
fi

UN_ARGS=(
    --install-lib-dir "${INSTALL_LIB_DIR}"
    --lock-timeout "${LOCK_TIMEOUT}"
)
if [[ "${PURGE}" -eq 1 ]]; then
    UN_ARGS+=(--purge)
fi
if [[ -n "${CONFIG_DIR_ARG}" ]]; then
    UN_ARGS+=(--config-dir "${CONFIG_DIR_ARG}")
fi
if [[ -n "${STATE_DIR_ARG}" ]]; then
    UN_ARGS+=(--state-dir "${STATE_DIR_ARG}")
fi

export PYTHONPATH="${PY_ROOT}"
exec python3 -m leikwan_tools.ownership uninstall "${UN_ARGS[@]}"
