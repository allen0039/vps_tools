#!/usr/bin/env bash
# 独立入口。自动补齐 Python；iperf3 由 Python 入口检测、安装。
set -Eeuo pipefail
TOOL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
die() { printf '错误：%s\n' "$*" >&2; exit 1; }
python_ready() {
    command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))'
}
if ! python_ready; then
    [[ $(uname -s) == Linux ]] || die '请在 Linux VPS 上运行。'
    privilege=()
    if (( EUID != 0 )); then
        command -v sudo >/dev/null 2>&1 || die '自动安装 Python 需要 root 或 sudo 权限。'
        privilege=(sudo --)
    fi
    # 按发行版及其上游选择包管理器；无 os-release 时探测可用命令。
    ID= ID_LIKE=
    if [[ -r /etc/os-release ]]; then source /etc/os-release; fi
    managers=(apt-get dnf yum zypper apk pacman)
    for identity in $ID $ID_LIKE; do
        case $identity in
            debian|ubuntu) managers=(apt-get); break ;;
            rhel|fedora|centos|rocky|almalinux|amzn) managers=(dnf yum); break ;;
            suse|opensuse|opensuse-leap|opensuse-tumbleweed) managers=(zypper); break ;;
            alpine) managers=(apk); break ;;
            arch|manjaro) managers=(pacman); break ;;
        esac
    done
    manager=
    for candidate in "${managers[@]}"; do
        if command -v "$candidate" >/dev/null 2>&1; then manager=$candidate; break; fi
    done
    [[ -n $manager ]] || die '无法识别包管理器，请手动安装 Python 3.8+ 后重试。'
    printf '检测到 %s，缺少 Python 3.8+，正在使用 %s 自动安装……\n' "${PRETTY_NAME:-Linux}" "$manager"
    install_python() {
        case $manager in
            apt-get)
                "${privilege[@]}" apt-get update &&
                "${privilege[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y python3 ;;
            dnf|yum) "${privilege[@]}" "$manager" install -y python3 ;;
            zypper) "${privilege[@]}" zypper --non-interactive install python3 ;;
            apk) "${privilege[@]}" apk add --no-cache python3 ;;
            pacman) "${privilege[@]}" pacman -S --needed --noconfirm python ;;
        esac
    }
    install_python || die 'Python 安装失败，请检查权限、网络及软件源后重试。'
    python_ready || die '安装后仍缺少 Python 3.8+；请使用提供较新 Python 的软件源或升级系统。'
fi
exec python3 "$TOOL_DIR/iperf3_tool.py" "$@"
