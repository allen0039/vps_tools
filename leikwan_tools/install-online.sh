#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '用法: bash install-online.sh [github|gitee]\n'
}

die() {
    printf '错误: %s\n' "$*" >&2
    exit 1
}

(( $# <= 1 )) || { usage >&2; exit 2; }
case "${1-github}" in
    github) repository=https://github.com/allen0039/vps_tools.git ;;
    gitee) repository=https://gitee.com/allen0039/vps_tools.git ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

(( EUID == 0 )) || die '请以 root 或 sudo 运行。'
[[ -r /etc/os-release ]] || die '无法识别系统；请使用本地 install.sh。'
source /etc/os-release
[[ "${ID:-}" == debian ]] && command -v apt-get >/dev/null || die '自动安装依赖仅支持 Debian；其他系统请使用本地 install.sh。'
[[ -d /run/systemd/system ]] && command -v systemctl >/dev/null || die '此安装需要正在运行的 systemd。'

packages=()
command -v git >/dev/null || packages+=(git)
command -v python3 >/dev/null || packages+=(python3)
if ! command -v ip >/dev/null || ! command -v ss >/dev/null; then
    packages+=(iproute2)
fi
command -v ping >/dev/null || packages+=(iputils-ping)
[[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)

if (( ${#packages[@]} )); then
    printf '正在安装缺失依赖：%s\n' "${packages[*]}"
    apt-get update || die '无法更新 APT 软件包索引，请检查软件源和网络。'
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}" || die '依赖安装失败，尚未部署利群助手。'
fi

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
git clone --depth 1 --single-branch --branch main "$repository" "$work_dir/vps_tools" || die '仓库下载失败，请检查网络或改用另一渠道。'
bash "$work_dir/vps_tools/leikwan_tools/install.sh"
