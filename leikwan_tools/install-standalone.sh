#!/usr/bin/env bash
set -euo pipefail

SOURCE_CHANNEL="gitee"
SKIP_REALM_INSTALL=0
WORK_DIR=""

usage() {
    cat <<'EOF'
用法: bash install-standalone.sh [选项]

上传这一个文件到 Debian 12/13 VPS 后运行。脚本会自动安装缺失依赖，
下载完整利群助手源码和已校验的 Realm 二进制，然后调用正式安装器。

选项:
  --source gitee|github  源码下载渠道（默认: gitee）
  --config-dir <dir>    传给正式安装器的配置目录
  --state-dir <dir>     传给正式安装器的状态目录
  --skip-realm-install  跳过 Realm 安装，稍后手动执行 install-realm
  -h, --help            显示帮助
EOF
}

die() {
    printf '错误: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
        rm -rf -- "${WORK_DIR}"
    fi
}

trap cleanup EXIT

INSTALL_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)
            [[ $# -ge 2 ]] || die "--source 需要 gitee 或 github"
            SOURCE_CHANNEL="$2"
            shift 2
            ;;
        --config-dir|--state-dir)
            [[ $# -ge 2 ]] || die "$1 需要目录参数"
            INSTALL_ARGS+=("$1" "$2")
            shift 2
            ;;
        --skip-realm-install)
            SKIP_REALM_INSTALL=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "未知参数: $1"
            ;;
    esac
done

case "${SOURCE_CHANNEL}" in
    gitee)
        SOURCE_ARCHIVE_URL="https://gitee.com/allen0039/vps_tools/repository/archive/main.tar.gz"
        ;;
    github)
        SOURCE_ARCHIVE_URL="https://codeload.github.com/allen0039/vps_tools/tar.gz/refs/heads/main"
        ;;
    *)
        die "--source 只能是 gitee 或 github"
        ;;
esac

(( EUID == 0 )) || die "请以 root 或 sudo 运行"
[[ -r /etc/os-release ]] || die "无法识别系统"
source /etc/os-release
[[ "${ID:-}" == "debian" ]] || die "自动依赖安装仅支持 Debian；其他系统请使用本地 install.sh"
[[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1 || die "此安装需要正在运行的 systemd"

packages=()
for command_name in curl tar gzip python3; do
    command -v "${command_name}" >/dev/null 2>&1 || packages+=("${command_name}")
done
if ! command -v ip >/dev/null 2>&1 || ! command -v ss >/dev/null 2>&1; then
    packages+=(iproute2)
fi
command -v ping >/dev/null 2>&1 || packages+=(iputils-ping)
[[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)

if (( ${#packages[@]} > 0 )); then
    printf '正在安装缺失依赖：%s\n' "${packages[*]}"
    apt-get update || die "APT 软件源更新失败"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        "${packages[@]}" || die "依赖安装失败"
fi

WORK_DIR="$(mktemp -d -t leikwan-standalone.XXXXXX)"
SOURCE_TARBALL="${WORK_DIR}/vps_tools.tar.gz"

printf '[1/3] 下载利群助手源码（%s）...\n' "${SOURCE_CHANNEL}"
curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 180 \
    "${SOURCE_ARCHIVE_URL}" -o "${SOURCE_TARBALL}" ||
    die "源码下载失败，请检查 VPS 到 ${SOURCE_CHANNEL} 的网络连接"
tar -xzf "${SOURCE_TARBALL}" -C "${WORK_DIR}"
SOURCE_DIR="$(find "${WORK_DIR}" -mindepth 1 -maxdepth 1 -type d -name 'vps_tools-*' -print -quit)"
[[ -n "${SOURCE_DIR}" && -f "${SOURCE_DIR}/leikwan_tools/install.sh" ]] ||
    die "源码压缩包内容不完整"

if (( SKIP_REALM_INSTALL )); then
    printf '[2/3] 跳过 Realm 下载。\n'
    printf '[3/3] 安装利群助手...\n'
    bash "${SOURCE_DIR}/leikwan_tools/install.sh" --skip-realm-install "${INSTALL_ARGS[@]}"
    exit
fi

realm_arch=$(uname -m)
case "${realm_arch}" in
    x86_64|amd64)
        REALM_ASSET="realm-x86_64-unknown-linux-musl.tar.gz"
        REALM_SHA256="b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65"
        ;;
    aarch64|arm64)
        REALM_ASSET="realm-aarch64-unknown-linux-musl.tar.gz"
        REALM_SHA256="f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488"
        ;;
    *)
        die "暂不支持当前架构: ${realm_arch}，可使用 --skip-realm-install"
        ;;
esac
REALM_ARCHIVE="${WORK_DIR}/${REALM_ASSET}"

printf '[2/3] 下载并校验 Realm v2.9.6...\n'
REALM_UPSTREAM="https://github.com/zhboner/realm/releases/download/v2.9.6/${REALM_ASSET}"
realm_urls=(
    "https://ghfast.top/${REALM_UPSTREAM}"
    "https://gh-proxy.com/${REALM_UPSTREAM}"
    "${REALM_UPSTREAM}"
)
downloaded=0
for realm_url in "${realm_urls[@]}"; do
    printf '  尝试 %s\n' "${realm_url}"
    if curl -fL --retry 2 --connect-timeout 15 --max-time 180 \
        "${realm_url}" -o "${REALM_ARCHIVE}.part"; then
        if printf '%s  %s\n' "${REALM_SHA256}" "${REALM_ARCHIVE}.part" | sha256sum -c -; then
            mv -- "${REALM_ARCHIVE}.part" "${REALM_ARCHIVE}"
            downloaded=1
            break
        fi
        rm -f -- "${REALM_ARCHIVE}.part"
        printf '  校验失败，继续尝试下一个地址\n' >&2
    fi
done
(( downloaded == 1 )) || die "Realm 下载或校验失败；可使用 --skip-realm-install 后手动安装"

printf '[3/3] 安装利群助手...\n'
bash "${SOURCE_DIR}/leikwan_tools/install.sh" \
    --realm-tarball "${REALM_ARCHIVE}" "${INSTALL_ARGS[@]}"
