#!/usr/bin/env bash
# 先取得并检查完整脚本，再调用原安装器。
set -Eeuo pipefail
CHANNEL=github
STAGE=
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FILES=(vpstools.sh install.sh safe-ssh-port/safe-ssh-port.sh dns_tool/dns_tool.sh
       swap_tool/swap_tool.sh restart-mmw-agent/restart-mmw-agent
       bbr-tune/install.sh bbr-tune/bbr-tune.sh bbr-tune/bbr-kernel.sh web_tool/netcheck.py
       iperf3_tool/iperf3-tool.sh iperf3_tool/iperf3_tool.py Fail2ban/f2btool.py
       system_tool/install.sh system_tool/ipv6_tool.py tcp-tool/install.sh tcp-tool/tcp_tool.py
       ssh-key/install.sh ssh-key/ssh_key_tool.py)

die() { printf '[vpstools] 错误：%s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' '用法：sudo bash install.sh [--channel github|gitee]' \
        '在仓库根目录运行时安装本地文件；单独下载安装器时从所选渠道下载。' \
        '仅部署程序并保存 DNS 初始备份；完成后运行 vpstools 打开菜单。'
}
cleanup() { [[ -z $STAGE ]] || rm -rf -- "$STAGE"; }

download() {
    local url=$1 target=$2
    if command -v curl >/dev/null; then
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 "$url" -o "$target"
    elif command -v wget >/dev/null; then
        wget -q -T 60 -t 3 -O "$target" "$url"
    else
        die '下载需要 curl 或 wget。'
    fi
}

prepare_sources() {
    local file base api sha
    STAGE=$(mktemp -d)
    trap cleanup EXIT
    if [[ -f $SOURCE_DIR/vpstools.sh && -f $SOURCE_DIR/safe-ssh-port/safe-ssh-port.sh ]]; then
        printf '[vpstools] 使用本地仓库文件。\n'
        base=
    else
        case $CHANNEL in
            github)
                api=https://api.github.com/repos/allen0039/vps_tools/commits/main
                base=https://raw.githubusercontent.com/allen0039/vps_tools ;;
            gitee)
                api=https://gitee.com/api/v5/repos/allen0039/vps_tools/branches/main
                base=https://gitee.com/allen0039/vps_tools/raw ;;
        esac
        download "${api}?vpstools_refresh=$$-$RANDOM" "$STAGE/commit.json" || die '无法查询渠道最新提交，请更换渠道重试。'
        sha=$(grep -oEm1 '"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]{40}"' "$STAGE/commit.json" | head -n 1 | grep -oE '[0-9a-f]{40}' || true)
        [[ $sha =~ ^[0-9a-f]{40}$ ]] || die '渠道未返回有效提交编号。'
        base=$base/$sha
        printf '[vpstools] 下载渠道：%s，固定提交：%s\n' "$CHANNEL" "$sha"
    fi
    for file in "${FILES[@]}"; do
        mkdir -p "$(dirname "$STAGE/$file")"
        if [[ -z $base ]]; then
            cp "$SOURCE_DIR/$file" "$STAGE/$file" || die "缺少本地文件：$file"
        else
            download "$base/$file" "$STAGE/$file" || die "下载失败：$file；尚未开始安装。"
        fi
        [[ -s $STAGE/$file ]] || die "文件为空：$file"
        if [[ $file == *.py ]]; then
            head -n 1 "$STAGE/$file" | grep -q '^#!/usr/bin/env python3' || die "文件不是 Python 脚本：$file"
            python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$STAGE/$file" || die "语法检查失败：$file"
        else
            head -n 1 "$STAGE/$file" | grep -q '^#!/usr/bin/env bash' || die "文件不是 Bash 脚本：$file"
            bash -n "$STAGE/$file" || die "语法检查失败：$file"
        fi
    done
}

install_tools() {
    # 各工具保留自己的备份、权限检查和 BBR 操作锁。
    bash "$STAGE/safe-ssh-port/safe-ssh-port.sh" install || die 'SSH 工具安装失败。此前已完成的安装保留，可修复后重试。'
    bash "$STAGE/dns_tool/dns_tool.sh" install || die 'DNS 工具安装失败。此前已完成的安装保留，可修复后重试。'
    install -m 0755 "$STAGE/swap_tool/swap_tool.sh" /usr/local/bin/swaptool
    install -m 0755 "$STAGE/restart-mmw-agent/restart-mmw-agent" /usr/local/sbin/restart-mmw-agent
    install -m 0755 "$STAGE/web_tool/netcheck.py" /usr/local/bin/netcheck
    install -m 0755 "$STAGE/iperf3_tool/iperf3_tool.py" /usr/local/bin/iperfprobe
    install -m 0755 "$STAGE/Fail2ban/f2btool.py" /usr/local/sbin/f2btool
    bash "$STAGE/system_tool/install.sh" || die 'Ipv4/ipv6管理工具安装失败。此前已完成的安装保留，可修复后重试。'
    bash "$STAGE/tcp-tool/install.sh" || die 'TCP 工具安装失败。此前已完成的安装保留，可修复后重试。'
    bash "$STAGE/ssh-key/install.sh" || die 'SSH 密钥工具安装失败。此前已完成的安装保留，可修复后重试。'
    bash "$STAGE/bbr-tune/install.sh" --install-only || die 'BBR 安装失败。此前已完成的安装保留，可修复后重试。'
    install -m 0755 "$STAGE/install.sh" /usr/local/lib/vpstools/install.sh
    install -m 0755 "$STAGE/vpstools.sh" /usr/local/bin/vpstools
    printf '\n[vpstools] 全部安装完成，输入 vpstools 打开工具箱。\n'
}

main() {
    while (( $# )); do
        case $1 in
            --channel) (( $# >= 2 )) || die '--channel 缺少值。'; CHANNEL=$2; shift 2 ;;
            --help|-h) usage; return ;;
            *) die "未知参数：$1" ;;
        esac
    done
    [[ $CHANNEL == github || $CHANNEL == gitee ]] || die '渠道必须为 github 或 gitee。'
    [[ $(uname -s) == Linux ]] || die '请在 Linux VPS 上安装。'
    (( EUID == 0 )) || die '请使用 sudo bash install.sh 或以 root 运行。'
    command -v flock >/dev/null || die '缺少 flock，请先安装 util-linux。'
    command -v python3 >/dev/null || die '网址检测需要 Python 3.8 或更新版本，请先安装 python3。'
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die '需要 Python 3.8 或更新版本。'
    mkdir -p /usr/local/bin /usr/local/sbin /usr/local/lib/vpstools
    exec 9>/usr/local/lib/vpstools/install.lock
    flock -n 9 || die '另一个工具箱安装正在运行。'
    prepare_sources
    install_tools
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
