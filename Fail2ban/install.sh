#!/usr/bin/env bash
# 独立部署 Fail2ban SSH 防护及配套的 safe-ssh-port。
set -Eeuo pipefail

CHANNEL=github
STAGE=
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FILES=(safe-ssh-port/safe-ssh-port.sh Fail2ban/f2btool.py)
CONFIG_ARGS=()

die() { printf '[f2b-install] 错误：%s\n' "$*" >&2; exit 1; }
log() { printf '[f2b-install] %s\n' "$*"; }
cleanup() { [[ -z $STAGE ]] || rm -rf -- "$STAGE"; }

usage() {
    cat <<'EOF'
用法：sudo bash Fail2ban/install.sh [选项]

  --channel github|gitee   远程下载渠道；本地仓库运行时使用本地文件
  --scope ssh|all          仅封禁 SSH 端口（默认）或宿主机全部入站端口
  --bantime 秒数           封禁时长，默认 604800（7 天）
  --findtime 秒数          检测窗口，默认 600
  --maxretry 次数          失败阈值，默认 5
  --ignore-ip IP/CIDR      额外管理白名单，可重复指定
  --help                   显示帮助

自动安装或更新 safe-ssh-port 与 f2btool，然后配置并启用 SSH 防护。
EOF
}

download() {
    local url=$1 target=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 "$url" -o "$target"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 60 -t 3 -O "$target" "$url"
    else
        die '下载需要 curl 或 wget。'
    fi
}

prepare_sources() {
    local base= api= sha= file
    STAGE=$(mktemp -d)
    trap cleanup EXIT
    if [[ -f $SOURCE_DIR/f2btool.py && -f $SOURCE_DIR/../safe-ssh-port/safe-ssh-port.sh ]]; then
        log '使用本地仓库文件。'
    else
        case $CHANNEL in
            github)
                api=https://api.github.com/repos/allen0039/vps_tools/commits/main
                base=https://raw.githubusercontent.com/allen0039/vps_tools ;;
            gitee)
                api=https://gitee.com/api/v5/repos/allen0039/vps_tools/branches/main
                base=https://gitee.com/allen0039/vps_tools/raw ;;
        esac
        download "${api}?f2b_refresh=$$-$RANDOM" "$STAGE/commit.json" ||
            die '无法查询渠道最新提交，请更换渠道重试。'
        sha=$(python3 - "$STAGE/commit.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    data = json.load(stream)
value = data.get("sha") if isinstance(data, dict) else None
if value is None and isinstance(data, dict):
    commit = data.get("commit")
    value = commit.get("sha") if isinstance(commit, dict) else None
if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value):
    print(value)
PY
        ) || die '渠道未返回有效提交编号。'
        [[ $sha =~ ^[0-9a-f]{40}$ ]] || die '渠道未返回有效提交编号。'
        base=$base/$sha
        log "下载渠道：${CHANNEL}，固定提交：$sha"
    fi
    for file in "${FILES[@]}"; do
        mkdir -p "$(dirname "$STAGE/$file")"
        if [[ -z $base ]]; then
            cp "$SOURCE_DIR/../$file" "$STAGE/$file" || die "缺少本地文件：$file"
        else
            download "$base/$file" "$STAGE/$file" || die "下载失败：${file}；尚未开始安装。"
        fi
        [[ -s $STAGE/$file ]] || die "文件为空：$file"
        if [[ $file == *.py ]]; then
            head -n 1 "$STAGE/$file" | grep -q '^#!/usr/bin/env python3' || die "文件不是 Python 脚本：$file"
            python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$STAGE/$file" ||
                die "语法检查失败：$file"
        else
            head -n 1 "$STAGE/$file" | grep -q '^#!/usr/bin/env bash' || die "文件不是 Bash 脚本：$file"
            bash -n "$STAGE/$file" || die "语法检查失败：$file"
        fi
    done
}

install_and_configure() {
    local target=/usr/local/sbin/f2btool
    if [[ -e $target || -L $target ]]; then
        [[ -f $target && ! -L $target ]] || die "拒绝覆盖非普通文件：$target"
        if ! cmp -s "$STAGE/Fail2ban/f2btool.py" "$target"; then
            grep -Fqx 'CONFIG_NAME = "99-vpstools-sshd.local"' "$target" ||
                die "目标不是可识别的 f2btool 文件，拒绝覆盖：$target"
        fi
    fi
    # safe-ssh-port 的 install --yes 只自动覆盖其自身的旧文件。
    bash "$STAGE/safe-ssh-port/safe-ssh-port.sh" install --yes ||
        die 'safe-ssh-port 安装失败；尚未启用 Fail2ban。'
    install -m 0755 "$STAGE/Fail2ban/f2btool.py" "$target"
    log '已安装配套工具，正在配置 Fail2ban SSH 防护。'
    "$target" configure --yes "${CONFIG_ARGS[@]}" ||
        die '配置失败；工具文件已安装，请修复错误后重新运行。'
    "$target" status
    log '部署完成。以后运行 sudo f2btool 管理 SSH 防护。'
}

main() {
    while (( $# )); do
        case $1 in
            --channel)
                (( $# >= 2 )) || die '--channel 缺少值。'
                CHANNEL=$2; shift 2 ;;
            --scope|--bantime|--findtime|--maxretry|--ignore-ip)
                (( $# >= 2 )) || die "$1 缺少值。"
                CONFIG_ARGS+=("$1" "$2"); shift 2 ;;
            --help|-h) usage; return 0 ;;
            *) die "未知参数：$1" ;;
        esac
    done
    [[ $CHANNEL == github || $CHANNEL == gitee ]] || die '渠道必须为 github 或 gitee。'
    [[ $(uname -s) == Linux ]] || die '请在 Linux VPS 上安装。'
    (( EUID == 0 )) || die '请使用 sudo bash Fail2ban/install.sh 或以 root 运行。'
    command -v python3 >/dev/null 2>&1 || die '缺少 Python 3。'
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die '需要 Python 3.8 或更新版本。'
    command -v flock >/dev/null 2>&1 || die '缺少 flock，请先安装 util-linux。'
    mkdir -p /usr/local/lib/vpstools /usr/local/sbin /usr/local/bin
    exec 9>/usr/local/lib/vpstools/install.lock
    flock -n 9 || die '另一个工具箱安装正在运行。'
    prepare_sources
    install_and_configure
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
