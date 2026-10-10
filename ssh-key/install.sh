#!/usr/bin/env bash
# 只部署程序；不改变 SSH 认证、密钥和登录策略。
set -Eeuo pipefail
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEST_DIR=${1:-/usr/local/sbin}
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    printf '%s\n' '用法：sudo bash ssh-key/install.sh [安装目录]' \
        '默认安装 /usr/local/sbin/sshkeytool；安装不修改 SSH 或生成密钥。'
    exit 0
fi
(( $# <= 1 )) || { printf '最多指定一个安装目录。\n' >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { printf '请在 Linux VPS 上安装。\n' >&2; exit 1; }
(( EUID == 0 )) || { printf '请使用 sudo 或 root 安装。\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf '需要 Python 3.8+。\n' >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || { printf '需要 Python 3.8+。\n' >&2; exit 1; }
command -v ssh-keygen >/dev/null || { printf '需要 OpenSSH 客户端的 ssh-keygen。\n' >&2; exit 1; }
python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$SOURCE_DIR/ssh_key_tool.py"
mkdir -p "$DEST_DIR"
target=$DEST_DIR/sshkeytool
if [[ -e $target || -L $target ]]; then
    [[ -f $target && ! -L $target ]] || { printf '拒绝覆盖非普通文件：%s\n' "$target" >&2; exit 1; }
    grep -Fqx 'TOOL_ID = "vps-tools-sshkeytool"' "$target" || { printf '目标不是 sshkeytool，拒绝覆盖。\n' >&2; exit 1; }
fi
temporary=$(mktemp "$DEST_DIR/.sshkeytool-install.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
install -m 0755 "$SOURCE_DIR/ssh_key_tool.py" "$temporary"
mv -f -- "$temporary" "$target"
printf '已安装：%s\n运行 sudo %s 打开中文菜单。\n' "$target" "$target"
