#!/usr/bin/env bash
# 仅安装程序；不修改 TCP/sysctl 配置。
set -Eeuo pipefail
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEST_DIR=${1:-/usr/local/sbin}
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    printf '%s\n' '用法：sudo bash tcp-tool/install.sh [安装目录]' '默认安装 /usr/local/sbin/tcptool；安装不会应用参数。'
    exit 0
fi
(( $# <= 1 )) || { printf '最多指定一个安装目录。\n' >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { printf '请在 Linux VPS 上安装。\n' >&2; exit 1; }
(( EUID == 0 )) || { printf '请使用 sudo 或 root 安装。\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf '需要 Python 3.8+。\n' >&2; exit 1; }
command -v sysctl >/dev/null || { printf '需要 sysctl（procps）。\n' >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || { printf '需要 Python 3.8+。\n' >&2; exit 1; }
python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$SOURCE_DIR/tcp_tool.py"
mkdir -p "$DEST_DIR"
target=$DEST_DIR/tcptool
if [[ -e $target || -L $target ]]; then
    [[ -f $target && ! -L $target ]] || { printf '拒绝覆盖非普通文件：%s\n' "$target" >&2; exit 1; }
    grep -Fqx 'TOOL_ID = "vps-tools-tcptool"' "$target" || { printf '目标不是 tcptool，拒绝覆盖：%s\n' "$target" >&2; exit 1; }
fi
temporary=$(mktemp "$DEST_DIR/.tcptool-install.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
install -m 0755 "$SOURCE_DIR/tcp_tool.py" "$temporary"
mv -f -- "$temporary" "$target"
printf '已安装：%s\n运行 sudo %s 打开中文菜单。\n' "$target" "$target"
