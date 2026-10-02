#!/usr/bin/env bash
# 单独安装 netcheck，不安装 pip 包或修改系统网络配置。
set -Eeuo pipefail
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEST_DIR=${NETCHECK_BIN_DIR:-"$HOME/.local/bin"}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    printf '%s\n' '用法：bash install.sh [安装目录]' \
        '默认安装到 ~/.local/bin；系统安装：sudo bash install.sh /usr/local/bin'
    exit 0
fi
(( $# <= 1 )) || { printf '最多指定一个安装目录。\n' >&2; exit 2; }
[[ $# == 0 ]] || DEST_DIR=$1
command -v python3 >/dev/null || { printf '请先安装 Python 3.8 或更新版本。\n' >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || {
    printf '需要 Python 3.8 或更新版本。\n' >&2; exit 1;
}
python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$SOURCE_DIR/netcheck.py"
mkdir -p "$DEST_DIR"
install -m 0755 "$SOURCE_DIR/netcheck.py" "$DEST_DIR/netcheck"
printf '已安装：%s/netcheck\n直接运行该文件打开菜单；使用 --help 查看命令。\n' "$DEST_DIR"
case ":$PATH:" in
    *":$DEST_DIR:"*) ;;
    *) printf '安装目录未在 PATH 中，可以使用完整路径，或将此目录加入 PATH。\n' ;;
esac
