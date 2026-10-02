#!/usr/bin/env bash
# 独立入口。只检查依赖；不安装常驻服务、不修改 TCP 或防火墙配置。
set -Eeuo pipefail
TOOL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    printf '缺少 Python 3.8+。Debian/Ubuntu：sudo apt-get install python3 iperf3\n' >&2
    exit 1
fi
exec python3 "$TOOL_DIR/iperf3_tool.py" "$@"
