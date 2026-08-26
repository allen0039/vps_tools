#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="${VPSPC_REPOSITORY:-allen0039/vps_tools}"
REVISION="${VPSPC_REF:-main}"
SOURCE_ROOT="${VPSPC_SOURCE_ROOT:-/opt/vps-audit-src}"
ACTION="${1:-install}"
TEMP_ROOT=""

die() {
  echo "错误: $*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$TEMP_ROOT" && -d "$TEMP_ROOT" ]]; then
    rm -rf -- "$TEMP_ROOT"
  fi
}

download() {
  local url="$1"
  local output="$2"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --silent --show-error --retry 3 --output "$output" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=3 --output-document="$output" "$url"
  else
    die "需要 curl 或 wget 下载项目"
  fi
}

[[ "$(id -u)" -eq 0 ]] || die "请使用 sudo bash remote-install.sh"
[[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux"
command -v tar >/dev/null 2>&1 || die "需要 tar"
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "VPSPC_REPOSITORY 格式无效"
[[ "$REVISION" =~ ^[A-Za-z0-9._/-]+$ ]] || die "VPSPC_REF 格式无效"
[[ "$SOURCE_ROOT" == /* && "$SOURCE_ROOT" != "/" ]] || die "VPSPC_SOURCE_ROOT 必须是具体的绝对路径"
case "$ACTION" in install|rollback|destroy) ;; *) die "用法: sudo bash remote-install.sh [install|rollback|destroy]" ;; esac

TEMP_ROOT="$(mktemp -d /tmp/vpspc-install.XXXXXX)"
trap cleanup EXIT
ARCHIVE="$TEMP_ROOT/source.tar.gz"
ARCHIVE_URL="https://github.com/$REPOSITORY/archive/$REVISION.tar.gz"

echo "正在下载 $REPOSITORY ($REVISION)..."
download "$ARCHIVE_URL" "$ARCHIVE"
tar -xzf "$ARCHIVE" -C "$TEMP_ROOT"

INSTALLER_LIST="$TEMP_ROOT/installers.txt"
find "$TEMP_ROOT" -mindepth 2 -maxdepth 4 -type f -path '*/vpspc/install.sh' -print > "$INSTALLER_LIST"
[[ "$(wc -l < "$INSTALLER_LIST" | tr -d ' ')" == "1" ]] || die "下载包中未找到唯一的 vpspc/install.sh"
IFS= read -r INSTALLER_PATH < "$INSTALLER_LIST"
SOURCE_DIR="$(dirname -- "$INSTALLER_PATH")"
[[ -f "$SOURCE_DIR/vps_audit/runtime.py" ]] || die "下载包缺少运行时文件"
[[ -f "$SOURCE_DIR/deploy/systemd/vps-audit.service" ]] || die "下载包缺少 systemd 模板"

if [[ -d "$SOURCE_ROOT" && ! -f "$SOURCE_ROOT/.vpspc-source-managed" ]]; then
  if [[ ! -f "$SOURCE_ROOT/install.sh" || ! -f "$SOURCE_ROOT/vps_audit/runtime.py" ]]; then
    die "源码目录已存在且不属于 vpspc，拒绝覆盖: $SOURCE_ROOT"
  fi
  echo "检测到旧版 vpspc 源码目录，将补充管理标记后原位升级。"
fi
install -d -m 0755 "$SOURCE_ROOT"
cp -a "$SOURCE_DIR/." "$SOURCE_ROOT/"
chmod 0755 "$SOURCE_ROOT/install.sh" "$SOURCE_ROOT/remote-install.sh"
printf 'managed-by=vpspc-remote-installer\n' > "$SOURCE_ROOT/.vpspc-source-managed"
chmod 0600 "$SOURCE_ROOT/.vpspc-source-managed"

if [[ "$ACTION" == "destroy" ]]; then
  echo "源码已准备，开始彻底卸载 vpspc。"
elif [[ "$ACTION" == "rollback" ]]; then
  echo "源码已准备，开始恢复上一次 vpspc 配置。"
else
  echo "源码已保存到 ${SOURCE_ROOT}，开始交互安装。"
fi
"$SOURCE_ROOT/install.sh" "$ACTION"
if [[ "$ACTION" == "destroy" && "$0" == "/tmp/vpspc-install.sh" ]]; then
  rm -f -- "$0"
fi
