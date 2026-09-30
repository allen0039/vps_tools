#!/usr/bin/env bash
# install.sh - bbr-tune 一键安装与启动脚本
set -Eeuo pipefail

RAW_BASE="${BBR_TUNE_RAW_BASE:-https://raw.githubusercontent.com/allen0039/vps_tools/main/bbr-tune}"
INSTALL_PATH="${BBR_TUNE_INSTALL_PATH:-/usr/local/sbin/bbr-tune}"
LINK_PATH="${BBR_TUNE_LINK_PATH:-/usr/local/bin/bbr-tune}"
LAUNCH_AFTER_INSTALL="1"
TEMP_FILE=""
TEMP_KERNEL_FILE=""
DOWNLOAD_NONCE="${BBR_TUNE_DOWNLOAD_NONCE:-$$-$RANDOM-$RANDOM}"

log() { printf '[安装] %s\n' "$*"; }
warn() { printf '[警告] %s\n' "$*" >&2; }
die() { printf '[错误] %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  [[ -z "$TEMP_FILE" ]] || rm -f "$TEMP_FILE"
  [[ -z "$TEMP_KERNEL_FILE" ]] || rm -f "$TEMP_KERNEL_FILE"
}

usage() {
  cat <<'USAGE'
bbr-tune 一键安装脚本

用法：
  sudo bash install.sh                  安装或更新并启动交互界面
  sudo bash install.sh --install-only   仅安装或更新，不立即启动
  bash install.sh --help                查看帮助

安装位置：
  /usr/local/sbin/bbr-tune
  /usr/local/bin/bbr-tune -> /usr/local/sbin/bbr-tune
  /usr/local/bin/bbrtcp -> /usr/local/sbin/bbr-tune
USAGE
}

parse_args() {
  while (( $# )); do
    case "$1" in
      --install-only) LAUNCH_AFTER_INSTALL="0"; shift ;;
      --help|-h) usage; exit 0 ;;
      *) die "未知参数：$1" ;;
    esac
  done
}

require_linux_root() {
  [[ "$(uname -s)" == "Linux" ]] || die "该安装脚本只能在远程 Linux 服务器运行"
  (( EUID == 0 )) || die "请使用 root 权限运行，例如：sudo bash install.sh"
}

missing_runtime_commands() {
  local cmd missing=()
  for cmd in bash ip tc ss sysctl modprobe flock awk mktemp tee install grep head cp ln mkdir rm dirname uname; do
    have "$cmd" || missing+=("$cmd")
  done
  printf '%s\n' "${missing[@]:-}"
}

install_runtime_dependencies() {
  local missing
  missing="$(missing_runtime_commands)"
  [[ -z "$missing" ]] && return 0

  missing="${missing//$'\n'/ }"
  warn "检测到缺少服务器基础命令：${missing% }"
  log "正在安装基础运行依赖"
  if have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y bash iproute2 procps kmod coreutils grep gawk util-linux ca-certificates curl
  elif have dnf; then
    dnf install -y bash iproute procps-ng kmod coreutils grep gawk util-linux ca-certificates curl
  elif have yum; then
    yum install -y bash iproute procps-ng kmod coreutils grep gawk util-linux ca-certificates curl
  elif have zypper; then
    zypper --non-interactive install bash iproute2 procps kmod coreutils grep gawk util-linux ca-certificates curl
  elif have apk; then
    apk add --no-cache bash iproute2 procps-ng kmod coreutils grep gawk util-linux ca-certificates curl
  elif have pacman; then
    pacman -Sy --needed --noconfirm bash iproute2 procps-ng kmod coreutils grep gawk util-linux ca-certificates curl
  else
    die "无法识别服务器包管理器，请先安装：bash、iproute2、procps、kmod、coreutils、awk"
  fi

  missing="$(missing_runtime_commands)"
  missing="${missing//$'\n'/ }"
  [[ -z "${missing// /}" ]] || die "依赖安装完成后仍缺少命令：${missing% }"
}

local_payload_path() {
  local source_path="${BASH_SOURCE[0]:-}" source_dir
  [[ -n "$source_path" && -f "$source_path" ]] || return 1
  source_dir="$(cd "$(dirname "$source_path")" 2>/dev/null && pwd)" || return 1
  [[ -r "${source_dir}/bbr-tune.sh" ]] || return 1
  printf '%s\n' "${source_dir}/bbr-tune.sh"
}

download_payload() {
  local destination="$1" filename="${2:-bbr-tune.sh}"
  local url="${RAW_BASE}/${filename}?bbr_tune_refresh=${DOWNLOAD_NONCE}"
  if have curl; then
    curl -fL --retry 3 --connect-timeout 15 -H 'Cache-Control: no-cache' "$url" -o "$destination"
  elif have wget; then
    wget -O "$destination" "$url"
  else
    die "服务器缺少 curl 或 wget，无法下载主程序"
  fi
}

validate_payload() {
  local source_file="$1"
  [[ -s "$source_file" ]] || die "主程序文件为空"
  head -n 1 "$source_file" | grep -q '^#!/usr/bin/env bash' || die "下载内容不是有效的 Bash 主程序"
  bash -n "$source_file" || die "主程序语法检查失败"
}

version_is_older() {
  local candidate="$1" current="$2" i
  local -a candidate_parts current_parts
  [[ "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$current" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a candidate_parts <<<"$candidate"
  IFS=. read -r -a current_parts <<<"$current"
  for i in 0 1 2; do
    if (( 10#${candidate_parts[i]} < 10#${current_parts[i]} )); then return 0; fi
    if (( 10#${candidate_parts[i]} > 10#${current_parts[i]} )); then return 1; fi
  done
  return 1
}

install_payload() {
  local source_file="$1" install_path="${2:-$INSTALL_PATH}" link_path="${3:-$LINK_PATH}"
  local helper="${4:-${source_file%/*}/bbr-kernel.sh}" version helper_version shortcut_path installed_version
  validate_payload "$source_file"
  validate_payload "$helper"
  version="$(sed -n 's/^VERSION="\([^"]*\)"$/\1/p' "$source_file")"
  helper_version="$(sed -n 's/^KERNEL_HELPER_VERSION="\([^"]*\)"$/\1/p' "$helper")"
  [[ -n "$version" && "$version" == "$helper_version" ]] || die "主程序与内核管理脚本版本不匹配，未安装"
  if [[ -x "$install_path" ]]; then
    installed_version="$("$install_path" --version 2>/dev/null || true)"
    installed_version="${installed_version##* }"
    version_is_older "$version" "$installed_version" && die "下载版本 ${version} 低于已安装版本 ${installed_version}，已拒绝降级"
  fi
  shortcut_path="$(dirname "$link_path")/bbrtcp"
  if [[ "$shortcut_path" != "$install_path" && "$shortcut_path" != "$link_path" ]] &&
     { [[ -e "$shortcut_path" ]] || [[ -L "$shortcut_path" ]]; } &&
     { [[ ! -L "$shortcut_path" ]] || [[ "$(readlink "$shortcut_path")" != "$install_path" ]]; }; then
    die "快捷命令已被其他文件占用：$shortcut_path"
  fi
  mkdir -p "$(dirname "$install_path")" "$(dirname "$link_path")"
  install -m 0755 "$helper" "${install_path}-kernel"
  install -m 0755 "$source_file" "$install_path"
  if [[ "$link_path" != "$install_path" ]]; then
    ln -sfn "$install_path" "$link_path"
  fi
  if [[ "$shortcut_path" != "$install_path" && "$shortcut_path" != "$link_path" ]]; then
    ln -sfn "$install_path" "$shortcut_path"
  fi
}

launch_tool() {
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    log "正在启动交互界面"
    "$LINK_PATH" </dev/tty >/dev/tty 2>&1
  else
    warn "当前环境没有可用终端，已完成安装但不自动启动"
    printf '请登录服务器后执行：sudo %s\n' "$LINK_PATH"
  fi
}

acquire_install_lock() {
  local pending=/var/lib/bbr-tcp-tuning/pending-latest backup
  have flock || die "缺少 flock，无法安全更新"
  umask 077
  mkdir -p /var/lib/bbr-tcp-tuning
  exec 8>/var/lib/bbr-tcp-tuning/operation.lock
  flock -n 8 || die "调优或内核操作正在运行，请结束后再更新"
  if [[ -f "${pending}/armed" ]]; then
    backup="$(cat "${pending}/backup" 2>/dev/null || true)"
    [[ -n "$backup" && -s "${backup}/rollback-runner.sh" ]] || die "旧版调优仍待确认，请先执行 bbr-tune confirm 或 rollback，再更新"
  fi
}

main() {
  local source_file=""
  parse_args "$@"
  require_linux_root
  install_runtime_dependencies
  acquire_install_lock

  TEMP_FILE="$(mktemp /tmp/bbr-tune.XXXXXX)"
  TEMP_KERNEL_FILE="$(mktemp /tmp/bbr-kernel.XXXXXX)"
  trap cleanup EXIT
  if source_file="$(local_payload_path)"; then
    log "使用当前目录中的主程序：$source_file"
    cp "$source_file" "$TEMP_FILE"
    cp "${source_file%/*}/bbr-kernel.sh" "$TEMP_KERNEL_FILE"
  else
    log "正在从 ${RAW_BASE} 下载最新主程序"
    download_payload "$TEMP_FILE"
    download_payload "$TEMP_KERNEL_FILE" bbr-kernel.sh
  fi

  install_payload "$TEMP_FILE" "$INSTALL_PATH" "$LINK_PATH" "$TEMP_KERNEL_FILE"
  log "安装完成：$INSTALL_PATH"
  log "命令入口：$LINK_PATH"
  log "快捷入口：$(dirname "$LINK_PATH")/bbrtcp"
  "$LINK_PATH" --version

  cleanup
  TEMP_FILE=""; TEMP_KERNEL_FILE=""
  trap - EXIT
  flock -u 8
  exec 8>&-
  if (( LAUNCH_AFTER_INSTALL )); then launch_tool; fi
}

if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
