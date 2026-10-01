#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
STATE_DIR="$tmp/state"; BACKUP_ROOT="$STATE_DIR/backups"; LATEST_BACKUP="$STATE_DIR/latest"
SYSCTL_FILE="$tmp/sysctl.conf"; MODULES_FILE="$tmp/modules.conf"; ENV_FILE="$tmp/env.conf"
QDISC_HELPER="$tmp/qdisc-helper"; SERVICE_FILE="$tmp/service.conf"
mkdir -p "$STATE_DIR"
printf 'original latest\n' >"$tmp/latest-target"
ln -s "$tmp/latest-target" "$LATEST_BACKUP"
printf 'net.ipv4.tcp_congestion_control=bbr\n' >"$SYSCTL_FILE"
require_linux() { :; }
require_root() { :; }
have() { :; }
systemd_available() { return 1; }
resolve_iface() { printf 'eth0\n'; }
sysctl_exists() { :; }
sysctl_get() { printf 'saved-%s\n' "$1"; }
tc() { printf 'qdisc fq 0: root refcnt 2\n'; }
root_qdisc_kind() { printf 'fq\n'; }

BACKUP_REMARK=""
backup_current_command >"$tmp/first.out"
first="$(original_backup_path_readonly)"
[[ -d "$first" && "$(cat "$first/remark.txt")" == 默认 ]] || fail 'default remark or original marker missing'
[[ "$(cat "$STATE_DIR/original-backup")" == "${first##*/}" ]] || fail 'first manual backup not original'
[[ -r "$first/observed.tsv" && -r "$first/qdisc.txt" && -r "$first/files.tsv" ]] || fail 'manual snapshot incomplete'
grep -Fq $'net.ipv4.tcp_congestion_control\tsaved-net.ipv4.tcp_congestion_control' "$first/observed.tsv" || fail 'current sysctl missing'
[[ "$(readlink "$LATEST_BACKUP")" == "$tmp/latest-target" ]] || fail 'manual backup changed default rollback target'
status_original_comparison eth0 >"$tmp/status.out"
grep -Fq '原始备份备注：默认' "$tmp/status.out" || fail 'status does not show original remark'

BACKUP_REMARK='调整前参数'
backup_current_command >"$tmp/second.out"
[[ "$(original_backup_path_readonly)" == "$first" ]] || fail 'second backup replaced original'
second="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d ! -path "$first" -print -quit)"
[[ -n "$second" && "$(cat "$second/remark.txt")" == 调整前参数 ]] || fail 'custom remark missing'
[[ "$(readlink "$LATEST_BACKUP")" == "$tmp/latest-target" ]] || fail 'second backup changed default rollback target'
printf '0\n' | cleanup_backups_interactive >"$tmp/list.out"
grep -Fq '备注：调整前参数' "$tmp/list.out" || fail 'cleanup list does not show remark'

ui_execute() { printf '%s\n' "$*" >>"$tmp/ui-calls"; }
IFACE=auto
printf '1\n\n' | ui_status >"$tmp/ui.out"
grep -Fqx '1 status --iface auto' "$tmp/ui-calls" || fail 'status menu did not read root-owned baseline'
grep -Fqx '1 backup-current --iface auto --remark 默认' "$tmp/ui-calls" || fail 'status menu did not request default manual backup'
printf 'All manual backup tests passed.\n'
