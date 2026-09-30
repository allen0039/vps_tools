#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
STATE_DIR="$tmp/state"; BACKUP_ROOT="$STATE_DIR/backups"
mkdir -p "$BACKUP_ROOT"

status_original_comparison eth0 >"$tmp/empty"
grep -Fq '尚无可用的原始备份' "$tmp/empty" || fail 'missing baseline not explained'
[[ ! -e "$STATE_DIR/original-backup" ]] || fail 'status created original marker'

backup="$BACKUP_ROOT/20260101-first"
mkdir -p "$backup"
touch "$backup/files.tsv" "$backup/sysctl.tsv"
printf 'IFACE=eth0\n' >"$backup/meta.env"
printf 'qdisc fq_codel 0: root\n' >"$backup/qdisc.txt"
cat >"$backup/observed.tsv" <<'SNAPSHOT'
net.ipv4.tcp_congestion_control	cubic
net.core.default_qdisc	fq_codel
net.core.rmem_max	4194304
net.core.wmem_max	4194304
net.ipv4.tcp_rmem	4096 87380 4194304
net.ipv4.tcp_wmem	4096 16384 4194304
SNAPSHOT
sysctl_get() {
  case "$1" in
    net.ipv4.tcp_congestion_control) echo bbr ;;
    net.core.default_qdisc) echo fq ;;
    net.core.rmem_max|net.core.wmem_max) echo 8388608 ;;
    net.ipv4.tcp_rmem) echo '4096 87380 8388608' ;;
    net.ipv4.tcp_wmem) echo '4096 16384 8388608' ;;
    net.ipv4.tcp_mem) echo '100 200 300' ;;
  esac
}
root_qdisc_kind() { echo fq; }
status_original_comparison eth0 >"$tmp/comparison"
grep -Fq '首次完整备份 20260101-first' "$tmp/comparison" || fail 'original backup not identified'
grep -Fq '原始：cubic' "$tmp/comparison" || fail 'original congestion control missing'
grep -Fq '当前：bbr' "$tmp/comparison" || fail 'current congestion control missing'
grep -Fq '原始：4194304 bytes (4.00 MiB)' "$tmp/comparison" || fail 'original buffer missing'
grep -Fq '原始：未记录' "$tmp/comparison" || fail 'missing old field not identified'
grep -Fq '原始：fq_codel' "$tmp/comparison" || fail 'original qdisc missing'
[[ ! -e "$STATE_DIR/original-backup" ]] || fail 'status wrote legacy marker'

printf 'IFACE=eth1\n' >"$backup/meta.env"
status_original_comparison eth0 >"$tmp/other-iface"
grep -Fq '无法直接对比' "$tmp/other-iface" || fail 'qdisc compared across interfaces'

rm "$backup/observed.tsv"
printf 'net.ipv4.tcp_congestion_control\tcubic\n' >"$backup/sysctl.tsv"
status_original_comparison eth0 >"$tmp/legacy"
grep -Fq '原始：cubic' "$tmp/legacy" || fail 'legacy sysctl snapshot ignored'

printf 'All status comparison tests passed.\n'
