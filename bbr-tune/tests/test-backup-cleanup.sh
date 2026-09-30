#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
STATE_DIR="$tmp/state"
BACKUP_ROOT="$STATE_DIR/backups"
LATEST_BACKUP="$STATE_DIR/latest"
PENDING_DIR="$STATE_DIR/pending"
mkdir -p "$BACKUP_ROOT" "$PENDING_DIR" "$tmp/outside"

# Migration protects the oldest pre-existing session, even without a marker.
for id in 20260101-original 20260201-old 20260301-pending 20260401-latest; do
  mkdir -p "$BACKUP_ROOT/$id"
  touch "$BACKUP_ROOT/$id/meta.env" "$BACKUP_ROOT/$id/files.tsv" "$BACKUP_ROOT/$id/sysctl.tsv" "$BACKUP_ROOT/$id/qdisc.txt"
done
ln -s "$tmp/outside" "$BACKUP_ROOT/20260501-external"
ln -s "$BACKUP_ROOT/20260401-latest" "$LATEST_BACKUP"
mkdir -p "$PENDING_DIR/20260301-pending"
: >"$PENDING_DIR/20260301-pending/armed"
[[ "$(original_backup_path)" == "$BACKUP_ROOT/20260101-original" ]] || fail 'legacy original not selected'
[[ "$(cat "$STATE_DIR/original-backup")" == 20260101-original ]] || fail 'original marker missing'

printf '1\n0\n' | cleanup_backups_interactive >"$tmp/original.out" 2>&1
[[ -d "$BACKUP_ROOT/20260101-original" ]] || fail 'original backup deleted'
grep -q '原始备份不能删除' "$tmp/original.out" || fail 'original protection not explained'

printf '3\n0\n' | cleanup_backups_interactive >"$tmp/pending.out" 2>&1
[[ -d "$BACKUP_ROOT/20260301-pending" ]] || fail 'pending backup deleted'
grep -q '安全回滚保护' "$tmp/pending.out" || fail 'pending protection not explained'

printf '4\nn\n0\n' | cleanup_backups_interactive >"$tmp/cancel.out" 2>&1
[[ -d "$BACKUP_ROOT/20260401-latest" ]] || fail 'cancelled deletion removed backup'

printf '4\ny\n0\n' | cleanup_backups_interactive >"$tmp/latest.out" 2>&1
[[ ! -e "$BACKUP_ROOT/20260401-latest" ]] || fail 'latest backup not deleted'
[[ "$(readlink -f "$LATEST_BACKUP")" == "$(readlink -f "$BACKUP_ROOT/20260301-pending")" ]] || fail 'latest link not updated'

printf '2\ny\n0\n' | cleanup_backups_interactive >"$tmp/old.out" 2>&1
[[ ! -e "$BACKUP_ROOT/20260201-old" ]] || fail 'old backup not deleted'
[[ -d "$BACKUP_ROOT/20260101-original" && -d "$BACKUP_ROOT/20260301-pending" ]] || fail 'protected backup missing'
[[ -d "$tmp/outside" && -L "$BACKUP_ROOT/20260501-external" ]] || fail 'external symlink touched'

printf 'missing\n' >"$STATE_DIR/original-backup"
if printf '2\ny\n' | cleanup_backups_interactive >"$tmp/invalid.out" 2>&1; then fail 'invalid original marker allowed cleanup'; fi
[[ -d "$BACKUP_ROOT/20260301-pending" ]] || fail 'invalid marker allowed deletion'
rm -f "$STATE_DIR/original-backup"
mkdir -p "$BACKUP_ROOT/20251231-incomplete"
[[ "$(original_backup_path)" == "$BACKUP_ROOT/20260101-original" ]] || fail 'incomplete snapshot selected as original'

for id in 20260601-batch 20260602-batch; do
  mkdir -p "$BACKUP_ROOT/$id"
  touch "$BACKUP_ROOT/$id/meta.env" "$BACKUP_ROOT/$id/files.tsv" "$BACKUP_ROOT/$id/sysctl.tsv" "$BACKUP_ROOT/$id/qdisc.txt"
done
ln -sfn "$BACKUP_ROOT/20260602-batch" "$LATEST_BACKUP"
printf '2,4\n0\n' | cleanup_backups_interactive >"$tmp/batch-protected.out" 2>&1
[[ -d "$BACKUP_ROOT/20260601-batch" && -d "$BACKUP_ROOT/20260101-original" ]] || fail 'protected backup batch partially deleted'
printf '4,5\nn\n0\n' | cleanup_backups_interactive >"$tmp/batch-cancel.out" 2>&1
[[ -d "$BACKUP_ROOT/20260601-batch" && -d "$BACKUP_ROOT/20260602-batch" ]] || fail 'cancelled backup batch deleted'
printf '4,5\ny\n0\n' | cleanup_backups_interactive >"$tmp/batch.out" 2>&1
[[ ! -e "$BACKUP_ROOT/20260601-batch" && ! -e "$BACKUP_ROOT/20260602-batch" ]] || fail 'backup batch not deleted'
[[ "$(readlink -f "$LATEST_BACKUP")" == "$(readlink -f "$BACKUP_ROOT/20260301-pending")" ]] || fail 'latest backup pointer not repaired after batch'
[[ -d "$BACKUP_ROOT/20260101-original" && -d "$BACKUP_ROOT/20260301-pending" ]] || fail 'protected backup removed by batch'
SESSION_ROOT="$STATE_DIR/sessions"; ACTIVE_SESSION_FILE="$STATE_DIR/active-session"
mkdir -p "$SESSION_ROOT/20260701-active" "$BACKUP_ROOT/20260701-active"
touch "$BACKUP_ROOT/20260701-active/meta.env" "$BACKUP_ROOT/20260701-active/files.tsv" "$BACKUP_ROOT/20260701-active/sysctl.tsv" "$BACKUP_ROOT/20260701-active/qdisc.txt"
printf '20260701-active\n' >"$ACTIVE_SESSION_FILE"
printf '4,1\n0\n' | cleanup_backups_interactive >"$tmp/batch-active.out" 2>&1
[[ -d "$BACKUP_ROOT/20260701-active" ]] || fail 'active backup deleted'
grep -Fq '当前使用会话的备份不能删除' "$tmp/batch-active.out" || fail 'active backup protection not explained'
printf 'All backup cleanup and protection tests passed.\n'
