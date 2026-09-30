#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
STATE_DIR="$tmp/state"; SESSION_ROOT="$STATE_DIR/sessions"
BACKUP_ROOT="$STATE_DIR/backups"; PENDING_DIR="$STATE_DIR/pending"
HISTORY_FILE="$STATE_DIR/history.tsv"
mkdir -p "$SESSION_ROOT" "$BACKUP_ROOT" "$PENDING_DIR" "$tmp/outside"

completed=20260101-completed
pending=20260102-pending
orphan=20260103-interrupted
index_only=20260104-index-only
linked=20260105-linked
for id in "$completed" "$pending" "$orphan"; do
  mkdir -p "$SESSION_ROOT/$id" "$BACKUP_ROOT/$id"
  printf 'evidence\n' >"$SESSION_ROOT/$id/results.tsv"
done
ln -s "$tmp/outside" "$SESSION_ROOT/$linked"
printf 'keep\n' >"$tmp/outside/keep.txt"
mkdir -p "$PENDING_DIR/$pending"
: >"$PENDING_DIR/$pending/armed"
cat >"$HISTORY_FILE" <<EOF_HISTORY
time	session	before_single_mbps	after_single_mbps
2026-01-01	$completed	100	120
2026-01-02	$pending	100	130
2026-01-04	$index_only	100	140
2026-01-05	$linked	100	150
EOF_HISTORY

printf '2\n0\n' | cleanup_history_interactive >"$tmp/pending.out" 2>&1
[[ -d "$SESSION_ROOT/$pending" ]] || fail 'pending session deleted'
grep -Fq '安全回滚保护' "$tmp/pending.out" || fail 'pending protection not explained'

printf '1\nn\n0\n' | cleanup_history_interactive >"$tmp/cancel.out" 2>&1
[[ -d "$SESSION_ROOT/$completed" ]] || fail 'cancelled deletion removed session'

if ! printf '1\ny\n0\n' | cleanup_history_interactive >"$tmp/completed.out" 2>&1; then
  cat "$tmp/completed.out"
  fail 'completed cleanup failed'
fi
[[ ! -e "$SESSION_ROOT/$completed" ]] || fail 'completed session directory kept'
[[ -d "$BACKUP_ROOT/$completed" ]] || fail 'backup deleted with history'
if grep -Fq "$completed" "$HISTORY_FILE"; then fail 'completed session index kept'; fi
grep -Fq "$pending" "$HISTORY_FILE" || fail 'unrelated history index removed'

printf '2\ny\n0\n' | cleanup_history_interactive >"$tmp/orphan.out" 2>&1
[[ ! -e "$SESSION_ROOT/$orphan" ]] || fail 'unindexed session directory kept'

printf '2\ny\n0\n' | cleanup_history_interactive >"$tmp/index-only.out" 2>&1
if grep -Fq "$index_only" "$HISTORY_FILE"; then fail 'index-only record kept'; fi

printf '2\ny\n0\n' | cleanup_history_interactive >"$tmp/linked.out" 2>&1
[[ -f "$tmp/outside/keep.txt" ]] || fail 'external symlink target touched'
grep -Fq "$linked" "$HISTORY_FILE" || fail 'symlinked session index deleted'
grep -Fq '会话状态已变化' "$tmp/linked.out" || fail 'symlink guard not explained'

[[ "$(head -n 1 "$HISTORY_FILE")" == $'time\tsession\tbefore_single_mbps\tafter_single_mbps' ]] || fail 'history header changed'
cleanup_backups_interactive() { printf 'backup choice\n'; }
cleanup_history_interactive() { printf 'history choice\n'; }
printf '1\n2\n0\n' | cleanup_data_interactive >"$tmp/menu.out"
grep -Fq 'backup choice' "$tmp/menu.out" || fail 'backup submenu not reached'
grep -Fq 'history choice' "$tmp/menu.out" || fail 'history submenu not reached'
parse_args cleanup-history
[[ "$COMMAND" == cleanup-history ]] || fail 'history cleanup command not parsed'
parse_args cleanup-data
[[ "$COMMAND" == cleanup-data ]] || fail 'data cleanup command not parsed'
printf 'All history cleanup tests passed.\n'
