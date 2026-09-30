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
ACTIVE_SESSION_FILE="$STATE_DIR/active-session"
mkdir -p "$SESSION_ROOT" "$BACKUP_ROOT" "$PENDING_DIR" "$tmp/outside"
cleanup_parse_selection '1, 3 5' 5 || fail 'mixed batch selection rejected'
[[ "${CLEANUP_SELECTION[*]}" == '0 2 4' ]] || fail 'batch selection parsed incorrectly'
for invalid in '1,1' '1,6' '0,1' '1,a'; do
  if cleanup_parse_selection "$invalid" 5; then fail "invalid batch selection accepted: $invalid"; fi
done

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
echo "$completed" >"$STATE_DIR/active-session"
printf '1\n0\n' | cleanup_history_interactive >"$tmp/active.out" 2>&1
[[ -d "$SESSION_ROOT/$completed" ]] || fail 'active session deleted'
grep -Fq '当前使用会话' "$tmp/active.out" || fail 'active session not listed'
grep -Fq '当前使用会话，不能删除' "$tmp/active.out" || fail 'active session protection not explained'
rm -f "$STATE_DIR/active-session"

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
batch_one=20260106-batch-one
batch_two=20260107-batch-two
for id in "$batch_one" "$batch_two"; do
  mkdir -p "$SESSION_ROOT/$id" "$BACKUP_ROOT/$id"
  printf 'evidence\n' >"$SESSION_ROOT/$id/results.tsv"
  printf '2026-01-06\t%s\t100\t120\n' "$id" >>"$HISTORY_FILE"
done
printf '1,2\n0\n' | cleanup_history_interactive >"$tmp/batch-protected.out" 2>&1
[[ -d "$SESSION_ROOT/$batch_one" ]] || fail 'protected history batch partially deleted'
printf '2,3\nn\n0\n' | cleanup_history_interactive >"$tmp/batch-cancel.out" 2>&1
[[ -d "$SESSION_ROOT/$batch_one" && -d "$SESSION_ROOT/$batch_two" ]] || fail 'cancelled history batch deleted'
printf '2,3\ny\n0\n' | cleanup_history_interactive >"$tmp/batch.out" 2>&1
[[ ! -e "$SESSION_ROOT/$batch_one" && ! -e "$SESSION_ROOT/$batch_two" ]] || fail 'history batch directories kept'
if grep -Eq "$batch_one|$batch_two" "$HISTORY_FILE"; then fail 'history batch index kept'; fi
[[ -d "$BACKUP_ROOT/$batch_one" && -d "$BACKUP_ROOT/$batch_two" ]] || fail 'backup removed with history batch'
grep -Fq "$pending" "$HISTORY_FILE" || fail 'protected history index removed'
mkdir -p "$STATE_DIR/network-tests" "$tmp/csv"
printf 'old output\n' >"$STATE_DIR/network-tests/old.log"
printf 'keep\n' >"$STATE_DIR/network-tests/notes.txt"
printf 'old CSV\n' >"$tmp/csv/zstatic_nping_20260930.csv"
printf 'keep\n' >"$tmp/csv/unrelated.csv"
printf '1,2\nn\n0\n' | cleanup_speedtest_files_interactive "$tmp/csv" >"$tmp/speed-cancel.out" 2>&1
[[ -f "$STATE_DIR/network-tests/old.log" && -f "$tmp/csv/zstatic_nping_20260930.csv" ]] || fail 'cancelled speed cleanup deleted files'
printf '1,1\n0\n' | cleanup_speedtest_files_interactive "$tmp/csv" >"$tmp/speed-invalid.out" 2>&1
grep -Fq '不重复编号' "$tmp/speed-invalid.out" || fail 'duplicate speed selection accepted'
printf '1,2\ny\n0\n' | cleanup_speedtest_files_interactive "$tmp/csv" >"$tmp/speed-deleted.out" 2>&1
[[ ! -e "$STATE_DIR/network-tests/old.log" && ! -e "$tmp/csv/zstatic_nping_20260930.csv" ]] || fail 'selected speed files retained'
[[ -f "$STATE_DIR/network-tests/notes.txt" && -f "$tmp/csv/unrelated.csv" ]] || fail 'unrelated speed files deleted'
cleanup_backups_interactive() { printf 'backup choice\n'; }
cleanup_history_interactive() { printf 'history choice\n'; }
cleanup_speedtest_files_interactive() { printf 'speed choice\n'; }
printf '1\n2\n3\n0\n' | cleanup_data_interactive >"$tmp/menu.out"
grep -Fq 'backup choice' "$tmp/menu.out" || fail 'backup submenu not reached'
grep -Fq 'history choice' "$tmp/menu.out" || fail 'history submenu not reached'
grep -Fq 'speed choice' "$tmp/menu.out" || fail 'speed submenu not reached'
parse_args cleanup-history
[[ "$COMMAND" == cleanup-history ]] || fail 'history cleanup command not parsed'
parse_args cleanup-data
[[ "$COMMAND" == cleanup-data ]] || fail 'data cleanup command not parsed'
printf 'All history cleanup tests passed.\n'
