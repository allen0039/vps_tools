#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
STATE_DIR="$tmp/state"; SESSION_ROOT="$STATE_DIR/sessions"; BACKUP_ROOT="$STATE_DIR/backups"
LATEST_BACKUP="$STATE_DIR/latest"; ACTIVE_SESSION_FILE="$STATE_DIR/active-session"
PENDING_DIR="$STATE_DIR/pending"; PENDING_LATEST="$STATE_DIR/pending-latest"
HISTORY_FILE="$STATE_DIR/history.tsv"; SESSION_ID=old-session
mkdir -p "$SESSION_ROOT/$SESSION_ID"
COMPARISON_FILE="$SESSION_ROOT/$SESSION_ID/comparison.txt"
TARGET_MBPS=500; RTT_MS=20; BALANCE_MULTI_STREAMS=8; BEST_BUFFER_MIB=8
OUTCOME=best-effort-runtime; STRATEGY=balanced
BASELINE_SINGLE_MBPS=100; FINAL_SINGLE_MBPS=120
BASELINE_MULTI_MBPS=300; FINAL_MULTI_MBPS=340
append_history
printf 'stage\tround\tmode\tconfig\tstreams\tbuffer_mib\nfinal\t1\tsingle\tbbr-fq\t1\t8\nfinal\t1\tmulti\tbbr-fq\t8\t8\n' >"$SESSION_ROOT/$SESSION_ID/results.tsv"
cat >"$SESSION_ROOT/$SESSION_ID/system-before.txt" <<'BEFORE'
kernel=Linux old
interface=eth0
net.ipv4.tcp_congestion_control=cubic
net.core.default_qdisc=fq
net.core.rmem_max=4194304
net.core.wmem_max=4194304
net.ipv4.tcp_rmem=4096 87380 4194304
net.ipv4.tcp_wmem=4096 16384 4194304
net.ipv4.tcp_mem=100 200 300
memory_total_mib=1024
memory_effective_mib=1024
memory_tcp_budget_mib=682
memory_buffer_cap_mib=682
[qdisc]
qdisc fq 0: root
BEFORE
cat >"$SESSION_ROOT/$SESSION_ID/system-after.txt" <<'AFTER'
kernel=Linux old
interface=eth0
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq
net.core.rmem_max=8388608
net.core.wmem_max=8388608
net.ipv4.tcp_rmem=4096 87380 8388608
net.ipv4.tcp_wmem=4096 16384 8388608
net.ipv4.tcp_mem=100 200 300
memory_total_mib=1024
memory_effective_mib=1024
memory_tcp_budget_mib=682
memory_buffer_cap_mib=682
[qdisc]
qdisc fq 0: root
AFTER
HISTORY_SESSION=old-session
history_params_command >"$tmp/before.txt" || fail 'original parameters unavailable'
grep -Fq 'net.ipv4.tcp_congestion_control=cubic' "$tmp/before.txt" || fail 'original congestion control missing'
grep -Fq 'net.core.rmem_max=4194304' "$tmp/before.txt" || fail 'original buffer missing'
HISTORY_PARAMS_AFTER=1
history_params_command >"$tmp/after.txt" || fail 'final parameters unavailable'
grep -Fq 'net.core.rmem_max=8388608' "$tmp/after.txt" || fail 'final buffer missing'
HISTORY_PARAMS_AFTER=0
mv "$SESSION_ROOT/$SESSION_ID/system-before.txt" "$tmp/before.saved"
if history_params_command >"$tmp/missing.log" 2>&1; then fail 'missing original snapshot accepted'; fi
mv "$tmp/before.saved" "$SESSION_ROOT/$SESSION_ID/system-before.txt"
require_linux() { :; }; resolve_iface() { printf 'eth0\n'; }; detect_memory_limits() { :; }
capture_state() {
  cat >"$2" <<'CURRENT'
kernel=Linux current
interface=eth0
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq
net.core.rmem_max=12582912
net.core.wmem_max=12582912
net.ipv4.tcp_rmem=4096 87380 12582912
net.ipv4.tcp_wmem=4096 16384 12582912
net.ipv4.tcp_mem=120 240 360
memory_total_mib=2048
memory_effective_mib=2048
memory_tcp_budget_mib=1365
memory_buffer_cap_mib=1365
[qdisc]
qdisc fq 0: root
CURRENT
}
history_compare_command >"$tmp/comparison.txt" || fail 'three-way history comparison failed'
grep -Fq '当前' "$tmp/comparison.txt" || fail 'current column missing'
grep -Fq '测试前' "$tmp/comparison.txt" || fail 'original column missing'
grep -Fq '选中历史' "$tmp/comparison.txt" || fail 'selected history column missing'
grep -Fq '12.00 MiB (12582912 bytes)' "$tmp/comparison.txt" || fail 'current buffer missing'
grep -Fq '4.00 MiB (4194304 bytes)' "$tmp/comparison.txt" || fail 'original buffer missing'
grep -Fq '8.00 MiB (8388608 bytes)' "$tmp/comparison.txt" || fail 'historical buffer missing'
if grep -Fq 'kernel.panic=' "$tmp/comparison.txt"; then fail 'unrelated raw settings leaked into comparison'; fi
mv "$SESSION_ROOT/$SESSION_ID/system-after.txt" "$tmp/after.saved"
history_compare_command >"$tmp/comparison-missing.txt" || fail 'comparison should tolerate a missing final snapshot'
grep -Fq '未记录' "$tmp/comparison-missing.txt" || fail 'missing historical values not marked'
mv "$tmp/after.saved" "$SESSION_ROOT/$SESSION_ID/system-after.txt"
python3 - "$ROOT/bbr-tune.sh" "$STATE_DIR" <<'PY'
import os, pty, select, subprocess, sys, time
master, slave = pty.openpty()
command = '''source "$1"; STATE_DIR="$2"; SESSION_ROOT="$STATE_DIR/sessions"; HISTORY_FILE="$STATE_DIR/history.tsv"
require_linux() { :; }; resolve_iface() { printf 'eth0\\n'; }; detect_memory_limits() { :; }
capture_state() { printf 'interface=eth0\\nnet.ipv4.tcp_congestion_control=bbr\\nnet.core.rmem_max=12582912\\n' >"$2"; }
history_command'''
child = subprocess.Popen(['bash', '-c', command, '_', sys.argv[1], sys.argv[2]],
                         stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
os.write(master, b'1\n0\n')
output = bytearray()
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    readable, _, _ = select.select([master], [], [], 0.1)
    if readable:
        try:
            chunk = os.read(master, 65536)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
    if child.poll() is not None and not readable:
        break
child.wait(timeout=1)
os.close(master)
screen = output.decode('utf-8', errors='replace')
assert child.returncode == 0, screen
assert '关键参数对比' in screen, screen
assert '选中历史' in screen and '8.00 MiB' in screen, screen
PY
history_candidate old-session || fail 'valid historical candidate rejected'
[[ "${HISTORY_FIELDS[3]}" == 8 ]] || fail 'wrong historical buffer'

cp "$SESSION_ROOT/$SESSION_ID/results.tsv" "$tmp/results.good"
sed -i.bak 's/multi.*8$/multi\tbbr-fq\t8\t16/' "$SESSION_ROOT/$SESSION_ID/results.tsv"
if history_candidate old-session >"$tmp/bad.log" 2>&1; then fail 'mismatched final result accepted'; fi
mv "$tmp/results.good" "$SESSION_ROOT/$SESSION_ID/results.tsv"
printf 'net.core.wmem_max=16777216\n' >"$SESSION_ROOT/$SESSION_ID/system-after.txt"
if history_candidate old-session >"$tmp/bad.log" 2>&1; then fail 'mismatched applied state accepted'; fi
printf 'net.core.rmem_max=8388608\nnet.core.wmem_max=8388608\n' >"$SESSION_ROOT/$SESSION_ID/system-after.txt"

require_linux() { :; }; require_root() { :; }; have() { :; }
resolve_iface() { printf 'eth0\n'; }; ip() { :; }
detect_memory_limits() { MEM_BUFFER_CAP_MIB="${test_cap:-64}"; }
prepare_tcp_rules() { TCP_RDEFAULT=131072; TCP_WDEFAULT=16384; }
init_session() {
  SESSION_ID=new-session; SESSION_DIR="$SESSION_ROOT/$SESSION_ID"
  mkdir -p "$SESSION_DIR"
}
select_tuning_qdisc() { QDISC_POLICY=preserve; }
ensure_bbr() { :; }
create_backup() { mkdir -p "$BACKUP_ROOT/new-session"; printf '%s\n' "$BACKUP_ROOT/new-session"; }
real_pending_guard="$(declare -f pending_guard)"
pending_guard() { :; }
schedule_rollback() { mkdir -p "$PENDING_DIR/new-session"; : >"$PENDING_DIR/new-session/owner"; }
apply_candidate() { printf '%s %s\n' "$1" "$2" >"$tmp/applied"; }
capture_state() { printf 'applied\n' >"$2"; }
write_persistent_config() { [[ "${3:-}" == tcp-only ]] || fail 'historical persistence may overwrite queue settings'; : >"$tmp/persisted"; }
HISTORY_SESSION=old-session; YES=1; PERSIST_FINAL=0
(apply_history_command) >"$tmp/apply.log"
[[ "$(cat "$tmp/applied")" == 'eth0 8' ]] || fail 'historical buffer not applied'
[[ ! -e "$tmp/persisted" ]] || fail 'unexpected persistence'
[[ -r "$SESSION_ROOT/new-session/history-application.txt" ]] || fail 'application record missing'
[[ -d "$BACKUP_ROOT/new-session" ]] || fail 'backup missing'
(PERSIST_FINAL=1; apply_history_command) >"$tmp/persist.log"
[[ -e "$tmp/persisted" ]] || fail 'requested persistence skipped'

# Skipping backup must not leave a new timer or reuse the previous backup.
mkdir -p "$PENDING_DIR/previous"
printf '%s\n' "$BACKUP_ROOT/new-session" >"$PENDING_DIR/previous/backup"
: >"$PENDING_DIR/previous/armed"
ln -sfn "$PENDING_DIR/previous" "$PENDING_LATEST"
ln -sfn "$BACKUP_ROOT/new-session" "$LATEST_BACKUP"
printf 'old-session\n' >"$ACTIVE_SESSION_FILE"
rm -f "$tmp/applied" "$tmp/persisted"
(
  eval "$real_pending_guard"
  parse_args apply-history --session old-session --no-backup --persist --yes
  BACKUP_DIR="$BACKUP_ROOT/new-session"
  init_session() { SESSION_ID=no-backup; SESSION_DIR="$SESSION_ROOT/$SESSION_ID"; mkdir -p "$SESSION_DIR"; }
  create_backup() { fail 'no-backup created a backup'; }
  schedule_rollback() { fail 'no-backup scheduled rollback'; }
  apply_candidate() {
    [[ ! -e "$PENDING_LATEST" && ! -e "$PENDING_DIR/previous/armed" ]] || fail 'previous timer still armed at application'
    [[ ! -e "$ACTIVE_SESSION_FILE" ]] || fail 'previous active marker remains during application'
    printf '%s %s\n' "$1" "$2" >"$tmp/applied"
  }
  apply_history_command
  [[ -z "$BACKUP_DIR" ]] || fail 'no-backup reused an old backup'
  [[ "$(active_session_id)" == no-backup ]] || fail 'no-backup active session missing'
) >"$tmp/no-backup.log"
[[ "$(cat "$tmp/applied")" == 'eth0 8' && -f "$tmp/persisted" ]] || fail 'no-backup did not apply and persist'
[[ ! -e "$PENDING_LATEST" && ! -d "$BACKUP_ROOT/no-backup" ]] || fail 'no-backup created recovery state'
[[ "$(readlink "$LATEST_BACKUP")" == "$BACKUP_ROOT/new-session" && -d "$BACKUP_ROOT/new-session" ]] || fail 'no-backup changed an existing backup'
grep -Fq '本次备份：未备份' "$SESSION_ROOT/no-backup/history-application.txt" || fail 'missing no-backup record'
grep -Fq '安全回滚：关闭' "$tmp/no-backup.log" || fail 'missing disabled rollback notice'
if grep -Fq '验证业务后执行' "$tmp/no-backup.log"; then fail 'no-backup requests confirmation'; fi
if (parse_args autotune --no-backup) >"$tmp/invalid-option.log" 2>&1; then fail 'other commands accept no-backup'; fi

# An error without a backup must report the failure without restoring old state.
set +e
(
  set -e
  HISTORY_NO_BACKUP=1
  init_session() { SESSION_ID=failed-apply; SESSION_DIR="$SESSION_ROOT/$SESSION_ID"; mkdir -p "$SESSION_DIR"; }
  restore_backup() { fail 'failed no-backup restored an older backup'; }
  apply_candidate() { return 23; }
  apply_history_command
) >"$tmp/failed-apply.log" 2>&1
failed_rc=$?
set -e
[[ "$failed_rc" == 23 ]] || fail 'failed application did not preserve its exit status'
grep -Fq '无法自动恢复应用前参数' "$tmp/failed-apply.log" || fail 'missing no-backup failure notice'
[[ ! -e "$ACTIVE_SESSION_FILE" ]] || fail 'failed application retained stale active session'

# Exercise the actual terminal choices, including default backup and cancellation.
{
  printf 'source %q\n' "$ROOT/bbr-tune.sh"
  declare -f fail require_linux require_root have resolve_iface ip detect_memory_limits \
    prepare_tcp_rules select_tuning_qdisc ensure_bbr pending_guard apply_candidate capture_state
  cat <<'RUNNER'
tmp="$1"; test_session="$2"
STATE_DIR="$tmp/state"; SESSION_ROOT="$STATE_DIR/sessions"; BACKUP_ROOT="$STATE_DIR/backups"
PENDING_DIR="$STATE_DIR/pending"; PENDING_LATEST="$STATE_DIR/pending-latest"
LATEST_BACKUP="$STATE_DIR/latest"; ACTIVE_SESSION_FILE="$STATE_DIR/active-session"
HISTORY_FILE="$STATE_DIR/history.tsv"
init_session() { SESSION_ID="$test_session"; SESSION_DIR="$SESSION_ROOT/$SESSION_ID"; mkdir -p "$SESSION_DIR"; }
create_backup() { mkdir -p "$BACKUP_ROOT/$test_session"; printf '%s\n' "$BACKUP_ROOT/$test_session"; }
schedule_rollback() { mkdir -p "$PENDING_DIR/$test_session"; : >"$PENDING_DIR/$test_session/armed"; }
parse_args apply-history --session old-session ${3:+"$3"}
apply_history_command
RUNNER
} >"$tmp/terminal-apply.sh"
python3 - "$tmp" <<'PY'
import os, pty, select, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv[1])
cases = [
    ('choose-no', b'n\ny\n', False, True, ''),
    ('default-backup', b'\ny\n', True, True, ''),
    ('cancel-no', b'n\nn\n', False, False, ''),
    ('cancel-backup', b'y\nn\n', False, False, ''),
    ('explicit-no', b'y\n', False, True, '--no-backup'),
    ('retry-choice', b'invalid\nn\ny\n', False, True, ''),
]
for name, inputs, backup, applied, option in cases:
    (root/'applied').unlink(missing_ok=True)
    master, slave = pty.openpty()
    child = subprocess.Popen(['bash', str(root/'terminal-apply.sh'), str(root), name, option],
                             stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    os.write(master, inputs)
    output = bytearray()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
        if child.poll() is not None and not readable:
            break
    child.wait(timeout=1)
    os.close(master)
    screen = output.decode('utf-8', errors='replace')
    assert child.returncode == 0, (name, screen)
    assert '确认应用历史参数？' in screen, (name, screen)
    assert ('应用前备份当前参数' in screen) == (not option), (name, screen)
    assert (root/'state/backups'/name).exists() == backup, (name, screen)
    assert (root/'state/pending'/name/'armed').exists() == backup, (name, screen)
    assert (root/'applied').exists() == applied, (name, screen)
    assert (root/'state/sessions'/name).exists() == applied, (name, screen)
    if applied and not backup:
        assert (root/'state/active-session').read_text().strip() == name, (name, screen)
        assert '安全回滚：关闭' in screen, (name, screen)
PY

test_cap=4
if (apply_history_command) >"$tmp/oversize.log" 2>&1; then fail 'oversized historical buffer accepted'; fi
grep -q '超过当前服务器上限' "$tmp/oversize.log" || fail 'missing memory limit explanation'
printf 'All historical application tests passed.\n'
