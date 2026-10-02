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
[[ -d "$first" && "$(cat "$first/remark.txt")" == 初始备份 ]] || fail 'initial name or original marker missing'
[[ "$(cat "$STATE_DIR/original-backup")" == "${first##*/}" ]] || fail 'first manual backup not original'
[[ -r "$first/observed.tsv" && -r "$first/qdisc.txt" && -r "$first/files.tsv" ]] || fail 'manual snapshot incomplete'
grep -Fq $'net.ipv4.tcp_congestion_control\tsaved-net.ipv4.tcp_congestion_control' "$first/observed.tsv" || fail 'current sysctl missing'
[[ "$(readlink "$LATEST_BACKUP")" == "$tmp/latest-target" ]] || fail 'manual backup changed default rollback target'
status_original_comparison eth0 >"$tmp/status.out"
grep -Fq '原始备份备注：初始备份' "$tmp/status.out" || fail 'status does not show original remark'

BACKUP_REMARK='调整前参数'
backup_current_command >"$tmp/second.out"
[[ "$(original_backup_path_readonly)" == "$first" ]] || fail 'second backup replaced original'
second="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d ! -path "$first" -print -quit)"
[[ -n "$second" && "$(cat "$second/remark.txt")" == 调整前参数 ]] || fail 'custom remark missing'
[[ "$(readlink "$LATEST_BACKUP")" == "$tmp/latest-target" ]] || fail 'second backup changed default rollback target'
printf '0\n' | cleanup_backups_interactive >"$tmp/list.out"
grep -Fq '备注：调整前参数' "$tmp/list.out" || fail 'cleanup list does not show remark'

# All backup entry points share the terminal naming behavior in create_backup.
{
  printf 'source %q\n' "$ROOT/bbr-tune.sh"
  declare -f systemd_available sysctl_exists sysctl_get tc
  cat <<'RUNNER'
STATE_DIR="$1"; BACKUP_ROOT="$STATE_DIR/backups"; LATEST_BACKUP="$STATE_DIR/latest"
mkdir -p "$STATE_DIR"
SYSCTL_FILE="$STATE_DIR/sysctl.conf"; MODULES_FILE="$STATE_DIR/modules.conf"
ENV_FILE="$STATE_DIR/env"; QDISC_HELPER="$STATE_DIR/helper"; SERVICE_FILE="$STATE_DIR/service"
if [[ "$2" == subsequent ]]; then
  SESSION_ID=seed; BACKUP_REMARK=seed
  create_backup eth0 >/dev/null
fi
SESSION_ID=sample; BACKUP_REMARK="${3:-}"
create_backup eth0 >"$STATE_DIR/result"
RUNNER
} >"$tmp/naming.sh"
python3 - "$tmp" <<'PY'
import os, pty, select, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv[1])
cases = [
    ('initial-default', 'initial', '', b'\n', '初始备份'),
    ('initial-custom', 'initial', '', '原始环境\n'.encode(), '初始备份 - 原始环境'),
    ('subsequent-default', 'subsequent', '', b'\n', 'sample'),
    ('subsequent-custom', 'subsequent', '', '切换前\n'.encode(), '切换前'),
    ('explicit-remark', 'subsequent', '已指定', b'', '已指定'),
    ('retry-remark', 'subsequent', '', ('x'*101+'\n正常备注\n').encode(), '正常备注'),
]
for name, mode, remark, inputs, expected in cases:
    state = root/name
    master, slave = pty.openpty()
    child = subprocess.Popen(['bash', str(root/'naming.sh'), str(state), mode, remark],
                             stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    if inputs:
        os.write(master, inputs)
    output = bytearray()
    deadline = time.monotonic()+5
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
    screen = output.decode(errors='replace')
    assert child.returncode == 0, (name, screen)
    assert ('备份备注（回车保留默认命名）' in screen) == (not remark), (name, screen)
    assert (state/'backups/sample/remark.txt').read_text().strip() == expected, (name, screen)
    assert (state/'original-backup').read_text().strip() == ('seed' if mode=='subsequent' else 'sample')
    assert (state/'result').read_text().strip() == str(state/'backups/sample'), (name, screen)
    assert (state/'backups/sample/full-sysctl.tsv').stat().st_size > 0
PY

# A tuning run snapshots once before probing and names that same backup afterward.
{
  printf 'source %q\n' "$ROOT/bbr-tune.sh"
  declare -f systemd_available sysctl_exists sysctl_get tc
  cat <<'RUNNER'
STATE_DIR="$1"; BACKUP_ROOT="$STATE_DIR/backups"; LATEST_BACKUP="$STATE_DIR/latest"
mkdir -p "$STATE_DIR"
SYSCTL_FILE="$STATE_DIR/sysctl.conf"; MODULES_FILE="$STATE_DIR/modules.conf"
ENV_FILE="$STATE_DIR/env"; QDISC_HELPER="$STATE_DIR/helper"; SERVICE_FILE="$STATE_DIR/service"
SESSION_ID=one-tuning-run
BACKUP_DIR="$(create_backup eth0 1 "" 0)"
printf 'PROBING_DONE\n'
name_completed_tuning_backup "$BACKUP_DIR"
RUNNER
} >"$tmp/deferred-naming.sh"
python3 - "$tmp" <<'PY'
import os, pty, select, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv[1])
for suffix, typed, expected in [('default', b'\n', '初始备份'),
                                ('custom', '全部测试完成\n'.encode(), '初始备份 - 全部测试完成')]:
    state = root/('deferred-'+suffix)
    master, slave = pty.openpty()
    child = subprocess.Popen(['bash', str(root/'deferred-naming.sh'), str(state)],
                             stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    os.write(master, typed)
    output = bytearray()
    deadline = time.monotonic()+5
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
    screen = output.decode(errors='replace')
    assert child.returncode == 0, screen
    assert screen.index('PROBING_DONE') < screen.index('备份备注（回车保留默认命名）'), screen
    backups = list((state/'backups').iterdir())
    assert len(backups) == 1, backups
    assert (backups[0]/'remark.txt').read_text().strip() == expected
    assert (state/'latest').resolve() == backups[0].resolve()
PY

ui_execute() { printf '%s\n' "$*" >>"$tmp/ui-calls"; }
IFACE=auto
printf '1\n\n' | ui_status >"$tmp/ui.out"
grep -Fqx '1 status --iface auto' "$tmp/ui-calls" || fail 'status menu did not read root-owned baseline'
grep -Fqx '1 backup-current --iface auto' "$tmp/ui-calls" || fail 'status menu did not delegate backup naming'
printf 'All manual backup tests passed.\n'
