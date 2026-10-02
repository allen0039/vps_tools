#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

{
  printf 'source %q\n' "$ROOT/bbr-tune.sh"
  cat <<'RUNNER'
STATE_DIR="$1"; BACKUP_ROOT="$STATE_DIR/backups"; LATEST_BACKUP="$STATE_DIR/latest"
SESSION_ROOT="$STATE_DIR/sessions"; ACTIVE_SESSION_FILE="$STATE_DIR/active-session"
PENDING_DIR="$STATE_DIR/pending"; PENDING_LATEST="$STATE_DIR/pending-latest"
require_linux() { :; }; require_root() { :; }; systemd_available() { return 1; }
sysctl() {
  printf '%s\n' "$2" >>"$STATE_DIR/writes"
}
sysctl_get() { awk -F= -v key="$1" '$1==key{value=$2} END{print value}' "$STATE_DIR/writes"; }
restore_qdisc() { printf '%s %s\n' "$4" "$5" >"$STATE_DIR/queue-policy"; }
parse_args "$2" ${3:+"$3"} ${4:+"$4"}
case "$COMMAND" in restore) restore_interactive ;; rollback) rollback_command ;; esac
RUNNER
} >"$tmp/restore.sh"

python3 - "$tmp" <<'PY'
import os, pty, select, subprocess, sys, time
from pathlib import Path
root=Path(sys.argv[1])
cases=[
    ('latest', ['restore'], b'1\ny\n', 'bbr', 'changes', 0),
    ('original', ['restore'], b'2\ny\n', 'cubic', 'original', 0),
    ('specified', ['restore'], b'3\n2\ny\n', 'reno', 'changes', 0),
    ('specified-initial', ['restore'], b'3\n1\ny\n', 'cubic', 'original', 0),
    ('cancel-restore', ['restore'], b'2\nn\n', None, None, 0),
    ('return', ['restore'], b'0\n', None, None, 0),
    ('return-list', ['restore'], b'3\n0\n0\n', None, None, 0),
    ('invalid-selection', ['restore'], b'x\n3\n9999\n2\ny\n', 'reno', 'changes', 0),
    ('cli-original', ['rollback', '--original', '--yes'], b'', 'cubic', 'original', 0),
    ('legacy-original', ['restore'], b'2\ny\n', 'cubic', 'original', 0),
    ('missing-original', ['restore'], b'2\ny\n', None, None, 1),
]
for name,args,inputs,cc,scope,status in cases:
    state=root/name
    for id,setting in [('01-initial','cubic'),('02-named','reno'),('03-latest','bbr')]:
        backup=state/'backups'/id
        backup.mkdir(parents=True)
        (backup/'meta.env').write_text('IFACE=eth0\nROOT_QDISC=fq\nQDISC_POLICY=preserve\n')
        (backup/'files.tsv').write_text('')
        # The initial snapshot originated from a queue-only operation.
        (backup/'sysctl.tsv').write_text('' if id=='01-initial' else f'net.ipv4.tcp_congestion_control\t{setting}\n')
        (backup/'full-sysctl.tsv').write_text(f'net.ipv4.tcp_congestion_control\t{setting}\nnet.core.default_qdisc\tfq\n')
        (backup/'qdisc.txt').write_text('qdisc fq 0: root\n')
        (backup/'remark.txt').write_text('初始备份\n' if id=='01-initial' else '切换前参数\n')
    (state/'original-backup').write_text('01-initial\n' if name!='missing-original' else 'missing\n')
    (state/'latest').symlink_to(state/'backups/03-latest')
    pending=state/'pending/03-latest'
    pending.mkdir(parents=True)
    (pending/'armed').write_text('token\n')
    (pending/'backup').write_text(str(state/'backups/03-latest')+'\n')
    (state/'pending-latest').symlink_to(pending)
    (state/'active-session').write_text('old-session\n')
    if name=='legacy-original':
        (state/'backups/01-initial/full-sysctl.tsv').unlink()
        (state/'backups/01-initial/observed.tsv').write_text('net.ipv4.tcp_congestion_control\tcubic\nnet.core.default_qdisc\tfq\nkernel.panic\t1\nnet.core.wmem_max\t<内核不支持>\n')
    master,slave=pty.openpty()
    child=subprocess.Popen(['bash',str(root/'restore.sh'),str(state),*args],stdin=slave,stdout=slave,stderr=slave)
    os.close(slave)
    if inputs:
        os.write(master,inputs)
    output=bytearray()
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        readable,_,_=select.select([master],[],[],0.1)
        if readable:
            try:
                chunk=os.read(master,65536)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
        if child.poll() is not None and not readable:
            break
    child.wait(timeout=1)
    os.close(master)
    screen=output.decode(errors='replace')
    assert child.returncode==status,(name,screen)
    if cc:
        writes=(state/'writes').read_text()
        assert f'net.ipv4.tcp_congestion_control={cc}' in writes,(name,screen)
        assert (state/'queue-policy').read_text().strip()==f'{"manage" if scope=="original" else "preserve"} {scope}',(name,screen)
        assert ('net.core.default_qdisc=fq' in writes)==(scope=='original'),(name,screen)
        assert 'kernel.panic' not in writes and '<' not in writes,(name,screen)
        assert not (state/'pending-latest').exists() and not (state/'active-session').exists(),(name,screen)
        assert '恢复目标：' in screen,(name,screen)
    else:
        assert not (state/'writes').exists(),(name,screen)
        assert (pending/'armed').exists() and (state/'active-session').exists(),(name,screen)
    if name=='specified':
        assert '初始备份' in screen and '切换前参数' in screen,(name,screen)
PY
if (parse_args rollback --original --backup /somewhere) >/dev/null 2>&1; then fail 'conflicting restore targets accepted'; fi

# An explicit original restore can recover queue options saved before a later
# operation, while automatic rollback still refuses unrelated queue changes.
(
  export QDISC_TEST_DIR="$tmp/exact"
  mkdir -p "$QDISC_TEST_DIR" "$tmp/bin" "$tmp/original-queue"
  cp "$ROOT/tests/fixtures/qdisc-command-mock.py" "$tmp/bin/tc"
  chmod +x "$tmp/bin/tc"
  export PATH="$tmp/bin:$PATH"
  python3 - "$QDISC_TEST_DIR" "$tmp/original-queue" <<'PY'
import json, sys
from pathlib import Path
state,backup=map(Path,sys.argv[1:])
defaults={'fq':{'limit':10000,'quantum':1514},
          'cake':{'bandwidth':'unlimited','diffserv':'diffserv3','flowmode':'triple-isolate',
                  'nat':False,'wash':False,'ingress':False,'ack-filter':'disabled',
                  'split_gso':True,'rtt':100000,'raw':False,'atm':'noatm','overhead':0,'fwmark':'0'}}
(state/'defaults.json').write_text(json.dumps(defaults))
opts=dict(defaults['cake']); opts.update(bandwidth=23750000,nat=True,overhead=44)
saved=[{'kind':'cake','handle':'1:','root':True,'options':opts}]
(backup/'qdisc-original.json').write_text(json.dumps(saved))
(backup/'qdisc.txt').write_text('qdisc cake 1: root bandwidth 190Mbit\n')
(state/'live.json').write_text(json.dumps([{'kind':'fq','handle':'1:','root':True,'options':defaults['fq']}]))
PY
  backup="$tmp/original-queue"
  if restore_qdisc "$backup" eth0 cake preserve >"$tmp/unrelated-queue.log" 2>&1; then fail 'ordinary rollback overwrote unrelated queue'; fi
  [[ ! -s "$QDISC_TEST_DIR/live-writes" ]] || fail 'ordinary rollback modified queue before refusal'
  restore_qdisc "$backup" eth0 cake manage original || fail 'original queue restore failed'
  qdisc_json equal "$backup/qdisc-original.json" "$QDISC_TEST_DIR/live.json" || fail 'original CAKE bandwidth or options lost'
)
printf 'All restore menu, original snapshot and timer cancellation tests passed.\n'
