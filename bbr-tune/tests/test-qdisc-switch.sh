#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
export QDISC_TEST_DIR="$TMP"
mkdir -p "$TMP/bin" "$TMP/session" "$TMP/config" "$TMP/state/backups"
cp "$ROOT/tests/fixtures/qdisc-command-mock.py" "$TMP/bin/tc"
cp "$TMP/bin/tc" "$TMP/bin/ip"
printf '#!/usr/bin/env bash
[[ ! -f "$QDISC_TEST_DIR/fail-lock" ]]
' >"$TMP/bin/flock"
chmod +x "$TMP/bin/"{tc,ip,flock}
export PATH="$TMP/bin:$PATH"
SESSION_DIR="$TMP/session"; STATE_DIR="$TMP/state"; SESSION_ROOT="$STATE_DIR/sessions"
BACKUP_ROOT="$STATE_DIR/backups"; LATEST_BACKUP="$STATE_DIR/latest"; PENDING_DIR="$STATE_DIR/pending"
PENDING_LATEST="$STATE_DIR/pending-latest"; ACTIVE_SESSION_FILE="$STATE_DIR/active-session"
SYSCTL_FILE="$TMP/config/sysctl"; MODULES_FILE="$TMP/config/modules"
ENV_FILE="$TMP/config/env"; QDISC_HELPER="$TMP/config/helper"; SERVICE_FILE="$TMP/config/service"
QDISC_ONLY=1; session=0
systemd_available() { return 1; }
sysctl_exists() { return 1; }
sysctl_get() { printf 'original\n'; }
sysctl() { fail 'queue-only command changed TCP or global sysctls'; }
python3 - "$TMP" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
defaults={
 'fq':{'limit':10000,'flow_limit':100,'buckets':1024,'orphan_mask':1023,'quantum':3028,'initial_quantum':15140,'low_rate_threshold':68750,'refill_delay':40000,'timer_slack':10000,'horizon':10000000,'horizon_drop':None},
 'fq_codel':{'limit':10240,'flows':1024,'quantum':1514,'target':5000,'interval':100000,'memory_limit':33554432,'ecn':True,'drop_batch':64},
 'cake':{'bandwidth':'unlimited','diffserv':'diffserv3','flowmode':'triple-isolate','nat':False,'wash':False,'ingress':False,'ack-filter':'disabled','split_gso':True,'rtt':100000,'raw':False,'atm':'noatm','overhead':0,'memlimit':33554432,'fwmark':'0'}
}
(p/'defaults.json').write_text(json.dumps(defaults))
for kind,opts in defaults.items():
 (p/(kind+'.json')).write_text(json.dumps([{'kind':kind,'handle':'1:','root':True,'options':opts}]))
fq_new=dict(defaults['fq'])
fq_new.update(bands=3, priomap=[2,2,2,2,1,1,0,0,0,0,0,0,0,0,0,0], weights=[589,35,1], offload_horizon=200000)
(p/'fq_new.json').write_text(json.dumps([{'kind':'fq','handle':'1:','root':True,'options':fq_new}]))
fq_new_tc=dict(fq_new)
fq_new_tc['priomap ']=fq_new_tc.pop('priomap')
fq_new_tc['weights ']=fq_new_tc.pop('weights')
(p/'fq_new_tc.json').write_text(json.dumps([{'kind':'fq','handle':'1:','root':True,'options':fq_new_tc}]))
cake=dict(defaults['cake']); cake.update(bandwidth=25000000, diffserv='diffserv4', nat=True, overhead=44, fwmark='0xff', **{'ack-filter':'enabled'})
(p/'shaped.json').write_text(json.dumps([{'kind':'cake','handle':'1:','root':True,'options':cake}]))
raw=dict(defaults['cake']); raw.update(raw=True, autorate='autorate-ingress'); raw.pop('atm')
(p/'raw.json').write_text(json.dumps([{'kind':'cake','handle':'1:','root':True,'options':raw}]))
(p/'noqueue.json').write_text('[{"kind":"noqueue","handle":"0:","root":true,"options":{}}]')
(p/'mq.json').write_text(json.dumps([{'kind':'mq','handle':'1:','root':True,'options':{}}]+[
 {'kind':'fq_codel','handle':f'{i}0:','parent':f'1:{i}','options':defaults['fq_codel']} for i in (1,2)]))
(p/'mq_fq_new.json').write_text(json.dumps([{'kind':'mq','handle':'0:','root':True,'options':{}}]+[
 {'kind':'fq','handle':f'{i}0:','parent':f'0:{i}','options':fq_new} for i in (1,2)]))
(p/'mq_fq_new_tc.json').write_text(json.dumps([{'kind':'mq','handle':'0:','root':True,'options':{}}]+[
 {'kind':'fq','handle':f'{i}0:','parent':f'0:{i}','options':fq_new_tc} for i in (1,2)]))
PY
set_live() {
  session=$((session+1)); SESSION_ID="switch-$session"; BACKUP_DIR=""
  cp "$TMP/$1.json" "$TMP/live.json"
  rm -f "$TMP/"{live-writes,filters.json,unsupported-cake,false-success,fail-namespace,fail-restore-probe,fail-parent,fail-lock,drift-after-probe}
}
no_live_writes() { [[ ! -s "$TMP/live-writes" ]] || fail "live mutation before valid preflight: $(cat "$TMP/live-writes")"; }
no_namespace_leaks() {
  [[ -z "$(find "$TMP" -maxdepth 1 -name 'bbrq-*.json' -print)" ]] || fail 'temporary namespace leaked'
}
# CLI and UI validation, including bandwidth distinct from test target.
(parse_args autotune --qdisc cake --cake-bandwidth-mbps 190 --bandwidth-mbps 200; validate_autotune_options;
 [[ "$TUNING_QDISC" == fq && "$REQUESTED_QDISC" == cake && "$TARGET_MBPS" == 200 && "$CAKE_BANDWIDTH_MBPS" == 190 ]]) || fail 'CLI queue options'
for kind in bad 'cake;id'; do
 if (REQUESTED_QDISC="$kind"; validate_qdisc_options) >/dev/null 2>&1; then fail 'invalid algorithm accepted'; fi
done
for bw in -1 0.00000001 NaN inf '200;id' 100001; do
 if (REQUESTED_QDISC=cake; CAKE_BANDWIDTH_MBPS="$bw"; validate_qdisc_options) >/dev/null 2>&1; then fail 'invalid bandwidth accepted'; fi
done
if (REQUESTED_QDISC=fq; CAKE_BANDWIDTH_MBPS=100; validate_qdisc_options) >/dev/null 2>&1; then fail 'non-CAKE bandwidth accepted'; fi
(parse_args qdisc --qdisc fq --no-backup; [[ "$QDISC_NO_BACKUP" == 1 && "$HISTORY_NO_BACKUP" == 0 ]]) || fail 'queue no-backup CLI option'
if (parse_args autotune --no-backup) >"$TMP/invalid-no-backup.log" 2>&1; then fail 'autotune accepted no-backup'; fi
[[ "$(printf '\n' | ui_select_qdisc 2>/dev/null)" == auto ]] || fail 'default queue choice'
[[ "$(printf '2\n' | ui_select_qdisc 2>/dev/null)" == keep ]] || fail 'keep choice'
[[ "$(printf '3\n' | ui_select_qdisc switch 2>/dev/null)" == cake ]] || fail 'CAKE switch choice'
[[ "$(printf '\n' | ui_read_cake_bandwidth 2>/dev/null)" == '' ]] || fail 'CAKE leave-unchanged choice'
[[ "$(printf '0\n' | ui_read_cake_bandwidth 2>/dev/null)" == 0 ]] || fail 'CAKE unlimited choice'

if printf '0\n' | ui_select_qdisc switch >/dev/null 2>&1; then fail 'queue menu cannot return'; fi

# Full preflight, apply and original-option restoration for each direction.
for route in 'fq cake' 'fq_new cake' 'fq_new_tc cake' 'fq_codel fq' 'cake fq_codel' 'shaped fq' 'raw fq' 'shaped cake' 'noqueue cake' 'mq cake'; do
 read -r original target <<<"$route"
 set_live "$original"; REQUESTED_QDISC="$target"; CAKE_BANDWIDTH_MBPS=""
 [[ "$original $target" != 'shaped cake' ]] || CAKE_BANDWIDTH_MBPS=190
 select_tuning_qdisc eth0 || fail "preflight $route"
 no_live_writes; no_namespace_leaks
 BACKUP_DIR="$(create_backup eth0)"
 [[ ! -s "$BACKUP_DIR/sysctl.tsv" ]] || fail 'queue-only backup includes unrelated sysctls'
 apply_tuning_qdisc eth0 || fail "apply $route"
 qdisc_json matches "$TMP/live.json" "$target" "$CAKE_BANDWIDTH_MBPS" || fail "readback $route"
 restore_qdisc "$BACKUP_DIR" eth0 "$(awk '$1=="qdisc" && / root/{print $2}' "$BACKUP_DIR/qdisc.txt")" || fail "restore $route"
 qdisc_json equal "$TMP/$original.json" "$TMP/live.json" || fail "original options not restored $route"
 if [[ "$original" == mq ]] && grep -q 'root' "$TMP/live-writes"; then fail 'numbered mq root was replaced'; fi
done

# No change means no netns privilege is required. Existing CAKE cap is retained
# unless explicitly set; zero explicitly removes it without clearing other opts.
set_live shaped; REQUESTED_QDISC=cake; CAKE_BANDWIDTH_MBPS=""
touch "$TMP/fail-namespace"
select_tuning_qdisc eth0 || fail 'existing CAKE cannot remain unchanged'
BACKUP_DIR="$(create_backup eth0)"
apply_tuning_qdisc eth0 || fail 'existing CAKE apply failed'
qdisc_json equal "$TMP/shaped.json" "$TMP/live.json" || fail 'existing CAKE cap lost'
no_live_writes
rm "$TMP/fail-namespace"
CAKE_BANDWIDTH_MBPS=0
select_tuning_qdisc eth0 || fail 'unlimited preflight'
BACKUP_DIR="$(create_backup eth0)"
apply_tuning_qdisc eth0 || fail 'unlimited apply'
python3 - "$TMP/live.json" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))[0]['options']
assert o['bandwidth']=='unlimited' and o['overhead']==44 and o['nat'] and o['ack-filter']=='enabled'
PY

# Unsupported algorithms, missing privileges, non-reproducible original params
# and existing filters must stop before any live interface writes.
for failure in unsupported-cake fail-namespace fail-restore-probe filters; do
 set_live shaped; REQUESTED_QDISC=cake; CAKE_BANDWIDTH_MBPS=190
 if [[ "$failure" == filters ]]; then echo '[{"kind":"bpf"}]' >"$TMP/filters.json"; else touch "$TMP/$failure"; fi
 if select_tuning_qdisc eth0 >"$TMP/failure.log" 2>&1; then fail "accepted $failure"; fi
 no_live_writes; no_namespace_leaks
done

# Unknown fields/trees and anonymous mq cannot be overwritten even with force.
set_live fq; REQUESTED_QDISC=cake; CAKE_BANDWIDTH_MBPS=""; FORCE=1
python3 - "$TMP/live.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d[0]['options']['unknown_gain']=1; json.dump(d,open(p,'w'))
PY
if select_tuning_qdisc eth0 2>/dev/null; then fail 'unknown original options accepted'; fi
no_live_writes
set_live fq_new; REQUESTED_QDISC=fq; CAKE_BANDWIDTH_MBPS=""
select_tuning_qdisc eth0 || fail 'existing fq with newer options cannot remain unchanged'
BACKUP_DIR="$(create_backup eth0)"
apply_tuning_qdisc eth0 || fail 'existing fq with newer options apply failed'
qdisc_json equal "$TMP/fq_new.json" "$TMP/live.json" || fail 'existing fq options changed'
no_live_writes
set_live fq_new_tc; REQUESTED_QDISC=fq; CAKE_BANDWIDTH_MBPS=""
select_tuning_qdisc eth0 || fail 'tc JSON array labels with trailing spaces rejected'
BACKUP_DIR="$(create_backup eth0)"
apply_tuning_qdisc eth0 || fail 'tc JSON array labels with trailing spaces apply failed'
qdisc_json equal "$TMP/fq_new.json" "$TMP/live.json" || fail 'tc JSON array labels changed fq options'
no_live_writes
set_live mq_fq_new; REQUESTED_QDISC=fq; CAKE_BANDWIDTH_MBPS=""
select_tuning_qdisc eth0 || fail 'existing mq with newer fq leaves cannot remain unchanged'
BACKUP_DIR="$(create_backup eth0)"
apply_tuning_qdisc eth0 || fail 'existing mq fq apply failed'
qdisc_json equal "$TMP/mq_fq_new.json" "$TMP/live.json" || fail 'existing mq fq options changed'
no_live_writes
set_live mq_fq_new_tc; REQUESTED_QDISC=fq; CAKE_BANDWIDTH_MBPS=""
select_tuning_qdisc eth0 || fail 'existing mq with tc JSON array labels rejected'
BACKUP_DIR="$(create_backup eth0)"
apply_tuning_qdisc eth0 || fail 'existing mq with tc JSON array labels apply failed'
qdisc_json equal "$TMP/mq_fq_new.json" "$TMP/live.json" || fail 'existing mq tc JSON array labels changed fq options'
no_live_writes
set_live fq_new; REQUESTED_QDISC=cake
python3 - "$TMP/live.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d[0]['options']['priomap']=[0]*15; json.dump(d,open(p,'w'))
PY
if select_tuning_qdisc eth0 2>/dev/null; then fail 'invalid fq priomap accepted'; fi
no_live_writes
set_live fq_new_tc; REQUESTED_QDISC=cake
python3 - "$TMP/live.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d[0]['options']['priomap']=[0]*16; json.dump(d,open(p,'w'))
PY
if select_tuning_qdisc eth0 2>/dev/null; then fail 'duplicate fq priomap spellings accepted'; fi
no_live_writes
set_live mq
sed -e 's/1:/0:/g' "$TMP/live.json" >"$TMP/anonymous.json"; mv "$TMP/anonymous.json" "$TMP/live.json"
if select_tuning_qdisc eth0 2>/dev/null; then fail 'anonymous mq switched'; fi
no_live_writes
set_live mq; CAKE_BANDWIDTH_MBPS=200
if select_tuning_qdisc eth0 2>/dev/null; then fail 'aggregate cap multiplied across mq leaves'; fi
no_live_writes; FORCE=0

# Partially changed numbered mq restores only after a failure and never deletes
# its root. A false-success tc response must not be accepted as a new algorithm.
set_live mq; REQUESTED_QDISC=cake; CAKE_BANDWIDTH_MBPS=""
select_tuning_qdisc eth0; BACKUP_DIR="$(create_backup eth0)"
echo '1:2' >"$TMP/fail-parent"
if apply_tuning_qdisc eth0 2>/dev/null; then fail 'partial write failure accepted'; fi
# The untouched second leaf still rejects writes; recovery must skip it.
restore_qdisc "$BACKUP_DIR" eth0 mq || fail 'partial mq recovery failed'
qdisc_json equal "$TMP/mq.json" "$TMP/live.json" || fail 'partial mq options lost'
set_live fq; REQUESTED_QDISC=cake; select_tuning_qdisc eth0; BACKUP_DIR="$(create_backup eth0)"
touch "$TMP/false-success"
if apply_tuning_qdisc eth0 2>/dev/null; then fail 'false success accepted'; fi
rm "$TMP/false-success"
restore_qdisc "$BACKUP_DIR" eth0 fq || fail 'unchanged state could not recover'

# TCP generation, modules and helper reflect the selected algorithm and cap.
set_live fq; REQUESTED_QDISC=cake; CAKE_BANDWIDTH_MBPS=190
select_tuning_qdisc eth0; BACKUP_DIR="$(create_backup eth0)"; apply_tuning_qdisc eth0
build_sysctl_content 8388608 >"$TMP/tcp.conf"
grep -Fqx 'net.core.default_qdisc = cake' "$TMP/tcp.conf" || fail 'TCP profile still forces fq'
write_qdisc_persistence eth0
grep -Fqx 'sch_cake' "$MODULES_FILE" || fail 'wrong boot module'
grep -Fqx 'BBR_CAKE_BANDWIDTH_MBPS=190' "$ENV_FILE" || fail 'CAKE rate not persisted'
sed "s|source /etc/default/bbr-tcp-tuning|source $ENV_FILE|" "$QDISC_HELPER" >"$TMP/boot-helper"
cp "$TMP/fq.json" "$TMP/live.json"
bash "$TMP/boot-helper" || fail 'CAKE boot helper failed'
qdisc_json matches "$TMP/live.json" cake 190 || fail 'boot helper lost shaping cap'
# Persisted selection can replace a CAKE created during boot, without losing
# its fresh recovery snapshot or silently preserving the wrong algorithm.
TUNING_QDISC=fq; REQUESTED_QDISC=fq; CAKE_BANDWIDTH_MBPS=""
write_qdisc_persistence eth0
sed "s|source /etc/default/bbr-tcp-tuning|source $ENV_FILE|" "$QDISC_HELPER" >"$TMP/boot-helper"
cp "$TMP/shaped.json" "$TMP/live.json"
bash "$TMP/boot-helper" || fail 'explicit fq boot policy refused CAKE'
qdisc_json matches "$TMP/live.json" fq '' || fail 'boot remained CAKE instead of fq'
[[ -n "$(find "$STATE_DIR/queue-boot" -name qdisc-original.json -print)" ]] || fail 'fresh boot snapshot missing'

# Boot uses the same writer lock, refuses changed state after preflight, and
# recovers a partially updated mq without replacing its root.
set_live shaped; touch "$TMP/fail-lock"
if bash "$TMP/boot-helper" >"$TMP/boot-locked.log" 2>&1; then fail 'boot ignored writer lock'; fi
no_live_writes
set_live shaped; touch "$TMP/drift-after-probe"
if bash "$TMP/boot-helper" >"$TMP/boot-drift.log" 2>&1; then fail 'boot ignored external queue change'; fi
no_live_writes
qdisc_json equal "$TMP/fq_codel.json" "$TMP/live.json" || fail 'boot overwrote external change'
set_live mq; echo '1:2' >"$TMP/fail-parent"
if bash "$TMP/boot-helper" >"$TMP/boot-partial.log" 2>&1; then fail 'partial boot failure accepted'; fi
qdisc_json equal "$TMP/mq.json" "$TMP/live.json" || fail 'partial boot failure not recovered'
if grep -q 'root' "$TMP/live-writes"; then fail 'boot replaced mq root'; fi
no_namespace_leaks

# Queue-only lifecycle owns an independent backup and safety timer. It does not
# run iperf3, change TCP sysctls or claim throughput improvement.
(
 set_live shaped; REQUESTED_QDISC=fq; CAKE_BANDWIDTH_MBPS=""
 QDISC_NO_BACKUP=0
 require_linux() { :; }; require_root() { :; }; install_python3_if_needed() { :; }; modprobe() { :; }
 init_session() { SESSION_DIR="$TMP/command"; mkdir -p "$SESSION_DIR"; }
 resolve_iface() { echo eth0; }; capture_state() { echo snapshot >"$2"; }
 pending_guard() { :; }; schedule_rollback() { echo armed >"$TMP/armed"; }
 PERSIST_FINAL=1
 qdisc_command >"$TMP/command.log" 2>&1 || fail 'queue-only lifecycle failed'
 [[ -f "$TMP/armed" && -s "$SESSION_DIR/queue-comparison.txt" ]] || fail 'queue command lacks safety/report'
 grep -Fq 'TCP 缓存与拥塞控制：未修改' "$SESSION_DIR/queue-comparison.txt" || fail 'queue-only report misleading'
 grep -Fqx 'BBR_QDISC=fq' "$ENV_FILE" || fail 'queue-only persistence missing'
) || { cat "$TMP/command.log" >&2; fail 'queue-only command failed'; }
# Explicit no-backup must neither create a backup nor arm a timer. It may
# still persist the chosen queue and must record that recovery is unavailable.
(
 set_live shaped; REQUESTED_QDISC=fq; CAKE_BANDWIDTH_MBPS=""; QDISC_NO_BACKUP=1; PERSIST_FINAL=1
 require_linux() { :; }; require_root() { :; }; install_python3_if_needed() { :; }; modprobe() { :; }
 init_session() { SESSION_ID=no-backup-qdisc; SESSION_DIR="$SESSION_ROOT/$SESSION_ID"; mkdir -p "$SESSION_DIR"; }
 resolve_iface() { echo eth0; }; capture_state() { echo snapshot >"$2"; }
 create_backup() { fail 'queue no-backup created a backup'; }
 schedule_rollback() { fail 'queue no-backup scheduled rollback'; }
 mkdir -p "$PENDING_DIR/previous"
 printf '%s\n' "$BACKUP_ROOT/previous" >"$PENDING_DIR/previous/backup"
 : >"$PENDING_DIR/previous/armed"
 ln -sfn "$PENDING_DIR/previous" "$PENDING_LATEST"
 qdisc_command >"$TMP/no-backup-command.log" 2>&1 || fail 'queue no-backup lifecycle failed'
 [[ -z "$BACKUP_DIR" && ! -e "$PENDING_LATEST" && ! -d "$BACKUP_ROOT/no-backup-qdisc" ]] || fail 'queue no-backup left recovery state'
 [[ "$(cat "$ACTIVE_SESSION_FILE")" == no-backup-qdisc ]] || fail 'queue no-backup active session missing'
 qdisc_json matches "$TMP/live.json" fq '' || fail 'queue no-backup did not switch'
 grep -Fq '本次备份：未备份' "$SESSION_DIR/queue-comparison.txt" || fail 'queue no-backup report missing'
 grep -Fq '安全回滚：关闭' "$SESSION_DIR/queue-comparison.txt" || fail 'queue no-backup rollback report missing'
 grep -Fqx 'BBR_QDISC=fq' "$ENV_FILE" || fail 'queue no-backup persistence missing'
 if grep -Fq '验证代理业务后执行 bbr-tune confirm' "$TMP/no-backup-command.log"; then fail 'queue no-backup requests confirmation'; fi
) || { cat "$TMP/no-backup-command.log" >&2; fail 'queue no-backup command failed'; }
(
 set_live shaped; REQUESTED_QDISC=fq; CAKE_BANDWIDTH_MBPS=""; QDISC_NO_BACKUP=1; PERSIST_FINAL=0
 require_linux() { :; }; require_root() { :; }; install_python3_if_needed() { :; }; modprobe() { :; }
 init_session() { SESSION_ID=failed-no-backup-qdisc; SESSION_DIR="$SESSION_ROOT/$SESSION_ID"; mkdir -p "$SESSION_DIR"; }
 resolve_iface() { echo eth0; }; capture_state() { echo snapshot >"$2"; }
 create_backup() { fail 'failed queue no-backup created a backup'; }
 schedule_rollback() { fail 'failed queue no-backup scheduled rollback'; }
 restore_backup() { fail 'failed queue no-backup restored an older backup'; }
 apply_tuning_qdisc() { return 23; }
 qdisc_command
) >"$TMP/failed-no-backup-command.log" 2>&1 && fail 'failed queue no-backup accepted'
grep -Fq '无法自动恢复原队列' "$TMP/failed-no-backup-command.log" || fail 'failed queue no-backup warning missing'
(
 ui_select_qdisc() { echo fq; }
 ui_read_text() { echo auto; }
 ui_execute() { printf '%s\n' "$*" >"$TMP/ui-qdisc-args"; }
 printf 'n\nn\ny\n' | ui_qdisc >"$TMP/ui-qdisc-no-backup.log"
 grep -Fq -- '--no-backup' "$TMP/ui-qdisc-args" || fail 'queue menu did not forward no-backup choice'
 grep -Fq '安全回滚：关闭' "$TMP/ui-qdisc-no-backup.log" || fail 'queue menu hid no-backup consequence'
 printf 'n\n\ny\n' | ui_qdisc >"$TMP/ui-qdisc-backup.log"
 if grep -Fq -- '--no-backup' "$TMP/ui-qdisc-args"; then fail 'queue menu default skipped backup'; fi
 grep -Fq '安全回滚：' "$TMP/ui-qdisc-backup.log" || fail 'queue menu hid backup timer'
) || fail 'queue menu backup selection failed'
no_namespace_leaks
printf 'All explicit queue selection, CAKE shaping, exact recovery and UI tests passed.\n'
