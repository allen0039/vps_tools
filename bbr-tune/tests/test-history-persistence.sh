#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
export QDISC_TEST_DIR="$TMP"
mkdir -p "$TMP/bin" "$TMP/state/sessions/old-session"
cp "$ROOT/tests/fixtures/qdisc-command-mock.py" "$TMP/bin/tc"
cp "$TMP/bin/tc" "$TMP/bin/ip"
printf '#!/usr/bin/env bash\nexit 0\n' >"$TMP/bin/flock"
chmod +x "$TMP/bin/tc" "$TMP/bin/ip" "$TMP/bin/flock"
export PATH="$TMP/bin:$PATH"
STATE_DIR="$TMP/state"; SESSION_ROOT="$STATE_DIR/sessions"; BACKUP_ROOT="$STATE_DIR/backups"
LATEST_BACKUP="$STATE_DIR/latest"; PENDING_DIR="$STATE_DIR/pending"; PENDING_LATEST="$STATE_DIR/pending-latest"
HISTORY_FILE="$STATE_DIR/history.tsv"
SESSION_ID=old-session; COMPARISON_FILE="$SESSION_ROOT/$SESSION_ID/comparison.txt"
TARGET_MBPS=500; RTT_MS=20; BALANCE_MULTI_STREAMS=8; BEST_BUFFER_MIB=8
OUTCOME=best-effort-runtime; STRATEGY=balanced
BASELINE_SINGLE_MBPS=100; FINAL_SINGLE_MBPS=120; BASELINE_MULTI_MBPS=300; FINAL_MULTI_MBPS=340
append_history
printf 'stage\tround\tmode\tconfig\tstreams\tbuffer_mib\nfinal\t1\tsingle\tbbr-fq\t1\t8\nfinal\t1\tmulti\tbbr-fq\t8\t8\n' >"$SESSION_ROOT/$SESSION_ID/results.tsv"
printf 'net.core.rmem_max=8388608\nnet.core.wmem_max=8388608\n' >"$SESSION_ROOT/$SESSION_ID/system-after.txt"
python3 - "$TMP" <<'PY'
import json, sys
from pathlib import Path
p=Path(sys.argv[1])
defaults={'fq':{'limit':10000,'quantum':1514},
          'cake':{'bandwidth':'unlimited','diffserv':'diffserv3','flowmode':'triple-isolate',
                  'nat':False,'wash':False,'ingress':False,'ack-filter':'disabled',
                  'split_gso':True,'rtt':100000,'raw':False,'atm':'noatm','overhead':0,'fwmark':'0'}}
(p/'defaults.json').write_text(json.dumps(defaults))
for kind in ('fq','cake'):
    opts=dict(defaults[kind])
    if kind=='cake': opts.update(bandwidth=23750000,nat=True,overhead=44)
    (p/(kind+'.json')).write_text(json.dumps([{'kind':kind,'handle':'1:','root':True,'options':opts}]))
PY
# Kernel, service and memory observations are isolated; actual persistence,
# backup, history validation and queue helper functions remain under test.
require_linux() { :; }; require_root() { :; }; modprobe() { :; }
SYSTEMD_ACTIVE=0
systemd_available() { [[ "$SYSTEMD_ACTIVE" == 1 ]]; }
systemctl() {
  case "$1" in
    is-enabled) echo enabled ;;
    is-active) echo active ;;
    *) fail 'TCP-only persistence changed the queue service' ;;
  esac
}
resolve_iface() { echo eth0; }
detect_memory_limits() {
  MEM_BUFFER_CAP_MIB=64; TCP_MEM_LOW_PAGES=1024
  TCP_MEM_PRESSURE_PAGES=1536; TCP_MEM_HIGH_PAGES=2048
}
sysctl_get() { awk -F '\t' -v key="$1" '$1==key{print $2}' "$TMP/sysctl-runtime.tsv"; }
sysctl_exists() { [[ -n "$(sysctl_get "$1")" ]]; }
sysctl() {
  [[ "$1" == -w ]] || fail 'unexpected sysctl invocation'
  local key="${2%%=*}" value="${2#*=}"
  [[ "$key" != net.core.default_qdisc ]] || fail 'historical application changed the default queue'
  awk -F '\t' -v key="$key" '$1!=key' "$TMP/sysctl-runtime.tsv" >"$TMP/sysctl-next.tsv"
  printf '%s\t%s\n' "$key" "$value" >>"$TMP/sysctl-next.tsv"
  mv "$TMP/sysctl-next.tsv" "$TMP/sysctl-runtime.tsv"
}
capture_state() { awk -F '\t' '{print $1 "=" $2}' "$TMP/sysctl-runtime.tsv" >"$2"; }
init_session() { SESSION_ID="apply-$scenario"; SESSION_DIR="$SESSION_ROOT/$SESSION_ID"; mkdir -p "$SESSION_DIR"; }
schedule_rollback() {
  local pending
  pending="$(pending_path "$1")"; mkdir -p "$pending"
  printf '%s\n' "$1" >"$pending/backup"
  printf 'test-token\n' >"$pending/armed"
  : >"$pending/owner"
  ln -sfn "$pending" "$PENDING_LATEST"
}
reset_runtime() {
  cat >"$TMP/sysctl-runtime.tsv" <<'SYSCTL'
net.core.default_qdisc	fq
net.ipv4.tcp_available_congestion_control	cubic bbr
net.ipv4.tcp_congestion_control	cubic
net.core.rmem_max	33554432
net.core.wmem_max	33554432
net.ipv4.tcp_rmem	4096 131072 33554432
net.ipv4.tcp_wmem	4096 65536 33554432
net.ipv4.tcp_mem	100 200 300
net.ipv4.tcp_moderate_rcvbuf	1
net.ipv4.tcp_sack	1
net.ipv4.tcp_dsack	1
net.ipv4.tcp_window_scaling	1
SYSCTL
}
HISTORY_SESSION=old-session; YES=1; PERSIST_FINAL=1
for scenario in managed-cake external-cake fresh-fq; do
  config="$TMP/config-$scenario"; mkdir -p "$config"
  SYSCTL_FILE="$config/sysctl.conf"; MODULES_FILE="$config/modules.conf"
  ENV_FILE="$config/env"; QDISC_HELPER="$config/helper"; SERVICE_FILE="$config/service"
  reset_runtime
  SYSTEMD_ACTIVE=0
  REQUESTED_QDISC=auto; CAKE_BANDWIDTH_MBPS=""; QDISC_ONLY=0
  if [[ "$scenario" == fresh-fq ]]; then
    cp "$TMP/fq.json" "$TMP/live.json"
  else
    cp "$TMP/cake.json" "$TMP/live.json"
    if [[ "$scenario" == managed-cake ]]; then
      QDISC_POLICY=manage; TUNING_QDISC=cake; REQUESTED_QDISC=cake; CAKE_BANDWIDTH_MBPS=190
      write_qdisc_persistence eth0 >"$config/setup.log" 2>&1
      printf '# owned default\nnet.core.default_qdisc = fq\n' >"$SYSCTL_FILE"
      for name in env helper service modules.conf; do cp "$config/$name" "$config/$name.before"; done
    else
      # Retain unrelated modules, including files without a trailing newline.
      printf '# existing modules\nsch_cake\nsch_fq' >"$MODULES_FILE"
      cp "$MODULES_FILE" "$config/modules.conf.before"
    fi
  fi
  cp "$TMP/live.json" "$config/queue.before.json"
  REQUESTED_QDISC=auto; CAKE_BANDWIDTH_MBPS=""
  SYSTEMD_ACTIVE=1
  apply_history_command >"$config/application.log" 2>&1
  [[ "$(sysctl_get net.core.rmem_max)" == 8388608 ]] || fail "$scenario did not apply TCP buffers"
  grep -Fqx 'net.core.rmem_max = 8388608' "$SYSCTL_FILE" || fail "$scenario did not persist TCP buffers"
  grep -Fqx 'net.ipv4.tcp_mem = 1024 1536 2048' "$SYSCTL_FILE" || fail "$scenario lost current memory thresholds"
  qdisc_json equal "$config/queue.before.json" "$TMP/live.json" || fail "$scenario changed the live queue"
  [[ -f "$(pending_path "$BACKUP_DIR")/armed" && ! -e "$(pending_path "$BACKUP_DIR")/owner" ]] || fail "$scenario lost rollback protection"
  grep -Fq '队列开机配置：保留，未修改' "$SESSION_DIR/history-application.txt" || fail 'report lacks preservation status'
  if [[ "$scenario" == managed-cake ]]; then
    for name in env helper service modules.conf; do cmp "$config/$name.before" "$config/$name" || fail "managed CAKE $name changed"; done
    grep -Fqx 'BBR_QDISC_POLICY=manage' "$ENV_FILE" || fail 'managed boot policy lost'
    grep -Fqx 'BBR_CAKE_BANDWIDTH_MBPS=190' "$ENV_FILE" || fail 'CAKE boot bandwidth lost'
    grep -Fqx 'net.core.default_qdisc = fq' "$SYSCTL_FILE" || fail 'owned default setting lost'
  else
    for path in "$ENV_FILE" "$QDISC_HELPER" "$SERVICE_FILE"; do [[ ! -e "$path" ]] || fail "$scenario created queue boot files"; done
    if grep -q '^net.core.default_qdisc' "$SYSCTL_FILE"; then fail "$scenario introduced a default queue override"; fi
    [[ "$(grep -Ec '^[[:space:]]*tcp_bbr[[:space:]]*$' "$MODULES_FILE")" == 1 ]] || fail "$scenario lacks BBR boot module"
    if [[ "$scenario" == external-cake ]]; then
      python3 - "$config/modules.conf.before" "$MODULES_FILE" <<'PY'
from pathlib import Path
import sys
before, after=(Path(p).read_bytes() for p in sys.argv[1:])
assert after.startswith(before+b'\n'), 'existing module entries were rewritten'
PY
    fi
  fi
  # A second save must remain idempotent and leave all queue boot files alone.
  cp "$MODULES_FILE" "$config/modules.saved"
  write_persistent_config eth0 8 tcp-only
  cmp "$config/modules.saved" "$MODULES_FILE" || fail 'BBR module duplicated on repeated save'
  if [[ "$scenario" == managed-cake ]]; then
    # Simulate the next boot before rollback, on a separate mock interface.
    boot_dir="$TMP/boot-$scenario"; mkdir -p "$boot_dir"
    cp "$TMP/defaults.json" "$boot_dir/defaults.json"
    cp "$TMP/fq.json" "$boot_dir/live.json"
    sed "s|source /etc/default/bbr-tcp-tuning|source $ENV_FILE|" "$QDISC_HELPER" >"$config/boot-helper"
    QDISC_TEST_DIR="$boot_dir" bash "$config/boot-helper" >"$config/boot.log" 2>&1
    qdisc_json matches "$boot_dir/live.json" cake 190 || fail 'retained boot helper did not restore CAKE shaping'
  fi
  SYSTEMD_ACTIVE=0
  restore_backup "$BACKUP_DIR" >"$config/restore.log" 2>&1
  cancel_rollback_for_backup "$BACKUP_DIR"
  [[ "$(sysctl_get net.core.rmem_max)" == 33554432 ]] || fail "$scenario failed TCP rollback"
  if [[ "$scenario" == fresh-fq ]]; then
    [[ ! -e "$SYSCTL_FILE" && ! -e "$MODULES_FILE" ]] || fail 'rollback did not remove newly created TCP files'
  fi
done
# Inline-comment module entries must also remain byte-for-byte unchanged.
printf '# existing\ntcp_bbr # BBR module\nsch_cake\n' >"$MODULES_FILE"
cp "$MODULES_FILE" "$TMP/modules-comment.before"
QDISC_POLICY=preserve
write_persistent_config eth0 8 tcp-only
cmp "$TMP/modules-comment.before" "$MODULES_FILE" || fail 'commented BBR module entry was rewritten'
# A mistaken TCP-only call must fail before writing a new default queue.
cp "$SYSCTL_FILE" "$TMP/sysctl-scope.before"
if (QDISC_POLICY=manage; write_persistent_config eth0 16 tcp-only) >"$TMP/scope.log" 2>&1; then fail 'TCP-only scope accepted a managed queue'; fi
cmp "$TMP/sysctl-scope.before" "$SYSCTL_FILE" || fail 'invalid persistence scope modified TCP configuration'
printf 'All historical TCP persistence, CAKE boot preservation and rollback tests passed.\n'
