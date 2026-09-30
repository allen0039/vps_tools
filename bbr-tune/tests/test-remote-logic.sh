#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/bbr-tune.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "$3: expected '$2', got '$1'"; }

SERVER_ADDRESS=""
SSH_CONNECTION="198.51.100.8 50123 203.0.113.20 22"
assert_eq "$(guess_server_address)" "203.0.113.20" "SSH server address"
SERVER_ADDRESS="speed.example.com"
assert_eq "$(guess_server_address)" "speed.example.com" "explicit server address"

# Rollback timers are cancellable and leave no stale pending marker.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
STATE_DIR="$tmp"
PENDING_DIR="${tmp}/pending"
PENDING_LATEST="${tmp}/pending-latest"
AUTO_ROLLBACK_SECONDS="30"
SCRIPT_PATH="${ROOT}/bbr-tune.sh"
backup="${tmp}/backups/test-backup"
mkdir -p "$backup"
schedule_rollback "$backup"
pending="$(pending_path "$backup")"
[[ -f "${pending}/armed" ]] || fail "rollback armed marker"
[[ -L "$PENDING_LATEST" ]] || fail "rollback latest link"
pending_guard
[[ ! -e "$pending" ]] || fail "new autotune cancels previous pending rollback"
[[ ! -e "$PENDING_LATEST" ]] || fail "new autotune removes previous pending link"

# A broken latest symlink is stale state and must never block a new run.
ln -sfn "${tmp}/missing-pending" "$PENDING_LATEST"
pending_guard
[[ ! -L "$PENDING_LATEST" ]] || fail "broken pending symlink cleanup"

# Explicit cancellation remains idempotent.
mkdir -p "$backup"
schedule_rollback "$backup"
cancel_rollback_for_backup "$backup"
[[ ! -e "$(pending_path "$backup")" ]] || fail "rollback cancellation"

# The retained comparison is a technical report that includes both traffic
# patterns, the memory budget, kernel parameters, and convergence evidence.
SESSION_ID="test-session"
SESSION_DIR="$tmp/session"
mkdir -p "$SESSION_DIR"
RUN_LOG="${SESSION_DIR}/run.log"
REPORT_FILE="${SESSION_DIR}/results.tsv"
COMPARISON_FILE="${SESSION_DIR}/comparison.txt"
printf 'stage\tround\tmode\tconfig\tstreams\tbuffer_mib\tbdp_ratio\trtt_ms\tmbps\tretrans\tretrans_percent\tmetric_score\tpassed\tbalance_score\teligible\n' >"$REPORT_FILE"
printf 'before\t0\tsingle\toriginal\t1\t6\toriginal\t180\t200\t20\t0.0100\t20\tno\t32.7273\tyes\n' >>"$REPORT_FILE"
printf 'before\t0\tmulti\toriginal\t8\t6\toriginal\t180\t900\t30\t0.0060\t90\tyes\t32.7273\tyes\n' >>"$REPORT_FILE"
printf 'final\t4\tsingle\tbbr-fq\t1\t64\t2.98\t180\t260\t10\t0.0050\t26\tno\t41.6000\tyes\n' >>"$REPORT_FILE"
printf 'final\t4\tmulti\tbbr-fq\t8\t64\t2.98\t180\t1040\t10\t0.0030\t104\tyes\t41.6000\tyes\n' >>"$REPORT_FILE"
: >"$RUN_LOG"
SERVER_ADDRESS="speed.example.com"
TARGET_MBPS="1000"; TARGET_UTILIZATION="90"; MAX_RETRANS_PERCENT="1"; RTT_MS="180"; RTT_SOURCE="simulated TCP RTT"
BALANCE_MULTI_STREAMS="8"; BALANCE_MIN_RETENTION_PERCENT="95"
MEM_TOTAL_MIB="8192"; MEM_AVAILABLE_MIB="4096"; MEM_EFFECTIVE_MIB="8192"
MEM_TCP_BUDGET_MIB="5461"; MEM_BUFFER_CAP_MIB="2047"; BDP_MIB="21.46"
TCP_MEM_LOW_PAGES="699050"; TCP_MEM_PRESSURE_PAGES="1048576"; TCP_MEM_HIGH_PAGES="1398101"
BEFORE_CC="cubic"; BEFORE_QDISC="fq_codel"; BEFORE_RMEM="4096 131072 6291456"; BEFORE_WMEM="4096 16384 4194304"
BEFORE_TCP_MEM="196608 262144 393216"; BEFORE_BUFFER_BYTES="6291456"
BASELINE_SINGLE_MBPS="200"; BASELINE_SINGLE_RETRANS="20"; BASELINE_SINGLE_RETRANS_PERCENT="0.0100"; BASELINE_SINGLE_PASS="no"
BASELINE_MULTI_MBPS="900"; BASELINE_MULTI_RETRANS="30"; BASELINE_MULTI_RETRANS_PERCENT="0.0060"; BASELINE_MULTI_PASS="yes"
BASELINE_SCORE="32.7273"; BASELINE_PASS="no"
FINAL_SINGLE_MBPS="260"; FINAL_SINGLE_RETRANS="10"; FINAL_SINGLE_RETRANS_PERCENT="0.0050"; FINAL_SINGLE_PASS="no"
FINAL_MULTI_MBPS="1040"; FINAL_MULTI_RETRANS="10"; FINAL_MULTI_RETRANS_PERCENT="0.0030"; FINAL_MULTI_PASS="yes"
FINAL_SCORE="41.6000"; FINAL_PASS="no"
OUTCOME="best-effort-runtime"; BEST_KIND="candidate-2"; BEST_BUFFER_MIB="64"; BEST_FACTOR="2.98"
BEST_SINGLE_MBPS="260"; BEST_MULTI_MBPS="1040"; QOS_DETECTED="1"; SEARCH_ROUNDS="4"; OVERSHOOT_DETECTED="1"; OVERSHOOT_MIB="128"
sysctl_get() {
  case "$1" in
    net.ipv4.tcp_congestion_control) echo bbr ;;
    net.ipv4.tcp_rmem) echo '4096 131072 67108864' ;;
    net.ipv4.tcp_wmem) echo '4096 16384 67108864' ;;
    net.ipv4.tcp_mem) echo '699050 1048576 1398101' ;;
  esac
}
root_qdisc_kind() { echo fq; }
write_comparison eth0 67108864 >/dev/null
for text in \
  'TCP/BBR 参数优化评估报告' \
  '[5] 性能对比' \
  '[7] 系统与 TCP 参数审计（含未修改项）' \
  '[8] 最优候选' \
  '联合模型：单连接与 8 连接场景等权评估' \
  'TCP 聚合内存预算：5461.00 MiB' \
  'kernel / VM / 路由策略：保留会话开始时的值' \
  '绝对目标未完全满足；已采用本次会话中单/多连接综合表现最优的候选' \
  '单连接吞吐' \
  '  - 调优后：260 Mbps' \
  '8 连接聚合吞吐' \
  '  - 调优后：1040 Mbps' \
  'tcp_mem' \
  '  - 调优前：196608 262144 393216' \
  '  - 调优后：699050 1048576 1398101' \
  '在 128 MiB 检测到综合性能回落' \
  '最终复核：最优候选' \
  '[复核 / 轮次 4]' \
  '单连接（1 流）：260 Mbps' \
  '多连接（8 流）：1040 Mbps'; do
  grep -Fq "$text" "$COMPARISON_FILE" || fail "technical report field missing: $text"
done
[[ -s "${SESSION_DIR}/sysctl-comparison.tsv" ]] || fail "sysctl comparison data missing"
grep -Fq $'parameter\tbefore\tafter\tstatus' "${SESSION_DIR}/sysctl-comparison.tsv" || fail "sysctl comparison header"
if grep -q '^|' "$COMPARISON_FILE"; then fail "terminal report must not contain markdown table rows"; fi

printf 'All remote-role tests passed.\n'
