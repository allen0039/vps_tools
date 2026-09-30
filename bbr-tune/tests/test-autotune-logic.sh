#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/bbr-tune.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "$3: expected '$2', got '$1'"; }

# Missing iperf3 is installed only on the remote server.
(
  fake_bin="$(mktemp -d)"
  export FAKE_BIN="$fake_bin"
  export INSTALL_LOG="${fake_bin}/install.log"
  trap 'rm -rf "$fake_bin"' EXIT
  cat >"${fake_bin}/apt-get" <<'FAKE_APT'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$INSTALL_LOG"
if [[ " $* " == *" install "* ]]; then
  cat >"${FAKE_BIN}/iperf3" <<'FAKE_IPERF'
#!/usr/bin/env bash
printf 'iperf 3.test\n'
FAKE_IPERF
  chmod +x "${FAKE_BIN}/iperf3"
fi
FAKE_APT
  chmod +x "${fake_bin}/apt-get"
  PATH="${fake_bin}:/usr/bin:/bin"
  require_root() { :; }
  install_iperf3_if_needed
  [[ -x "${fake_bin}/iperf3" ]] || fail "iperf3 automatic installation"
  grep -qx 'update' "$INSTALL_LOG" || fail "apt update invocation"
  grep -qx 'install -y iperf3' "$INSTALL_LOG" || fail "apt install invocation"
)

parse_iperf_json "${ROOT}/tests/fixtures/iperf3-reverse.json"
assert_eq "$RESULT_MBPS" "793.60" "receiver goodput parser"
assert_eq "$RESULT_BYTES" "125000000" "JSON byte parser"
assert_eq "$RESULT_RETRANS" "1000" "JSON retrans parser"
assert_eq "$RESULT_RETRANS_PERCENT" "1.1584" "JSON retrans percentage"
assert_eq "$RESULT_RTT_MS" "180.00" "JSON TCP RTT parser"
assert_eq "$RESULT_CLIENT_ADDRESS" "198.51.100.8" "JSON client address parser"

# Missing interval telemetry must stay unknown, not perfect stability.
assert_eq "$RESULT_CV_PERCENT" "NA" "unknown CV is explicit"
assert_eq "$RESULT_RATE_SOURCE" "receiver" "goodput source"

TARGET_MBPS="1000"
TARGET_UTILIZATION="90"
MAX_RETRANS_PERCENT="1"
RESULT_MBPS="920"
RESULT_RETRANS_PERCENT="0.5"
calculate_result_quality
assert_eq "$RESULT_PASS" "yes" "passing result"
pass_score="$RESULT_SCORE"
RESULT_MBPS="850"
RESULT_RETRANS_PERCENT="0.2"
calculate_result_quality
assert_eq "$RESULT_PASS" "no" "low-throughput result"
awk -v passing="$pass_score" -v failing="$RESULT_SCORE" 'BEGIN {exit !(passing>failing)}' || fail "passing result score"

# Balanced evaluation protects both single-connection and multi-connection
# throughput relative to their independent baselines.
BASELINE_SINGLE_MBPS="200"
BASELINE_MULTI_MBPS="900"
BALANCE_MIN_RETENTION_PERCENT="95"
PAIR_SINGLE_RETRANS_PERCENT="0.1"
PAIR_MULTI_RETRANS_PERCENT="0.1"
PAIR_SINGLE_MBPS="189"
PAIR_MULTI_MBPS="1000"
calculate_pair_quality yes
assert_eq "$PAIR_ELIGIBLE" "no" "single-connection baseline protection"
PAIR_SINGLE_MBPS="220"
PAIR_MULTI_MBPS="854"
calculate_pair_quality yes
assert_eq "$PAIR_ELIGIBLE" "no" "multi-connection baseline protection"
PAIR_SINGLE_MBPS="220"
PAIR_MULTI_MBPS="900"
calculate_pair_quality yes
assert_eq "$PAIR_ELIGIBLE" "yes" "balanced candidate eligibility"

PAIR_SINGLE_MBPS="600"; PAIR_MULTI_MBPS="600"
calculate_pair_quality no
balanced_score="$PAIR_SCORE"
PAIR_SINGLE_MBPS="1000"; PAIR_MULTI_MBPS="200"
calculate_pair_quality no
biased_score="$PAIR_SCORE"
awk -v balanced="$balanced_score" -v biased="$biased_score" 'BEGIN {exit !(balanced>biased)}' || fail "harmonic score must penalize one-sided performance"

# Best-effort selection always keeps a measured candidate. Candidates that
# preserve both baselines take precedence, then the harmonic score decides.
BEST_KIND="none"; BEST_SCORE="-999999"; BEST_ELIGIBLE="no"
PAIR_SCORE="55"; PAIR_ELIGIBLE="no"
candidate_better_than_best || fail "first measured candidate must be selectable"
PAIR_SINGLE_MBPS="300"; PAIR_SINGLE_RETRANS_PERCENT="0.1"
PAIR_MULTI_MBPS="700"; PAIR_MULTI_RETRANS_PERCENT="0.1"
set_best_from_pair candidate-1 32 1.5
PAIR_SCORE="50"; PAIR_ELIGIBLE="yes"
candidate_better_than_best || fail "baseline-safe candidate must outrank unsafe candidate"
set_best_from_pair candidate-2 64 3.0
PAIR_SCORE="80"; PAIR_ELIGIBLE="no"
if candidate_better_than_best; then fail "unsafe candidate must not displace baseline-safe best"; fi

assert_eq "$(detect_iperf_family 203.0.113.20)" "-4" "IPv4 iperf family"
assert_eq "$(detect_iperf_family 2001:db8::20)" "-6" "IPv6 iperf family"

# A malformed TCP connection must not consume the one-shot iperf3 server.
# The supervisor restarts the listener until a complete measurement exists.
(
  fake_bin="$(mktemp -d)"
  trap 'rm -rf "$fake_bin"' EXIT
  export IPERF_ATTEMPTS="${fake_bin}/attempts"
  export IPERF_ARGS="${fake_bin}/args"
  export IPERF_FIXTURE="${ROOT}/tests/fixtures/iperf3-reverse.json"
  printf '0\n' >"$IPERF_ATTEMPTS"
  cat >"${fake_bin}/iperf3" <<'FAKE_IPERF_SERVER'
#!/usr/bin/env bash
count="$(cat "$IPERF_ATTEMPTS")"
count=$((count+1))
printf '%s\n' "$count" >"$IPERF_ATTEMPTS"
printf '%s\n' "$*" >>"$IPERF_ARGS"
if (( count == 1 )); then
  printf '{"start":{"connected":[]},"end":{},"error":"unable to receive cookie"}\n'
else
  cat "$IPERF_FIXTURE"
fi
FAKE_IPERF_SERVER
  chmod +x "${fake_bin}/iperf3"
  PATH="${fake_bin}:/usr/bin:/bin"
  final_json="${fake_bin}/final.json"
  final_err="${fake_bin}/final.err"
  iperf_server_loop "$final_json" "$final_err" 34567 -4
  assert_eq "$(cat "$IPERF_ATTEMPTS")" "2" "invalid connection listener restart"
  grep -q -- '-4 -s -1 -J -p 34567' "$IPERF_ARGS" || fail "iperf server address-family arguments"
  grep -q 'ignored_connection=1' "$final_err" || fail "ignored connection audit log"
  parse_iperf_json "$final_json"
  assert_eq "$RESULT_MBPS" "793.60" "supervised iperf result"
)

# Listener detection works with IPv4, IPv6 and wildcard addresses.
(
  ss() {
    cat <<'SS_OUTPUT'
LISTEN 0 4096 0.0.0.0:22000 0.0.0.0:*
LISTEN 0 4096 [::]:23000 [::]:*
SS_OUTPUT
  }
  if port_is_free 22000; then fail "IPv4 occupied port"; fi
  if port_is_free 23000; then fail "IPv6 occupied port"; fi
  port_is_free 24000 || fail "free port"
)

# Random port retries occupied candidates.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '0\n' >"${tmp}/checks"
port_is_free() {
  local count
  count="$(cat "${tmp}/checks")"
  count=$((count+1))
  printf '%s\n' "$count" >"${tmp}/checks"
  (( count >= 3 ))
}
port="$(choose_random_port)"
(( port >= 20000 && port <= 59999 )) || fail "random port range"
assert_eq "$(cat "${tmp}/checks")" "3" "occupied ports skipped"

forbidden='pro''mpt'
if grep -qi "$forbidden" "${ROOT}/bbr-tune.sh"; then fail "script contains prohibited development wording"; fi

# Simulate a complete balanced search: baseline pair, three growth candidates,
# six backtracking candidates, and one final verification pair. Exercise both
# managed fq and preserved CAKE through the complete search/report lifecycle.
for simulated_qdisc in fq_codel cake; do
(
  sim="$(mktemp -d)"
  trap 'rm -rf "$sim"' EXIT
  STATE_DIR="$sim/state"; SESSION_ROOT="${STATE_DIR}/sessions"; BACKUP_ROOT="${STATE_DIR}/backups"
  LATEST_BACKUP="${STATE_DIR}/latest"; PENDING_DIR="${STATE_DIR}/pending"; PENDING_LATEST="${STATE_DIR}/pending-latest"
  HISTORY_FILE="${STATE_DIR}/history.tsv"
  TARGET_MBPS="1000"; START_STREAMS="8"; TEST_REPEATS=1; TEST_STREAMS="1"
  TARGET_UTILIZATION="90"; MAX_RETRANS_PERCENT="1"; AUTO_ROLLBACK_SECONDS="0"
  SERVER_ADDRESS="speed.example.com"; IFACE="auto"; PERSIST_FINAL="0"; FORCE="0"
  require_linux() { :; }; require_root() { :; }; have() { return 0; }; pending_guard() { :; }
  install_iperf3_if_needed() { :; }; install_python3_if_needed() { :; }; ensure_bbr() { :; }; schedule_rollback() { :; }
  resolve_iface() { echo eth0; }; guess_server_address() { echo speed.example.com; }; choose_random_port() { echo 34567; }
  tc() { echo "qdisc $simulated_qdisc 0: root"; }
  ip() { return 0; }; qdisc_layout_safe() { [[ "$simulated_qdisc" != cake ]]; }; root_qdisc_kind() { echo "$simulated_qdisc"; }; apply_candidate() { :; }
  detect_memory_limits() {
    MEM_TOTAL_MIB=8192; MEM_AVAILABLE_MIB=4096; MEM_EFFECTIVE_MIB=8192
    MEM_TCP_BUDGET_MIB=5461; MEM_BUFFER_CAP_MIB=128; PAGE_SIZE_BYTES=4096
    TCP_MEM_LOW_PAGES=699050; TCP_MEM_PRESSURE_PAGES=1048576; TCP_MEM_HIGH_PAGES=1398101
    SEARCH_BUFFER_CAP_MIB=128
  }
  current_buffer_max() { echo 16777216; }
  sysctl_get() {
    case "$1" in
      net.ipv4.tcp_available_congestion_control) echo 'reno cubic bbr' ;;
      net.ipv4.tcp_congestion_control) echo bbr ;;
      net.core.default_qdisc) echo fq ;;
      net.core.rmem_max|net.core.wmem_max) echo 16777216 ;;
      net.ipv4.tcp_rmem) echo '4096 131072 16777216' ;;
      net.ipv4.tcp_wmem) echo '4096 16384 16777216' ;;
      net.ipv4.tcp_mem) echo '699050 1048576 1398101' ;;
      *) echo 1 ;;
    esac
  }
  init_session() {
    SESSION_ID="${sim_name:-simulated}"; SESSION_DIR="${SESSION_ROOT}/${SESSION_ID}"; mkdir -p "$SESSION_DIR"
    RUN_LOG="${SESSION_DIR}/run.log"; REPORT_FILE="${SESSION_DIR}/results.tsv"; COMPARISON_FILE="${SESSION_DIR}/comparison.txt"
    : >"$RUN_LOG"
    printf 'stage\tround\tmode\tconfig\tstreams\tbuffer_mib\tbdp_ratio\trtt_ms\tmbps\tretrans\tretrans_percent\tmetric_score\tpassed\tbalance_score\teligible\tstrategy\tcv_percent\tmeasured_rtt_ms\trepeats\n' >"$REPORT_FILE"
  }
  capture_state() { printf 'state\n' >"$2"; }
  create_backup() { local d="${BACKUP_ROOT}/${SESSION_ID}"; mkdir -p "$d"; echo "$d"; }
  cancel_rollback_for_backup() { :; }; restore_backup() { :; }
  call=0
  test_mbps=(200 900 250 920 300 950 250 960 270 955 310 960 290 965 305 962 312 963 280 964 315 958)
  run_reverse_test() {
    call=$((call+1))
    RESULT_RTT_MS=180; RESULT_RTT_SOURCE="simulated TCP RTT"
    RESULT_MBPS="${test_mbps[$((call-1))]:-}"
    [[ -n "$RESULT_MBPS" ]] || fail "unexpected simulated test call $call"
    RESULT_RETRANS=10; RESULT_RETRANS_PERCENT=0.002; RESULT_BYTES=1000000000
    calculate_result_quality
  }
  autotune >"${sim}/autotune.log" 2>&1
  assert_eq "$call" "22" "balanced growth, backtrack and verification test count"
  assert_eq "$BEST_KIND" "candidate-5" "best balanced candidate selection"
  assert_eq "$BEST_BUFFER_MIB" "80" "best balanced buffer selection"
  assert_eq "$FINAL_SINGLE_MBPS" "315.00" "final single-connection verification"
  assert_eq "$FINAL_MULTI_MBPS" "958.00" "final multi-connection verification"
  assert_eq "$OUTCOME" "best-effort-runtime" "best-effort search outcome"
  assert_eq "$QOS_DETECTED" "1" "single-versus-multi difference classification"
  assert_eq "$OVERSHOOT_DETECTED" "1" "overshoot detection"
  assert_eq "$SEARCH_ROUNDS" "9" "adaptive search rounds"
  [[ -s "$REPORT_FILE" ]] || fail "simulated results log"
  [[ -s "$COMPARISON_FILE" ]] || fail "simulated comparison log"
  [[ -s "$HISTORY_FILE" ]] || fail "simulated history log"
  grep -q "$(printf 'single\tbbr-%s\t1\t80' "$TUNING_QDISC")" "$REPORT_FILE" || fail "single-connection candidate log"
  grep -q "$(printf 'multi\tbbr-%s\t8\t80' "$TUNING_QDISC")" "$REPORT_FILE" || fail "multi-connection candidate log"
  grep -Fq '绝对目标未完全满足；已采用本次会话中单/多连接综合表现最优的候选' "$COMPARISON_FILE" || fail "best-effort report conclusion"

  awk -F '\t' 'NF!=19 {exit 1}' "$REPORT_FILE" || fail "results header/data width mismatch"
  awk -F '\t' 'NF!=30 {exit 1}' "$HISTORY_FILE" || fail "history header/data width mismatch"

  # No measured candidate preserves baseline: keep the best valid candidate,
  # stop after two plateau steps, persist TCP-only settings, and renew safety.
  sim_name=plateau; call=0; renewals=0; restores=0
  test_mbps=(600 1100 500 950 500 950 500 950 500 950)
  PERSIST_FINAL=1; AUTO_ROLLBACK_SECONDS=3600; STRATEGY=retrans
  SYSCTL_FILE="$sim/persist/tcp.conf"; MODULES_FILE="$sim/persist/modules.conf"
  ENV_FILE="$sim/persist/env"; QDISC_HELPER="$sim/persist/qdisc"; SERVICE_FILE="$sim/persist/tc.service"
  schedule_rollback() { renewals=$((renewals+1)); }
  restore_backup() { restores=$((restores+1)); }
  sysctl_exists() { local key; for key in "${TUNING_SYSCTL_KEYS[@]}"; do [[ "$1" == "$key" ]] && return 0; done; return 1; }
  systemd_available() { return 0; }
  systemctl() { printf '%s\n' "$*" >>"$sim/systemctl.log"; }
  apply_candidate() { printf '%s\n' "$2" >>"$sim/applied.log"; }
  autotune >"${sim}/plateau.log" 2>&1
  assert_eq "$call" 10 "plateau measurement count"
  assert_eq "$SEARCH_ROUNDS" 3 "plateau must stop after two no-gain steps"
  assert_eq "$OVERSHOOT_DETECTED" 0 "plateau is not overshoot"
  assert_eq "$BEST_BUFFER_MIB" 32 "plateau keeps smaller equally performing candidate"
  assert_eq "$PAIR_ELIGIBLE" no "all candidates below baseline"
  assert_eq "$OUTCOME" best-effort-persistent "below-target candidate persisted"
  assert_eq "$restores" 0 "below-target performance alone does not trigger rollback"
  assert_eq "$renewals" 10 "rollback lease renewed at each candidate/final measurement and completion"
  assert_eq "$(tail -n1 "$sim/applied.log")" 32 "final application uses selected candidate"
  grep -Fqx 'net.ipv4.tcp_rmem = 4096 131072 33554432' "$SYSCTL_FILE" || fail "best candidate not persisted"
  grep -Fq 'Strategy=retrans;' "$SYSCTL_FILE" || fail "persisted strategy provenance"
  if grep -Eq '^(kernel|vm)\.' "$SYSCTL_FILE"; then fail "unrelated system policies persisted"; fi
  grep -Fq '最终复核至少一侧低于基线保护线' "$COMPARISON_FILE" || fail "below-baseline report omitted"
  grep -Fq '连续两档无显著评分收益' "$COMPARISON_FILE" || fail "plateau reason missing"
  awk -F '\t' 'NF!=19 {exit 1}' "$REPORT_FILE" || fail "plateau results schema mismatch"
  awk -F '\t' 'NF!=30 {exit 1}' "$HISTORY_FILE" || fail "plateau history schema mismatch"
  if [[ "$simulated_qdisc" == cake ]]; then
    assert_eq "$QDISC_POLICY" preserve "CAKE search preservation policy"
    grep -Fqx 'BBR_QDISC_POLICY=preserve' "$ENV_FILE" || fail "CAKE boot policy not persisted"
    grep -Fq '保留现有 CAKE' "$COMPARISON_FILE" || fail "CAKE report policy missing"
    if grep -q 'bbr-fq' "$REPORT_FILE"; then fail "CAKE results mislabeled as fq"; fi
    if grep -q '^net.core.default_qdisc' "$SYSCTL_FILE"; then fail "CAKE persistence changed default qdisc"; fi
  fi
  # Valid baseline, then missing candidate telemetry in stable mode: this is
  # an invalid experiment, not an eligible best-effort performance result.
  if (
    sim_name=invalid-candidate; call=0; STRATEGY=stable
    run_reverse_test() {
      call=$((call+1)); RESULT_MBPS=800; RESULT_RETRANS_PERCENT=0.01
      RESULT_RTT_MS=100; RESULT_MIN_RTT_MS=90; RESULT_CV_PERCENT=2
      RESULT_RETRANS=10; RESULT_BYTES=100000000; RESULT_RATE_SOURCE=receiver
      (( call<3 )) || RESULT_CV_PERCENT=NA
      calculate_result_quality
    }
    restore_backup() { printf 'restored\n' >"$sim/rollback.marker"; }
    write_persistent_config() { fail "invalid candidate must never persist"; }
    autotune
  ) >"$sim/invalid-candidate.log" 2>&1; then
    fail "invalid candidate telemetry must abort the experiment"
  fi
  [[ -f "$sim/rollback.marker" ]] || fail "invalid measurement did not restore baseline"
  grep -Fq '稳定优先缺少有效区间波动或 RTT 数据' "$sim/invalid-candidate.log" || fail "missing telemetry not explained"

  # Replace an old-schema index only by archiving it; never erase sessions.
  printf 'time\tsession\nold\tprevious-run\n' >"$HISTORY_FILE"
  append_history >"$sim/history-upgrade.log" 2>&1
  legacy=("$STATE_DIR"/history.legacy-*.tsv)
  [[ -f "${legacy[0]}" ]] || fail "legacy history not retained"
  grep -Fq previous-run "${legacy[0]}" || fail "legacy history data changed"
  awk -F '\t' 'NF!=30 {exit 1}' "$HISTORY_FILE" || fail "upgraded history schema mismatch"
  rm -rf "$sim"
)
done

printf 'All autotune logic tests passed.\n'
