#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "$3: expected '$2', got '$1'"; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

TARGET_MBPS=1000; TARGET_UTILIZATION=90; MAX_RETRANS_PERCENT=1
BASELINE_SINGLE_MBPS=900; BASELINE_MULTI_MBPS=900
BASELINE_SINGLE_RTT_MS=100; BASELINE_MULTI_RTT_MS=100
PAIR_SINGLE_RETRANS=10; PAIR_MULTI_RETRANS=10
measure_fast() {
  PAIR_SINGLE_MBPS=1100; PAIR_MULTI_MBPS=1100
  PAIR_SINGLE_RETRANS_PERCENT=1; PAIR_MULTI_RETRANS_PERCENT=1
  PAIR_SINGLE_CV_PERCENT=35; PAIR_MULTI_CV_PERCENT=35
  PAIR_SINGLE_RTT_MS=140; PAIR_MULTI_RTT_MS=140
  calculate_pair_quality yes
}
measure_consistent() {
  PAIR_SINGLE_MBPS=940; PAIR_MULTI_MBPS=980
  PAIR_SINGLE_RETRANS_PERCENT=0.01; PAIR_MULTI_RETRANS_PERCENT=0.01
  PAIR_SINGLE_CV_PERCENT=3; PAIR_MULTI_CV_PERCENT=3
  PAIR_SINGLE_RTT_MS=101; PAIR_MULTI_RTT_MS=101
  calculate_pair_quality yes
}
# Run the real selector with identical candidates but different objectives.
for strategy in balanced speed stable retrans; do
  STRATEGY="$strategy"; configure_strategy
  measure_fast; set_best_from_pair fast 64 3
  measure_consistent
  if candidate_better_than_best; then set_best_from_pair consistent 32 1.5; fi
  case "$strategy" in
    speed) assert_eq "$BEST_KIND" fast "speed priority" ;;
    stable|retrans) assert_eq "$BEST_KIND" consistent "$strategy priority" ;;
  esac
  # Neither mode may silently sacrifice single-connection performance.
  PAIR_SINGLE_MBPS=300; PAIR_MULTI_MBPS=2000
  calculate_pair_quality yes
  assert_eq "$PAIR_ELIGIBLE" no "$strategy single-connection protection"
  if candidate_better_than_best; then fail "$strategy accepted one-sided candidate"; fi
done
if (STRATEGY=unknown; configure_strategy) >/dev/null 2>&1; then fail "invalid strategy accepted"; fi
for repeats in 0 6 1.2 bad; do
  if (STRATEGY=balanced; TEST_REPEATS="$repeats"; validate_autotune_options) >/dev/null 2>&1; then fail "invalid repetitions"; fi
done
parse_args autotune --strategy stable --repeats 3 --bandwidth-mbps 500
validate_autotune_options
assert_eq "$STRATEGY" stable "CLI strategy"
assert_eq "$TEST_REPEATS" 3 "CLI repetitions"

# Formatting a tiny estimated percentage to zero must not imply zero retransmissions.
(
  TARGET_MBPS=1000; MAX_RETRANS_PERCENT=0
  RESULT_MBPS=1000; RESULT_RETRANS_PERCENT=0.0000; RESULT_RETRANS=1
  calculate_result_quality
  assert_eq "$RESULT_PASS" no "zero-retrans requirement survives display rounding"
  PAIR_SINGLE_MBPS=1000; PAIR_MULTI_MBPS=1000
  PAIR_SINGLE_RETRANS_PERCENT=0; PAIR_MULTI_RETRANS_PERCENT=0
  PAIR_SINGLE_RETRANS=1; PAIR_MULTI_RETRANS=0
  calculate_pair_quality no
  assert_eq "$PAIR_PASS" no "pair zero-retrans requirement"
  PAIR_SINGLE_RETRANS=0; calculate_pair_quality no
  assert_eq "$PAIR_PASS" yes "genuine zero-retrans result"
)

# Fallback selection still records below-target candidates, even below baseline.
BEST_KIND=none; PAIR_ELIGIBLE=no; PAIR_SCORE=20
candidate_better_than_best || fail "no best-effort fallback"
set_best_from_pair below-target 4 1
PAIR_SCORE=25
candidate_better_than_best || fail "best-effort ranking"

# JSON parser uses delivered goodput, preserves zero-rate intervals and rejects invalid tests.
python3 - "$ROOT/tests/fixtures/iperf3-reverse.json" "$TMP" <<'PY'
import json, sys, pathlib
base=json.load(open(sys.argv[1]))
base["start"]["tcp_mss_default"]=1200
base["intervals"]=[{"sum":{"start":i, "end":i+1,"bits_per_second":v}}
                   for i,v in enumerate([999e6,100e6,0,100e6,0])]
base["end"]["streams"][0]["sender"]["min_rtt"]=90000
out=pathlib.Path(sys.argv[2]); (out/"valid.json").write_text(json.dumps(base))
for name,mutate in (
    ("forward", lambda d:d["start"]["test_start"].update(reverse=0)),
    ("nan", lambda d:d["end"]["sum_sent"].update(bits_per_second=float("nan"))),
    ("receiver-nan", lambda d:d["end"]["sum_received"].update(bits_per_second=float("nan"))),
    ("receiver-negative", lambda d:d["end"]["sum_received"].update(bits_per_second=-1)),
    ("receiver-stall", lambda d:d["end"]["sum_received"].update(bits_per_second=0, seconds=10)),
    ("rtt-nan", lambda d:d["end"]["streams"][0]["sender"].update(mean_rtt=float("nan"))),
    ("no-retrans", lambda d:d["end"]["sum_sent"].pop("retransmits")),
    ("negative", lambda d:d["end"]["sum_sent"].update(retransmits=-1)),
):
    data=json.loads(json.dumps(base)); mutate(data)
    (out/(name+".json")).write_text(json.dumps(data))
PY
parse_iperf_json "$TMP/valid.json" 1 10
assert_eq "$RESULT_MBPS" 793.60 "receiver throughput"
assert_eq "$RESULT_CV_PERCENT" 100.0000 "CV includes stalls and excludes warm-up"
assert_eq "$RESULT_MIN_RTT_MS" 90.00 "minimum RTT"
assert_eq "$RESULT_RETRANS_PERCENT" 0.9600 "actual MSS retrans estimate"
assert_eq "$RESULT_RETRANS_SOURCE" estimated-mss "MSS provenance"
for file in forward nan receiver-nan receiver-negative receiver-stall rtt-nan no-retrans negative; do
  if parse_iperf_json "$TMP/$file.json" >/dev/null 2>&1; then fail "invalid JSON accepted: $file"; fi
done
if parse_iperf_json "$TMP/valid.json" 8 10 >/dev/null 2>&1; then fail "wrong stream count accepted"; fi
if parse_iperf_json "$TMP/valid.json" 1 30 >/dev/null 2>&1; then fail "short test accepted"; fi

# Stable mode must never infer perfect stability from missing telemetry.
for metrics in 'NA 100' '0 0'; do
  if (STRATEGY=stable; read -r RESULT_CV_PERCENT RESULT_RTT_MS <<<"$metrics"; validate_strategy_metrics) >/dev/null 2>&1; then
    fail "stable mode accepted missing CV/RTT: $metrics"
  fi
done
(STRATEGY=stable; RESULT_CV_PERCENT=0; RESULT_RTT_MS=100; validate_strategy_metrics) || fail "valid stability data rejected"

# A known mq root does not make custom child shaping safe to replace.
(
  tc() { printf 'qdisc mq 0: root\nqdisc cake 0: parent :1 bandwidth 200Mbit\n'; }
  if qdisc_layout_safe eth0; then fail "mq/CAKE child accepted without force"; fi
  tc() { printf 'qdisc mq 0: root\nqdisc fq_codel 0: parent :1\nqdisc fq 0: parent :2\n'; }
  qdisc_layout_safe eth0 || fail "standard mq child layout rejected"
)

# Aggregation uses medians, with cross-test CV rather than last-run bias.
(
  STRATEGY=balanced; TEST_REPEATS=3; SESSION_DIR="$TMP"; TUNING_ACTIVE=0; counter=0
  run_reverse_test() {
    counter=$((counter+1))
    case "$counter" in 1) RESULT_MBPS=100 ;; 2) RESULT_MBPS=300 ;; 3) RESULT_MBPS=110 ;; esac
    RESULT_RETRANS_PERCENT=0.1; RESULT_RTT_MS=100; RESULT_MIN_RTT_MS=90
    RESULT_CV_PERCENT=5; RESULT_BYTES=1000000; RESULT_RETRANS=1
  }
  run_repeated_test repeat 1 192.0.2.1 test
  assert_eq "$RESULT_MBPS" 110.00 "median throughput"
  awk -v cv="$RESULT_CV_PERCENT" 'BEGIN {exit !(cv>50)}' || fail "cross-test variation omitted"
  assert_eq "$(wc -l <"$TMP/repeat.measurements.tsv" | xargs)" 3 "replicate audit"
)

# Original TCP minimum/default values must remain coherent and unchanged.
(
  sysctl_get() { case "$1" in
    net.ipv4.tcp_rmem) echo '16384 262144 6291456' ;;
    net.ipv4.tcp_wmem) echo '8192 131072 4194304' ;;
  esac; }
  prepare_tcp_rules
  build_sysctl_content 4194304 >"$TMP/tcp.conf"
  grep -Fqx 'net.ipv4.tcp_rmem = 16384 262144 4194304' "$TMP/tcp.conf" || fail "rmem defaults changed"
  grep -Fqx 'net.ipv4.tcp_wmem = 8192 131072 4194304' "$TMP/tcp.conf" || fail "wmem defaults changed"
  if build_sysctl_content 65536 >/dev/null; then fail "maximum below defaults accepted"; fi
)

# Memory limit can bind before BDP; it must still yield a feasible test.
TCP_RDEFAULT=131072; TCP_WDEFAULT=16384; MEM_BUFFER_CAP_MIB=4
BDP_BYTES=500000000; generate_candidates
assert_eq "${CANDIDATE_MIBS[*]}" 4 "memory-constrained candidate"

# Failed qdisc replacement / incorrect sysctl readback must not be scored as applied.
(
  sysctl_get() { case "$1" in net.ipv4.tcp_congestion_control) echo bbr ;; *) echo 99999999 ;; esac; }
  if (validate_candidate_kernel_state 4194304) >/dev/null 2>&1; then fail "incorrect readback accepted"; fi
)
(
  apply_sysctl_content() { :; }; apply_qdisc() { return 1; }
  if (apply_candidate eth0 4) >/dev/null 2>&1; then fail "qdisc failure ignored"; fi
)

printf 'All strategy, evidence and measurement tests passed.\n'
