#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/bbr-tune.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "$3: expected '$2', got '$1'"; }
assert_true() { "$@" || fail "assertion failed: $*"; }

# The aggregate TCP memory high-water mark uses two thirds of effective total
# memory. MemAvailable does not participate in this calculation.
calculate_memory_buffer_cap 1024
assert_eq "$MEM_TCP_BUDGET_MIB" "682" "1 GiB aggregate TCP budget"
assert_eq "$MEM_BUFFER_CAP_MIB" "682" "1 GiB per-socket search cap"
low_1g="$TCP_MEM_LOW_PAGES"; pressure_1g="$TCP_MEM_PRESSURE_PAGES"; high_1g="$TCP_MEM_HIGH_PAGES"
(( low_1g < pressure_1g && pressure_1g < high_1g )) || fail "tcp_mem thresholds must be strictly increasing"
expected_high=$(( 1024 * 1048576 / PAGE_SIZE_BYTES * 2 / 3 ))
assert_eq "$high_1g" "$expected_high" "1 GiB tcp_mem high-water mark"

calculate_memory_buffer_cap 8192
assert_eq "$MEM_TCP_BUDGET_MIB" "5461" "8 GiB aggregate TCP budget"
assert_eq "$MEM_BUFFER_CAP_MIB" "2047" "8 GiB signed-sysctl per-socket ceiling"

calculate_memory_buffer_cap 65536
assert_eq "$MEM_TCP_BUDGET_MIB" "43690" "64 GiB aggregate TCP budget"
assert_eq "$MEM_BUFFER_CAP_MIB" "2047" "large-memory per-socket ceiling"

calculate_memory_buffer_cap 256
assert_eq "$MEM_TCP_BUDGET_MIB" "170" "256 MiB aggregate TCP budget"
assert_eq "$MEM_BUFFER_CAP_MIB" "170" "256 MiB per-socket search cap"

TARGET_MBPS="1000"
RTT_MS="180"
MEM_BUFFER_CAP_MIB="128"
calculate_bdp
assert_eq "$BDP_BYTES" "22500000" "BDP bytes"
assert_eq "$BDP_MIB" "21.46" "BDP MiB"
generate_candidates
assert_eq "${CANDIDATE_MIBS[*]}" "32 64 128" "unbounded growth candidates to memory cap"
assert_eq "${CANDIDATE_FACTORS[*]}" "1.49 2.98 5.97" "actual candidate BDP ratios"

# A non-power-of-two technical limit must still be tested as the final
# candidate instead of stopping at the previous power of two.
MEM_BUFFER_CAP_MIB="682"
generate_candidates
assert_eq "${CANDIDATE_MIBS[*]}" "32 64 128 172" "8 BDP experimental boundary"

TARGET_MBPS="200"
RTT_MS="30"
MEM_BUFFER_CAP_MIB="170"
calculate_bdp
assert_eq "$BDP_BYTES" "750000" "short-link BDP"
generate_candidates
assert_eq "${CANDIDATE_MIBS[*]}" "4 6" "short link stops at 8 BDP rather than all memory"


# Only TCP data-path knobs are mutable. Existing minima/defaults remain intact.
TUNING_QDISC="fq"
MEM_EFFECTIVE_MIB="8192"; MEM_TCP_BUDGET_MIB="5461"; MEM_BUFFER_CAP_MIB="2047"
TCP_MEM_LOW_PAGES="699050"; TCP_MEM_PRESSURE_PAGES="1048576"; TCP_MEM_HIGH_PAGES="1398101"
TARGET_MBPS="1000"; RTT_MS="180"; BDP_MIB="21.46"
TCP_RMIN=4096; TCP_RDEFAULT=131072; TCP_WMIN=8192; TCP_WDEFAULT=65536
profile="$(build_sysctl_content 67108864)"
for expected in \
  'net.core.default_qdisc = fq' \
  'net.core.rmem_max = 67108864' \
  'net.ipv4.tcp_rmem = 4096 131072 67108864' \
  'net.ipv4.tcp_wmem = 8192 65536 67108864' \
  'net.ipv4.tcp_congestion_control = bbr'; do
  grep -Fq "$expected" <<<"$profile" || fail "generated profile missing: $expected"
done
if qdisc_safe cake; then fail "existing CAKE parameters cannot be assumed restorable"; fi
for key in "${TUNING_SYSCTL_KEYS[@]}"; do
  grep -Fq "$key = " <<<"$profile" || fail "managed key missing from generated profile: $key"
done
for disallowed in kernel. vm. tcp_fastopen tcp_fack tcp_adv_win_scale tcp_notsent_lowat tcp_fin_timeout rp_filter arp_ignore ip_local_port_range; do
  if grep -v '^#' <<<"$profile" | grep -Fq "$disallowed"; then fail "unjustified change: $disallowed"; fi
done

# Unsupported kernel knobs are commented instead of aborting the profile.
(
  input="$(mktemp)"; output="$(mktemp)"
  printf 'net.core.rmem_max = 1048576\nnet.test.unsupported = 1\n' >"$input"
  sysctl_exists() { [[ "$1" == "net.core.rmem_max" ]]; }
  UNSUPPORTED_SYSCTL_KEYS_SEEN="|"
  filter_supported_sysctl_file "$input" "$output"
  grep -Fqx 'net.core.rmem_max = 1048576' "$output" || fail "supported sysctl filtering"
  grep -Fqx '# unsupported: net.test.unsupported = 1' "$output" || fail "unsupported sysctl filtering"
)

printf 'All memory-plan tests passed.\n'
