#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

STATE_DIR="$tmp/state"
PENDING_LATEST="$tmp/no-pending"
TMPDIR="$tmp"
NETWORK_TEST_CALLS="$tmp/upstream-args"
NETWORK_TEST_RC=0
export NETWORK_TEST_CALLS NETWORK_TEST_RC TMPDIR
require_linux() { :; }
require_root() { :; }
curl() {
  local output="" previous="" arg
  for arg in "$@"; do
    if [[ "$previous" == -o ]]; then output="$arg"; break; fi
    previous="$arg"
  done
  [[ -n "$output" ]] || fail 'missing download destination'
  cat >"$output" <<'UPSTREAM'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$NETWORK_TEST_CALLS"
printf 'mock TcpQuality result\n'
exit "$NETWORK_TEST_RC"
UPSTREAM
}

for mode in both route speed; do
  NETWORK_TEST_MODE="$mode" network_test_command >"$tmp/${mode}.out" 2>&1 || fail "$mode failed"
done
[[ -f "$NETWORK_TEST_CALLS" ]] || { cat "$tmp/both.out" >&2; fail 'upstream was not called'; }
[[ "$(sed -n '1p' "$NETWORK_TEST_CALLS")" == '-v4 -v6 --speedtest --no-rank-upload' ]] || fail 'combined mode arguments'
[[ "$(sed -n '2p' "$NETWORK_TEST_CALLS")" == '-v4 -v6 --no-rank-upload' ]] || fail 'route mode arguments'
[[ "$(sed -n '3p' "$NETWORK_TEST_CALLS")" == '--only-speedtest --no-rank-upload' ]] || fail 'speed mode arguments'
[[ "$(find "$STATE_DIR/network-tests" -name '*.log' | wc -l | tr -d ' ')" == 3 ]] || fail 'missing test logs'
NETWORK_TEST_RC=37
export NETWORK_TEST_RC
if NETWORK_TEST_MODE=speed network_test_command >"$tmp/failure.out" 2>&1; then
  fail 'upstream failure was ignored'
fi
grep -q '退出码 37' "$tmp/failure.out" || fail 'failure status hidden'
if NETWORK_TEST_MODE=unknown network_test_command >"$tmp/invalid.out" 2>&1; then
  fail 'invalid test mode accepted'
fi
[[ "$(wc -l <"$NETWORK_TEST_CALLS" | tr -d ' ')" == 4 ]] || fail 'unexpected upstream invocation'

# Tuning ends without starting or offering a three-network test.
guess_server_address() { echo 203.0.113.10; }
ui_select_strategy() { echo balanced; }
ui_select_qdisc() { echo auto; }
ui_read_number() { printf '%s\n' "$2"; }
ui_read_text() { printf '%s\n' "${2:-203.0.113.10}"; }
ui_yes_no() {
  case "$1" in
    '最优参数通过复测后写入开机配置') return 1 ;;
    '现在运行三网回程和单线程速度检测') fail 'unexpected post-tune question' ;;
    *) return 0 ;;
  esac
}
UI_ACTIONS="$tmp/ui-actions"
ui_execute() {
  printf '%s\n' "$*" >>"$UI_ACTIONS"
  [[ "${FAIL_TUNE:-0}" != 1 || "$2" != autotune ]]
}
ui_autotune >"$tmp/ui-success.out" || fail 'interactive tune failed'
[[ "$(sed -n '1p' "$UI_ACTIONS")" == *'autotune --strategy balanced'* ]] || fail 'tune not started'
[[ "$(wc -l <"$UI_ACTIONS" | tr -d ' ')" == 1 ]] || fail 'network test started after tuning'
: >"$UI_ACTIONS"
FAIL_TUNE=1
if ui_autotune >"$tmp/ui-failure.out"; then fail 'failed tune reported success'; fi
[[ "$(wc -l <"$UI_ACTIONS" | tr -d ' ')" == 1 ]] || fail 'network test started after failed tuning'
FAIL_TUNE=0
: >"$UI_ACTIONS"
printf '1\n' | ui_network_test >"$tmp/manual.out" || fail 'manual network test failed'
[[ "$(cat "$UI_ACTIONS")" == '1 network-test --mode both' ]] || fail 'manual menu did not start detection'

printf 'All three-network detection and manual-start tests passed.\n'
