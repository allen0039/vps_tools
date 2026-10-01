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
NETWORK_UPLOAD_CALLS="$tmp/upload-requests"
NETWORK_UPLOAD_DATA="$tmp/upload-data"
NETWORK_TEST_RC=0
NETWORK_TEST_CSV=1
NETWORK_UPLOAD_STATUS=200
export NETWORK_TEST_CALLS NETWORK_UPLOAD_CALLS NETWORK_UPLOAD_DATA NETWORK_TEST_RC NETWORK_TEST_CSV NETWORK_UPLOAD_STATUS TMPDIR
mkdir -p "$STATE_DIR/network-tests"
printf 'legacy log\n' >"$STATE_DIR/network-tests/previous.log"
printf 'preserve this file\n' >"$STATE_DIR/network-tests/notes.txt"
require_linux() { :; }
require_root() { :; }
curl() {
  local output="" upload="" previous="" arg
  for arg in "$@"; do
    if [[ "$previous" == -o ]]; then output="$arg"; fi
    if [[ "$previous" == --data-binary ]]; then upload="$arg"; fi
    previous="$arg"
  done
  [[ -n "$output" ]] || fail 'missing download destination'
  if [[ -n "$upload" ]]; then
    printf '%s\n' "$upload" >>"$NETWORK_UPLOAD_CALLS"
    cat "${upload#@}" >>"$NETWORK_UPLOAD_DATA"
    printf '{"url":"https://tcpquality.ibsgss.uk/r/mock"}\n' >"$output"
    printf '%s' "$NETWORK_UPLOAD_STATUS"
    return 0
  fi
  cat >"$output" <<'UPSTREAM'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$NETWORK_TEST_CALLS"
printf '\033[2m特价VPS补货TG频道： ibsgss | 感谢 Zstatic CDN 节点\033[0m\n'
printf 'mock TcpQuality result\n'
if [[ "$NETWORK_TEST_CSV" == 1 ]]; then
  printf 'mock CSV for %s\n' "$*" >"$TCPQUALITY_OUTPUT_DIR/zstatic_nping_mock.csv"
fi
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
[[ ! -e "$STATE_DIR/network-tests/previous.log" ]] || fail 'legacy log was retained'
[[ -f "$STATE_DIR/network-tests/notes.txt" ]] || fail 'unrelated file was deleted'
if find "$STATE_DIR/network-tests" -name '*.log' | grep -q .; then
  fail 'persistent network test log was created'
fi
if grep -q '特价VPS补货TG频道' "$tmp/both.out"; then
  fail 'upstream advertisement leaked into output'
fi
grep -q 'mock TcpQuality result' "$tmp/both.out" || fail 'measurement output was hidden'
if grep -q 'network-tests/' "$tmp/both.out"; then fail 'obsolete log path was shown'; fi
NETWORK_TEST_RC=37
export NETWORK_TEST_RC
printf 'legacy failure log\n' >"$STATE_DIR/network-tests/previous-failure.log"
if NETWORK_TEST_MODE=speed network_test_command >"$tmp/failure.out" 2>&1; then
  fail 'upstream failure was ignored'
fi
grep -q '退出码 37' "$tmp/failure.out" || fail 'failure status hidden'
[[ ! -e "$STATE_DIR/network-tests/previous-failure.log" ]] || fail 'legacy log survived failed test exit'
if find "$tmp" -maxdepth 1 -name 'bbr-tcpquality.*' | grep -q .; then
  fail 'temporary entry survived test exit'
fi
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

network_test_can_ask_upload() { return 0; }
NETWORK_TEST_RC=0
export NETWORK_TEST_RC
printf '\n' | NETWORK_TEST_MODE=both network_test_command >"$tmp/default-no.out" 2>&1 || fail 'default-no test failed'
[[ ! -e "$NETWORK_UPLOAD_CALLS" ]] || fail 'default answer uploaded a report'
grep -q '已跳过报告上传' "$tmp/default-no.out" || fail 'default-no outcome hidden'
printf 'n\n' | NETWORK_TEST_MODE=route network_test_command >"$tmp/explicit-no.out" 2>&1 || fail 'explicit-no test failed'
[[ ! -e "$NETWORK_UPLOAD_CALLS" ]] || fail 'negative answer uploaded a report'
printf 'y\n' | NETWORK_TEST_MODE=speed network_test_command >"$tmp/upload.out" 2>&1 || fail 'confirmed upload test failed'
[[ "$(wc -l <"$NETWORK_UPLOAD_CALLS" | tr -d ' ')" == 1 ]] || fail 'confirmed upload did not post exactly once'
grep -q 'mock CSV for --only-speedtest --no-rank-upload' "$NETWORK_UPLOAD_DATA" || fail 'upload used the wrong test result'
grep -q 'https://tcpquality.ibsgss.uk/r/mock' "$tmp/upload.out" || fail 'report link not shown'
if find "$tmp" -maxdepth 1 -name 'bbr-tcpquality.*' | grep -q .; then fail 'upload left temporary files'; fi

NETWORK_TEST_CSV=0
export NETWORK_TEST_CSV
printf 'stale CSV\n' >"$tmp/zstatic_nping_stale.csv"
printf 'y\n' | NETWORK_TEST_MODE=route network_test_command >"$tmp/no-csv.out" 2>&1 || fail 'missing CSV should preserve completed test status'
grep -q '未找到唯一且有效的本次测速 CSV' "$tmp/no-csv.out" || fail 'missing CSV was not explained'
[[ "$(wc -l <"$NETWORK_UPLOAD_CALLS" | tr -d ' ')" == 1 ]] || fail 'stale CSV was uploaded'

NETWORK_TEST_CSV=1
NETWORK_UPLOAD_STATUS=503
export NETWORK_TEST_CSV NETWORK_UPLOAD_STATUS
printf 'y\n' | NETWORK_TEST_MODE=both network_test_command >"$tmp/upload-failure.out" 2>&1 || fail 'upload failure changed completed test status'
grep -q '报告上传失败' "$tmp/upload-failure.out" || fail 'upload failure was hidden'
if find "$tmp" -maxdepth 1 -name 'bbr-tcpquality.*' | grep -q .; then fail 'upload failure left temporary files'; fi

printf 'All three-network detection and manual-start tests passed.\n'
