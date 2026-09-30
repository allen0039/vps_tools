#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
ui_init
[[ -z "$UI_BLUE$UI_GREEN$UI_RED$UI_RESET" ]] || fail 'color leaked to redirected output'
{
  ui_title; ui_menu_options
  section '单连接与多连接对比'
} >"$tmp/screen.txt"
python3 - "$tmp/screen.txt" <<'PY'
import re,sys,unicodedata
s=open(sys.argv[1]).read()
assert '\x1b' not in s
assert '调优与记录' in s and '参数管理' in s
options=[int(x) for x in re.findall(r'(?m)^\s+(\d+) {2}',s)]
assert options==[1,2,3,4,5,6,7,8,9,10,0],options
for line in s.splitlines():
    width=sum(2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in line)
    assert width<=72,(width,line)
PY
# Do not bypass confirmation for destructive menu actions.
if grep -q 'ui_execute 1 rollback --yes' "$ROOT/bbr-tune.sh"; then fail 'menu rollback bypasses confirmation'; fi
value="$(printf '1.5\n08\n' | ui_read_number count 8 2 64 integer 2>"$tmp/input.err")"
[[ "$value" == 08 ]] || fail 'integer input validation'
grep -q '整数' "$tmp/input.err" || fail 'integer retry feedback'
HISTORY_FILE="$tmp/history.tsv"
printf 'time\tsession\ttarget\trtt\tstreams\tbefore_single_mbps\tafter_single_mbps\tsingle_delta\tbefore_multi\tafter_multi\tdelta\tr1\tr2\tr3\tr4\ts1\ts2\tbuffer\toutcome\treport\tstrategy\n' >"$HISTORY_FILE"
printf '2026-09-29\ttest-session\t500\t20\t8\t100\t120\t20\t300\t360\t20\t0\t0\t0\t0\t1\t2\t32\tbest-effort-runtime\t/tmp/report\tspeed\n' >>"$HISTORY_FILE"
history_command >"$tmp/history.txt"
grep -q '单连接：100 → 120 Mbps' "$tmp/history.txt" || fail 'history single comparison'
grep -q '多连接：300 → 360 Mbps' "$tmp/history.txt" || fail 'history multi comparison'
grep -q '速度优先' "$tmp/history.txt" || fail 'history strategy name'
if grep -q '^|' "$tmp/history.txt"; then fail 'unrendered markdown table in terminal'; fi
# Keep development wording out of all shipped files, including generated output.
python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1]); needle='pro'+'mpt'
for p in [root/'README.md',*root.glob('*.sh'),*root.glob('tests/test-*.sh')]:
    assert needle not in p.read_text().lower(),p
readme=(root/'README.md').read_text()
for text in ('PY_STATE','k_install','test-kernel.sh','评分权重','git commit'):
    assert text not in readme,text
PY
printf 'All terminal UI, history, input and wording tests passed.\n'
