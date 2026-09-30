#!/usr/bin/env bash
# Regression tests use synthetic JSON and a fake iperf3; no sockets or sysctl writes.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/bbr-tune.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "$3: expected '$2', got '$1'"; }

python3 - "$ROOT" "$TMP" <<'PY_FIXTURES'
import json, pathlib, sys
root, out=map(pathlib.Path, sys.argv[1:])
base=json.loads((root/'tests/fixtures/iperf3-reverse-server-placeholder.json').read_text())
def variant(name, change):
    data=json.loads(json.dumps(base)); change(data)
    (out/(name+'.json')).write_text(json.dumps(data))
variant('placeholder', lambda d: None)
variant('legacy', lambda d: [d['end'][key].pop('sender') for key in ('sum_sent','sum_received')])
variant('missing-receiver', lambda d: d['end'].pop('sum_received'))
variant('real-receiver', lambda d: d['end']['sum_received'].update(bytes=1488000000, bits_per_second=793600000, sender=False))
variant('receiving-role', lambda d: d['end']['sum_received'].update(sender=False))
variant('sending-role-false', lambda d: d['end']['sum_sent'].update(sender=False))
variant('zero-with-bytes', lambda d: d['end']['sum_received'].update(bytes=100))
variant('negative-rate', lambda d: d['end']['sum_received'].update(bits_per_second=-1))
variant('infinite-rate', lambda d: d['end']['sum_received'].update(bits_per_second=float('inf')))
variant('nan-sender', lambda d: d['end']['sum_sent'].update(bits_per_second=float('nan')))
variant('missing-retrans', lambda d: d['end']['sum_sent'].pop('retransmits'))
variant('negative-rtt', lambda d: d['end']['streams'][0]['sender'].update(mean_rtt=-1))
variant('negative-interval', lambda d: d['intervals'][2]['sum'].update(bits_per_second=-1))
variant('short-duration', lambda d: d['end']['sum_sent'].update(seconds=2))
PY_FIXTURES

for name in placeholder legacy; do
  parse_iperf_json "$TMP/$name.json" 1 15 || fail "$name rejected"
  assert_eq "$RESULT_MBPS" 800.00 "$name sender rate"
  assert_eq "$RESULT_RATE_SOURCE" sender-unreported-receiver "$name source"
  assert_eq "$RESULT_RETRANS" 1000 "$name retransmits preserved"
  assert_eq "$RESULT_RTT_MS" 180.00 "$name RTT preserved"
  assert_eq "$RESULT_CV_PERCENT" 0.0000 "$name interval telemetry preserved"
done
parse_iperf_json "$TMP/real-receiver.json" 1 15
assert_eq "$RESULT_MBPS" 793.60 'real receiver rate preferred'
assert_eq "$RESULT_RATE_SOURCE" receiver 'real receiver source'
parse_iperf_json "$TMP/missing-receiver.json" 1 15
assert_eq "$RESULT_MBPS" 800.00 'absent receiver fallback'
assert_eq "$RESULT_RATE_SOURCE" sender 'absent receiver source'

for name in receiving-role sending-role-false zero-with-bytes negative-rate infinite-rate nan-sender missing-retrans negative-rtt negative-interval short-duration; do
  if parse_iperf_json "$TMP/$name.json" 1 15 >"$TMP/$name.out" 2>"$TMP/$name.validation"; then fail "invalid metrics accepted: $name"; fi
  grep -q '\[PARSE\]' "$TMP/$name.validation" || fail "missing diagnostic: $name"
done
grep -Fq 'end.sum_received.bits_per_second=-1' "$TMP/negative-rate.validation" || fail 'invalid field/value missing'
grep -Fq 'end.sum_sent.retransmits=None' "$TMP/missing-retrans.validation" || fail 'missing retrans diagnostic'
grep -Fq 'end.sum_sent.seconds=2' "$TMP/short-duration.validation" || fail 'duration diagnostic'
if parse_iperf_json "$TMP/placeholder.json" 8 15 >/dev/null 2>"$TMP/streams.validation"; then fail 'wrong streams accepted'; fi
grep -Fq 'end.streams' "$TMP/streams.validation" || fail 'stream diagnostic'

# Bound the supervisor tests so a regression cannot restart fake sessions forever.
python3 - "$ROOT" "$TMP" "$BASH" <<'PY_SUPERVISOR'
import os, pathlib, signal, subprocess, sys
root, tmp=map(pathlib.Path, sys.argv[1:3]); bash=sys.argv[3]
bin_dir=tmp/'bin'; bin_dir.mkdir()
fake=bin_dir/'iperf3'
fake.write_text('''#!/usr/bin/env bash
set -eu
count=$(cat "$ATTEMPTS"); count=$((count+1)); printf '%s\\n' "$count" >"$ATTEMPTS"
printf '%s\\n' "$*" >>"$ARGUMENTS"
if [[ "$count" == 1 && "$FIRST" == cookie ]]; then
  printf '{"start":{},"end":{},"error":"unable to receive cookie"}\\n'; exit 1
elif [[ "$count" == 1 && "$FIRST" == truncated ]]; then
  printf '{"start":'; exit 1
fi
cat "$FIXTURE"
exit "$IPERF_EXIT"
'''); fake.chmod(0o755)
cases=[
    ('placeholder','placeholder',1,15,'none',0,0,1),
    ('cookie-recovery','placeholder',1,15,'cookie',0,0,2),
    ('truncated-recovery','placeholder',1,15,'truncated',0,0,2),
    ('bad-rate','negative-rate',1,15,'none',0,65,1),
    ('wrong-streams','placeholder',8,15,'none',0,65,1),
    ('too-short','short-duration',1,15,'none',0,65,1),
    ('nonzero-exit','placeholder',1,15,'none',1,65,1),
]
for name, fixture, streams, duration, first, exit_code, expected_rc, expected_attempts in cases:
    directory=tmp/name; directory.mkdir()
    attempts=directory/'attempts'; attempts.write_text('0\n')
    args=directory/'args'; final=directory/'result.json'; errors=directory/'result.err'
    env=dict(os.environ, PATH=str(bin_dir)+os.pathsep+os.environ['PATH'],
             ATTEMPTS=str(attempts), ARGUMENTS=str(args), FIRST=first,
             FIXTURE=str(tmp/(fixture+'.json')), IPERF_EXIT=str(exit_code))
    proc=subprocess.Popen([bash,'-c','source "$1"; iperf_server_loop "$2" "$3" 34567 -4 "$4" "$5"',
                           'result-test',str(root/'bbr-tune.sh'),str(final),str(errors),str(streams),str(duration)],
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr=proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid,signal.SIGKILL); proc.communicate()
        raise AssertionError(f'{name}: supervisor did not terminate')
    assert proc.returncode==expected_rc, (name,proc.returncode,stdout,stderr)
    assert int(attempts.read_text())==expected_attempts, (name,attempts.read_text())
    assert all(line=='-4 -s -1 -J -p 34567' for line in args.read_text().splitlines()), name
    if expected_rc==0:
        assert final.exists(), name
        assert final.read_text()==(tmp/(fixture+'.json')).read_text(), name
    else:
        assert not final.exists(), name
        assert 'ignored_connection=' not in errors.read_text(), name
    if expected_attempts>1 or expected_rc!=0:
        raw=directory/'result.attempt-001.json'
        diagnostic=directory/'result.attempt-001.validation.log'
        assert raw.exists() and diagnostic.stat().st_size>0, name
        assert str(raw) in errors.read_text(), name
    if expected_attempts>1:
        assert 'ignored_connection=1' in errors.read_text(), name
    if name=='bad-rate': assert 'end.sum_received.bits_per_second=-1' in diagnostic.read_text()
    if name=='nonzero-exit': assert '[PROCESS]' in diagnostic.read_text()
    print('PASS: iperf supervisor '+name)
PY_SUPERVISOR
printf 'PASS: reverse-server JSON validation and attempt diagnostics\n'
