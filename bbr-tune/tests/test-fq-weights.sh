#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export QDISC_TEST_DIR="$tmp"
mkdir -p "$tmp/bin"
cp "$ROOT/tests/fixtures/qdisc-command-mock.py" "$tmp/bin/tc"
cp "$tmp/bin/tc" "$tmp/bin/ip"
chmod +x "$tmp/bin/"{tc,ip}
export PATH="$tmp/bin:$PATH"
printf '{"fq":{"weights":[589824,196608,65536]}}\n' >"$tmp/defaults.json"
printf '[{"kind":"fq","root":true,"handle":"1:","options":{"weights":[589824,196608,65536]}}]\n' >"$tmp/saved.json"
no_leaks() { [[ -z "$(find "$tmp" -name 'bbrq-*.json' -print)" ]]; }
[[ "$(qdisc_fq_weights_syntax)" == normal ]]; no_leaks
touch "$tmp/broken-weights"
[[ "$(qdisc_fq_weights_syntax)" == skip-first ]]; no_leaks
qdisc_json restore-plan "$tmp/saved.json" >"$tmp/plan"
grep -q 'weights 0 589824 196608 65536' "$tmp/plan"
unset QDISC_FQ_WEIGHTS_SYNTAX
# Recovery runs within an EXIT trap; older Bash must still clean nested probes.
(trap 'qdisc_fq_weights_syntax >"$tmp/exit-result"' EXIT)
[[ "$(cat "$tmp/exit-result")" == skip-first ]]; no_leaks
touch "$tmp/unsupported-weights"
if qdisc_fq_weights_syntax >"$tmp/unsupported.log" 2>&1; then exit 1; fi
no_leaks
touch "$tmp/fail-namespace"
# Saving/validating a queue that needs no change must not create a namespace.
qdisc_json plan "$tmp/saved.json" >"$tmp/plain-plan"
grep -q 'weights 589824 196608 65536' "$tmp/plain-plan"
printf 'All fq weights syntax, no-op and EXIT cleanup tests passed.\n'
