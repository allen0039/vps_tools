#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export Q_TEST_DIR="$TMP"
mkdir -p "$TMP/bin" "$TMP/backup"
# Stateful tc double: never invokes host networking or privileges. Also used by
# the standalone boot helper, not just by sourced shell functions.
cat >"$TMP/bin/tc" <<'PY'
#!/usr/bin/env python3
import os
import pathlib
import sys
base = pathlib.Path(os.environ['Q_TEST_DIR'])
args = sys.argv[1:]
layout = base / 'layout'
if 'show' in args:
    if (base / 'show-fails').exists():
        sys.exit(1)
    print(layout.read_text(), end='')
    sys.exit(0)
with (base / 'calls').open('a') as f:
    f.write(' '.join(args) + '\n')
if (base / 'write-fails').exists():
    sys.exit(1)
fail_parent = base / 'fail-parent'
if fail_parent.exists() and 'parent' in args and args[args.index('parent')+1] == fail_parent.read_text().strip():
    sys.exit(1)
if (base / 'false-success').exists():
    sys.exit(0)
assert args[:3] == ['qdisc', 'replace', 'dev'], args
lines = layout.read_text().splitlines()
kind = args[-1]
if 'parent' in args:
    parent = args[args.index('parent')+1]
    changed = False
    for i, line in enumerate(lines):
        parts = line.split()
        if parts and parts[0] == 'qdisc' and 'parent' in parts:
            if parts[parts.index('parent')+1] == parent:
                parts[1] = kind
                parts[2] = '8001:'  # tc may allocate a new leaf handle
                lines[i] = ' '.join(parts)
                changed = True
    assert changed, args
else:
    assert 'root' in args, args
    handle = args[args.index('handle')+1] if 'handle' in args else '8002:'
    lines = [f'qdisc {kind} {handle} root']
layout.write_text('\n'.join(lines) + '\n')
PY
chmod +x "$TMP/bin/tc"
export PATH="$TMP/bin:$PATH"
reset_mock() { rm -f "$TMP/"{calls,show-fails,write-fails,false-success,sysctl-called,fail-parent}; }
no_writes() { [[ ! -s "$TMP/calls" ]] || fail "unexpected tc mutation: $(cat "$TMP/calls")"; }

# Real reported anonymous mq + fq layout must be preserved byte-for-byte, even
# on kernels where every replacement of an anonymous mq leaf would fail.
cp "$ROOT/tests/fixtures/qdisc-mq-fq.txt" "$TMP/layout"
cp "$TMP/layout" "$TMP/backup/qdisc.txt"
touch "$TMP/write-fails"
qdisc_layout_safe eth0 || fail 'standard anonymous mq rejected'
qdisc_preflight eth0 fq || fail 'existing fq is not usable'
apply_qdisc eth0 fq || fail 'existing fq tried to replace anonymous leaves'
restore_qdisc "$TMP/backup" eth0 mq || fail 'unchanged anonymous mq restore failed'
no_writes
cmp "$TMP/layout" "$TMP/backup/qdisc.txt" || fail 'fq options or mq root changed'
(
  apply_sysctl_content() { touch "$TMP/sysctl-called"; }
  validate_candidate_kernel_state() { [[ "$1" == 8388608 ]] || fail 'incorrect buffer candidate'; }
  apply_candidate eth0 8 || fail 'already-fq candidate rejected'
)
[[ -f "$TMP/sysctl-called" ]] || fail 'valid fq candidate never applied TCP parameters'
no_writes

# The emitted persistent helper must use the same safe behavior. Only its
# configuration path is redirected to a temporary fixture.
render_qdisc_helper | sed "s|source /etc/default/bbr-tcp-tuning|source $TMP/env|" >"$TMP/helper"
printf 'BBR_IFACE=eth0\nBBR_QDISC=fq\n' >"$TMP/env"
bash -n "$TMP/helper"
bash "$TMP/helper" || fail 'boot helper replaced already-fq leaves'
no_writes

# Counter variations, record order and :1 vs 0:1 are not topology changes.
sed -e 's/parent :/parent 0:/g' -e 's/643/644/g' "$TMP/layout" >"$TMP/reordered"
mv "$TMP/reordered" "$TMP/layout"
restore_qdisc "$TMP/backup" eth0 mq || fail 'normalized parents not accepted'
no_writes

# Flat fq and independent ingress/clsact queues require no egress mutation.
printf 'qdisc fq 8001: root limit 9000p\nqdisc clsact ffff: parent ffff:fff1\n' >"$TMP/layout"
apply_qdisc eth0 fq || fail 'fq root no-op failed'
no_writes

# Addressable mq: only a non-fq leaf is changed, root and fq sibling retained.
reset_mock
printf 'qdisc mq 1: root\nqdisc fq 100: parent 1:1 quantum 3028b\nqdisc fq_codel 0: parent 1:2\n' >"$TMP/layout"
cp "$TMP/layout" "$TMP/backup/qdisc.txt"
apply_qdisc eth0 fq || fail 'numbered mq apply failed'
[[ "$(cat "$TMP/calls")" == 'qdisc replace dev eth0 parent 1:2 fq' ]] || fail 'unnecessary mq mutation'
restore_qdisc "$TMP/backup" eth0 mq || fail 'numbered mq restore failed'
grep -Fqx 'qdisc replace dev eth0 parent 1:2 fq_codel' "$TMP/calls" || fail 'changed leaf not restored'
[[ "$(wc -l <"$TMP/calls" | xargs)" == 2 ]] || fail 'unexpected restore writes'
if grep -Eq 'root|qdisc del' "$TMP/calls"; then fail 'mq root touched'; fi
# Verify that boot-time application also only changes the non-fq sibling.
: >"$TMP/calls"
bash "$TMP/helper" || fail 'numbered mq boot helper failed'
[[ "$(cat "$TMP/calls")" == 'qdisc replace dev eth0 parent 1:2 fq' ]] || fail 'boot-time mq mutation differs'

# A partially completed apply is recoverable without rebuilding mq or touching
# the sibling that never changed.
reset_mock
printf 'qdisc mq 1: root\nqdisc fq_codel 0: parent 1:1\nqdisc fq_codel 0: parent 1:2\n' >"$TMP/layout"
cp "$TMP/layout" "$TMP/backup/qdisc.txt"
echo '1:2' >"$TMP/fail-parent"
if apply_qdisc eth0 fq 2>/dev/null; then fail 'partial failure ignored'; fi
restore_qdisc "$TMP/backup" eth0 mq || fail 'partial failure was not recoverable'
[[ "$(tail -n 1 "$TMP/calls")" == 'qdisc replace dev eth0 parent 1:1 fq_codel' ]] || fail 'wrong partial rollback'
[[ "$(wc -l <"$TMP/calls" | xargs)" == 3 ]] || fail 'partial rollback wrote untouched leaf'
if grep -Eq 'root|qdisc del' "$TMP/calls"; then fail 'partial rollback rebuilt mq'; fi

# A no-error tc restore is still a failure if the leaf did not change.
reset_mock
printf 'qdisc mq 1: root\nqdisc fq 0: parent 1:1\nqdisc fq 0: parent 1:2\n' >"$TMP/layout"
touch "$TMP/false-success"
if restore_qdisc "$TMP/backup" eth0 mq 2>/dev/null; then fail 'restore false success accepted'; fi

# Anonymous mq with a non-fq leaf must be refused BEFORE sysctl writes, even
# with --force. A 0: parent must not be guessed to mean 1:.
reset_mock
printf 'qdisc mq 0: root\nqdisc fq_codel 0: parent :1\nqdisc fq 0: parent :2\n' >"$TMP/layout"
if qdisc_preflight eth0 fq 2>"$TMP/diag"; then fail 'anonymous non-fq preflight succeeded'; fi
if (FORCE=1; apply_qdisc eth0 fq) 2>/dev/null; then fail 'force bypassed parent safety'; fi
(
  apply_sysctl_content() { touch "$TMP/sysctl-called"; }
  apply_candidate eth0 8
) >"$TMP/candidate.log" 2>&1 && fail 'anonymous non-fq candidate succeeded'
[[ ! -e "$TMP/sysctl-called" ]] || fail 'sysctl changed before queue validation'
if bash "$TMP/helper" 2>/dev/null; then fail 'boot helper bypassed parent safety'; fi
no_writes

# A newly introduced custom queue must not be flattened by the boot helper or
# by later search candidates after the initial preflight.
reset_mock
printf 'qdisc cake 8001: root bandwidth 200Mbit\n' >"$TMP/layout"
if apply_qdisc eth0 fq 2>/dev/null; then fail 'custom root overwritten without force'; fi
if bash "$TMP/helper" 2>/dev/null; then fail 'boot helper overwrote custom root'; fi
printf 'qdisc mq 1: root\nqdisc fq 0: parent 1:1\nqdisc cake 0: parent 1:2 bandwidth 200Mbit\n' >"$TMP/layout"
if apply_qdisc eth0 fq 2>/dev/null; then fail 'custom leaf overwritten without force'; fi
no_writes

# All reads fail closed, including malformed/truncated snapshots.
for text in '' 'qdisc mq 0: root' 'qdisc fq 0: parent :1' \
  $'qdisc fq 0: root\nqdisc fq 1: root' \
  $'qdisc mq 1: root\nqdisc fq 0: parent 2:1' \
  $'qdisc mq 0: root\nqdisc fq 0: parent :1\nqdisc fq 0: parent 0:1'; do
  printf '%s\n' "$text" >"$TMP/layout"
  if apply_qdisc eth0 fq 2>/dev/null; then fail "invalid layout accepted: $text"; fi
  no_writes
done
touch "$TMP/show-fails"
if qdisc_layout_safe eth0 2>/dev/null; then fail 'unreadable layout is safe'; fi
if apply_qdisc eth0 fq 2>/dev/null; then fail 'unreadable layout applied'; fi
no_writes

# A successful tc exit code with unchanged state must fail readback validation.
reset_mock
printf 'qdisc mq 1: root\nqdisc fq_codel 0: parent 1:1\n' >"$TMP/layout"
touch "$TMP/false-success"
if apply_qdisc eth0 fq 2>/dev/null; then fail 'mq false success accepted'; fi
printf 'qdisc fq_codel 0: root\n' >"$TMP/layout"
if apply_qdisc eth0 fq 2>/dev/null; then fail 'root false success accepted'; fi

# A failed queue mutation must also precede TCP writes.
reset_mock
touch "$TMP/write-fails"
(
  apply_sysctl_content() { touch "$TMP/sysctl-called"; }
  apply_candidate eth0 8
) >"$TMP/write-failure.log" 2>&1 && fail 'failed tc candidate succeeded'
[[ ! -e "$TMP/sysctl-called" ]] || fail 'sysctl changed before failed tc'

# Flat roots restore with a readback check, not an unconditional delete.
reset_mock
printf 'qdisc fq_codel 123: root\n' >"$TMP/layout"
cp "$TMP/layout" "$TMP/backup/qdisc.txt"
apply_qdisc eth0 fq || fail 'flat root apply failed'
restore_qdisc "$TMP/backup" eth0 fq_codel || fail 'flat root restore failed'
grep -Fqx 'qdisc replace dev eth0 root handle 123: fq_codel' "$TMP/calls" || fail 'original root handle lost'
if grep -q 'qdisc del' "$TMP/calls"; then fail 'unnecessary root deletion'; fi

# Restoring mq never recreates the root on a drifted topology or handles.
reset_mock
cp "$ROOT/tests/fixtures/qdisc-mq-fq.txt" "$TMP/backup/qdisc.txt"
for text in 'qdisc fq 8001: root' \
  $'qdisc mq 1: root\nqdisc fq 0: parent 1:1\nqdisc fq 0: parent 1:2' \
  $'qdisc mq 0: root\nqdisc fq 0: parent :1' \
  $'qdisc mq 0: root\nqdisc fq_codel 0: parent :1\nqdisc fq 0: parent :2'; do
  printf '%s\n' "$text" >"$TMP/layout"
  if restore_qdisc "$TMP/backup" eth0 mq 2>/dev/null; then fail 'unsafe mq recovery accepted'; fi
  no_writes
done

# Validate the whole restore plan before any writes, including unknown leaves.
printf 'qdisc mq 1: root\nqdisc fq_codel 0: parent 1:1\nqdisc custom 0: parent 1:2\n' >"$TMP/backup/qdisc.txt"
printf 'qdisc mq 1: root\nqdisc fq 0: parent 1:1\nqdisc fq 0: parent 1:2\n' >"$TMP/layout"
if restore_qdisc "$TMP/backup" eth0 mq 2>/dev/null; then fail 'unsupported leaf recovery accepted'; fi
no_writes

# Broken/missing old snapshots must not delete or replace any existing queue.
printf 'error\n' >"$TMP/backup/qdisc.txt"
if restore_qdisc "$TMP/backup" eth0 mq 2>/dev/null; then fail 'invalid backup accepted'; fi
rm "$TMP/backup/qdisc.txt"
if restore_qdisc "$TMP/backup" eth0 mq 2>/dev/null; then fail 'missing backup accepted'; fi
no_writes

# Exercise real backup creation and real persistent helper generation using
# redirected paths. Missing/malformed snapshots cannot become the latest backup.
(
  reset_mock
  STATE_DIR="$TMP/state"; BACKUP_ROOT="$STATE_DIR/backups"; LATEST_BACKUP="$STATE_DIR/latest"
  SYSCTL_FILE="$TMP/persist/sysctl"; MODULES_FILE="$TMP/persist/modules"
  ENV_FILE="$TMP/persist/env"; QDISC_HELPER="$TMP/persist/helper"; SERVICE_FILE="$TMP/persist/service"
  mkdir -p "$TMP/persist" "$BACKUP_ROOT"
  systemd_available() { return 1; }
  sysctl_exists() { return 0; }
  sysctl_get() { printf '1\n'; }
  SESSION_ID=snapshot
  cp "$ROOT/tests/fixtures/qdisc-mq-fq.txt" "$TMP/layout"
  backup="$(create_backup eth0)" || fail 'valid snapshot rejected'
  [[ -L "$LATEST_BACKUP" && -s "$backup/qdisc.txt" ]] || fail 'snapshot not saved'
  [[ "$(cat "$STATE_DIR/original-backup")" == snapshot ]] || fail 'first snapshot not protected'
  restore_qdisc "$backup" eth0 mq || fail 'saved mq snapshot not readable'
  no_writes
  SESSION_ID=broken
  touch "$TMP/show-fails"
  if create_backup eth0 >"$TMP/bad-backup.out" 2>/dev/null; then fail 'unreadable snapshot accepted'; fi
  [[ "$(readlink "$LATEST_BACKUP")" == "$backup" ]] || fail 'broken snapshot replaced latest'
  [[ "$(cat "$STATE_DIR/original-backup")" == snapshot ]] || fail 'failed snapshot changed original'
  rm "$TMP/show-fails"
  printf 'invalid\n' >"$TMP/layout"
  if create_backup eth0 >"$TMP/bad-backup.out" 2>/dev/null; then fail 'invalid snapshot accepted'; fi
  [[ "$(readlink "$LATEST_BACKUP")" == "$backup" ]] || fail 'invalid snapshot replaced latest'
  cp "$ROOT/tests/fixtures/qdisc-mq-fq.txt" "$TMP/layout"
  write_persistent_config eth0 8 >"$TMP/persist.log" 2>&1
  cmp "$QDISC_HELPER" <(render_qdisc_helper) || fail 'persistent helper differs from safe runtime'
  sed "s|source /etc/default/bbr-tcp-tuning|source $ENV_FILE|" "$QDISC_HELPER" >"$TMP/persist/standalone"
  touch "$TMP/write-fails"
  bash "$TMP/persist/standalone" || fail 'installed helper repeated anonymous leaf replacement'
  no_writes
)

# Rollback restores legacy files and enablement without executing a previously
# active oneshot helper (which could repeat the old mq replacement failure).
(
  backup="$TMP/service-backup"; mkdir -p "$backup"
  SERVICE_FILE="$TMP/old.service"; touch "$SERVICE_FILE"
  printf 'IFACE=eth0\nROOT_QDISC=mq\nSERVICE_ACTIVE=active\nSERVICE_ENABLED=enabled\n' >"$backup/meta.env"
  : >"$backup/files.tsv"; : >"$backup/sysctl.tsv"
  cp "$ROOT/tests/fixtures/qdisc-mq-fq.txt" "$TMP/layout"
  cp "$TMP/layout" "$backup/qdisc.txt"
  systemd_available() { return 0; }
  systemctl() {
    printf '%s\n' "$*" >>"$TMP/systemctl-calls"
    case "$1" in start|restart) fail 'rollback executed legacy helper' ;; esac
    return 0
  }
  restore_backup "$backup" >"$TMP/legacy-recovery.log" 2>&1 || fail 'legacy service recovery failed'
  grep -Fq '[INFO ] 开机服务文件及启用状态已还原' "$TMP/legacy-recovery.log" || fail 'legacy helper notice missing'
  grep -Fqx 'enable bbr-tcp-tuning.service' "$TMP/systemctl-calls" || fail 'enablement not restored'
)

printf 'All qdisc apply, rollback and boot-helper safety tests passed.\n'
