#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Numeric fields must not be interpreted as octal or accept shell syntax.
(
  TARGET_MBPS=500; START_STREAMS=08; DURATION=015; TEST_REPEATS=02
  SERVER_ADDRESS=2001:db8::1
  validate_autotune_options
  [[ "$START_STREAMS:$DURATION:$TEST_REPEATS" == 8:15:2 ]] || fail 'decimal normalization'
  for invalid in '$(touch /tmp/invalid)' '1+1' '1.5' '999999999999999999999999'; do
    if (START_STREAMS="$invalid"; validate_autotune_options) >/dev/null 2>&1; then fail 'invalid stream count accepted'; fi
  done
  for invalid in 'host;id' 'https://host' 'host address' '-option'; do
    if (SERVER_ADDRESS="$invalid"; validate_autotune_options) >/dev/null 2>&1; then fail 'unsafe address accepted'; fi
  done
  if (TARGET_MBPS=100001; validate_autotune_options) >/dev/null 2>&1; then fail 'unbounded bandwidth'; fi
)

# Files must not be destroyed when their recorded backup is missing.
(
  mkdir -p "$tmp/missing-file"
  echo existing >"$tmp/keep.conf"
  printf 'config\tpresent\t%s\n' "$tmp/keep.conf" >"$tmp/missing-file/files.tsv"
  if restore_files "$tmp/missing-file" >/dev/null 2>&1; then fail 'missing copy reported successful'; fi
  [[ "$(cat "$tmp/keep.conf")" == existing ]] || fail 'missing copy destroyed config'
)

# Restore every key, verify reads, and report partial failures rather than success.
(
  backup="$tmp/restore"; mkdir -p "$backup"
  printf 'IFACE=eth0\nROOT_QDISC=fq\n' >"$backup/meta.env"
  : >"$backup/files.tsv"
  printf 'net.core.rmem_max\t4096\nnet.core.wmem_max\t8192\n' >"$backup/sysctl.tsv"
  systemd_available() { return 1; }
  restore_qdisc() { echo queue >>"$tmp/restored"; }
  sysctl_get() { case "$1" in net.core.rmem_max) echo 4096 ;; *) echo 8192 ;; esac; }
  sysctl() { printf '%s\n' "$*" >>"$tmp/restored"; }
  restore_backup "$backup" || fail 'valid restore rejected'
  sysctl() { [[ "$2" != net.core.rmem_max=* ]]; }
  if restore_backup "$backup" >/dev/null 2>&1; then fail 'write failure ignored'; fi
  sysctl() { :; }; sysctl_get() { echo 0; }
  if restore_backup "$backup" >/dev/null 2>&1; then fail 'readback mismatch ignored'; fi
  sysctl_get() { case "$1" in net.core.rmem_max) echo 4096 ;; *) echo 8192 ;; esac; }
  restore_qdisc() { return 1; }
  if restore_backup "$backup" >/dev/null 2>&1; then fail 'queue failure ignored'; fi
)

# Expired tasks cannot undo a newer confirmation/window, and failed recovery
# leaves the marker and backups available for manual retry.
(
  PENDING_DIR="$tmp/pending"; PENDING_LATEST="$tmp/pending-latest"
  BACKUP_PATH="$tmp/rollback"; mkdir -p "$BACKUP_PATH"
  pending="$(pending_path "$BACKUP_PATH")"; mkdir -p "$pending"
  printf 'new-token\n' >"$pending/armed"
  printf '%s\n' "$BACKUP_PATH" >"$pending/backup"
  ln -s "$pending" "$PENDING_LATEST"
  require_linux() { :; }; require_root() { :; }; YES=1
  BBR_AUTO_ROLLBACK=1; BBR_ROLLBACK_TOKEN=old-token
  restore_backup() { fail 'stale timer restored parameters'; }
  rollback_command >/dev/null
  [[ -f "$pending/armed" ]] || fail 'stale timer removed new marker'
  BBR_ROLLBACK_TOKEN=new-token
  restore_backup() { return 1; }
  if (rollback_command) >/dev/null 2>&1; then fail 'failed restore reported success'; fi
  [[ -f "$pending/armed" ]] || fail 'failed restore discarded marker'
  restore_backup() { :; }
  rollback_command >/dev/null
  [[ ! -e "$pending" ]] || fail 'successful restore did not clean up'
)

# Never signal a recycled PID or a session whose timer has been superseded.
(
  PENDING_DIR="$tmp/owners"; BACKUP_PATH="$tmp/owner-backup"
  pending="$(pending_path "$BACKUP_PATH")"; mkdir -p "$pending"
  printf 'token\n' >"$pending/armed"; printf '1234 9876\n' >"$pending/owner"
  BBR_ROLLBACK_TOKEN=token
  process_start_id() { echo 5555; }
  kill() { fail 'recycled PID signaled'; }
  stop_expired_session
  process_start_id() { echo 9876; }
  BBR_ROLLBACK_TOKEN=stale
  stop_expired_session
  BBR_ROLLBACK_TOKEN=token
  kill() { [[ "$*" == '-TERM 1234' ]] || fail 'unexpected signal'; echo stopped >"$tmp/stopped"; }
  stop_expired_session >/dev/null 2>&1
  [[ -f "$tmp/stopped" ]] || fail 'expired active session not stopped'
)

# A failed baseline must not cancel the previous safety rollback.
(
  SESSION_DIR="$tmp/baseline"; mkdir -p "$SESSION_DIR"
  TARGET_MBPS=500
  require_linux() { :; }; require_root() { :; }; have() { return 0; }
  init_session() { :; }; install_iperf3_if_needed() { :; }; install_python3_if_needed() { :; }
  resolve_iface() { echo eth0; }; ip() { :; }; guess_server_address() { echo 203.0.113.10; }
  choose_random_port() { echo 50001; }; detect_iperf_family() { echo -4; }
  detect_memory_limits() { :; }; ensure_bbr() { :; }; prepare_tcp_rules() { :; }
  sysctl_get() { echo 4096; }; root_qdisc_kind() { echo fq; }; current_buffer_max() { echo 4096; }
  tc() { echo "qdisc fq 0: root"; }
  qdisc_layout_safe() { :; }; capture_state() { :; }
  pending_guard() { echo cancelled >"$tmp/premature-cancel"; }
  run_balanced_pair() { die 'simulated baseline failure'; }
  autotune
) >"$tmp/baseline.log" 2>&1 && fail 'baseline failure ignored'
[[ ! -e "$tmp/premature-cancel" ]] || fail 'previous timer cancelled before valid baseline'

# The installer, TCP writer and kernel writer share one operation lock.
# Test lock acquisition/refusal without modifying the host filesystem.
(
  STATE_DIR="$tmp/locks"; require_linux() { :; }; require_root() { :; }
  flock() { printf '%s\n' "$*" >"$tmp/lock-call"; }
  acquire_operation_lock
  [[ -f "$STATE_DIR/operation.lock" && "$(cat "$tmp/lock-call")" == '-n 8' ]] || fail 'TCP lock missing'
  flock() { return 1; }
  if (acquire_operation_lock) >/dev/null 2>&1; then fail 'concurrent TCP writer allowed'; fi
)

printf 'All input, rollback, watchdog and operation-lock safety tests passed.\n'
