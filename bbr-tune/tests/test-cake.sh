#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-tune.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
STATE_DIR="$TMP/state"; BACKUP_ROOT="$STATE_DIR/backups"; LATEST_BACKUP="$STATE_DIR/latest"
SYSCTL_FILE="$TMP/config/tcp.conf"; MODULES_FILE="$TMP/config/modules.conf"
ENV_FILE="$TMP/config/env"; QDISC_HELPER="$TMP/config/helper"; SERVICE_FILE="$TMP/config/service"
SESSION_ID=cake; SESSION_DIR="$TMP/session"
mkdir -p "$BACKUP_ROOT" "$TMP/config" "$SESSION_DIR"
# No host networking, modules, services or kernel settings are modified.
tc() {
  case " $* " in
    *' show '*) [[ ! -e "$TMP/read-error" ]] || return 1; cat "$TMP/layout" ;;
    *) echo "$*" >>"$TMP/tc-writes"; return 1 ;;
  esac
}
systemd_available() { return 1; }
sysctl_get() { awk -F '\t' -v k="$1" '$1==k{print $2}' "$TMP/sysctl.tsv"; }
sysctl_exists() { [[ -n "$(sysctl_get "$1")" ]]; }
sysctl() {
  [[ "$1" == -w ]] || fail 'unexpected sysctl command'
  local key="${2%%=*}" value="${2#*=}"
  echo "$2" >>"$TMP/sysctl-writes"
  [[ "$key" != net.core.default_qdisc ]] || fail 'default qdisc must not be written'
  awk -F '\t' -v k="$key" '$1!=k' "$TMP/sysctl.tsv" >"$TMP/new-sysctl"
  printf '%s\t%s\n' "$key" "$value" >>"$TMP/new-sysctl"
  mv "$TMP/new-sysctl" "$TMP/sysctl.tsv"
}
cat >"$TMP/sysctl.tsv" <<'SYSCTL'
net.core.default_qdisc	cake
net.ipv4.tcp_congestion_control	cubic
net.core.rmem_max	67108864
net.core.wmem_max	67108864
net.ipv4.tcp_rmem	4096 87380 67108864
net.ipv4.tcp_wmem	4096 65536 67108864
net.ipv4.tcp_mem	22347 29797 44694
net.ipv4.tcp_moderate_rcvbuf	1
net.ipv4.tcp_sack	1
net.ipv4.tcp_dsack	1
net.ipv4.tcp_window_scaling	1
SYSCTL
printf 'qdisc cake 8001: root refcnt 2 bandwidth 200Mbit diffserv4 triple-isolate nat wash ack-filter overhead 44\n Sent 123 bytes 2 pkt (dropped 0, overlimits 0 requeues 0)\n' >"$TMP/shaped"
printf 'qdisc cake 8001: root refcnt 2 unlimited besteffort triple-isolate nonat nowash no-ack-filter overhead 0\n' >"$TMP/unlimited"
printf 'qdisc mq 0: root\nqdisc cake 0: parent :1 bandwidth 100Mbit diffserv4\nqdisc fq 0: parent :2 quantum 3028b\n' >"$TMP/mq"
printf 'qdisc htb 1: root\nqdisc cake 10: parent 1:10 bandwidth 200Mbit diffserv4\n' >"$TMP/tree"

# CAKE is safe to retain, not safe to assume fully reconstructible. Never
# solve the guard by adding it to the list of replaceable default queues.
if qdisc_safe cake; then fail 'CAKE became safe to overwrite'; fi
for kind in shaped unlimited mq tree; do
  for FORCE in 0 1; do
    cp "$TMP/$kind" "$TMP/layout"
    select_tuning_qdisc eth0
    [[ "$QDISC_POLICY" == preserve ]] || fail "$kind was not preserved"
    apply_tuning_qdisc eth0 || fail "$kind blocked TCP tuning"
    [[ ! -e "$TMP/tc-writes" ]] || fail "$kind attempted tc mutation"
    cmp "$TMP/$kind" "$TMP/layout" || fail "$kind options changed"
  done
done
FORCE=0
cp "$TMP/shaped" "$TMP/layout"
select_tuning_qdisc eth0
prepare_tcp_rules
TCP_MEM_LOW_PAGES=168192; TCP_MEM_PRESSURE_PAGES=252288; TCP_MEM_HIGH_PAGES=336384
printf '# original\nnet.core.default_qdisc = cake\n' >"$SYSCTL_FILE"
backup="$(create_backup eth0)"
grep -Fqx 'QDISC_POLICY=preserve' "$backup/meta.env" || fail 'backup policy missing'
if grep -Fq 'net.core.default_qdisc' "$backup/sysctl.tsv"; then fail 'unchanged default scheduled for restore'; fi
apply_candidate eth0 8 || fail 'CAKE TCP candidate failed'
[[ "$(sysctl_get net.core.wmem_max)" == 8388608 ]] || fail 'TCP cache was not tuned'
[[ "$(sysctl_get net.ipv4.tcp_congestion_control)" == bbr ]] || fail 'BBR was not enabled'
[[ "$(sysctl_get net.core.default_qdisc)" == cake ]] || fail 'default qdisc changed'
[[ ! -e "$TMP/tc-writes" ]] || fail 'candidate changed CAKE'
build_sysctl_content 8388608 >"$TMP/runtime.conf"
if grep -q '^net.core.default_qdisc' "$TMP/runtime.conf"; then fail 'runtime profile overwrites queue default'; fi
write_rule_plan
grep -Fq '保留现有 CAKE' "$RULES_FILE" || fail 'rule plan mislabeled as fq'

# Persistence must never recreate a bare CAKE (losing bandwidth and options) or
# replace it with fq. Existing owned default settings are retained verbatim.
write_persistent_config eth0 8
grep -Fqx 'BBR_QDISC_POLICY=preserve' "$ENV_FILE" || fail 'persistent preservation policy missing'
grep -Fqx 'BBR_QDISC=cake' "$ENV_FILE" || fail 'wrong queue saved'
grep -Fqx 'net.core.default_qdisc = cake' "$SYSCTL_FILE" || fail 'owned default setting lost'
if grep -Fq sch_fq "$MODULES_FILE"; then fail 'fq forced on preservation path'; fi
printf 'tcp_bbr\nsch_cake\nsch_fq\n' >"$MODULES_FILE"
write_persistent_config eth0 8
for module in sch_cake sch_fq; do
  grep -Fqx "$module" "$MODULES_FILE" || fail "previous boot module lost: $module"
done
if grep -Fq 'net.core.default_qdisc=fq' "$TMP/sysctl-writes"; then fail 'default fq applied'; fi
# A foreign service may create CAKE later in boot: the helper must not touch
# queues, or require a currently present interface, in preservation mode.
sed "s|source /etc/default/bbr-tcp-tuning|source $ENV_FILE|" "$QDISC_HELPER" >"$TMP/boot-helper"
printf '\nBBR_IFACE=missing-interface\n' >>"$ENV_FILE"
mkdir -p "$TMP/bin"
printf '#!/usr/bin/env bash\necho unexpected >>"$CAKE_TEST_DIR/boot-calls"\nexit 1\n' >"$TMP/bin/tc"
cp "$TMP/bin/tc" "$TMP/bin/ip"; chmod +x "$TMP/bin/tc" "$TMP/bin/ip"
CAKE_TEST_DIR="$TMP" PATH="$TMP/bin:$PATH" bash "$TMP/boot-helper"
[[ ! -e "$TMP/boot-calls" ]] || fail 'preservation boot helper inspected or changed networking'
# No previously owned setting: leave other administrators config files alone.
rm "$SYSCTL_FILE"
write_persistent_config eth0 8
if grep -q '^net.core.default_qdisc' "$SYSCTL_FILE"; then fail 'new default setting introduced'; fi

# A normal rollback restores the TCP snapshot without reconstructing CAKE.
restore_backup "$backup" || fail 'CAKE rollback failed'
[[ "$(sysctl_get net.core.wmem_max)" == 67108864 ]] || fail 'TCP snapshot not restored'
[[ "$(sysctl_get net.ipv4.tcp_congestion_control)" == cubic ]] || fail 'congestion baseline not restored'
[[ ! -e "$TMP/tc-writes" ]] || fail 'CAKE was modified during rollback'
cmp "$TMP/shaped" "$TMP/layout" || fail 'CAKE options lost'

# External tree replacement or read failure aborts before further TCP writes;
# rollback in preserve mode cannot forcibly restore a queue it never modified.
printf 'qdisc fq 8001: root\n' >"$TMP/layout"
cp "$TMP/sysctl-writes" "$TMP/writes-before"
if (apply_candidate eth0 16) >"$TMP/drift.log" 2>&1; then fail 'queue drift ignored'; fi
cmp "$TMP/sysctl-writes" "$TMP/writes-before" || fail 'drifted candidate modified TCP'
if restore_qdisc "$backup" eth0 cake preserve 2>/dev/null; then fail 'drifted queue reported restored'; fi
[[ ! -e "$TMP/tc-writes" ]] || fail 'rollback overwrote external change'
touch "$TMP/read-error"
if (apply_candidate eth0 16) >"$TMP/read-error.log" 2>&1; then fail 'unreadable queue accepted'; fi
cmp "$TMP/sysctl-writes" "$TMP/writes-before" || fail 'unreadable candidate modified TCP'
rm "$TMP/read-error"

# A later ordinary interface must not inherit preservation mode from a prior
# session, and unsupported custom layouts still require explicit handling.
printf 'qdisc fq_codel 0: root\n' >"$TMP/layout"
select_tuning_qdisc eth0
[[ "$QDISC_POLICY" == manage && "$TUNING_QDISC" == fq && -z "$PRESERVED_QDISC_LAYOUT" ]] || fail 'policy leaked across sessions'
printf 'qdisc htb 1: root\nqdisc fq 10: parent 1:10\n' >"$TMP/layout"
select_tuning_qdisc eth0
[[ "$QDISC_POLICY" == manage ]] || fail 'non-CAKE custom layout silently bypassed'
if qdisc_layout_safe eth0; then fail 'unrelated custom shaping accepted as default'; fi
printf 'All CAKE preservation, TCP application, persistence and recovery tests passed.\n'
