#!/usr/bin/env bash
# bbr-tune.sh - 远程 Linux 服务器 TCP/BBR 自动测试与参数寻优工具
set -Eeuo pipefail

VERSION="2.10.3"
PROGRAM="${0##*/}"
SCRIPT_PATH="${BASH_SOURCE[0]}"
[[ "$SCRIPT_PATH" == /* ]] || SCRIPT_PATH="${PWD}/${SCRIPT_PATH}"

STATE_DIR="/var/lib/bbr-tcp-tuning"
SESSION_ROOT="${STATE_DIR}/sessions"
BACKUP_ROOT="${STATE_DIR}/backups"
LATEST_BACKUP="${STATE_DIR}/latest"
PENDING_DIR="${STATE_DIR}/pending"
PENDING_LATEST="${STATE_DIR}/pending-latest"
HISTORY_FILE="${STATE_DIR}/history.tsv"
SYSCTL_FILE="/etc/sysctl.d/99-bbr-tcp-tuning.conf"
MODULES_FILE="/etc/modules-load.d/bbr-tcp-tuning.conf"
ENV_FILE="/etc/default/bbr-tcp-tuning"
QDISC_HELPER="/usr/local/sbin/bbr-tcp-qdisc"
SERVICE_FILE="/etc/systemd/system/bbr-tcp-tuning.service"

KERNEL_ARGS=()
COMMAND="menu"
IFACE="auto"
SERVER_ADDRESS=""
TARGET_MBPS=""
RTT_MS=""
RTT_SOURCE=""
START_STREAMS="8"
DURATION="15"
WAIT_SECONDS="300"
TARGET_UTILIZATION="90"
MAX_RETRANS_PERCENT="1"
AUTO_ROLLBACK_SECONDS="3600"
TCP_BUFFER_SYSCTL_MAX_MIB="2047"
BALANCE_MIN_RETENTION_PERCENT="95"
STRATEGY="balanced"
STRATEGY_NAME="均衡"
WEIGHT_SPEED=70
WEIGHT_STABILITY=15
WEIGHT_RETRANS=15
TEST_REPEATS=2
SEARCH_BUFFER_CAP_MIB=0
SEARCH_STOP_REASON=""
PLATEAU_STEPS=0
TCP_RMIN=4096
TCP_RDEFAULT=131072
TCP_WMIN=4096
TCP_WDEFAULT=16384
RULES_FILE=""
TUNING_QDISC="fq"
REQUESTED_QDISC="auto"
CAKE_BANDWIDTH_MBPS=""
QUEUE_SWITCH_READY=0
QDISC_ORIGINAL_JSON=""
QDISC_ORIGINAL_PLAN=""
QDISC_LAST_JSON=""
QDISC_ONLY=0
QDISC_POLICY="manage"
PRESERVED_QDISC_LAYOUT=""
PERSIST_FINAL="0"
FORCE="0"
YES="0"
BACKUP_PATH=""
HISTORY_SESSION=""
HISTORY_PARAMS_AFTER="0"
UPDATE_CHANNEL="github"
QUIET="0"
UI_BLUE=""; UI_GREEN=""; UI_YELLOW=""; UI_RED=""; UI_RESET=""

SESSION_ID=""
SESSION_DIR=""
RUN_LOG=""
REPORT_FILE=""
COMPARISON_FILE=""
TEST_PORT=""
IPERF_FAMILY="-4"
CURRENT_TEST_PID=""
BACKUP_DIR=""
TUNING_ACTIVE="0"

MEM_TOTAL_MIB="0"
MEM_AVAILABLE_MIB="0"
MEM_EFFECTIVE_MIB="0"
MEM_TCP_BUDGET_MIB="0"
MEM_BUFFER_CAP_MIB="0"
PAGE_SIZE_BYTES="4096"
TCP_MEM_LOW_PAGES="0"
TCP_MEM_PRESSURE_PAGES="0"
TCP_MEM_HIGH_PAGES="0"
BDP_BYTES="0"
BDP_MIB="0"

RESULT_MBPS="0"
RESULT_BYTES="0"
RESULT_RETRANS="0"
RESULT_RETRANS_PERCENT="100"
RESULT_RTT_MS="0"
RESULT_RTT_SOURCE=""
RESULT_CLIENT_ADDRESS=""
RESULT_CV_PERCENT="NA"
RESULT_MIN_RTT_MS=0
RESULT_RETRANS_SOURCE="estimated-1448"
RESULT_RATE_SOURCE="sender"
RESULT_SCORE="-999999"
RESULT_PASS="no"


BASELINE_SINGLE_MBPS="0"
BASELINE_SINGLE_RETRANS="0"
BASELINE_SINGLE_RETRANS_PERCENT="100"
BASELINE_SINGLE_PASS="no"
BASELINE_SINGLE_CV_PERCENT="NA"
BASELINE_SINGLE_RTT_MS=0
BASELINE_MULTI_MBPS="0"
BASELINE_MULTI_RETRANS="0"
BASELINE_MULTI_RETRANS_PERCENT="100"
BASELINE_MULTI_PASS="no"
BASELINE_MULTI_CV_PERCENT="NA"
BASELINE_MULTI_RTT_MS=0
BALANCE_MULTI_STREAMS="8"

PAIR_SINGLE_MBPS="0"
PAIR_SINGLE_RETRANS="0"
PAIR_SINGLE_RETRANS_PERCENT="100"
PAIR_SINGLE_SCORE="-999999"
PAIR_SINGLE_PASS="no"
PAIR_SINGLE_CV_PERCENT="NA"
PAIR_SINGLE_RTT_MS=0
PAIR_MULTI_MBPS="0"
PAIR_MULTI_RETRANS="0"
PAIR_MULTI_RETRANS_PERCENT="100"
PAIR_MULTI_SCORE="-999999"
PAIR_MULTI_PASS="no"
PAIR_MULTI_CV_PERCENT="NA"
PAIR_MULTI_RTT_MS=0
PAIR_SCORE="-999999"
PAIR_ELIGIBLE="no"
PAIR_PASS="no"

BASELINE_SCORE="-999999"
BASELINE_PASS="no"
BASELINE_BUFFER_BYTES="0"

BEST_KIND="none"
BEST_BUFFER_MIB="0"
BEST_FACTOR="未选择"
BEST_SCORE="-999999"
BEST_ELIGIBLE="no"

BEST_SINGLE_MBPS="0"
BEST_SINGLE_RETRANS_PERCENT="100"
BEST_MULTI_MBPS="0"
BEST_MULTI_RETRANS_PERCENT="100"

FINAL_SINGLE_MBPS="0"
FINAL_SINGLE_RETRANS="0"
FINAL_SINGLE_RETRANS_PERCENT="100"
FINAL_SINGLE_PASS="no"
FINAL_SINGLE_CV_PERCENT="NA"
FINAL_SINGLE_RTT_MS=0
FINAL_MULTI_MBPS="0"
FINAL_MULTI_RETRANS="0"
FINAL_MULTI_RETRANS_PERCENT="100"
FINAL_MULTI_PASS="no"
FINAL_MULTI_CV_PERCENT="NA"
FINAL_MULTI_RTT_MS=0

FINAL_SCORE="-999999"
FINAL_PASS="no"
FINAL_BUFFER_BYTES="0"
OUTCOME=""
QOS_DETECTED="0"

BEFORE_CC=""
BEFORE_QDISC=""
BEFORE_RMEM=""
BEFORE_WMEM=""
BEFORE_TCP_MEM=""
BEFORE_BUFFER_BYTES="0"

CANDIDATE_MIBS=()
CANDIDATE_FACTORS=()
SEARCH_ROUNDS="0"
OVERSHOOT_DETECTED="0"
OVERSHOOT_MIB="0"

# Every mutable sysctl is declared once so backup, rollback, state capture and
# reporting always cover the same server-side settings.
OBSERVED_SYSCTL_KEYS=(
  kernel.pid_max kernel.panic kernel.sysrq kernel.core_pattern kernel.printk
  kernel.numa_balancing kernel.sched_autogroup_enabled
  vm.swappiness vm.dirty_ratio vm.dirty_background_ratio vm.panic_on_oom
  vm.overcommit_memory vm.min_free_kbytes
  net.core.default_qdisc net.core.netdev_max_backlog net.core.rmem_max
  net.core.wmem_max net.core.rmem_default net.core.wmem_default
  net.core.somaxconn net.core.optmem_max
  net.ipv4.tcp_fastopen net.ipv4.tcp_timestamps net.ipv4.tcp_tw_reuse
  net.ipv4.tcp_fin_timeout net.ipv4.tcp_slow_start_after_idle
  net.ipv4.tcp_max_tw_buckets net.ipv4.tcp_sack net.ipv4.tcp_dsack
  net.ipv4.tcp_fack net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.ipv4.tcp_mem
  net.ipv4.tcp_mtu_probing net.ipv4.tcp_congestion_control
  net.ipv4.tcp_notsent_lowat net.ipv4.tcp_window_scaling
  net.ipv4.tcp_adv_win_scale net.ipv4.tcp_moderate_rcvbuf
  net.ipv4.tcp_no_metrics_save net.ipv4.tcp_max_syn_backlog
  net.ipv4.tcp_max_orphans net.ipv4.tcp_synack_retries
  net.ipv4.tcp_syn_retries net.ipv4.tcp_abort_on_overflow
  net.ipv4.tcp_stdurg net.ipv4.tcp_rfc1337 net.ipv4.tcp_syncookies
  net.ipv4.ip_local_port_range net.ipv4.ip_no_pmtu_disc
  net.ipv4.route.gc_timeout net.ipv4.neigh.default.gc_stale_time
  net.ipv4.neigh.default.gc_thresh3 net.ipv4.neigh.default.gc_thresh2
  net.ipv4.neigh.default.gc_thresh1 net.ipv4.icmp_echo_ignore_broadcasts
  net.ipv4.icmp_ignore_bogus_error_responses net.ipv4.conf.all.rp_filter
  net.ipv4.conf.default.rp_filter net.ipv4.conf.all.arp_announce
  net.ipv4.conf.default.arp_announce net.ipv4.conf.all.arp_ignore
  net.ipv4.conf.default.arp_ignore
)

TUNING_SYSCTL_KEYS=(
  net.core.default_qdisc net.ipv4.tcp_congestion_control
  net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem net.ipv4.tcp_wmem
  net.ipv4.tcp_mem net.ipv4.tcp_moderate_rcvbuf net.ipv4.tcp_sack
  net.ipv4.tcp_dsack net.ipv4.tcp_window_scaling
)

log_line() {
  local level="$1"; shift
  (( QUIET )) && [[ "$level" == "INFO" ]] && return 0
  printf '[%s] [%-5s] %s\n' "$(date '+%H:%M:%S')" "$level" "$*"
}
info() { log_line INFO "$*"; }
warn() { log_line WARN "$*" >&2; }
error() { log_line ERROR "$*" >&2; }
die() { error "$*"; exit 1; }

ui_rule() {
  local width=64
  if [[ -t 1 && "${COLUMNS:-}" =~ ^[0-9]+$ ]]; then
    width="$COLUMNS"; (( width > 72 )) && width=72
    (( width < 20 )) && width=20
  fi
  printf '%*s\n' "$width" '' | tr ' ' '-'
}

section() {
  printf '\n%s%s%s\n' "${UI_BLUE:-}" "$*" "${UI_RESET:-}"
  ui_rule
}

process_start_id() {
  local stat
  [[ "$1" =~ ^[0-9]+$ && -r "/proc/$1/stat" ]] || return 1
  stat="$(cat "/proc/$1/stat")" || return 1
  stat="${stat##*) }"
  awk '{print $20}' <<<"$stat"
}

stop_expired_session() {
  local pending pid started actual token
  [[ -n "$BACKUP_PATH" && -n "${BBR_ROLLBACK_TOKEN:-}" ]] || return 0
  pending="$(pending_path "$BACKUP_PATH")"
  token="$(cat "${pending}/armed" 2>/dev/null || true)"
  [[ "$token" == "$BBR_ROLLBACK_TOKEN" && -r "${pending}/owner" ]] || return 0
  read -r pid started <"${pending}/owner" || return 0
  [[ "$pid" =~ ^[0-9]+$ && "$started" =~ ^[0-9]+$ ]] || return 0
  actual="$(process_start_id "$pid" || true)"
  if [[ "$actual" == "$started" ]]; then
    warn "安全计时器已到期，正在终止当前调优并等待参数恢复"
    kill -TERM "$pid" 2>/dev/null || true
  fi
}

acquire_operation_lock() {
  require_linux; require_root
  have flock || die "缺少 flock，请先使用一键安装补齐运行依赖"
  umask 077
  mkdir -p "$STATE_DIR"
  exec 8>"${STATE_DIR}/operation.lock"
  if [[ "${BBR_AUTO_ROLLBACK:-0}" == 1 ]]; then
    # A watchdog must not restore the baseline while a test is applying a candidate.
    flock 8 || die "无法取得安全回滚锁"
  else
    flock -n 8 || die "已有 TCP 调优、内核或更新操作正在运行；请等待完成，不要同时修改参数"
  fi
}

usage() {
  cat <<'USAGE'
远程服务器 TCP/BBR 自动寻优工具

用法：
  bbrtcp                                    打开交互界面（安装后）
  sudo ./bbr-tune.sh                         交互界面
  sudo ./bbr-tune.sh autotune [参数]         自动测试并选择最优参数
  sudo ./bbr-tune.sh qdisc --qdisc ALGO      单独更改出口队列，不改 TCP 参数
  ./bbr-tune.sh status [--iface DEV]         查看当前 TCP/BBR 状态
  ./bbr-tune.sh history                      查看历史测试会话
  ./bbr-tune.sh history-compare --session ID  对比当前、测试前及历史选中参数
  ./bbr-tune.sh history-params --session ID   查看历史会话测试前的原始参数
  sudo ./bbr-tune.sh apply-history --session ID [--persist]  应用历史测试的 TCP 参数
  sudo ./bbr-tune.sh update --channel github|gitee       选择来源更新工具
  sudo ./bbr-tune.sh kernel [操作]         BBRv3 内核检测、安装、试用与恢复
  sudo ./bbr-tune.sh confirm                 确认保留当前参数并取消安全回滚
  sudo ./bbr-tune.sh rollback [--backup DIR] 恢复调优前参数

自动寻优参数：
  --bandwidth-mbps N       期望的端到端下载带宽，单位 Mbps，必填
                           方向为“远程服务器 → 本地电脑”；通常填写
                           服务器出站上限与本地下载上限中的较小值
  --server-address HOST    本地 iperf3 应连接的服务器地址
  --qdisc ALGO             auto 自动（默认）| keep 保留 | fq | fq_codel | cake
  --cake-bandwidth-mbps N  CAKE 整形带宽；0 不限速；不填则保留已有值，新建时不限速
  --iface auto|DEV         出口网卡，默认自动识别
  --parallel N             多连接评估的并发流数，默认 8；单连接始终单独测试
  --duration N             每轮测试时长，默认 15 秒
  --strategy MODE          balanced 均衡（默认）| speed 速度 | stable 稳定 | retrans 低重传
  --repeats N              每组单/多连接各复测次数，默认 2，范围 1～5
  --target-utilization N   达标吞吐百分比，默认 90
  --max-retrans-percent N  最大估算重传比例，默认 1
  --persist                最优参数复测后写入开机配置
  --force                  旧自动模式的自定义队列覆盖；显式切换仍须通过恢复预检

自动测试规则：
  1. 脚本只在远程 Linux 服务器修改 TCP/BBR 参数。
  2. 本地电脑只运行屏幕显示的 iperf3 客户端命令，不改任何本地参数。
  3. 首轮反向 iperf3 会自动测量本地与服务器之间的 TCP RTT，无需填写 RTT。
  4. TCP 聚合内存高水位按有效总内存的 2/3 计算，适用于专用网络代理服务器。
  5. 每组参数分别测试单连接与多连接；满足双侧基线保护的候选优先，再按所选方案的综合评分选优。
  6. 即使没有候选达到绝对目标，也会应用本次会话中实测综合表现最优的候选。
  7. 不设固定候选数量；BDP/内存约束下探测，连续两档无收益停止，回落后回退精调。
  8. 每轮等待连接 300 秒；每次测量前续期 3600 秒回滚，完成后重新计时等待确认。
  9. 所有结果和原始 JSON 长期保存在 /var/lib/bbr-tcp-tuning/sessions。
USAGE
}
is_integer() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }
is_number() { [[ "${1:-}" =~ ^[0-9]+([.][0-9]+)?$ ]]; }
have() { command -v "$1" >/dev/null 2>&1; }
systemd_available() { [[ -d /run/systemd/system ]] && have systemctl; }
require_linux() { [[ "$(uname -s)" == "Linux" ]] || die "该操作只能在远程 Linux 服务器执行"; }
require_root() { (( EUID == 0 )) || die "该操作需要 root 权限，请使用 sudo"; }

need_value() {
  [[ $# -ge 2 && -n "${2:-}" ]] || die "参数 $1 缺少值"
}

parse_args() {
  if (( $# == 0 )); then
    COMMAND="menu"
    return
  fi
  case "$1" in
    kernel) COMMAND=kernel; shift; KERNEL_ARGS=("$@"); return ;;
    menu|autotune|qdisc|status|history|history-compare|history-params|apply-history|update|confirm|rollback|help) COMMAND="$1"; shift ;;
    --help|-h) COMMAND="help"; shift ;;
    --version) printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
    *) die "未知命令：$1" ;;
  esac

  while (( $# )); do
    case "$1" in
      --bandwidth-mbps) need_value "$@"; TARGET_MBPS="$2"; shift 2 ;;
      --server-address) need_value "$@"; SERVER_ADDRESS="$2"; shift 2 ;;
      --qdisc) need_value "$@"; REQUESTED_QDISC="$2"; shift 2 ;;
      --cake-bandwidth-mbps) need_value "$@"; CAKE_BANDWIDTH_MBPS="$2"; shift 2 ;;
      --iface) need_value "$@"; IFACE="$2"; shift 2 ;;
      --parallel) need_value "$@"; START_STREAMS="$2"; shift 2 ;;
      --duration) need_value "$@"; DURATION="$2"; shift 2 ;;
      --strategy) need_value "$@"; STRATEGY="$2"; shift 2 ;;
      --repeats) need_value "$@"; TEST_REPEATS="$2"; shift 2 ;;
      --target-utilization) need_value "$@"; TARGET_UTILIZATION="$2"; shift 2 ;;
      --max-retrans-percent) need_value "$@"; MAX_RETRANS_PERCENT="$2"; shift 2 ;;
      --backup) need_value "$@"; BACKUP_PATH="$2"; shift 2 ;;
      --session) need_value "$@"; HISTORY_SESSION="$2"; shift 2 ;;
      --after) HISTORY_PARAMS_AFTER="1"; shift ;;
      --channel) need_value "$@"; UPDATE_CHANNEL="$2"; shift 2 ;;
      --persist) PERSIST_FINAL="1"; shift ;;
      --force) FORCE="1"; shift ;;
      --yes|-y) YES="1"; shift ;;
      --quiet|-q) QUIET="1"; shift ;;
      --help|-h) usage; exit 0 ;;
      *) die "未知参数：$1" ;;
    esac
  done
}

configure_strategy() {
  # Weights are an explicit selection policy, not Linux congestion-control gains.
  case "$STRATEGY" in
    balanced) STRATEGY_NAME="均衡"; WEIGHT_SPEED=70; WEIGHT_STABILITY=15; WEIGHT_RETRANS=15 ;;
    speed) STRATEGY_NAME="速度优先"; WEIGHT_SPEED=90; WEIGHT_STABILITY=5; WEIGHT_RETRANS=5 ;;
    stable) STRATEGY_NAME="稳定优先"; WEIGHT_SPEED=40; WEIGHT_STABILITY=45; WEIGHT_RETRANS=15 ;;
    retrans) STRATEGY_NAME="低重传优先"; WEIGHT_SPEED=45; WEIGHT_STABILITY=10; WEIGHT_RETRANS=45 ;;
    *) die "无效调优方案：${STRATEGY}；请选择 balanced、speed、stable 或 retrans" ;;
  esac
}

validate_autotune_options() {
  validate_qdisc_options
  configure_strategy
  local name value
  for name in START_STREAMS DURATION TEST_REPEATS; do
    value="${!name}"
    [[ "$value" =~ ^[0-9]{1,9}$ ]] || die "${name} 必须是范围内的整数"
    printf -v "$name" '%s' "$((10#$value))"
  done
  is_integer "$TEST_REPEATS" && (( TEST_REPEATS >= 1 && TEST_REPEATS <= 5 )) || die "复测次数必须为 1～5 的整数"
  [[ -n "$TARGET_MBPS" ]] || die "autotune 需要 --bandwidth-mbps"
  is_number "$TARGET_MBPS" || die "目标带宽必须是正数"
  is_integer "$START_STREAMS" || die "并发流数必须是整数"
  is_integer "$DURATION" || die "测试时长必须是整数"
  is_number "$TARGET_UTILIZATION" || die "目标利用率必须是数字"
  is_number "$MAX_RETRANS_PERCENT" || die "重传比例必须是数字"
  awk -v v="$TARGET_MBPS" 'BEGIN {exit !(v>0 && v<=100000)}' || die "目标带宽必须大于 0 且不超过 100000 Mbps"
  (( START_STREAMS >= 1 && START_STREAMS <= 64 )) || die "并发流数必须在 1~64"
  (( DURATION >= 5 && DURATION <= 300 )) || die "测试时长必须在 5~300 秒"
  awk -v v="$TARGET_UTILIZATION" 'BEGIN {exit !(v>0 && v<=100)}' || die "目标利用率必须在 0~100"
  if [[ -n "$SERVER_ADDRESS" ]]; then
    [[ "$SERVER_ADDRESS" =~ ^[a-zA-Z0-9:][a-zA-Z0-9.:%_-]*$ ]] || die "服务器地址只能填写 IP 或域名，不能包含空格、协议前缀或命令字符"
  fi
  awk -v v="$MAX_RETRANS_PERCENT" 'BEGIN {exit !(v>=0 && v<=100)}' || die "重传比例必须在 0~100"
}
resolve_iface() {
  if [[ "$IFACE" != "auto" ]]; then
    printf '%s\n' "$IFACE"
    return
  fi
  ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

guess_server_address() {
  if [[ -n "$SERVER_ADDRESS" ]]; then
    printf '%s\n' "$SERVER_ADDRESS"
  elif [[ -n "${SSH_CONNECTION:-}" ]]; then
    awk '{print $3}' <<<"$SSH_CONNECTION"
  else
    ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
  fi
}

guess_client_address() {
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    awk '{print $1}' <<<"$SSH_CONNECTION"
  elif [[ -n "${SSH_CLIENT:-}" ]]; then
    awk '{print $1}' <<<"$SSH_CLIENT"
  fi
}

measure_ping_rtt() {
  local address="$1" output value
  [[ -n "$address" ]] && have ping || return 1
  output="$(ping -n -c 5 -W 2 "$address" 2>/dev/null)" || return 1
  value="$(awk -F= '/min\/avg\/max|round-trip/ {gsub(/[[:space:]]/,"",$2); split($2,a,"/"); print a[2]; exit}' <<<"$output")"
  is_number "$value" || return 1
  awk -v v="$value" 'BEGIN {printf "%.2f",v}'
}

format_bytes_mib() {
  awk -v b="${1:-0}" 'BEGIN {printf "%d bytes (%.2f MiB)",b,b/1048576}'
}

format_mib() {
  awk -v m="${1:-0}" 'BEGIN {printf "%.2f MiB",m}'
}

format_pass() {
  [[ "$1" == "yes" ]] && printf '是' || printf '否'
}

sysctl_get() { sysctl -n "$1" 2>/dev/null || true; }
sysctl_exists() { sysctl -n "$1" >/dev/null 2>&1; }

install_iperf3_if_needed() {
  have iperf3 && return 0
  require_root
  info "服务器未安装 iperf3，开始自动安装"
  if have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y iperf3
  elif have dnf; then
    dnf install -y iperf3
  elif have yum; then
    yum install -y iperf3
  elif have zypper; then
    zypper --non-interactive install iperf3
  elif have apk; then
    apk add --no-cache iperf3
  elif have pacman; then
    pacman -S --needed --noconfirm iperf3
  else
    die "无法识别服务器包管理器，请手动安装 iperf3"
  fi
  have iperf3 || die "包管理器执行完成，但仍未找到 iperf3"
  info "iperf3 已安装：$(iperf3 --version 2>/dev/null | head -1)"
}

install_python3_if_needed() {
  have python3 && return 0
  require_root
  info "服务器未安装 python3，安装 JSON 与区间统计解析依赖"
  if have apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3
  elif have dnf; then dnf install -y python3
  elif have yum; then yum install -y python3
  elif have zypper; then zypper --non-interactive install python3
  elif have apk; then apk add --no-cache python3
  elif have pacman; then pacman -S --needed --noconfirm python
  else die "请在服务器安装 python3 后重试"; fi
  have python3 || die "python3 安装失败"
}

port_is_free() {
  local port="$1" listeners
  listeners="$(ss -H -ltn 2>/dev/null)" || return 1
  if awk -v target="$port" '{addr=$4; sub(/^.*:/,"",addr); if(addr==target) found=1} END{exit !found}' <<<"$listeners"; then
    return 1
  fi
  return 0
}

choose_random_port() {
  local port attempt
  for ((attempt=1; attempt<=300; attempt++)); do
    port=$((20000 + (((RANDOM << 15) | RANDOM) % 40000)))
    if port_is_free "$port"; then
      printf '%s\n' "$port"
      return 0
    fi
  done
  return 1
}

detect_iperf_family() {
  local address="$1"
  if [[ "$address" == *:* ]]; then
    printf '%s\n' '-6'
  elif [[ "$address" =~ ^[0-9]+([.][0-9]+){3}$ ]]; then
    printf '%s\n' '-4'
  elif have getent && getent ahostsv4 "$address" >/dev/null 2>&1; then
    printf '%s\n' '-4'
  elif have getent && getent ahostsv6 "$address" >/dev/null 2>&1; then
    printf '%s\n' '-6'
  else
    printf '%s\n' '-4'
  fi
}

floor_pow2() {
  awk -v n="$1" 'BEGIN {p=1; while(p*2<=n)p*=2; print p}'
}

ceil_pow2() {
  awk -v n="$1" 'BEGIN {p=1; while(p<n)p*=2; print p}'
}

detect_memory_limits() {
  local total_kib available_kib cgroup_bytes="" cgroup_mib
  total_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  available_kib="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
  [[ -n "$available_kib" ]] || available_kib="$(awk '/^MemFree:/ {print $2}' /proc/meminfo)"
  MEM_TOTAL_MIB=$(( total_kib / 1024 ))
  MEM_AVAILABLE_MIB=$(( available_kib / 1024 ))
  MEM_EFFECTIVE_MIB="$MEM_TOTAL_MIB"

  if [[ -r /sys/fs/cgroup/memory.max ]]; then
    read -r cgroup_bytes </sys/fs/cgroup/memory.max || true
  elif [[ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]]; then
    read -r cgroup_bytes </sys/fs/cgroup/memory/memory.limit_in_bytes || true
  fi
  if [[ "$cgroup_bytes" =~ ^[0-9]+$ ]] && (( cgroup_bytes > 0 && cgroup_bytes < 9223372036854771712 )); then
    cgroup_mib=$(( cgroup_bytes / 1048576 ))
    if (( cgroup_mib > 0 && cgroup_mib < MEM_EFFECTIVE_MIB )); then
      MEM_EFFECTIVE_MIB="$cgroup_mib"
    fi
  fi

  calculate_memory_buffer_cap "$MEM_EFFECTIVE_MIB"
}

calculate_memory_buffer_cap() {
  local total_mib="$1" budget_mib page_size pages_per_mib total_pages max_pages=2147483647
  budget_mib=$(( total_mib * 2 / 3 ))
  (( budget_mib < 4 )) && budget_mib=4
  MEM_TCP_BUDGET_MIB="$budget_mib"

  # Linux stores these byte-valued sysctl entries in signed 32-bit integers on
  # common kernels. Keep the per-socket ceiling below INT_MAX while allowing
  # the system-wide TCP allocator to use the requested memory budget.
  MEM_BUFFER_CAP_MIB="$budget_mib"
  (( MEM_BUFFER_CAP_MIB > TCP_BUFFER_SYSCTL_MAX_MIB )) && MEM_BUFFER_CAP_MIB="$TCP_BUFFER_SYSCTL_MAX_MIB"
  (( MEM_BUFFER_CAP_MIB < 4 )) && MEM_BUFFER_CAP_MIB=4

  page_size="$(getconf PAGESIZE 2>/dev/null || true)"
  [[ "$page_size" =~ ^[0-9]+$ ]] || page_size=4096
  PAGE_SIZE_BYTES="$page_size"
  pages_per_mib=$(( 1048576 / page_size ))
  (( pages_per_mib < 1 )) && pages_per_mib=1
  total_pages=$(( total_mib * pages_per_mib ))

  TCP_MEM_HIGH_PAGES=$(( total_pages * 2 / 3 ))
  if (( TCP_MEM_HIGH_PAGES > max_pages )); then
    TCP_MEM_HIGH_PAGES="$max_pages"
    TCP_MEM_PRESSURE_PAGES=$(( TCP_MEM_HIGH_PAGES * 3 / 4 ))
    TCP_MEM_LOW_PAGES=$(( TCP_MEM_HIGH_PAGES / 2 ))
  else
    TCP_MEM_LOW_PAGES=$(( total_pages / 3 ))
    TCP_MEM_PRESSURE_PAGES=$(( total_pages / 2 ))
  fi
  (( TCP_MEM_LOW_PAGES < 1 )) && TCP_MEM_LOW_PAGES=1
  (( TCP_MEM_PRESSURE_PAGES <= TCP_MEM_LOW_PAGES )) && TCP_MEM_PRESSURE_PAGES=$(( TCP_MEM_LOW_PAGES + 1 ))
  (( TCP_MEM_HIGH_PAGES <= TCP_MEM_PRESSURE_PAGES )) && TCP_MEM_HIGH_PAGES=$(( TCP_MEM_PRESSURE_PAGES + 1 ))
  return 0
}
calculate_bdp() {
  BDP_BYTES="$(awk -v bw="$TARGET_MBPS" -v rtt="$RTT_MS" 'BEGIN {printf "%.0f", bw*1000000*(rtt/1000)/8}')"
  BDP_MIB="$(awk -v b="$BDP_BYTES" 'BEGIN {printf "%.2f", b/1048576}')"
}

candidate_factor() {
  local mib="$1"
  awk -v bytes="$(( mib * 1048576 ))" -v bdp="$BDP_BYTES" 'BEGIN {if(bdp<=0) print "0.00"; else printf "%.2f",bytes/bdp}'
}

add_candidate() {
  local mib="$1" existing
  for existing in "${CANDIDATE_MIBS[@]:-}"; do
    [[ "$existing" == "$mib" ]] && return 0
  done
  CANDIDATE_MIBS+=("$mib")
  CANDIDATE_FACTORS+=("$(candidate_factor "$mib")")
}

generate_candidates() {
  local need_mib current floor_bytes="$TCP_RDEFAULT"
  (( TCP_WDEFAULT > floor_bytes )) && floor_bytes="$TCP_WDEFAULT"
  CANDIDATE_MIBS=(); CANDIDATE_FACTORS=()
  need_mib="$(awk -v b="$BDP_BYTES" -v floor="$floor_bytes" 'BEGIN {if(b<floor)b=floor; print int((b+1048575)/1048576)}')"
  (( need_mib < 4 )) && need_mib=4
  (( floor_bytes <= MEM_BUFFER_CAP_MIB * 1048576 )) || die "内存预算不足以保留 TCP 原最小/默认缓存"
  # 8 BDP is a bounded experiment envelope, not a claimed Linux optimum.
  SEARCH_BUFFER_CAP_MIB="$(awk -v b="$BDP_BYTES" -v n="$need_mib" 'BEGIN {x=int((b*8+1048575)/1048576); print (x<n?n:x)}')"
  (( SEARCH_BUFFER_CAP_MIB > MEM_BUFFER_CAP_MIB )) && SEARCH_BUFFER_CAP_MIB="$MEM_BUFFER_CAP_MIB"
  current="$(ceil_pow2 "$need_mib")"
  (( current > SEARCH_BUFFER_CAP_MIB )) && current="$SEARCH_BUFFER_CAP_MIB"
  while true; do
    add_candidate "$current"
    (( current >= SEARCH_BUFFER_CAP_MIB )) && break
    current=$(( current * 2 ))
    (( current > SEARCH_BUFFER_CAP_MIB )) && current="$SEARCH_BUFFER_CAP_MIB"
  done
}

current_buffer_max() {
  local core_r core_w tcp_r tcp_w tr tw max=0 n
  core_r="$(sysctl_get net.core.rmem_max)"
  core_w="$(sysctl_get net.core.wmem_max)"
  tcp_r="$(sysctl_get net.ipv4.tcp_rmem)"
  tcp_w="$(sysctl_get net.ipv4.tcp_wmem)"
  tr="$(awk '{print $3}' <<<"$tcp_r")"
  tw="$(awk '{print $3}' <<<"$tcp_w")"
  for n in "$core_r" "$core_w" "$tr" "$tw"; do
    [[ "$n" =~ ^[0-9]+$ ]] && (( n > max )) && max="$n"
  done
  printf '%s\n' "$max"
}

root_qdisc_kind() {
  tc qdisc show dev "$1" 2>/dev/null | awk '$1=="qdisc" && $0~/[[:space:]]root([[:space:]]|$)/{print $2; exit}'
}

qdisc_error() { printf '[QDISC] %s\n' "$*" >&2; }

# Read only qdisc records; tc -s -d also includes counters and diagnostic lines.
# Format: attachment (root or normalized parent), kind, handle.
qdisc_parse_layout() {
  awk '
    function hex(s) { s=tolower(s); sub(/^0+/, "", s); return s=="" ? "0" : s }
    function id(s, a) { split(s,a,":"); return hex(a[1]) ":" (a[2]=="" ? "" : hex(a[2])) }
    $1=="qdisc" {
      if ($2=="ingress" || $2=="clsact") next
      if ($2!~/^[a-zA-Z0-9_]+$/ || $3!~/^[[:xdigit:]]+:$/) {bad=1; next}
      parent=""; isroot=0
      for(i=4;i<=NF;i++) {
        if($i=="root") isroot++
        if($i=="parent") {if(parent!="")bad=1; parent=$(i+1)}
      }
      if(isroot==1 && parent=="") {
        roots++; rootkind=$2; handle=id($3)
      } else if(isroot==0 && parent~/^[[:xdigit:]]*:[[:xdigit:]]+$/) {
        parent=id(parent)
        if(parent~/:0$/ || parent in kinds) bad=1
        kinds[parent]=$2; handles[parent]=id($3); leaves++
      } else bad=1
    }
    END {
      if(roots!=1) bad=1
      if(rootkind=="mq") {
        if(!leaves) bad=1
        for(parent in kinds) {
          split(parent,a,":")
          if(a[1] ":" != handle) bad=1
        }
      }
      if(bad) exit 1
      print "root\t" rootkind "\t" handle
      for(parent in kinds) print parent "\t" kinds[parent] "\t" handles[parent]
    }
  ' | LC_ALL=C sort
}

qdisc_read_layout() {
  local text layout
  text="$(tc qdisc show dev "$1")" || { qdisc_error "无法读取 $1 的队列，未执行队列变更"; return 1; }
  layout="$(qdisc_parse_layout <<<"$text")" || { qdisc_error "$1 的队列信息为空、不完整或格式无法确认，未执行队列变更"; return 1; }
  printf '%s\n' "$layout"
}

qdisc_safe() {
  case "$1" in noqueue|pfifo_fast|fq_codel|fq|mq) return 0 ;; *) return 1 ;; esac
}

qdisc_layout_safe() {
  local layout parent kind handle
  layout="$(qdisc_read_layout "$1")" || return 1
  while read -r parent kind handle; do
    qdisc_safe "$kind" || return 1
  done <<<"$layout"
}

# Keep root identity and leaf attachment/type; auto-assigned leaf handles may
# change when replacing a leaf. Queue options are never rewritten for a no-op.
qdisc_shape() {
  awk '{print $1, $2, ($1=="root" ? $3 : "")}' <<<"$1"
}

qdisc_can_apply_layout() {
  local layout="$1" target="$2" root handle parent kind unused
  case "$target" in fq|fq_codel|pfifo_fast|sfq|cake) ;;
    *) qdisc_error "不支持的目标队列：$target"; return 1 ;;
  esac
  read -r root handle <<<"$(awk '$1=="root"{print $2,$3}' <<<"$layout")"
  while read -r parent kind unused; do
    [[ "$kind" != "$target" ]] || continue
    if ! qdisc_safe "$kind" && [[ "${FORCE:-0}" != 1 && !( "$kind" == cake && "${QUEUE_SWITCH_READY:-0}" == 1 ) ]]; then
      qdisc_error "${parent} 上的 ${kind} 不是默认队列，保持原有 QoS 配置"
      return 1
    fi
  done <<<"$layout"
  if [[ "$root" == mq ]]; then
    while read -r parent kind unused; do
      [[ "$parent" != root && "$kind" != "$target" ]] || continue
      if [[ "$handle" == 0: ]]; then
        qdisc_error "mq 0: 的子队列 ${parent} 为 ${kind}，无法安全定位替换；保留根队列和原参数，请先由管理员配置可寻址的多队列布局"
        return 1
      fi
    done <<<"$layout"
  elif [[ "$(wc -l <<<"$layout" | tr -d ' ')" != 1 && "${FORCE:-0}" != 1 ]]; then
    qdisc_error "检测到分层队列，未执行替换；请先检查已有 QoS 配置"
    return 1
  fi
}

qdisc_preflight() {
  local layout
  layout="$(qdisc_read_layout "$1")" || return 1
  qdisc_can_apply_layout "$layout" "$2"
}

validate_qdisc_options() {
  case "$REQUESTED_QDISC" in auto|keep|fq|fq_codel|cake) ;;
    *) die "队列算法必须是 auto、keep、fq、fq_codel 或 cake" ;;
  esac
  if [[ -n "$CAKE_BANDWIDTH_MBPS" ]]; then
    [[ "$REQUESTED_QDISC" == cake ]] || die "--cake-bandwidth-mbps 仅可与 --qdisc cake 一起使用"
    is_number "$CAKE_BANDWIDTH_MBPS" && awk -v v="$CAKE_BANDWIDTH_MBPS" 'BEGIN{exit !(v==0 || (v>=0.001 && v<=100000))}' || die "CAKE 整形带宽必须为 0 或 0.001～100000 Mbps；0 表示不限速"
  fi
}

# Serialize only documented, reversible options from numeric tc JSON. Unknown
# options fail closed; no shell evaluation or rounded display values are used.
qdisc_json() {
  python3 - "$@" <<'PY_QDISC'
import json, sys, re
from decimal import Decimal

def ident(s):
    if not isinstance(s,str) or not re.fullmatch(r'[0-9a-fA-F]*:[0-9a-fA-F]*',s):
        raise ValueError('invalid qdisc handle')
    a,b=s.split(':'); return f'{int(a or "0",16):x}:' + (f'{int(b,16):x}' if b else '')

def load(path):
    data=json.load(open(path)); result={}
    if not isinstance(data,list): raise ValueError('tc JSON must be an array')
    for q in data:
        kind=q['kind']
        if kind in ('ingress','clsact'): continue
        if kind not in ('mq','noqueue','fq','fq_codel','cake'): raise ValueError(f'unsupported original queue: {kind}')
        if q.get('ingress_block') or q.get('egress_block') or q.get('offloaded'):
            raise ValueError('shared blocks or offloaded qdisc cannot be switched')
        parent='root' if q.get('root') else ident(q.get('parent'))
        if parent in result: raise ValueError('duplicate attachment')
        result[parent]={'kind':kind,'handle':ident(q['handle']),'options':q.get('options',{})}
        options(result[parent])
    if 'root' not in result: raise ValueError('missing root')
    root=result['root']
    if root['kind']=='mq':
        if len(result)<2: raise ValueError('empty mq')
        for p in result:
            if p!='root' and p.split(':')[0]+':'!=root['handle']: raise ValueError('mq parent mismatch')
    elif len(result)!=1: raise ValueError('custom hierarchical queues require keep')
    return result

def integer(v):
    if type(v)!=int or not 0<=v<=2**64-1: raise ValueError('invalid numeric option')
    return str(v)

def fwmark(v):
    # tc emits hexadecimal JSON strings (including "0"), not just integers.
    if isinstance(v,str) and re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|[0-9]+)',v):
        v=int(v,16 if v.lower().startswith('0x') else 10)
    if type(v)!=int or not 0<=v<=2**32-1: raise ValueError('invalid CAKE fwmark')
    return v

def options(q):
    kind=q['kind']; o=q['options']
    if not isinstance(o,dict): raise ValueError('invalid options')
    args=[]; known=set()
    def number(key,unit='',scale=1):
        known.add(key)
        if key in o: args.extend([key,str(int(integer(o[key]))*scale)+unit])
    def boolean(key,on,off):
        known.add(key)
        if key in o:
            if type(o[key])!=bool: raise ValueError('invalid boolean option')
            args.append(on if o[key] else off)
    def enum(key,allowed):
        known.add(key)
        if key in o:
            if o[key] not in allowed: raise ValueError(f'unsupported {key}: {o[key]}')
            args.append(o[key])
    if kind=='fq':
        for k in ('limit','flow_limit','buckets','orphan_mask','quantum','initial_quantum'): number(k)
        for k in ('maxrate','defrate','low_rate_threshold'): number(k,'bit',8)
        for k in ('refill_delay','ce_threshold','horizon'): number(k,'us')
        number('timer_slack','ns'); boolean('pacing','pacing','nopacing')
        if 'pacing' not in o: args.append('pacing')
        for k in ('horizon_cap','horizon_drop'):
            known.add(k)
            if k in o:
                if o[k] is not None: raise ValueError('invalid horizon mode')
                args.append(k)
    elif kind=='fq_codel':
        for k in ('limit','flows','quantum','memory_limit','drop_batch'): number(k)
        for k in ('target','interval','ce_threshold'): number(k,'us')
        boolean('ecn','ecn','noecn')
        if 'ecn' not in o: args.append('noecn')
        known.update(('ce_threshold_selector','ce_threshold_mask'))
        if 'ce_threshold_selector' in o or 'ce_threshold_mask' in o:
            args += ['ce_threshold_selector',integer(o['ce_threshold_selector'])+'/'+integer(o['ce_threshold_mask'])]
    elif kind=='cake':
        known.add('bandwidth')
        if 'bandwidth' not in o: raise ValueError('CAKE bandwidth missing')
        if o['bandwidth']=='unlimited': args.append('unlimited')
        else: args += ['bandwidth',str(int(integer(o['bandwidth']))*8)+'bit']
        enum('autorate',('autorate-ingress',))
        enum('diffserv',('besteffort','diffserv3','diffserv4','diffserv8'))
        enum('flowmode',('flowblind','srchost','dsthost','hosts','flows','dual-srchost','dual-dsthost','triple-isolate'))
        for k,on,off in [('nat','nat','nonat'),('wash','wash','nowash'),('ingress','ingress','egress'),('split_gso','split-gso','no-split-gso')]: boolean(k,on,off)
        known.add('ack-filter')
        if 'ack-filter' in o:
            args.append({'disabled':'no-ack-filter','enabled':'ack-filter','aggressive':'ack-filter-aggressive'}[o['ack-filter']])
        number('rtt','us'); known.add('raw')
        if o.get('raw') is True: args.append('raw')
        elif o.get('raw',False) is not False: raise ValueError('invalid raw flag')
        enum('atm',('atm','ptm','noatm'))
        known.add('overhead')
        if 'overhead' in o:
            if type(o['overhead'])!=int: raise ValueError('invalid overhead')
            args += ['overhead',str(o['overhead'])]
        for k in ('mpu','memlimit'): number(k)
        known.add('fwmark')
        if 'fwmark' in o: args += ['fwmark',hex(fwmark(o['fwmark']))]
    unknown=set(o)-known
    if unknown: raise ValueError('unrecognized options: '+','.join(sorted(unknown)))
    return args

def normalized(q):
    o=dict(q['options'])
    if q['kind']=='fq': o.setdefault('pacing',True)
    if q['kind']=='fq_codel': o.setdefault('ecn',False)
    if q['kind']=='cake': o['fwmark']=fwmark(o.get('fwmark',0))
    return q['kind'],o

try:
    mode=sys.argv[1]
    if mode=='filters':
        if json.load(open(sys.argv[2]))!=[]: raise ValueError('existing egress filters require keep')
    else:
        d=load(sys.argv[2])
        if mode=='plan':
            for p,q in sorted(d.items()): print('\t'.join((p,q['kind'],q['handle'],' '.join(options(q)))))
        elif mode=='equal':
            other=load(sys.argv[3]); ok=d.keys()==other.keys()
            for p,q in d.items():
                n=other.get(p,{})
                ok=ok and bool(n) and normalized(q)==normalized(n)
                if q['handle']!='0:': ok=ok and q['handle']==n.get('handle')
            sys.exit(0 if ok else 1)
        elif mode=='record-equal':
            original=d[sys.argv[3]]; sample=load(sys.argv[4]).get(sys.argv[3])
            ok=sample is not None and normalized(original)==normalized(sample)
            if original['handle']!='0:': ok=ok and original['handle']==sample.get('handle')
            sys.exit(0 if ok else 1)
        elif mode=='probe':
            original=d[sys.argv[3]]; sample=load(sys.argv[4])['root']
            if normalized(original)!=normalized(sample): raise ValueError('kernel did not reproduce original options')
        elif mode=='matches':
            target=sys.argv[3]; bw=sys.argv[4]; leaves=[q for p,q in d.items() if p!='root' or q['kind']!='mq']
            ok=all(q['kind']==target for q in leaves)
            if bw and target=='cake':
                rate=int(Decimal(bw)*Decimal(1000000)/8)
                ok=ok and all(q['options'].get('bandwidth')==('unlimited' if rate==0 else rate) and not q['options'].get('autorate') for q in leaves)
            sys.exit(0 if ok else 1)
        else: raise ValueError('unknown qdisc operation')
except (ValueError,KeyError,TypeError,OSError,json.JSONDecodeError) as exc:
    print('队列配置无法安全解析或重建：'+str(exc),file=sys.stderr); sys.exit(2)
PY_QDISC
}

qdisc_target_args() {
  QDISC_ARGS=()
  if [[ "$TUNING_QDISC" == cake ]]; then
    if [[ -n "$CAKE_BANDWIDTH_MBPS" ]] && awk -v b="$CAKE_BANDWIDTH_MBPS" 'BEGIN{exit !(b>0)}'; then
      QDISC_ARGS=(bandwidth "${CAKE_BANDWIDTH_MBPS}mbit")
    else
      QDISC_ARGS=(unlimited)
    fi
  fi
}

# Probe support and both directions of the switch on an isolated dummy device,
# never on the live interface. Lack of namespace privileges fails before writes.
qdisc_switch_probe() (
  local ns="bbrq-$$-${RANDOM}" created=0 parent kind handle text
  local opts=()
  trap '(( ! created )) || ip netns del "$ns" >/dev/null 2>&1' EXIT
  trap 'exit 130' INT TERM HUP
  ip netns add "$ns" || { qdisc_error '无法创建临时网络命名空间；请使用 --qdisc keep，或在有完整网络管理权限的宿主机切换'; return 1; }
  created=1
  ip -n "$ns" link add bbrprobe type dummy || return 1
  qdisc_target_args
  ip netns exec "$ns" tc qdisc replace dev bbrprobe root "$TUNING_QDISC" ${QDISC_ARGS[@]+"${QDISC_ARGS[@]}"} || return 1
  ip netns exec "$ns" tc -j -d qdisc show dev bbrprobe >"${SESSION_DIR}/qdisc-probe.json" || return 1
  qdisc_json matches "${SESSION_DIR}/qdisc-probe.json" "$TUNING_QDISC" "$CAKE_BANDWIDTH_MBPS" || return 1
  while IFS=$'\t' read -r parent kind handle text; do
    [[ "$kind" != mq && "$kind" != noqueue ]] || continue
    opts=(); [[ -z "$text" ]] || read -r -a opts <<<"$text"
    ip netns exec "$ns" tc qdisc replace dev bbrprobe root "$kind" ${opts[@]+"${opts[@]}"} || return 1
    ip netns exec "$ns" tc -j -d qdisc show dev bbrprobe >"${SESSION_DIR}/qdisc-probe.json" || return 1
    qdisc_json probe "$QDISC_ORIGINAL_JSON" "$parent" "${SESSION_DIR}/qdisc-probe.json" || return 1
    ip netns exec "$ns" tc qdisc replace dev bbrprobe root "$TUNING_QDISC" ${QDISC_ARGS[@]+"${QDISC_ARGS[@]}"} || return 1
    ip netns exec "$ns" tc -j -d qdisc show dev bbrprobe >"${SESSION_DIR}/qdisc-probe.json" || return 1
    qdisc_json matches "${SESSION_DIR}/qdisc-probe.json" "$TUNING_QDISC" "$CAKE_BANDWIDTH_MBPS" || return 1
    ip netns exec "$ns" tc qdisc replace dev bbrprobe root "$kind" ${opts[@]+"${opts[@]}"} || return 1
    ip netns exec "$ns" tc -j -d qdisc show dev bbrprobe >"${SESSION_DIR}/qdisc-probe.json" || return 1
    qdisc_json probe "$QDISC_ORIGINAL_JSON" "$parent" "${SESSION_DIR}/qdisc-probe.json" || return 1
  done <"$QDISC_ORIGINAL_PLAN"
)

prepare_qdisc_switch() {
  local iface="$1" parent kind handle text layout
  local attachment=()
  QDISC_ORIGINAL_JSON="${SESSION_DIR}/qdisc-original.json"
  QDISC_ORIGINAL_PLAN="${SESSION_DIR}/qdisc-original.tsv"
  tc -j -d qdisc show dev "$iface" >"$QDISC_ORIGINAL_JSON" || return 1
  qdisc_json plan "$QDISC_ORIGINAL_JSON" >"$QDISC_ORIGINAL_PLAN" || return 1
  layout="$(qdisc_read_layout "$iface")" || return 1
  if [[ "$TUNING_QDISC" == cake && -n "$CAKE_BANDWIDTH_MBPS" && "$(awk '$1=="root"{print $2}' <<<"$layout")" == mq ]]; then
    qdisc_error 'mq 每个发送队列独立运行；不能把网卡总整形带宽重复设置到各子队列，请留空 CAKE 带宽或选择 keep'
    return 1
  fi
  # Explicit selection authorizes replacing supported CAKE, never unknown trees.
  QUEUE_SWITCH_READY=1
  qdisc_preflight "$iface" "$TUNING_QDISC" || return 1
  if qdisc_json matches "$QDISC_ORIGINAL_JSON" "$TUNING_QDISC" "$CAKE_BANDWIDTH_MBPS"; then return 0; fi
  while IFS=$'\t' read -r parent kind handle text; do
    if [[ "$parent" == root ]]; then attachment=(root); else attachment=(parent "$parent"); fi
    tc -j filter show dev "$iface" "${attachment[@]}" >"${SESSION_DIR}/qdisc-filters.json" || return 1
    qdisc_json filters "${SESSION_DIR}/qdisc-filters.json" || return 1
  done <"$QDISC_ORIGINAL_PLAN"
  qdisc_switch_probe >"${SESSION_DIR}/qdisc-probe.log" 2>&1 || {
    cat "${SESSION_DIR}/qdisc-probe.log" >&2
    qdisc_error '队列切换或原配置恢复预检失败，尚未修改出口队列；请使用 keep 或查看 qdisc-probe.log'; return 1;
  }
}

restore_qdisc_exact() {
  local backup="$1" iface="$2" parent kind handle text current saved after
  local opts=() cmd=()
  saved="$(qdisc_parse_layout <"${backup}/qdisc.txt")" || return 1
  current="$(qdisc_read_layout "$iface")" || return 1
  if [[ "$(awk '$1=="root"{print $2}' <<<"$saved")" == mq ]]; then
    [[ "$(awk '$1=="root"{print $2,$3}' <<<"$saved")" == "$(awk '$1=="root"{print $2,$3}' <<<"$current")" && "$(awk '{print $1}' <<<"$saved")" == "$(awk '{print $1}' <<<"$current")" ]] || {
      qdisc_error 'mq 布局已变化，未重建根队列'; return 1;
    }
  elif [[ "$(wc -l <<<"$current" | tr -d ' ')" != 1 ]]; then
    qdisc_error '当前队列已变为分层布局，未执行覆盖恢复'; return 1
  fi
  tc -j -d qdisc show dev "$iface" >"${backup}/qdisc-current.json" || return 1
  qdisc_json plan "${backup}/qdisc-current.json" >"${backup}/qdisc-current.tsv" || return 1
  if qdisc_json equal "${backup}/qdisc-original.json" "${backup}/qdisc-current.json"; then return 0; fi
  [[ -f "${backup}/qdisc-changed" ]] || { qdisc_error '本次尚未修改队列；当前队列被其他操作改变，保持不动'; return 1; }
  qdisc_json plan "${backup}/qdisc-original.json" >"${backup}/qdisc-restore.tsv" || return 1
  while IFS=$'\t' read -r parent kind handle text; do
    [[ "$kind" != mq ]] || continue
    if qdisc_json record-equal "${backup}/qdisc-original.json" "$parent" "${backup}/qdisc-current.json"; then continue; fi
    cmd=(tc qdisc replace dev "$iface")
    if [[ "$parent" == root ]]; then cmd+=(root); else cmd+=(parent "$parent"); fi
    [[ "$handle" == 0: ]] || cmd+=(handle "$handle")
    opts=(); [[ -z "$text" ]] || read -r -a opts <<<"$text"
    if [[ "$kind" == noqueue ]]; then tc qdisc del dev "$iface" root || return 1
    else "${cmd[@]}" "$kind" ${opts[@]+"${opts[@]}"} || return 1; fi
  done <"${backup}/qdisc-restore.tsv"
  tc -j -d qdisc show dev "$iface" >"${backup}/qdisc-restored.json" || return 1
  qdisc_json equal "${backup}/qdisc-original.json" "${backup}/qdisc-restored.json" || { qdisc_error '队列恢复读回与原配置不一致'; return 1; }
}

select_tuning_qdisc() {
  local layout
  layout="$(qdisc_read_layout "$1")" || return 1
  TUNING_QDISC="fq"; QDISC_POLICY="manage"; PRESERVED_QDISC_LAYOUT=""
  QUEUE_SWITCH_READY=0; QDISC_ORIGINAL_JSON=""; QDISC_ORIGINAL_PLAN=""; QDISC_LAST_JSON=""
  if [[ "$REQUESTED_QDISC" == keep ]] || { [[ "$REQUESTED_QDISC" == auto ]] && awk '$2=="cake"{found=1} END{exit !found}' <<<"$layout"; }; then
    QDISC_POLICY="preserve"
    TUNING_QDISC="$(awk '$1=="root"{print $2}' <<<"$layout")"
    PRESERVED_QDISC_LAYOUT="$layout"
    info "保留现有队列及整形配置，仅调整 TCP/BBR 参数"
  elif [[ "$REQUESTED_QDISC" != auto ]]; then
    TUNING_QDISC="$REQUESTED_QDISC"
    prepare_qdisc_switch "$1" || return 1
  fi
}

qdisc_policy_summary() {
  if [[ "$QDISC_POLICY" == preserve ]]; then
    if [[ "$REQUESTED_QDISC" == keep ]]; then
      printf '保留现有队列及完整布局；不修改整形带宽、队列选项或系统默认队列'
    else
      printf '保留现有 CAKE 队列及完整布局；不修改整形带宽、队列选项或系统默认队列'
    fi
  else
    printf '使用 %s' "$TUNING_QDISC"
    if [[ "$TUNING_QDISC" == cake ]]; then
      if [[ -z "$CAKE_BANDWIDTH_MBPS" ]]; then
        printf '；CAKE 整形带宽：保留已有设置，新建时不限速'
      elif awk -v b="$CAKE_BANDWIDTH_MBPS" 'BEGIN{exit !(b==0)}'; then
        printf '；CAKE 整形带宽：不限速'
      else printf '；CAKE 整形带宽：%s Mbps' "$CAKE_BANDWIDTH_MBPS"; fi
    else printf '；不设置整形带宽'; fi
  fi
}

verify_preserved_qdisc() {
  local current
  [[ -n "$PRESERVED_QDISC_LAYOUT" ]] || { qdisc_error '缺少原队列布局，无法验证保留状态'; return 1; }
  current="$(qdisc_read_layout "$1")" || return 1
  [[ "$(qdisc_shape "$current")" == "$(qdisc_shape "$PRESERVED_QDISC_LAYOUT")" ]] || {
    qdisc_error '测速期间原队列布局已变化，停止本次候选；不会覆盖当前队列'; return 1;
  }
}

apply_tuning_qdisc() {
  if [[ "$QDISC_POLICY" == preserve ]]; then
    verify_preserved_qdisc "$1" || return 1
    printf '[QDISC] %s｜保留现有队列布局，不修改整形参数\n' "$1"
  else
    if [[ -n "$QDISC_ORIGINAL_JSON" ]]; then
      tc -j -d qdisc show dev "$1" >"${SESSION_DIR}/qdisc-before-apply.json" || return 1
      qdisc_json equal "${QDISC_LAST_JSON:-$QDISC_ORIGINAL_JSON}" "${SESSION_DIR}/qdisc-before-apply.json" || {
        qdisc_error '原队列配置已变化，未执行本次切换'; return 1;
      }
      [[ -z "$BACKUP_DIR" ]] || touch "${BACKUP_DIR}/qdisc-changed"
    fi
    apply_qdisc "$1" "$TUNING_QDISC" || return 1
    if [[ -n "$QDISC_ORIGINAL_JSON" ]]; then
      QDISC_LAST_JSON="${SESSION_DIR}/qdisc-applied.json"
      tc -j -d qdisc show dev "$1" >"$QDISC_LAST_JSON" || return 1
      qdisc_json matches "$QDISC_LAST_JSON" "$TUNING_QDISC" "$CAKE_BANDWIDTH_MBPS" || return 1
    fi
  fi
}

apply_qdisc_leaf() {
  local iface="$1" parent="$2" before="$3" target="$4" operation=replace
  local attachment=() args=()
  if [[ "$parent" == root ]]; then attachment=(root); else attachment=(parent "$parent"); fi
  if [[ "$before" == "$target" ]]; then
    [[ "$target" == cake && -n "${CAKE_BANDWIDTH_MBPS:-}" ]] || return 0
    if [[ "$parent" == root ]]; then
      local snapshot
      snapshot="$(mktemp)"
      if tc -j -d qdisc show dev "$iface" >"$snapshot" && qdisc_json matches "$snapshot" cake "$CAKE_BANDWIDTH_MBPS"; then
        rm -f "$snapshot"; return 0
      fi
      rm -f "$snapshot"
    fi
    operation=change
  fi
  if [[ "$target" == cake ]]; then
    if [[ -n "${CAKE_BANDWIDTH_MBPS:-}" ]] && awk -v b="$CAKE_BANDWIDTH_MBPS" 'BEGIN{exit !(b>0)}'; then
      args=(bandwidth "${CAKE_BANDWIDTH_MBPS}mbit")
    else args=(unlimited); fi
  fi
  tc qdisc "$operation" dev "$iface" "${attachment[@]}" "$target" ${args[@]+"${args[@]}"}
}

apply_qdisc() {
  local iface="$1" target="$2" before after expected root handle parent kind unused
  before="$(qdisc_read_layout "$iface")" || return 1
  qdisc_can_apply_layout "$before" "$target" || return 1
  read -r root handle <<<"$(awk '$1=="root"{print $2,$3}' <<<"$before")"
  if [[ "$root" == mq ]]; then
    [[ -z "${CAKE_BANDWIDTH_MBPS:-}" || "$target" != cake ]] || { qdisc_error 'mq 不支持设置整张网卡的 CAKE 整形带宽'; return 1; }
    expected="$(awk -v target="$target" 'BEGIN{OFS="\t"} $1!="root"{$2=target} {print $1,$2,$3}' <<<"$before")"
    if [[ "$(qdisc_shape "$before")" == "$(qdisc_shape "$expected")" ]]; then
      printf '[QDISC] %s｜保留 mq %s；子队列已为 %s，无需替换\n' "$iface" "$handle" "$target"
      return 0
    fi
    while read -r parent kind unused; do
      [[ "$parent" != root ]] || continue
      apply_qdisc_leaf "$iface" "$parent" "$kind" "$target" || return 1
    done <<<"$before"
    after="$(qdisc_read_layout "$iface")" || return 1
    [[ "$(qdisc_shape "$after")" == "$(qdisc_shape "$expected")" ]] || { qdisc_error '多队列读回结果与预期不一致'; return 1; }
  else
    apply_qdisc_leaf "$iface" root "$root" "$target" || return 1
    after="$(qdisc_read_layout "$iface")" || return 1
    [[ "$(awk '{print $1,$2}' <<<"$after")" == "root $target" ]] || { qdisc_error '根队列读回结果与预期不一致'; return 1; }
  fi
  if [[ "$target" == cake && -n "${CAKE_BANDWIDTH_MBPS:-}" ]]; then
    local snapshot
    snapshot="$(mktemp)"
    if ! tc -j -d qdisc show dev "$iface" >"$snapshot" || ! qdisc_json matches "$snapshot" cake "$CAKE_BANDWIDTH_MBPS"; then
      rm -f "$snapshot"; qdisc_error 'CAKE 带宽读回与请求值不一致'; return 1
    fi
    rm -f "$snapshot"
  fi
}

apply_boot_qdisc() {
  local iface="$1" target="$2"
  if [[ "${BBR_QDISC_EXPLICIT:-0}" != 1 ]]; then
    apply_qdisc "$iface" "$target"
    return
  fi
  # Explicit persistent selections may replace CAKE, but only after taking a
  # fresh snapshot and verifying recovery on this boot, under the writer lock.
  local state="${BBR_QDISC_STATE_DIR:-/var/lib/bbr-tcp-tuning}"
  local SESSION_DIR QDISC_ORIGINAL_JSON="" QDISC_ORIGINAL_PLAN="" QUEUE_SWITCH_READY=0
  local TUNING_QDISC="$target" FORCE=0
  umask 077
  mkdir -p "$state" || return 1
  exec 8>"${state}/operation.lock" || return 1
  flock -n 8 || { qdisc_error 'TCP 或队列操作正在运行，本次开机加载未修改队列'; return 1; }
  mkdir -p "${state}/queue-boot" || return 1
  SESSION_DIR="$(mktemp -d "${state}/queue-boot/$(date +%Y%m%d-%H%M%S).XXXXXX")" || return 1
  prepare_qdisc_switch "$iface" || return 1
  tc -s -d qdisc show dev "$iface" >"${SESSION_DIR}/qdisc.txt" || return 1
  tc -j -d qdisc show dev "$iface" >"${SESSION_DIR}/qdisc-before-apply.json" || return 1
  qdisc_json equal "$QDISC_ORIGINAL_JSON" "${SESSION_DIR}/qdisc-before-apply.json" || {
    qdisc_error '开机检查期间队列配置已变化，未执行切换'; return 1;
  }
  touch "${SESSION_DIR}/qdisc-changed" || return 1
  if apply_qdisc "$iface" "$target" &&
      tc -j -d qdisc show dev "$iface" >"${SESSION_DIR}/qdisc-applied.json" &&
      qdisc_json matches "${SESSION_DIR}/qdisc-applied.json" "$target" "$CAKE_BANDWIDTH_MBPS"; then
    return 0
  fi
  qdisc_error "开机队列应用失败，正在恢复本次快照：${SESSION_DIR}"
  restore_qdisc_exact "$SESSION_DIR" "$iface" || qdisc_error "恢复未完成，请通过控制台检查 ${SESSION_DIR}"
  return 1
}

render_qdisc_helper() {
  printf '#!/usr/bin/env bash\n# Managed by bbr-tune.sh\nset -Eeuo pipefail\n'
  declare -f qdisc_error qdisc_parse_layout qdisc_read_layout qdisc_safe qdisc_shape qdisc_can_apply_layout qdisc_preflight qdisc_json qdisc_target_args qdisc_switch_probe prepare_qdisc_switch restore_qdisc_exact apply_qdisc_leaf apply_qdisc apply_boot_qdisc
  cat <<'EOF_HELPER'
source /etc/default/bbr-tcp-tuning
CAKE_BANDWIDTH_MBPS="${BBR_CAKE_BANDWIDTH_MBPS:-}"
case "${BBR_QDISC_POLICY:-manage}" in
  preserve)
    printf '[QDISC] 保留已有队列；开机队列配置继续由原网络服务管理\n'
    exit 0 ;;
  manage) ;;
  *) qdisc_error '未知的开机队列策略，未修改任何队列'; exit 1 ;;
esac
iface="$BBR_IFACE"
if [[ "$iface" == auto ]]; then
  iface="$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
fi
[[ -n "$iface" ]] || { qdisc_error '无法识别出口网卡'; exit 1; }
apply_boot_qdisc "$iface" "${BBR_QDISC:-fq}"
EOF_HELPER
}

prepare_tcp_rules() {
  local rvec wvec
  rvec="$(sysctl_get net.ipv4.tcp_rmem)"; wvec="$(sysctl_get net.ipv4.tcp_wmem)"
  [[ "$rvec" =~ ^[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+$ ]] || die "无法读取合法 tcp_rmem"
  [[ "$wvec" =~ ^[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+$ ]] || die "无法读取合法 tcp_wmem"
  read -r TCP_RMIN TCP_RDEFAULT _ <<<"$rvec"
  read -r TCP_WMIN TCP_WDEFAULT _ <<<"$wvec"
  (( TCP_RMIN <= TCP_RDEFAULT && TCP_WMIN <= TCP_WDEFAULT )) || die "原 TCP 缓存向量顺序无效"
}

build_sysctl_content() {
  local buffer_bytes="$1"
  (( buffer_bytes >= TCP_RDEFAULT && buffer_bytes >= TCP_WDEFAULT )) || return 1
  if [[ "$QDISC_POLICY" != preserve ]]; then
    printf 'net.core.default_qdisc = %s\n' "$TUNING_QDISC"
  fi
  cat <<EOF_SYSCTL
# Managed by bbr-tune.sh ${VERSION}; generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Strategy=${STRATEGY}; weights throughput/stability/retrans=${WEIGHT_SPEED}/${WEIGHT_STABILITY}/${WEIGHT_RETRANS}
# Target=${TARGET_MBPS}Mbps, RTT=${RTT_MS}ms, BDP=${BDP_MIB}MiB
# Socket maxima are measured candidates, NOT an egress rate limiter.
# Keep original minima/defaults; kernel/VM/routing/application knobs are not throughput controls.
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = ${buffer_bytes}
net.core.wmem_max = ${buffer_bytes}
net.ipv4.tcp_rmem = ${TCP_RMIN} ${TCP_RDEFAULT} ${buffer_bytes}
net.ipv4.tcp_wmem = ${TCP_WMIN} ${TCP_WDEFAULT} ${buffer_bytes}
# Aggregate allocator thresholds in pages; this is not reserved memory.
net.ipv4.tcp_mem = ${TCP_MEM_LOW_PAGES} ${TCP_MEM_PRESSURE_PAGES} ${TCP_MEM_HIGH_PAGES}
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_window_scaling = 1
EOF_SYSCTL
}

UNSUPPORTED_SYSCTL_KEYS_SEEN="|"
REJECTED_SYSCTL_KEYS_SEEN="|"
filter_supported_sysctl_file() {
  local input="$1" output="$2" line key
  : >"$output"
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]]; then
      printf '%s\n' "$line" >>"$output"
      continue
    fi
    key="${line%%=*}"
    key="${key//[[:space:]]/}"
    if [[ "$REJECTED_SYSCTL_KEYS_SEEN" == *"|${key}|"* ]]; then
      printf '# rejected by runtime: %s\n' "$line" >>"$output"
    elif sysctl_exists "$key"; then
      printf '%s\n' "$line" >>"$output"
    else
      printf '# unsupported: %s\n' "$line" >>"$output"
      case "$UNSUPPORTED_SYSCTL_KEYS_SEEN" in
        *"|${key}|"*) ;;
        *) warn "当前内核不支持 ${key}，已跳过"; UNSUPPORTED_SYSCTL_KEYS_SEEN="${UNSUPPORTED_SYSCTL_KEYS_SEEN}${key}|" ;;
      esac
    fi
  done <"$input"
}

write_rule_plan() {
  RULES_FILE="${SESSION_DIR}/rules.txt"
  cat >"$RULES_FILE" <<EOF_RULES
TCP 参数决策依据
方案：${STRATEGY_NAME} (${STRATEGY})
评分权重（吞吐 / 稳定 / 低重传）：${WEIGHT_SPEED} / ${WEIGHT_STABILITY} / ${WEIGHT_RETRANS}
测量：每组单连接和多连接分别 ${TEST_REPEATS} 次，取中位数；区间波动使用发送端吞吐 CV。
BDP：${BDP_MIB} MiB；总内存技术上限：${MEM_BUFFER_CAP_MIB} MiB；本次搜索上限：${SEARCH_BUFFER_CAP_MIB} MiB。
缓存：从约 1 BDP 开始，在不超过 8 BDP 和内存预算的范围内实测；原最小/默认值不变。
扩容：只有评分未下降且尚未连续两档停滞才继续；发现回落后区间精调。
拥塞与恢复机制：BBR；启用窗口缩放、接收自动调节与 SACK/DSACK。
队列策略：$(qdisc_policy_summary)。
不调整：kernel.*、vm.*、rp_filter、ARP、邻居表、端口范围、连接重试/超时。
保留原值：Fast Open、notsent_lowat、MTU probing、backlog；缺少应用支持或瓶颈证据不修改。
不使用：已失效 tcp_fack、已废弃 tcp_adv_win_scale；不把通用 pacing 比率当作 BBR 增益。
限制：TCP 缓存不是速率限制器；不能仅靠 iperf3 认定运营商 QoS、随机丢包或 PMTU 故障。
结论：仅为本次已测试候选的最优结果，不保证全局最优；未达标仍应用最佳有效候选。
EOF_RULES
  info "本次参数记录：$RULES_FILE"
}

apply_sysctl_content() {
  local buffer_bytes="$1" raw filtered line key value before after
  raw="$(mktemp)"
  filtered="$(mktemp)"
  build_sysctl_content "$buffer_bytes" >"$raw"
  filter_supported_sysctl_file "$raw" "$filtered"
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]] && continue
    key="${line%%=*}"; key="${key//[[:space:]]/}"
    value="${line#*=}"; value="${value#${value%%[![:space:]]*}}"; value="${value%${value##*[![:space:]]}}"
    before="$(sysctl_get "$key")"
    if ! sysctl -w "${key}=${value}" >/dev/null 2>&1; then
      case "$REJECTED_SYSCTL_KEYS_SEEN" in
        *"|${key}|"*) ;;
        *) warn "运行环境拒绝写入 ${key}，已跳过并保留原值"; REJECTED_SYSCTL_KEYS_SEEN="${REJECTED_SYSCTL_KEYS_SEEN}${key}|" ;;
      esac
      rm -f "$raw" "$filtered"
      die "受管 TCP 参数 ${key} 应用失败，不能据此宣称候选生效"
    fi
    after="$(sysctl_get "$key")"
    [[ "$(awk '{$1=$1; print}' <<<"$after")" == "$(awk '{$1=$1; print}' <<<"$value")" ]] || die "${key} 读回值与请求值不一致"
    printf '[PARAM] %-36s | %s -> %s\n' "$key" "${before//$'\t'/ }" "${after//$'\t'/ }"
  done <"$filtered"
  rm -f "$raw" "$filtered"
}

ensure_bbr() {
  modprobe tcp_bbr 2>/dev/null || true
  local available
  available="$(sysctl_get net.ipv4.tcp_available_congestion_control)"
  [[ " $available " == *" bbr "* ]] || die "当前内核不支持 BBR"
  if [[ "$QDISC_POLICY" == manage ]]; then modprobe "sch_${TUNING_QDISC}" 2>/dev/null || true; fi
}

validate_candidate_kernel_state() {
  local expected="$1" rmax wmax rvec wvec rlimit wlimit cc value
  cc="$(sysctl_get net.ipv4.tcp_congestion_control)"
  [[ "$cc" == "bbr" ]] || die "BBR 未能在当前内核生效"
  rmax="$(sysctl_get net.core.rmem_max)"; wmax="$(sysctl_get net.core.wmem_max)"
  rvec="$(sysctl_get net.ipv4.tcp_rmem)"; wvec="$(sysctl_get net.ipv4.tcp_wmem)"
  rlimit="$(awk '{print $3}' <<<"$rvec")"; wlimit="$(awk '{print $3}' <<<"$wvec")"
  for value in "$rmax" "$wmax" "$rlimit" "$wlimit"; do
    [[ "$value" == "$expected" ]] || die "关键 TCP 缓存读回值与候选 ${expected} bytes 不一致"
  done
}

apply_candidate() {
  local iface="$1" buffer_mib="$2" buffer_bytes
  buffer_bytes=$(( buffer_mib * 1048576 ))
  apply_tuning_qdisc "$iface" || die "队列校验或应用失败，本候选未修改 TCP 参数"
  apply_sysctl_content "$buffer_bytes"
  validate_candidate_kernel_state "$buffer_bytes"
}

atomic_write() {
  local path="$1" mode="$2" tmp
  mkdir -p "$(dirname "$path")"
  tmp="$(mktemp "${path}.tmp.XXXXXX")"
  cat >"$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$path"
}

write_persistent_config() {
  local iface="$1" buffer_mib="$2" buffer_bytes raw filtered
  buffer_bytes=$(( buffer_mib * 1048576 ))
  raw="$(mktemp)"; filtered="$(mktemp)"
  build_sysctl_content "$buffer_bytes" >"$raw"
  filter_supported_sysctl_file "$raw" "$filtered"
  if [[ "$QDISC_POLICY" == preserve && -r "$SYSCTL_FILE" ]]; then
    awk '/^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=/ {print}' "$SYSCTL_FILE" >>"$filtered"
  fi
  atomic_write "$SYSCTL_FILE" 0644 <"$filtered"
  rm -f "$raw" "$filtered"
  write_qdisc_persistence "$iface"
}

write_qdisc_persistence() {
  local iface="$1"
  {
    printf '# Managed by bbr-tune.sh\n'
    printf 'tcp_bbr\n'
    if [[ "$QDISC_POLICY" == manage ]]; then
      printf 'sch_%s\n' "$TUNING_QDISC"
    elif [[ -r "$MODULES_FILE" ]]; then
      awk '$0!~/^[[:space:]]*tcp_bbr[[:space:]]*$/ {print}' "$MODULES_FILE"
    fi
  } | atomic_write "$MODULES_FILE" 0644
  cat <<EOF_ENV | atomic_write "$ENV_FILE" 0644
# Managed by bbr-tune.sh
BBR_IFACE=$(printf '%q' "$iface")
BBR_QDISC=$(printf '%q' "$TUNING_QDISC")
BBR_QDISC_POLICY=$(printf '%q' "$QDISC_POLICY")
BBR_CAKE_BANDWIDTH_MBPS=$(printf '%q' "$CAKE_BANDWIDTH_MBPS")
BBR_QDISC_EXPLICIT=$([[ "$REQUESTED_QDISC" == auto || "$REQUESTED_QDISC" == keep ]] && echo 0 || echo 1)
BBR_QDISC_STATE_DIR=$(printf '%q' "$STATE_DIR")
EOF_ENV
  render_qdisc_helper | atomic_write "$QDISC_HELPER" 0755
  cat <<'EOF_SERVICE' | atomic_write "$SERVICE_FILE" 0644
[Unit]
Description=TCP BBR and selected queue discipline setup
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bbr-tcp-qdisc

[Install]
WantedBy=multi-user.target
EOF_SERVICE
  if systemd_available; then
    systemctl daemon-reload
    systemctl enable bbr-tcp-tuning.service >/dev/null
    # The selected queue is already applied and verified by the caller. Do not
    # restart under the same operation lock; the helper runs on the next boot.
  elif [[ "$QDISC_POLICY" == preserve ]]; then
    info "TCP 开机配置已保存；现有队列的开机加载仍由原网络配置负责"
  else
    warn "当前未运行 systemd：队列加载文件已保存，但 ${TUNING_QDISC} qdisc 需要自行设置开机任务"
  fi
}

backup_file() {
  local backup="$1" path="$2" tag="$3"
  if [[ -e "$path" || -L "$path" ]]; then
    cp -a "$path" "${backup}/${tag}.file"
    printf '%s\tpresent\t%s\n' "$tag" "$path" >>"${backup}/files.tsv"
  else
    printf '%s\tabsent\t%s\n' "$tag" "$path" >>"${backup}/files.tsv"
  fi
}

create_backup() {
  local iface="$1" backup key value layout service_enabled="unknown" service_active="unknown"
  backup="${BACKUP_ROOT}/${SESSION_ID}"
  mkdir -p "$backup"
  : >"${backup}/files.tsv"
  backup_file "$backup" "$SYSCTL_FILE" sysctl
  backup_file "$backup" "$MODULES_FILE" modules
  backup_file "$backup" "$ENV_FILE" env
  backup_file "$backup" "$QDISC_HELPER" helper
  backup_file "$backup" "$SERVICE_FILE" service
  if systemd_available; then
    service_enabled="$(systemctl is-enabled bbr-tcp-tuning.service 2>/dev/null || true)"
    service_active="$(systemctl is-active bbr-tcp-tuning.service 2>/dev/null || true)"
  fi
  tc -s -d qdisc show dev "$iface" >"${backup}/qdisc.txt" || { error "无法备份出口队列"; return 1; }
  layout="$(qdisc_parse_layout <"${backup}/qdisc.txt")" || { error "队列备份不完整，尚未修改参数"; return 1; }
  if [[ -n "$QDISC_ORIGINAL_JSON" ]]; then
    tc -j -d qdisc show dev "$iface" >"${backup}/qdisc-original.json" || return 1
    qdisc_json equal "$QDISC_ORIGINAL_JSON" "${backup}/qdisc-original.json" || { error "队列配置在预检后发生变化，未开始修改"; return 1; }
    qdisc_json plan "${backup}/qdisc-original.json" >"${backup}/qdisc-original.tsv" || return 1
  fi
  cat >"${backup}/meta.env" <<EOF_META
IFACE=$(printf '%q' "$iface")
ROOT_QDISC=$(printf '%q' "$(awk '$1=="root"{print $2}' <<<"$layout")")
SERVICE_ENABLED=$(printf '%q' "$service_enabled")
SERVICE_ACTIVE=$(printf '%q' "$service_active")
QDISC_POLICY=$(printf '%q' "$QDISC_POLICY")
EOF_META
  : >"${backup}/sysctl.tsv"
  for key in "${TUNING_SYSCTL_KEYS[@]}"; do
    (( ! QDISC_ONLY )) || continue
    [[ "$QDISC_POLICY" != preserve || "$key" != net.core.default_qdisc ]] || continue
    if sysctl_exists "$key"; then
      value="$(sysctl_get "$key")"
      printf '%s\t%s\n' "$key" "$value" >>"${backup}/sysctl.tsv"
    fi
  done
  : >"${backup}/observed.tsv"
  for key in "${OBSERVED_SYSCTL_KEYS[@]}"; do
    value="$(sysctl_get "$key")"
    printf '%s\t%s\n' "$key" "${value:-<内核不支持>}" >>"${backup}/observed.tsv"
  done
  ln -sfn "$backup" "$LATEST_BACKUP"
  printf '%s\n' "$backup"
}

restore_files() {
  local backup="$1" tag state path
  while IFS=$'\t' read -r tag state path; do
    [[ -n "$tag" && -n "$path" ]] || continue
    if [[ "$state" == "present" ]]; then
      [[ -e "${backup}/${tag}.file" || -L "${backup}/${tag}.file" ]] || { error "缺少文件备份：${backup}/${tag}.file"; return 1; }
      rm -f "$path" || return 1
      cp -a "${backup}/${tag}.file" "$path" || return 1
    else
      rm -f "$path" || return 1
    fi
  done <"${backup}/files.tsv"
}

restore_qdisc() {
  if [[ -s "${1}/qdisc-original.json" ]]; then restore_qdisc_exact "$1" "$2"; return; fi
  local backup="$1" iface="$2" recorded_kind="$3" saved current after root handle current_root current_handle parent leaf unused present
  [[ -r "${backup}/qdisc.txt" ]] || { qdisc_error '缺少原始队列备份，当前队列保持不动'; return 1; }
  saved="$(qdisc_parse_layout <"${backup}/qdisc.txt")" || { qdisc_error '队列备份无法解析，当前队列保持不动'; return 1; }
  read -r root handle <<<"$(awk '$1=="root"{print $2,$3}' <<<"$saved")"
  [[ -z "$recorded_kind" || "$root" == "$recorded_kind" ]] || { qdisc_error '队列备份与元数据不一致'; return 1; }
  current="$(qdisc_read_layout "$iface")" || return 1
  if [[ "${4:-manage}" == preserve ]]; then
    [[ "$(qdisc_shape "$saved")" == "$(qdisc_shape "$current")" ]] || {
      qdisc_error '原队列布局已被其他操作改变；本次调优未修改队列，不执行覆盖恢复'; return 1;
    }
    printf '[QDISC] %s｜本次调优未修改队列，保留原有队列配置\n' "$iface"
    return 0
  fi
  if [[ "$(qdisc_shape "$saved")" == "$(qdisc_shape "$current")" ]]; then
    printf '[QDISC] %s｜队列布局与备份一致，保留现有队列\n' "$iface"
    return 0
  fi
  read -r current_root current_handle <<<"$(awk '$1=="root"{print $2,$3}' <<<"$current")"
  if [[ "$root" == mq ]]; then
    # Do not delete/recreate an mq root, even after a partially failed operation.
    if [[ "$current_root" != mq || "$current_handle" != "$handle" ||
          "$(awk '{print $1}' <<<"$saved")" != "$(awk '{print $1}' <<<"$current")" ]]; then
      qdisc_error "${iface} 的 mq 根句柄或子队列拓扑已变化，保持当前队列；请参考 ${backup}/qdisc.txt 手工恢复"
      return 1
    fi
    # Validate the complete restore plan before writing the first leaf.
    while read -r parent leaf unused; do
      [[ "$parent" != root ]] || continue
      present="$(awk -v p="$parent" '$1==p{print $2}' <<<"$current")"
      [[ "$leaf" != "$present" ]] || continue
      if [[ "$handle" == 0: ]]; then
        qdisc_error "无法安全定位 mq 0: 的子队列 ${parent}，未删除根队列；请参考 ${backup}/qdisc.txt 手工恢复"
        return 1
      fi
      qdisc_safe "$present" || { qdisc_error "${parent} 已变为自定义队列 ${present}，保持当前队列"; return 1; }
      case "$leaf" in fq|fq_codel|pfifo_fast|sfq|cake) ;;
        *) qdisc_error "子队列 ${parent} 的 ${leaf} 无法自动恢复"; return 1 ;;
      esac
    done <<<"$saved"
    while read -r parent leaf unused; do
      [[ "$parent" != root ]] || continue
      present="$(awk -v p="$parent" '$1==p{print $2}' <<<"$current")"
      [[ "$leaf" != "$present" ]] || continue
      tc qdisc replace dev "$iface" parent "$parent" "$leaf" || return 1
    done <<<"$saved"
    after="$(qdisc_read_layout "$iface")" || return 1
    [[ "$(qdisc_shape "$saved")" == "$(qdisc_shape "$after")" ]] || { qdisc_error '恢复后的多队列读回不一致'; return 1; }
  else
    # A flat root can be restored directly; never flatten an unexpected tree.
    [[ "$(wc -l <<<"$saved" | tr -d ' ')" == 1 &&
       "$(wc -l <<<"$current" | tr -d ' ')" == 1 ]] || { qdisc_error '队列层级已变化，未执行根队列恢复'; return 1; }
    qdisc_safe "$current_root" || { qdisc_error '当前为自定义根队列，保持不动'; return 1; }
    case "$root" in
      noqueue)
        # A noqueue root is supplied by the device, not created with replace.
        [[ "$current_root" != noqueue ]] || return 0
        tc qdisc del dev "$iface" root || return 1 ;;
      pfifo_fast|fq|fq_codel|sfq|cake)
        if [[ "$handle" == 0: ]]; then
          tc qdisc replace dev "$iface" root "$root" || return 1
        else
          tc qdisc replace dev "$iface" root handle "$handle" "$root" || return 1
        fi ;;
      *) qdisc_error "原队列 ${root} 无法自动重建，保持当前队列"; return 1 ;;
    esac
    after="$(qdisc_read_layout "$iface")" || return 1
    [[ "$(awk '{print $1,$2}' <<<"$after")" == "root $root" ]] || { qdisc_error '恢复后的根队列读回不一致'; return 1; }
    [[ "$handle" == 0: || "$(awk '$1=="root"{print $3}' <<<"$after")" == "$handle" ]] || return 1
  fi
}

restore_backup() {
  local backup="$1" iface="" kind="" key value after failed=0
  local IFACE="" ROOT_QDISC="" ROOT_QDISC_KIND="" SERVICE_ENABLED="unknown" SERVICE_ACTIVE="unknown" QDISC_POLICY="manage"
  [[ -r "${backup}/meta.env" && -r "${backup}/sysctl.tsv" && -r "${backup}/files.tsv" ]] || {
    error "备份文件不完整：$backup"; return 1;
  }
  source "${backup}/meta.env" || return 1
  iface="$IFACE"; kind="${ROOT_QDISC:-$ROOT_QDISC_KIND}"
  if systemd_available; then systemctl disable --now bbr-tcp-tuning.service >/dev/null 2>&1 || true; fi
  restore_files "$backup" || failed=1
  while IFS=$'\t' read -r key value; do
    [[ -n "$key" ]] || continue
    if ! sysctl -w "${key}=${value}" >/dev/null 2>&1; then
      error "恢复失败：${key}"; failed=1; continue
    fi
    after="$(sysctl_get "$key")"
    if [[ "$(awk '{$1=$1;print}' <<<"$after")" != "$(awk '{$1=$1;print}' <<<"$value")" ]]; then
      error "恢复读回不一致：${key}"; failed=1
    fi
  done <"${backup}/sysctl.tsv"
  restore_qdisc "$backup" "$iface" "$kind" "$QDISC_POLICY" || { error "队列恢复失败：${iface}，详见 ${backup}/qdisc.txt"; failed=1; }
  if systemd_available; then
    systemctl daemon-reload >/dev/null 2>&1 || failed=1
    if [[ -f "$SERVICE_FILE" ]]; then
      if [[ "$SERVICE_ENABLED" == "enabled" ]]; then
        systemctl enable bbr-tcp-tuning.service >/dev/null 2>&1 || failed=1
      else
        systemctl disable bbr-tcp-tuning.service >/dev/null 2>&1 || failed=1
      fi
      if [[ "$SERVICE_ACTIVE" == "active" ]]; then
        # The oneshot only applies qdisc settings. Re-running a restored older
        # helper could overwrite the queue we just recovered.
        info "开机服务文件及启用状态已还原；本次不重新执行旧队列脚本，当前队列以备份恢复结果为准"
      fi
    fi
  fi
  (( failed == 0 )) || { error "未能完整恢复；请检查备份和日志后重试：$backup"; return 1; }
}

pending_path() { printf '%s/%s\n' "$PENDING_DIR" "$(basename "$1")"; }

schedule_rollback() {
  local backup="$1" pending unit pid token runner started
  (( AUTO_ROLLBACK_SECONDS > 0 )) || return 0
  pending="$(pending_path "$backup")"
  mkdir -p "$pending"
  printf '%s\n' "$backup" >"${pending}/backup"
  token="$(date +%s)-$$-${RANDOM}-${RANDOM}"
  printf '%s\n' "$token" >"${pending}/armed"
  runner="${backup}/rollback-runner.sh"
  [[ -s "$runner" ]] || cp "$SCRIPT_PATH" "$runner"
  chmod 0700 "$runner"
  rm -f "${pending}/owner"
  if [[ "$TUNING_ACTIVE" == 1 ]]; then
    started="$(process_start_id "$$" || true)"
    [[ -z "$started" ]] || printf '%s %s\n' "$$" "$started" >"${pending}/owner"
  fi
  if have systemd-run && systemd_available; then
    unit="bbr-tcp-rollback-${token}"
    systemd-run --quiet --unit "$unit" --on-active="${AUTO_ROLLBACK_SECONDS}s" \
      /usr/bin/env BBR_AUTO_ROLLBACK=1 "BBR_ROLLBACK_TOKEN=$token" /bin/bash "$runner" rollback --backup "$backup" --yes
    printf 'TYPE=systemd\nID=%q\n' "$unit" >"${pending}/timer.env"
  else
    nohup /bin/bash -c '
      sleep "$1"; [[ -f "$2" ]] || exit 0
      BBR_AUTO_ROLLBACK=1 BBR_ROLLBACK_TOKEN="$6" /bin/bash "$3" rollback --backup "$4" --yes >>"$5" 2>&1
    ' _ "$AUTO_ROLLBACK_SECONDS" "${pending}/armed" "$runner" "$backup" "${backup}/rollback.log" "$token" 8>&- >/dev/null 2>&1 &
    pid=$!
    printf 'TYPE=process\nID=%q\nSTART=%q\n' "$pid" "$(process_start_id "$pid" || true)" >"${pending}/timer.env"
  fi
  ln -sfn "$pending" "$PENDING_LATEST"
  warn "已启用 ${AUTO_ROLLBACK_SECONDS} 秒安全回滚；确认服务器正常后执行 sudo $PROGRAM confirm"
}

cancel_pending_dir() {
  local pending="$1" type="" id="" recorded real started="" actual=""
  if [[ ! -d "$pending" ]]; then
    [[ -L "$PENDING_LATEST" ]] && rm -f "$PENDING_LATEST"
    return 0
  fi
  if [[ -r "${pending}/timer.env" ]]; then
    local TYPE="" ID="" START=""
    # shellcheck disable=SC1090
    source "${pending}/timer.env"
    type="$TYPE"; id="$ID"; started="$START"
  fi
  rm -f "${pending}/armed"
  if [[ "${BBR_AUTO_ROLLBACK:-0}" != "1" ]]; then
    case "$type" in
      systemd) systemctl stop "${id}.timer" "${id}.service" >/dev/null 2>&1 || true ;;
      process)
        if [[ "$id" =~ ^[0-9]+$ ]]; then
          actual="$(process_start_id "$id" || true)"
          if [[ -n "$started" && "$actual" == "$started" ]] || jobs -p | grep -Fxq "$id"; then
            kill "$id" 2>/dev/null || true
            wait "$id" 2>/dev/null || true
          fi
        fi
        ;;
    esac
  fi
  recorded="$(readlink -f "$PENDING_LATEST" 2>/dev/null || true)"
  real="$(readlink -f "$pending" 2>/dev/null || printf '%s' "$pending")"
  rm -rf "$pending"
  if [[ "$recorded" == "$real" || -L "$PENDING_LATEST" && -z "$recorded" ]]; then
    rm -f "$PENDING_LATEST"
  fi
  return 0
}

cancel_rollback_for_backup() {
  cancel_pending_dir "$(pending_path "$1")"
}

pending_guard() {
  local pending backup=""
  pending="$(readlink -f "$PENDING_LATEST" 2>/dev/null || true)"
  if [[ -z "$pending" ]]; then
    if [[ -L "$PENDING_LATEST" ]]; then
      rm -f "$PENDING_LATEST"
      warn "已清理失效的安全回滚标记"
    fi
    return 0
  fi
  if [[ ! -d "$pending" ]]; then
    rm -f "$PENDING_LATEST"
    warn "已清理不存在的安全回滚记录"
    return 0
  fi
  if [[ -r "${pending}/backup" ]]; then
    backup="$(cat "${pending}/backup" 2>/dev/null || true)"
  fi
  if [[ -f "${pending}/armed" ]]; then
    warn "检测到上一次调优尚未确认；新一轮调优将以当前服务器参数作为基线"
    cancel_pending_dir "$pending"
    info "已取消上一次安全回滚计时器，新会话可以继续"
  else
    cancel_pending_dir "$pending"
    info "已清理上一次会话遗留的无效状态"
  fi
  if [[ -n "$backup" && ! -d "$backup" ]]; then
    warn "上一次会话的备份目录已不存在：$backup"
  fi
}
confirm_tuning() {
  require_linux; require_root
  local pending backup
  pending="$(readlink -f "$PENDING_LATEST" 2>/dev/null || true)"
  if [[ -z "$pending" || ! -d "$pending" ]]; then
    info "当前没有待确认的参数"
    return
  fi
  backup="$(cat "${pending}/backup")"
  cancel_rollback_for_backup "$backup"
  info "已确认保留当前参数，安全回滚已取消"
}

rollback_command() {
  require_linux; require_root
  local backup="$BACKUP_PATH"
  [[ -n "$backup" ]] || backup="$(readlink -f "$LATEST_BACKUP" 2>/dev/null || true)"
  [[ -n "$backup" && -d "$backup" ]] || die "未找到可用备份"
  if (( ! YES )) && [[ -t 0 ]]; then
    local answer
    read -r -p "确认恢复 ${backup}？[y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || return 0
  elif (( ! YES )); then
    die "非交互回滚需要 --yes"
  fi
  if [[ "${BBR_AUTO_ROLLBACK:-0}" == 1 ]]; then
    local pending token
    pending="$(pending_path "$backup")"
    token="$(cat "${pending}/armed" 2>/dev/null || true)"
    [[ -n "${BBR_ROLLBACK_TOKEN:-}" && "$token" == "$BBR_ROLLBACK_TOKEN" ]] || { info "本次定时回滚已取消或更新，跳过"; return 0; }
  fi
  if restore_backup "$backup"; then
    cancel_rollback_for_backup "$backup"
    info "服务器 TCP/BBR 参数已恢复：$backup"
  else
    die "回滚未完整完成；备份已保留，请检查 ${backup} 后重试"
  fi
}

capture_state() {
  local iface="$1" file="$2" key
  {
    printf 'time=%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'kernel=%s\n' "$(uname -srmo)"
    printf 'bbr_runtime_version=%s\n' "$(cat /sys/module/tcp_bbr/version 2>/dev/null || echo unknown)"
    printf 'interface=%s\n' "$iface"
    printf 'memory_total_mib=%s\n' "$MEM_TOTAL_MIB"
    printf 'memory_available_mib=%s\n' "$MEM_AVAILABLE_MIB"
    printf 'memory_effective_mib=%s\n' "$MEM_EFFECTIVE_MIB"
    printf 'memory_tcp_budget_mib=%s\n' "$MEM_TCP_BUDGET_MIB"
    printf 'memory_buffer_cap_mib=%s\n' "$MEM_BUFFER_CAP_MIB"
    printf 'tcp_mem_pages=%s %s %s\n' "$TCP_MEM_LOW_PAGES" "$TCP_MEM_PRESSURE_PAGES" "$TCP_MEM_HIGH_PAGES"
    printf '%s=%s\n' net.ipv4.tcp_available_congestion_control "$(sysctl_get net.ipv4.tcp_available_congestion_control)"
    for key in "${OBSERVED_SYSCTL_KEYS[@]}"; do
      if sysctl_exists "$key"; then
        printf '%s=%s\n' "$key" "$(sysctl_get "$key")"
      else
        printf '%s=%s\n' "$key" "<unsupported>"
      fi
    done
    printf '\n[qdisc]\n'
    tc -s -d qdisc show dev "$iface" 2>&1 || true
    if have nstat; then
      printf '\n[tcp-counters]\n'
      nstat -az 2>/dev/null | awk '/TcpRetransSegs|TcpExtTCPTimeouts|TcpExtTCPLoss|TcpExtTCPSackRecovery|TcpExtTCPDSACKRecv/{print}' || true
    fi
  } >"$file"
}

init_session() {
  SESSION_ID="$(date +%Y%m%d-%H%M%S)-$$"
  SESSION_DIR="${SESSION_ROOT}/${SESSION_ID}"
  mkdir -p "$SESSION_DIR"
  RUN_LOG="${SESSION_DIR}/run.log"
  REPORT_FILE="${SESSION_DIR}/results.tsv"
  COMPARISON_FILE="${SESSION_DIR}/comparison.txt"
  : >"$RUN_LOG"
  exec > >(tee -a "$RUN_LOG" 8>&-) 2>&1
  ui_init
  printf 'stage\tround\tmode\tconfig\tstreams\tbuffer_mib\tbdp_ratio\trtt_ms\tmbps\tretrans\tretrans_percent\tmetric_score\tpassed\tbalance_score\teligible\tstrategy\tcv_percent\tmeasured_rtt_ms\trepeats\n' >"$REPORT_FILE"
}

parse_iperf_json() {
  local file="$1" expected_streams="${2:-0}" expected_duration="${3:-0}" values
  have python3 || { error "解析 JSON 需要服务器 python3"; return 1; }
  values="$(python3 - "$file" "$expected_streams" "$expected_duration" <<'PY_JSON'
import json, math, statistics, sys

def number(v, field, positive=False):
    if isinstance(v, bool) or not isinstance(v, (float, int)) or not math.isfinite(v):
        raise ValueError(f"{field}={v!r}；需要有限数值")
    if v < 0 or (positive and v <= 0):
        requirement = "大于 0" if positive else "大于或等于 0"
        raise ValueError(f"{field}={v!r}；要求{requirement}")
    return v

try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
    if data.get("error"):
        raise ValueError(data["error"])
    start = data["start"]
    test = start["test_start"]
    if test.get("protocol") != "TCP" or test.get("reverse") != 1:
        raise ValueError(f"start.test_start：要求 TCP 反向测试，实际 protocol={test.get('protocol')!r}, reverse={test.get('reverse')!r}")
    sent = data["end"]["sum_sent"]
    sent_rate = number(sent.get("bits_per_second"), "end.sum_sent.bits_per_second", True)
    sent_bytes = number(sent.get("bytes"), "end.sum_sent.bytes", True)
    retrans = number(sent.get("retransmits"), "end.sum_sent.retransmits")
    streams = data["end"].get("streams", [])
    if int(sys.argv[2]) and len(streams) != int(sys.argv[2]):
        raise ValueError(f"end.streams：实际 {len(streams)} 个流，要求 {sys.argv[2]} 个流")
    if int(sys.argv[3]) and number(sent.get("seconds"), "end.sum_sent.seconds", True) < int(sys.argv[3]) - 2:
        raise ValueError(f"end.sum_sent.seconds={sent['seconds']!r}；未达到请求时长 {sys.argv[3]} 秒（容差 2 秒）")
    received = data["end"].get("sum_received", {})
    rate, rate_source = sent_rate, "sender"
    if "bits_per_second" in received:
        receiver_rate = number(received["bits_per_second"], "end.sum_received.bits_per_second")
        receiver_bytes = number(received.get("bytes", 0), "end.sum_received.bytes")
        number(received.get("seconds", 0), "end.sum_received.seconds")
        # This parser consumes reverse-test SERVER output. iperf3 can emit an
        # unreported receiver summary with a positive duration and zero bytes/rate.
        # Its sender flag describes the local role, not the name of the summary.
        # Legacy server output may omit role flags; an explicit receiving role
        # or any positive received byte count must never be treated as a placeholder.
        placeholder = (receiver_rate == 0 and receiver_bytes == 0
                       and sent.get("sender") is not False
                       and received.get("sender") is not False)
        if placeholder:
            rate_source = "sender-unreported-receiver"
        else:
            rate, rate_source = number(receiver_rate, "end.sum_received.bits_per_second", True), "receiver"

    mss = start.get("tcp_mss_default", 0)
    if isinstance(mss, (int, float)) and math.isfinite(mss) and 0 < mss <= 65535:
        mss, retrans_source = float(mss), "estimated-mss"
    else:
        mss, retrans_source = 1448, "estimated-1448"
    rtts, min_rtts = [], []
    for stream_index, item in enumerate(streams):
        sender = item.get("sender", item)
        for field, target in (("mean_rtt", rtts), ("min_rtt", min_rtts)):
            if field in sender:
                value = number(sender[field], f"end.streams[{stream_index}].sender.{field}")
                if value > 0:
                    target.append(value / 1000)
    rates = []
    for interval_index, interval in enumerate(data.get("intervals", [])):
        total = interval.get("sum")
        if total is None:
            parts = interval.get("streams", [])
            if not parts:
                continue
            total = dict(start=min(x["start"] for x in parts), end=max(x["end"] for x in parts),
                         bits_per_second=sum(x["bits_per_second"] for x in parts),
                         omitted=any(x.get("omitted", False) for x in parts))
        # Ignore the first second and very short tail intervals, not real zero-throughput samples.
        if total.get("omitted") or total.get("start", 0) < 1 or total["end"] - total["start"] < 0.5:
            continue
        rates.append(number(total.get("bits_per_second"), f"intervals[{interval_index}].sum.bits_per_second"))
    cv = "NA"
    if len(rates) >= 3 and statistics.mean(rates) > 0:
        cv = f"{statistics.pstdev(rates)/statistics.mean(rates)*100:.4f}"
    rtt = statistics.mean(rtts) if rtts else 0
    minimum = min(min_rtts) if min_rtts else rtt
    connected = start.get("connected", [])
    client = connected[0].get("remote_host", "-") if connected else "-"
    print(f"{rate/1e6:.2f}\t{sent_bytes:.0f}\t{retrans:.0f}\t{retrans*mss/sent_bytes*100:.4f}"
          f"\t{rtt:.2f}\t{client}\t{cv}\t{minimum:.2f}\t{retrans_source}\t{rate_source}")
except (ValueError, KeyError, TypeError, AttributeError, OSError, OverflowError) as exc:
    print(f"[PARSE] 测试结果校验失败：{exc}", file=sys.stderr)
    sys.exit(1)
PY_JSON
)" || return 1
  IFS=$'\t' read -r RESULT_MBPS RESULT_BYTES RESULT_RETRANS RESULT_RETRANS_PERCENT RESULT_RTT_MS \
    RESULT_CLIENT_ADDRESS RESULT_CV_PERCENT RESULT_MIN_RTT_MS RESULT_RETRANS_SOURCE RESULT_RATE_SOURCE <<<"$values"
  RESULT_RTT_SOURCE="iperf3 JSON"
}

adopt_measured_rtt() {
  if is_number "$RESULT_RTT_MS" && awk -v v="$RESULT_RTT_MS" 'BEGIN {exit !(v>0)}'; then
    RTT_MS="$RESULT_RTT_MS"
    RTT_SOURCE="${RESULT_RTT_SOURCE:-TCP 实测均值}"
    if awk -v v="$RESULT_MIN_RTT_MS" 'BEGIN {exit !(v>0)}'; then
      RTT_MS="$RESULT_MIN_RTT_MS"; RTT_SOURCE="iperf3 最小 RTT（无此字段时使用均值）"
    fi
  fi
}

print_interval_log() {
  local file="$1"
  have python3 || return 0
  python3 - "$file" <<'PY_INTERVALS' || true
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        data=json.load(fh)
    rows=[]
    for item in data.get("intervals", []):
        total=item.get("sum")
        if not total:
            streams=item.get("streams", [])
            total={
                "start": min((x.get("start",0) for x in streams), default=0),
                "end": max((x.get("end",0) for x in streams), default=0),
                "bits_per_second": sum(x.get("bits_per_second",0) for x in streams),
                "retransmits": sum(x.get("retransmits",0) for x in streams),
            }
        rows.append((total.get("start",0),total.get("end",0),total.get("bits_per_second",0)/1e6,total.get("retransmits",0)))
    if rows:
        print("[TEST ] 区间日志：")
        for start,end,mbps,retr in rows:
            print(f"[TEST ] {start:5.1f}-{end:5.1f}s  {mbps:9.2f} Mbps  Retr={retr}")
except Exception:
    pass
PY_INTERVALS
}

calculate_result_quality() {
  local min_mbps
  min_mbps="$(awk -v bw="$TARGET_MBPS" -v p="$TARGET_UTILIZATION" 'BEGIN {printf "%.4f",bw*p/100}')"
  RESULT_PASS="$(awk -v s="$RESULT_MBPS" -v min="$min_mbps" -v r="$RESULT_RETRANS_PERCENT" -v maxr="$MAX_RETRANS_PERCENT" -v retr="$RESULT_RETRANS" \
    'BEGIN {print (s>=min && r<=maxr && (maxr>0 || retr==0))?"yes":"no"}')"
  RESULT_SCORE="$(awk -v s="$RESULT_MBPS" -v t="$TARGET_MBPS" 'BEGIN {printf "%.4f",(t>0?s/t*100:0)}')"
}

capture_pair_single() {
  PAIR_SINGLE_MBPS="$RESULT_MBPS"
  PAIR_SINGLE_RETRANS="$RESULT_RETRANS"
  PAIR_SINGLE_RETRANS_PERCENT="$RESULT_RETRANS_PERCENT"
  PAIR_SINGLE_SCORE="$RESULT_SCORE"
  PAIR_SINGLE_PASS="$RESULT_PASS"
  PAIR_SINGLE_CV_PERCENT="$RESULT_CV_PERCENT"
  PAIR_SINGLE_RTT_MS="$RESULT_RTT_MS"
}

capture_pair_multi() {
  PAIR_MULTI_MBPS="$RESULT_MBPS"
  PAIR_MULTI_RETRANS="$RESULT_RETRANS"
  PAIR_MULTI_RETRANS_PERCENT="$RESULT_RETRANS_PERCENT"
  PAIR_MULTI_SCORE="$RESULT_SCORE"
  PAIR_MULTI_PASS="$RESULT_PASS"
  PAIR_MULTI_CV_PERCENT="$RESULT_CV_PERCENT"
  PAIR_MULTI_RTT_MS="$RESULT_RTT_MS"
}

calculate_pair_quality() {
  local enforce_guard="${1:-yes}" values
  values="$(awk \
    -v sm="$PAIR_SINGLE_MBPS" -v mm="$PAIR_MULTI_MBPS" \
    -v sr="$PAIR_SINGLE_RETRANS_PERCENT" -v mr="$PAIR_MULTI_RETRANS_PERCENT" \
    -v sret="$PAIR_SINGLE_RETRANS" -v mret="$PAIR_MULTI_RETRANS" \
    -v scv="$PAIR_SINGLE_CV_PERCENT" -v mcv="$PAIR_MULTI_CV_PERCENT" \
    -v st="$PAIR_SINGLE_RTT_MS" -v mt="$PAIR_MULTI_RTT_MS" \
    -v bst="$BASELINE_SINGLE_RTT_MS" -v bmt="$BASELINE_MULTI_RTT_MS" \
    -v ws="$WEIGHT_SPEED" -v wv="$WEIGHT_STABILITY" -v wr="$WEIGHT_RETRANS" \
    -v target="$TARGET_MBPS" -v util="$TARGET_UTILIZATION" -v maxr="$MAX_RETRANS_PERCENT" \
    -v bsm="$BASELINE_SINGLE_MBPS" -v bmm="$BASELINE_MULTI_MBPS" \
    -v retain="$BALANCE_MIN_RETENTION_PERCENT" -v enforce="$enforce_guard" '
    function min(a,b) {return (a<b?a:b)}
    function stability(cv,rtt,base, inflation) {
      if(cv=="NA" || rtt<=0) return 0
      inflation=(base>0 && rtt>base ? rtt/base-1 : 0)
      return 100/(1+cv/20+4*inflation)
    }
    BEGIN {
      sq=min(sm/target*100,120); mq=min(mm/target*100,120)
      throughput=(sq+mq>0 ? 2*sq*mq/(sq+mq) : 0)
      stable=min(stability(scv,st,bst),stability(mcv,mt,bmt))
      scale=(maxr>0 ? maxr : 0.05)
      loss=min(100/(1+sr/scale),100/(1+mr/scale))
      score=(ws*throughput+wv*stable+wr*loss)/100
      eligible=1
      if(enforce=="yes") {
        if(bsm>0 && sm<bsm*retain/100) eligible=0
        if(bmm>0 && mm<bmm*retain/100) eligible=0
      }
      minimum=target*util/100
      passed=(sm>=minimum && mm>=minimum && sr<=maxr && mr<=maxr && (maxr>0 || (sret==0 && mret==0)) ? "yes" : "no")
      printf "%.4f\t%s\t%s",score,(eligible?"yes":"no"),passed
    }')"
  IFS=$'\t' read -r PAIR_SCORE PAIR_ELIGIBLE PAIR_PASS <<<"$values"
}

validate_strategy_metrics() {
  if [[ "$STRATEGY" == "stable" ]]; then
    is_number "$RESULT_CV_PERCENT" && is_number "$RESULT_RTT_MS" && \
      awk -v rtt="$RESULT_RTT_MS" 'BEGIN {exit !(rtt>0)}' || \
      die "稳定优先缺少有效区间波动或 RTT 数据；本轮不能用于稳定性评价"
  fi
}

run_repeated_test() {
  local label="$1" streams="$2" address="$3" display="$4" rep values
  local measurements="${SESSION_DIR}/${label}.measurements.tsv"
  : >"$measurements"
  for ((rep=1; rep<=TEST_REPEATS; rep++)); do
    if [[ "$TUNING_ACTIVE" == "1" ]] && (( AUTO_ROLLBACK_SECONDS > 0 )); then
      cancel_rollback_for_backup "$BACKUP_DIR"
      schedule_rollback "$BACKUP_DIR"
    fi
    run_reverse_test "${label}-r${rep}" "$streams" "$address" "${display}｜复测 ${rep}/${TEST_REPEATS}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$RESULT_MBPS" "$RESULT_RETRANS_PERCENT" "$RESULT_RTT_MS" \
      "$RESULT_CV_PERCENT" "$RESULT_MIN_RTT_MS" "$RESULT_RETRANS" "$RESULT_BYTES" "$RESULT_RATE_SOURCE" "$RESULT_RETRANS_SOURCE" >>"$measurements"
  done
  values="$(python3 - "$measurements" <<'PY_REPEAT'
import sys, statistics
with open(sys.argv[1]) as f: rows=[line.strip().split("\t") for line in f]
def med(i): return statistics.median(float(row[i]) for row in rows)
speeds=[float(row[0]) for row in rows]
cv="NA"
if all(row[3]!="NA" for row in rows):
    between=statistics.pstdev(speeds)/statistics.mean(speeds)*100 if statistics.mean(speeds)>0 else 100
    cv=f"{max(med(3),between):.4f}"
mins=[float(row[4]) for row in rows if float(row[4])>0]
print(f"{med(0):.2f}\t{med(1):.4f}\t{med(2):.2f}\t{cv}\t{min(mins) if mins else 0:.2f}"
      f"\t{sum(float(r[5]) for r in rows):.0f}\t{sum(float(r[6]) for r in rows):.0f}")
PY_REPEAT
)" || die "无法汇总重复测量结果"
  IFS=$'\t' read -r RESULT_MBPS RESULT_RETRANS_PERCENT RESULT_RTT_MS RESULT_CV_PERCENT \
    RESULT_MIN_RTT_MS RESULT_RETRANS RESULT_BYTES <<<"$values"
  validate_strategy_metrics
  calculate_result_quality
}

run_balanced_pair() {
  local label="$1" address="$2" display="$3" enforce_guard="${4:-yes}"
  run_repeated_test "${label}-single" 1 "$address" "${display}｜单连接"
  capture_pair_single
  [[ -n "$RTT_MS" ]] || adopt_measured_rtt
  run_repeated_test "${label}-multi" "$BALANCE_MULTI_STREAMS" "$address" "${display}｜${BALANCE_MULTI_STREAMS} 连接"
  capture_pair_multi
  [[ -n "$RTT_MS" ]] || adopt_measured_rtt
  calculate_pair_quality "$enforce_guard"
  printf '\n[BALANCE] 单连接 %s Mbps｜多连接 %s Mbps｜综合评分 %s｜保护条件 %s\n' \
    "$PAIR_SINGLE_MBPS" "$PAIR_MULTI_MBPS" "$PAIR_SCORE" "$([[ "$PAIR_ELIGIBLE" == "yes" ]] && echo "通过" || echo "未通过")"
}

record_pair_result() {
  local stage="$1" config="$2" buffer_mib="$3" factor="$4"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$stage" "$SEARCH_ROUNDS" single "$config" 1 "$buffer_mib" "$factor" "$RTT_MS" \
    "$PAIR_SINGLE_MBPS" "$PAIR_SINGLE_RETRANS" "$PAIR_SINGLE_RETRANS_PERCENT" "$PAIR_SINGLE_SCORE" \
    "$PAIR_SINGLE_PASS" "$PAIR_SCORE" "$PAIR_ELIGIBLE" "$STRATEGY" "$PAIR_SINGLE_CV_PERCENT" "$PAIR_SINGLE_RTT_MS" "$TEST_REPEATS" >>"$REPORT_FILE"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$stage" "$SEARCH_ROUNDS" multi "$config" "$BALANCE_MULTI_STREAMS" "$buffer_mib" "$factor" "$RTT_MS" \
    "$PAIR_MULTI_MBPS" "$PAIR_MULTI_RETRANS" "$PAIR_MULTI_RETRANS_PERCENT" "$PAIR_MULTI_SCORE" \
    "$PAIR_MULTI_PASS" "$PAIR_SCORE" "$PAIR_ELIGIBLE" "$STRATEGY" "$PAIR_MULTI_CV_PERCENT" "$PAIR_MULTI_RTT_MS" "$TEST_REPEATS" >>"$REPORT_FILE"
}

candidate_better_than_best() {
  [[ "$BEST_KIND" == "none" ]] && return 0
  if [[ "$PAIR_ELIGIBLE" == "yes" && "$BEST_ELIGIBLE" != "yes" ]]; then return 0; fi
  if [[ "$PAIR_ELIGIBLE" != "yes" && "$BEST_ELIGIBLE" == "yes" ]]; then return 1; fi
  awk -v a="$PAIR_SCORE" -v b="$BEST_SCORE" 'BEGIN {exit !(a>b+0.25)}'
}

candidate_regressed_from_best() {
  [[ "$BEST_KIND" == "none" ]] && return 1
  if [[ "$BEST_ELIGIBLE" == "yes" && "$PAIR_ELIGIBLE" != "yes" ]]; then return 0; fi
  if [[ "$BEST_ELIGIBLE" != "yes" && "$PAIR_ELIGIBLE" == "yes" ]]; then return 1; fi
  awk -v a="$PAIR_SCORE" -v b="$BEST_SCORE" 'BEGIN {exit !(a<b-0.75)}'
}

set_best_from_pair() {
  BEST_KIND="$1"
  BEST_BUFFER_MIB="$2"
  BEST_FACTOR="$3"
  BEST_SINGLE_MBPS="$PAIR_SINGLE_MBPS"
  BEST_SINGLE_RETRANS_PERCENT="$PAIR_SINGLE_RETRANS_PERCENT"
  BEST_MULTI_MBPS="$PAIR_MULTI_MBPS"
  BEST_MULTI_RETRANS_PERCENT="$PAIR_MULTI_RETRANS_PERCENT"
  BEST_SCORE="$PAIR_SCORE"
  BEST_ELIGIBLE="$PAIR_ELIGIBLE"
}

set_final_from_pair() {
  FINAL_SINGLE_MBPS="$PAIR_SINGLE_MBPS"
  FINAL_SINGLE_RETRANS="$PAIR_SINGLE_RETRANS"
  FINAL_SINGLE_RETRANS_PERCENT="$PAIR_SINGLE_RETRANS_PERCENT"
  FINAL_SINGLE_PASS="$PAIR_SINGLE_PASS"
  FINAL_SINGLE_CV_PERCENT="$PAIR_SINGLE_CV_PERCENT"
  FINAL_SINGLE_RTT_MS="$PAIR_SINGLE_RTT_MS"
  FINAL_MULTI_MBPS="$PAIR_MULTI_MBPS"
  FINAL_MULTI_RETRANS="$PAIR_MULTI_RETRANS"
  FINAL_MULTI_RETRANS_PERCENT="$PAIR_MULTI_RETRANS_PERCENT"
  FINAL_MULTI_PASS="$PAIR_MULTI_PASS"
  FINAL_MULTI_CV_PERCENT="$PAIR_MULTI_CV_PERCENT"
  FINAL_MULTI_RTT_MS="$PAIR_MULTI_RTT_MS"
  FINAL_SCORE="$PAIR_SCORE"
  FINAL_PASS="$PAIR_PASS"
}

sample_tcp_rtt() {
  local port="$1"
  ss -tin 2>/dev/null | awk -v needle=":${port}" '
    index($0,needle) {matched=1; next}
    matched && /rtt:/ {
      v=$0
      sub(/^.*rtt:/,"",v)
      sub(/\/.*/,"",v)
      gsub(/[[:space:]]/,"",v)
      if(v ~ /^[0-9]+([.][0-9]+)?$/) print v
      exit
    }
    matched && $0 !~ /^[[:space:]]/ {matched=0}
  '
}

average_rtt_samples() {
  local file="$1"
  awk 'NF && $1 ~ /^[0-9]+([.][0-9]+)?$/ {sum+=$1; n++} END {if(n) printf "%.2f",sum/n}' "$file"
}

iperf_result_is_valid() {
  local file="$1" streams="${2:-0}" duration="${3:-0}"
  parse_iperf_json "$file" "$streams" "$duration" || return 1
  awk -v bytes="$RESULT_BYTES" -v mbps="$RESULT_MBPS" 'BEGIN {exit !(bytes>0 && mbps>=0)}'
}

iperf_attempt_has_summary() {
  python3 - "$1" <<'PY_SUMMARY'
import json, sys
try:
    with open(sys.argv[1]) as f: data=json.load(f)
    # Transport errors and scans may leave a partial JSON object. A complete
    # summary with invalid metrics is different: retrying cannot fix the parser.
    end=data.get("end", {})
    complete=(not data.get("error") and isinstance(end, dict)
              and (isinstance(end.get("sum_sent"), dict)
                   or isinstance(end.get("sum_received"), dict)))
    sys.exit(0 if complete else 1)
except (ValueError, TypeError, AttributeError, OSError): sys.exit(1)
PY_SUMMARY
}

iperf_server_loop() {
  local final_json="$1" final_err="$2" port="$3" family="${4:--4}"
  local streams="${5:-0}" duration="${6:-0}" attempt_json attempt_err validation_file
  local server_pid="" rc=0 attempt=0 valid=0

  trap 'if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi; exit 143' TERM INT
  : >"$final_err"
  while true; do
    attempt=$((attempt+1))
    attempt_json="$(printf '%s.attempt-%03d.json' "${final_json%.json}" "$attempt")"
    attempt_err="${attempt_json%.json}.err"
    validation_file="${attempt_json%.json}.validation.log"
    : >"$attempt_json"; : >"$attempt_err"
    iperf3 "$family" -s -1 -J -p "$port" >"$attempt_json" 2>"$attempt_err" &
    server_pid=$!
    set +e
    wait "$server_pid"
    rc=$?
    set -e
    server_pid=""

    valid=0
    if iperf_result_is_valid "$attempt_json" "$streams" "$duration" 2>"$validation_file"; then valid=1; fi
    if (( rc != 0 )); then printf '[PROCESS] iperf3 退出码：%s\n' "$rc" >>"$validation_file"; fi
    if (( valid == 1 && rc == 0 )); then
      mv -f "$attempt_json" "$final_json"
      [[ ! -s "$attempt_err" ]] || cat "$attempt_err" >>"$final_err"
      rm -f "$attempt_err" "$validation_file"
      return 0
    fi

    {
      printf '[%s] attempt=%s server_exit=%s raw_json=%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$attempt" "$rc" "$attempt_json"
      cat "$attempt_err" "$validation_file"
    } >>"$final_err"
    if iperf_attempt_has_summary "$attempt_json"; then
      error "iperf3 已返回汇总，但结果校验或进程状态异常（退出码 ${rc}）；停止本轮，不作为端口扫描反复重试"
      cat "$validation_file" >&2
      error "原始结果：${attempt_json}；校验日志：${validation_file}"
      return 65
    fi
    printf 'ignored_connection=%s\n' "$attempt" >>"$final_err"
    warn "测试连接未完成，iperf3 监听已自动恢复（第 ${attempt} 次）；记录：${attempt_json}"
    sleep 0.1
  done
}

wait_for_iperf_listener() {
  local port="$1" process_id="$2" attempt
  for ((attempt=1; attempt<=100; attempt++)); do
    kill -0 "$process_id" 2>/dev/null || return 1
    if ! port_is_free "$port"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

run_reverse_test() {
  local label="$1" streams="$2" address="$3" display_label="${4:-$1}" json_file err_file rtt_file elapsed=0 limit rc sample fallback_addr fallback_rtt connected_seen=0
  json_file="${SESSION_DIR}/${label}.json"
  err_file="${SESSION_DIR}/${label}.err"
  rtt_file="${SESSION_DIR}/${label}.rtt-samples"
  port_is_free "$TEST_PORT" || die "测试端口 ${TEST_PORT} 已被占用"
  : >"$json_file"; : >"$err_file"; : >"$rtt_file"
  iperf_server_loop "$json_file" "$err_file" "$TEST_PORT" "$IPERF_FAMILY" "$streams" "$DURATION" 8>&- &
  CURRENT_TEST_PID=$!
  if ! wait_for_iperf_listener "$TEST_PORT" "$CURRENT_TEST_PID"; then
    kill "$CURRENT_TEST_PID" 2>/dev/null || true
    wait "$CURRENT_TEST_PID" 2>/dev/null || true
    CURRENT_TEST_PID=""
    cat "$err_file" >&2 || true
    die "iperf3 服务端未能在 TCP ${TEST_PORT} 建立监听"
  fi

  section "${display_label}｜${streams} 个 TCP 流｜端口 ${TEST_PORT}"
  printf '服务器监听状态：已确认 TCP %s 正在监听。\n' "$TEST_PORT"
  printf '本地只需执行下面一条命令（不会修改本地 TCP 参数）：\n\n'
  printf '  iperf3 %s -c %q -p %s -R -P %s -t %s -i 1\n\n' "$IPERF_FAMILY" "$address" "$TEST_PORT" "$streams" "$DURATION"
  printf '等待规则：最多等待连接 %s 秒；开始传输后约运行 %s 秒。\n' "$WAIT_SECONDS" "$DURATION"
  printf '未完成的连接会自动恢复监听；完整结果若校验异常则停止本轮并保留诊断，不反复要求重测。\n'
  printf '如仍提示连接被拒绝，请确认安全组和服务器防火墙允许 TCP %s。\n' "$TEST_PORT"
  limit=$(( WAIT_SECONDS + DURATION + 10 ))
  while kill -0 "$CURRENT_TEST_PID" 2>/dev/null; do
    sleep 1
    elapsed=$((elapsed+1))
    kill -0 "$CURRENT_TEST_PID" 2>/dev/null || break
    sample="$(sample_tcp_rtt "$TEST_PORT" || true)"
    if [[ -n "$sample" ]]; then
      connected_seen=1
      printf '%s\n' "$sample" >>"$rtt_file"
    fi
    if (( elapsed % 5 == 0 )); then
      if port_is_free "$TEST_PORT"; then
        printf '[TEST ] 状态：监听正在自动恢复｜已用 %3s 秒｜端口 %s\n' "$elapsed" "$TEST_PORT"
      elif (( connected_seen )); then
        printf '[TEST ] 状态：已检测到 TCP 连接，等待测试汇总｜已用 %3s 秒｜端口 %s\n' "$elapsed" "$TEST_PORT"
      else
        printf '[TEST ] 状态：等待连接或测试进行中｜已用 %3s 秒｜端口 %s｜监听正常\n' "$elapsed" "$TEST_PORT"
      fi
    fi
    if (( elapsed >= limit )); then
      kill "$CURRENT_TEST_PID" 2>/dev/null || true
      wait "$CURRENT_TEST_PID" 2>/dev/null || true
      CURRENT_TEST_PID=""
      die "本轮测试超时：未取得有效完成结果；端口 ${TEST_PORT}，连接等待 ${WAIT_SECONDS} 秒；请检查客户端输出和 ${err_file}"
    fi
  done
  set +e
  wait "$CURRENT_TEST_PID"; rc=$?
  set -e
  CURRENT_TEST_PID=""
  if (( rc != 0 )); then
    cat "$err_file" >&2 || true
    if (( rc == 65 )); then die "iperf3 汇总校验失败，已保留原始 JSON；这不是监听端口被拒绝，详情：${err_file}"; fi
    die "iperf3 测试失败，退出码 ${rc}；详情：${err_file}"
  fi
  parse_iperf_json "$json_file" "$streams" "$DURATION" || { cat "$json_file" >&2 || true; die "无法解析 iperf3 测试结果"; }
  if ! awk -v v="$RESULT_RTT_MS" 'BEGIN {exit !(v>0)}'; then
    RESULT_RTT_MS="$(average_rtt_samples "$rtt_file")"
    if [[ -n "$RESULT_RTT_MS" ]]; then RESULT_RTT_SOURCE="ss TCP socket"; else RESULT_RTT_MS="0"; fi
  fi
  if ! awk -v v="$RESULT_RTT_MS" 'BEGIN {exit !(v>0)}'; then
    fallback_addr="${RESULT_CLIENT_ADDRESS:-$(guess_client_address)}"
    fallback_rtt="$(measure_ping_rtt "$fallback_addr" || true)"
    if [[ -n "$fallback_rtt" ]]; then RESULT_RTT_MS="$fallback_rtt"; RESULT_RTT_SOURCE="ICMP ping 备用测量"; fi
  fi
  validate_strategy_metrics
  calculate_result_quality
  print_interval_log "$json_file"
  printf '\n  平均测试吞吐：%s Mbps\n' "$RESULT_MBPS"
  case "$RESULT_RATE_SOURCE" in
    receiver) printf '  吞吐来源：接收端实测统计\n' ;;
    sender-unreported-receiver) printf '  吞吐来源：发送端统计（服务端接收汇总为占位记录，不等于接收端实测速率）\n' ;;
    *) printf '  吞吐来源：发送端统计（未提供接收端速率）\n' ;;
  esac
  printf '  区间波动 CV：%s%%\n' "$RESULT_CV_PERCENT"
  printf '  TCP 重传次数：%s 次\n' "$RESULT_RETRANS"
  printf '  估算重传率：%s%%（%s，不是实际丢包率）\n' "$RESULT_RETRANS_PERCENT" "$RESULT_RETRANS_SOURCE"
  if awk -v v="$RESULT_RTT_MS" 'BEGIN {exit !(v>0)}'; then
    printf '  TCP 平均 RTT：%s ms\n' "$RESULT_RTT_MS"
  else
    printf '  TCP 平均 RTT：未取得\n'
  fi
  printf '  是否达到目标：%s\n\n' "$(format_pass "$RESULT_PASS")"
}
abort_without_changes() {
  trap - INT TERM HUP
  set +e
  [[ -n "$CURRENT_TEST_PID" ]] && kill "$CURRENT_TEST_PID" 2>/dev/null || true
  warn "测试已中断；尚未修改服务器 TCP 参数"
  exit 130
}

cleanup_tuning_on_exit() {
  local rc=$?
  trap - EXIT ERR INT TERM HUP
  if [[ -n "$CURRENT_TEST_PID" ]]; then
    kill "$CURRENT_TEST_PID" 2>/dev/null || true
    wait "$CURRENT_TEST_PID" 2>/dev/null || true
    CURRENT_TEST_PID=""
  fi
  if (( rc != 0 )) && [[ "$TUNING_ACTIVE" == "1" && -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then
    set +e
    [[ -n "$CURRENT_TEST_PID" ]] && kill "$CURRENT_TEST_PID" 2>/dev/null || true
    warn "调优异常退出，正在恢复调优前参数"
    if restore_backup "$BACKUP_DIR"; then
      cancel_rollback_for_backup "$BACKUP_DIR"
    else
      error "自动恢复未完整完成；请使用备份重试：${BACKUP_DIR}"
    fi
    TUNING_ACTIVE="0"
  fi
  exit "$rc"
}

stop_tuning_on_signal() {
  trap - INT TERM HUP
  set +e
  [[ -n "$CURRENT_TEST_PID" ]] && kill "$CURRENT_TEST_PID" 2>/dev/null || true
  warn "收到中断信号，准备恢复调优前参数"
  exit 130
}

backup_sysctl_value() {
  local key="$1" file="${BACKUP_DIR}/observed.tsv"
  [[ -r "$file" ]] || file="${BACKUP_DIR}/sysctl.tsv"
  [[ -r "$file" ]] || { printf '%s\n' '<未记录>'; return; }
  awk -F '\t' -v wanted="$key" '$1==wanted {sub(/^[^\t]*\t/,""); print; found=1; exit} END {if(!found) print "<内核不支持>"}' "$file"
}

write_sysctl_comparison() {
  local output="${SESSION_DIR}/sysctl-comparison.tsv" key before after status
  printf 'parameter\tbefore\tafter\tstatus\n' >"$output"
  printf '\n[7] 系统与 TCP 参数审计（含未修改项）\n' >>"$COMPARISON_FILE"
  printf '%s\n' '----------------------------------------------------------------' >>"$COMPARISON_FILE"
  for key in "${OBSERVED_SYSCTL_KEYS[@]}"; do
    before="$(backup_sysctl_value "$key")"
    if sysctl_exists "$key"; then after="$(sysctl_get "$key")"; else after="<内核不支持>"; fi
    before="${before//$'\t'/ }"; after="${after//$'\t'/ }"
    if [[ "$after" == "<内核不支持>" ]]; then status="不支持"
    elif [[ "$before" == "$after" ]]; then status="保持"
    else status="变更"; fi
    printf '%s\t%s\t%s\t%s\n' "$key" "$before" "$after" "$status" >>"$output"
    printf '%s [%s]\n  调优前：%s\n  调优后：%s\n\n' "$key" "$status" "$before" "$after" >>"$COMPARISON_FILE"
  done
}

write_comparison() {
  local iface="$1" final_buffer="$2"
  local single_delta multi_delta single_retrans_delta multi_retrans_delta score_delta
  local after_cc after_qdisc after_rmem after_wmem after_tcp_mem disposition boundary assessment
  single_delta="$(awk -v a="$BASELINE_SINGLE_MBPS" -v b="$FINAL_SINGLE_MBPS" 'BEGIN {if(a<=0)print "0.00";else printf "%+.2f",(b-a)/a*100}')"
  multi_delta="$(awk -v a="$BASELINE_MULTI_MBPS" -v b="$FINAL_MULTI_MBPS" 'BEGIN {if(a<=0)print "0.00";else printf "%+.2f",(b-a)/a*100}')"
  single_retrans_delta="$(awk -v a="$BASELINE_SINGLE_RETRANS_PERCENT" -v b="$FINAL_SINGLE_RETRANS_PERCENT" 'BEGIN {printf "%+.4f",b-a}')"
  multi_retrans_delta="$(awk -v a="$BASELINE_MULTI_RETRANS_PERCENT" -v b="$FINAL_MULTI_RETRANS_PERCENT" 'BEGIN {printf "%+.4f",b-a}')"
  score_delta="$(awk -v a="$BASELINE_SCORE" -v b="$FINAL_SCORE" 'BEGIN {printf "%+.4f",b-a}')"
  after_cc="$(sysctl_get net.ipv4.tcp_congestion_control)"
  after_qdisc="$(root_qdisc_kind "$iface")"
  after_rmem="$(sysctl_get net.ipv4.tcp_rmem)"
  after_wmem="$(sysctl_get net.ipv4.tcp_wmem)"
  after_tcp_mem="$(sysctl_get net.ipv4.tcp_mem)"
  case "$OUTCOME" in
    optimized-runtime) disposition="实测最优候选已满足联合目标，当前在运行时生效，等待管理员确认" ;;
    optimized-persistent) disposition="实测最优候选已满足联合目标，并已写入持久化配置" ;;
    best-effort-runtime) disposition="绝对目标未完全满足；已采用本次会话中单/多连接综合表现最优的候选，等待管理员确认" ;;
    best-effort-persistent) disposition="绝对目标未完全满足；已采用本次会话中单/多连接综合表现最优的候选，并写入持久化配置" ;;
    *) disposition="$OUTCOME" ;;
  esac
  if (( OVERSHOOT_DETECTED )); then
    boundary="在 ${OVERSHOOT_MIB} MiB 检测到综合性能回落，随后完成区间回退与收敛"
  else
    boundary="${SEARCH_STOP_REASON:-在 BDP/内存约束范围内完成搜索；未证明全局最优}"
  fi
  if [[ "$FINAL_PASS" == "yes" && "$PAIR_ELIGIBLE" == "yes" ]]; then
    assessment="单连接、多连接吞吐及重传指标均满足设定门槛"
  elif [[ "$PAIR_ELIGIBLE" == "yes" ]]; then
    assessment="候选保持了单连接与多连接基线能力，但至少一项绝对性能指标未达到设定门槛；报告按最佳努力结果归档"
  else
    assessment="最终复核至少一侧低于基线保护线；仍按所选方案保留搜索阶段最优候选，不将本次结果标记为性能提升"
  fi

  cat >"$COMPARISON_FILE" <<EOF_COMPARE
================================================================
TCP/BBR 参数优化评估报告
================================================================

[1] 执行结论
----------------------------------------------------------------
处置结果：
  ${disposition}
  请在确认窗口内执行 bbr-tune confirm，否则会恢复备份。

综合判定：
  ${assessment}

搜索收敛：
  ${boundary}

[2] 评估方法
----------------------------------------------------------------
测试方向：远程服务器 → 本地电脑（iperf3 反向测试）
调优方案：${STRATEGY_NAME} (${STRATEGY})
评分权重（吞吐 / 稳定 / 低重传）：${WEIGHT_SPEED} / ${WEIGHT_STABILITY} / ${WEIGHT_RETRANS}
联合模型：单连接与 ${BALANCE_MULTI_STREAMS} 连接场景等权评估，吞吐使用调和均值，波动/重传取较差侧
重复测量：每种连接数 ${TEST_REPEATS} 次；吞吐、RTT、估算重传比例取中位数
稳定性指标：区间吞吐 CV 与重复测量 CV 取较大值；结合负载 RTT 相对对应基线的增长
吞吐口径：优先接收端统计；反向服务端的接收占位记录回退为发送端速率，具体来源保留在各轮 *.measurements.tsv
数据限制：NA 表示缺失而非零；稳定优先缺失区间数据时拒绝选优；重传比例是估算值，不是实际丢包率
保护条件：单连接和多连接吞吐均不得低于对应基线的 ${BALANCE_MIN_RETENTION_PERCENT}%
选择原则：优先选择满足单/多连接保护线的候选，再按综合评分排序；未达到绝对目标时仍采用实测最优候选
最终复核：最优候选重新执行单连接与多连接测试；仅测试失败、参数应用失败或异常中断时执行安全回滚

[3] 测试环境
----------------------------------------------------------------
会话编号：${SESSION_ID}
运行内核：$(uname -r)
运行时 BBR 版本：$(cat /sys/module/tcp_bbr/version 2>/dev/null || echo unknown)
测试时间：$(date '+%Y-%m-%d %H:%M:%S %z')
服务器地址：${SERVER_ADDRESS}
出口网卡：${iface}
目标带宽：${TARGET_MBPS} Mbps
吞吐达标门槛：目标带宽的 ${TARGET_UTILIZATION}%
最大估算重传率：${MAX_RETRANS_PERCENT}%
实测 TCP RTT：${RTT_MS} ms（${RTT_SOURCE}）
候选搜索轮数：${SEARCH_ROUNDS}

[4] 内存与 TCP 缓存策略
----------------------------------------------------------------
物理总内存：$(format_mib "$MEM_TOTAL_MIB")
当前可用内存：$(format_mib "$MEM_AVAILABLE_MIB")（仅观测，不参与预算计算）
有效总内存：$(format_mib "$MEM_EFFECTIVE_MIB")（物理总内存与 cgroup 上限取较小值）
TCP 聚合内存预算：$(format_mib "$MEM_TCP_BUDGET_MIB")（有效总内存的 2/3）
单 socket 缓存技术上限：$(format_mib "$MEM_BUFFER_CAP_MIB")
链路 BDP：${BDP_MIB} MiB
TCP 内存页阈值：${TCP_MEM_LOW_PAGES} / ${TCP_MEM_PRESSURE_PAGES} / ${TCP_MEM_HIGH_PAGES}
本次缓存搜索上限：${SEARCH_BUFFER_CAP_MIB} MiB（8 BDP 实验边界与总内存技术上限取较小值）
队列策略：$(qdisc_policy_summary)
kernel / VM / 路由策略：保留会话开始时的值，不从下载测速推导系统级策略

[5] 性能对比
----------------------------------------------------------------
单连接吞吐
  - 调优前：${BASELINE_SINGLE_MBPS} Mbps
  - 调优后：${FINAL_SINGLE_MBPS} Mbps
  - 变化：${single_delta}%

${BALANCE_MULTI_STREAMS} 连接聚合吞吐
  - 调优前：${BASELINE_MULTI_MBPS} Mbps
  - 调优后：${FINAL_MULTI_MBPS} Mbps
  - 变化：${multi_delta}%

单连接估算重传率
  - 调优前：${BASELINE_SINGLE_RETRANS_PERCENT}%
  - 调优后：${FINAL_SINGLE_RETRANS_PERCENT}%
  - 变化：${single_retrans_delta} 个百分点

多连接估算重传率
  - 调优前：${BASELINE_MULTI_RETRANS_PERCENT}%
  - 调优后：${FINAL_MULTI_RETRANS_PERCENT}%
  - 变化：${multi_retrans_delta} 个百分点

单连接波动 CV / 负载 RTT
  - 调优前：${BASELINE_SINGLE_CV_PERCENT}% / ${BASELINE_SINGLE_RTT_MS} ms
  - 调优后：${FINAL_SINGLE_CV_PERCENT}% / ${FINAL_SINGLE_RTT_MS} ms
多连接波动 CV / 负载 RTT
  - 调优前：${BASELINE_MULTI_CV_PERCENT}% / ${BASELINE_MULTI_RTT_MS} ms
  - 调优后：${FINAL_MULTI_CV_PERCENT}% / ${FINAL_MULTI_RTT_MS} ms

综合评分（不同方案的评分不可直接横向比较）
  - 调优前：${BASELINE_SCORE}
  - 调优后：${FINAL_SCORE}
  - 变化：${score_delta}

联合目标状态
  - 调优前：$([[ "$BASELINE_PASS" == "yes" ]] && echo "达标" || echo "未达标")
  - 调优后：$([[ "$FINAL_PASS" == "yes" ]] && echo "达标" || echo "未达标")

[6] 内核参数对比
----------------------------------------------------------------
拥塞控制算法
  - 调优前：${BEFORE_CC}
  - 调优后：${after_cc}

出口队列规则
  - 调优前：${BEFORE_QDISC}
  - 调优后：${after_qdisc}

缓存最大值
  - 调优前：$(format_bytes_mib "$BEFORE_BUFFER_BYTES")
  - 调优后：$(format_bytes_mib "$final_buffer")

tcp_rmem
  - 调优前：${BEFORE_RMEM}
  - 调优后：${after_rmem}

tcp_wmem
  - 调优前：${BEFORE_WMEM}
  - 调优后：${after_wmem}

tcp_mem
  - 调优前：${BEFORE_TCP_MEM}
  - 调优后：${after_tcp_mem}

EOF_COMPARE

  write_sysctl_comparison

  cat >>"$COMPARISON_FILE" <<EOF_COMPARE
[8] 最优候选
----------------------------------------------------------------
候选标识：${BEST_KIND}
缓存上限：${BEST_BUFFER_MIB} MiB
缓存 / BDP：${BEST_FACTOR} 倍
单连接吞吐：${BEST_SINGLE_MBPS} Mbps
多连接吞吐：${BEST_MULTI_MBPS} Mbps
基线保护状态：$([[ "$BEST_ELIGIBLE" == "yes" ]] && echo "通过" || echo "未通过（作为最佳努力候选采用）")
单连接与多连接差异特征：$([[ "$QOS_DETECTED" == "1" ]] && echo "显著" || echo "不显著")
EOF_COMPARE

  {
    printf '\n[9] 逐轮测试明细\n'
    printf '%s\n' '----------------------------------------------------------------'
    awk -F '\t' '
      function stage_name(value) {
        if (value=="before") return "基线"
        if (value=="candidate") return "候选"
        if (value=="final") return "复核"
        return value
      }
      function result_name(value) { return (value=="yes" ? "达标" : "未达标") }
      function guard_name(value) {
        if (value=="yes") return "通过"
        if (value=="no") return "未通过"
        return "未评价"
      }
      function emit_pair() {
        if (!have_single) return
        printf "[%s / 轮次 %s]\n", stage_name(pair_stage), pair_round
        printf "  配置：缓存 %s MiB | RTT %s ms\n", pair_buffer, pair_rtt
        printf "  综合：评分 %s | 保护条件 %s\n", pair_score, guard_name(pair_guard)
        printf "  单连接（%s 流）：%s Mbps | 重传 %s%% | %s\n", single_streams, single_mbps, single_retrans, result_name(single_pass)
        if (pair_strategy!="") printf "  方案 %s | 单连接 CV %s%% / RTT %s ms\n",pair_strategy,single_cv,single_rtt
        if (have_multi)
          printf "  多连接（%s 流）：%s Mbps | 重传 %s%% | %s\n", multi_streams, multi_mbps, multi_retrans, result_name(multi_pass)
        else
          print "  多连接：无测试记录"
        if (have_multi && pair_strategy!="") printf "  多连接 CV %s%% / RTT %s ms\n",multi_cv,multi_rtt
        print ""
        have_single=0
        have_multi=0
      }
      NR==1 { next }
      $3=="single" {
        emit_pair()
        pair_stage=$1; pair_round=$2; pair_buffer=$6; pair_rtt=$8
        pair_score=($14=="" ? "-" : $14); pair_guard=$15
        pair_strategy=$16; single_cv=$17; single_rtt=$18
        single_streams=$5; single_mbps=$9; single_retrans=$11; single_pass=$13
        have_single=1
        next
      }
      $3=="multi" && have_single {
        multi_streams=$5; multi_mbps=$9; multi_retrans=$11; multi_pass=$13
        multi_cv=$17; multi_rtt=$18
        have_multi=1
        emit_pair()
        next
      }
      {
        printf "[%s / 轮次 %s]\n", stage_name($1), $2
        printf "  %s（%s 流）：%s Mbps | 重传 %s%% | %s\n\n", $3, $5, $9, $11, result_name($13)
      }
      END { emit_pair() }
    ' "$REPORT_FILE"
    printf '[10] 审计文件\n'
    printf '%s\n' '----------------------------------------------------------------'
    printf '完整运行日志：\n  %s\n' "$RUN_LOG"
    printf '结构化逐轮数据：\n  %s\n' "$REPORT_FILE"
    printf '调优前系统状态：\n  %s/system-before.txt\n' "$SESSION_DIR"
    printf '调优后系统状态：\n  %s/system-after.txt\n' "$SESSION_DIR"
    printf '完整参数对比数据：\n  %s/sysctl-comparison.tsv\n' "$SESSION_DIR"
    printf '决策依据：\n  %s/rules.txt\n' "$SESSION_DIR"
  } >>"$COMPARISON_FILE"
  section "调优结果 / 单连接与多连接对比"
  printf '  单连接吞吐  %s → %s Mbps（%s%%）\n' "$BASELINE_SINGLE_MBPS" "$FINAL_SINGLE_MBPS" "$single_delta"
  printf '  多连接吞吐  %s → %s Mbps（%s%%）\n' "$BASELINE_MULTI_MBPS" "$FINAL_MULTI_MBPS" "$multi_delta"
  printf '  单连接估算重传率  %s%% → %s%%\n' "$BASELINE_SINGLE_RETRANS_PERCENT" "$FINAL_SINGLE_RETRANS_PERCENT"
  printf '  多连接估算重传率  %s%% → %s%%\n' "$BASELINE_MULTI_RETRANS_PERCENT" "$FINAL_MULTI_RETRANS_PERCENT"
  printf '\n  评估：%s\n  处置：%s\n' "$assessment" "$disposition"
  printf '\n  完整报告：%s\n' "$COMPARISON_FILE"
}
append_history() {
  local expected_header current_header legacy_file single_delta multi_delta
  expected_header=$'time\tsession\ttarget_mbps\trtt_ms\tmulti_streams\tbefore_single_mbps\tafter_single_mbps\tsingle_delta_percent\tbefore_multi_mbps\tafter_multi_mbps\tmulti_delta_percent\tbefore_single_retrans_percent\tafter_single_retrans_percent\tbefore_multi_retrans_percent\tafter_multi_retrans_percent\tbefore_balance_score\tafter_balance_score\tbuffer_mib\toutcome\treport\tstrategy\tbefore_single_cv\tafter_single_cv\tbefore_multi_cv\tafter_multi_cv\tbefore_single_rtt\tafter_single_rtt\tbefore_multi_rtt\tafter_multi_rtt\trepeats'
  mkdir -p "$STATE_DIR"
  if [[ -s "$HISTORY_FILE" ]]; then
    IFS= read -r current_header <"$HISTORY_FILE" || current_header=""
    if [[ "$current_header" != "$expected_header" ]]; then
      legacy_file="${HISTORY_FILE%.tsv}.legacy-$(date +%Y%m%d-%H%M%S).tsv"
      mv "$HISTORY_FILE" "$legacy_file"
      warn "历史记录字段已升级，旧记录已保留：$legacy_file"
    fi
  fi
  if [[ ! -e "$HISTORY_FILE" ]]; then
    printf '%s\n' "$expected_header" >"$HISTORY_FILE"
  fi
  single_delta="$(awk -v a="$BASELINE_SINGLE_MBPS" -v b="$FINAL_SINGLE_MBPS" 'BEGIN {if(a<=0)print "0.00";else printf "%.2f",(b-a)/a*100}')"
  multi_delta="$(awk -v a="$BASELINE_MULTI_MBPS" -v b="$FINAL_MULTI_MBPS" 'BEGIN {if(a<=0)print "0.00";else printf "%.2f",(b-a)/a*100}')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$SESSION_ID" "$TARGET_MBPS" "$RTT_MS" "$BALANCE_MULTI_STREAMS" \
    "$BASELINE_SINGLE_MBPS" "$FINAL_SINGLE_MBPS" "$single_delta" "$BASELINE_MULTI_MBPS" "$FINAL_MULTI_MBPS" "$multi_delta" \
    "$BASELINE_SINGLE_RETRANS_PERCENT" "$FINAL_SINGLE_RETRANS_PERCENT" "$BASELINE_MULTI_RETRANS_PERCENT" "$FINAL_MULTI_RETRANS_PERCENT" \
    "$BASELINE_SCORE" "$FINAL_SCORE" "$BEST_BUFFER_MIB" "$OUTCOME" "$COMPARISON_FILE" "$STRATEGY" "$BASELINE_SINGLE_CV_PERCENT" "$FINAL_SINGLE_CV_PERCENT" \
    "$BASELINE_MULTI_CV_PERCENT" "$FINAL_MULTI_CV_PERCENT" "$BASELINE_SINGLE_RTT_MS" "$FINAL_SINGLE_RTT_MS" \
    "$BASELINE_MULTI_RTT_MS" "$FINAL_MULTI_RTT_MS" "$TEST_REPEATS" >>"$HISTORY_FILE"
}

autotune() {
  require_linux; require_root; validate_autotune_options
  for cmd in ip tc sysctl modprobe awk mktemp ss tee; do have "$cmd" || die "服务器缺少命令：$cmd"; done
  init_session
  install_iperf3_if_needed
  install_python3_if_needed

  local iface address root_kind candidate_count=0 index mib factor lower upper midpoint gain
  iface="$(resolve_iface)"
  [[ -n "$iface" ]] || die "无法识别出口网卡"
  ip link show dev "$iface" >/dev/null 2>&1 || die "出口网卡不存在：$iface"
  address="$(guess_server_address)"
  [[ -n "$address" ]] || die "无法识别服务器连接地址，请使用 --server-address"
  SERVER_ADDRESS="$address"
  TEST_PORT="$(choose_random_port)" || die "无法找到未占用的随机端口"
  IPERF_FAMILY="$(detect_iperf_family "$address")"
  BALANCE_MULTI_STREAMS="$START_STREAMS"
  (( BALANCE_MULTI_STREAMS < 2 )) && BALANCE_MULTI_STREAMS=8

  RTT_MS=""; RTT_SOURCE=""
  SEARCH_ROUNDS=0; OVERSHOOT_DETECTED=0; OVERSHOOT_MIB=0; PLATEAU_STEPS=0; SEARCH_STOP_REASON=""
  BEST_KIND="none"; BEST_BUFFER_MIB=0; BEST_FACTOR="未选择"; BEST_SCORE="-999999"; BEST_ELIGIBLE="no"; QOS_DETECTED=0

  detect_memory_limits
  select_tuning_qdisc "$iface" || die "无法安全读取出口队列；尚未修改 TCP 参数"
  ensure_bbr
  prepare_tcp_rules

  BEFORE_CC="$(sysctl_get net.ipv4.tcp_congestion_control)"
  BEFORE_QDISC="$(root_qdisc_kind "$iface")"
  BEFORE_RMEM="$(sysctl_get net.ipv4.tcp_rmem)"
  BEFORE_WMEM="$(sysctl_get net.ipv4.tcp_wmem)"
  BEFORE_TCP_MEM="$(sysctl_get net.ipv4.tcp_mem)"
  BEFORE_BUFFER_BYTES="$(current_buffer_max)"
  BASELINE_BUFFER_BYTES="$BEFORE_BUFFER_BYTES"
  root_kind="$BEFORE_QDISC"
  if [[ "$QDISC_POLICY" == preserve ]]; then
    verify_preserved_qdisc "$iface" || die "原队列布局已变化；尚未开始测速或修改 TCP 参数"
  else
    if ! qdisc_layout_safe "$iface" && (( ! FORCE && ! QUEUE_SWITCH_READY )); then
      die "检测到自定义队列布局（root qdisc 为 '${root_kind}'）；为避免破坏现有 QoS，需审计后使用 --force"
    fi
    qdisc_preflight "$iface" "$TUNING_QDISC" || die "当前队列不适合安全自动调整；尚未开始测速或修改 TCP 参数"
  fi
  capture_state "$iface" "${SESSION_DIR}/system-before.txt"

  section "自动优化会话 ${SESSION_ID}"
  printf '  测试方向：远程服务器 → 本地电脑\n'
  printf '  服务器地址：%s\n' "$address"
  printf '  出口网卡：%s\n' "$iface"
  printf '  目标带宽：%s Mbps\n' "$TARGET_MBPS"
  printf '  调优方案：%s｜权重（吞吐/稳定/低重传）：%s/%s/%s｜复测：%s 次\n' "$STRATEGY_NAME" "$WEIGHT_SPEED" "$WEIGHT_STABILITY" "$WEIGHT_RETRANS" "$TEST_REPEATS"
  printf '  评估模型：单连接与 %s 连接分别测试，采用所选方案的综合评分联合选优\n' "$BALANCE_MULTI_STREAMS"
  printf '  单项保护线：候选的单连接及多连接吞吐均不得低于各自基线的 %s%%\n' "$BALANCE_MIN_RETENTION_PERCENT"
  printf '  RTT：首轮 TCP 测试自动测量\n'
  printf '  随机测试端口：%s（%s）\n' "$TEST_PORT" "$([[ "$IPERF_FAMILY" == "-6" ]] && echo IPv6 || echo IPv4)"
  printf '  TCP 聚合内存预算：%s（有效总内存的 2/3）\n' "$(format_mib "$MEM_TCP_BUDGET_MIB")"
  printf '  单 socket 缓存技术上限：%s\n' "$(format_mib "$MEM_BUFFER_CAP_MIB")"
  printf '  参数范围：BBR / TCP 自动缓冲 / SACK；其余系统与网络策略保持原值\n'
  printf '  队列策略：%s\n' "$(qdisc_policy_summary)"
  printf '  连接等待 / 安全回滚：%s 秒 / %s 秒\n' "$WAIT_SECONDS" "$AUTO_ROLLBACK_SECONDS"
  printf '  日志目录：%s\n\n' "$SESSION_DIR"
  warn "请确认云安全组和服务器防火墙允许 TCP ${TEST_PORT}；本工具不会修改本地电脑"

  trap abort_without_changes INT TERM HUP
  trap cleanup_tuning_on_exit EXIT
  section "调优前基线：单连接与多连接"
  run_balanced_pair "before" "$address" "调优前基线" no
  [[ -n "$RTT_MS" ]] || die "无法自动取得本地与服务器之间的 RTT；请检查 iperf3 JSON、ss 或客户端 ICMP 可达性"

  BASELINE_SINGLE_MBPS="$PAIR_SINGLE_MBPS"
  BASELINE_SINGLE_RETRANS="$PAIR_SINGLE_RETRANS"
  BASELINE_SINGLE_RETRANS_PERCENT="$PAIR_SINGLE_RETRANS_PERCENT"
  BASELINE_SINGLE_PASS="$PAIR_SINGLE_PASS"
  BASELINE_SINGLE_CV_PERCENT="$PAIR_SINGLE_CV_PERCENT"
  BASELINE_SINGLE_RTT_MS="$PAIR_SINGLE_RTT_MS"
  BASELINE_MULTI_MBPS="$PAIR_MULTI_MBPS"
  BASELINE_MULTI_RETRANS="$PAIR_MULTI_RETRANS"
  BASELINE_MULTI_RETRANS_PERCENT="$PAIR_MULTI_RETRANS_PERCENT"
  BASELINE_MULTI_PASS="$PAIR_MULTI_PASS"
  BASELINE_MULTI_CV_PERCENT="$PAIR_MULTI_CV_PERCENT"
  BASELINE_MULTI_RTT_MS="$PAIR_MULTI_RTT_MS"
  calculate_pair_quality no
  BASELINE_SCORE="$PAIR_SCORE"
  BASELINE_PASS="$PAIR_PASS"
  record_pair_result before original "$(awk -v b="$BEFORE_BUFFER_BYTES" 'BEGIN {printf "%.2f",b/1048576}')" original

  calculate_bdp
  generate_candidates
  write_rule_plan
  gain="$(awk -v a="$BASELINE_SINGLE_MBPS" -v b="$BASELINE_MULTI_MBPS" 'BEGIN {if(a<=0)print 0;else printf "%.2f",(b-a)/a*100}')"
  if awk -v g="$gain" 'BEGIN {exit !(g>=15)}'; then QOS_DETECTED=1; fi

  section "链路测量与参数搜索范围"
  printf '  实测 TCP RTT：%s ms（%s）\n' "$RTT_MS" "$RTT_SOURCE"
  printf '  目标链路 BDP：%s MiB\n' "$BDP_MIB"
  printf '  缓存搜索起点：%s MiB\n' "${CANDIDATE_MIBS[0]}"
  printf '  单 socket 技术上限：%s MiB\n' "$MEM_BUFFER_CAP_MIB"
  printf '  TCP 聚合内存高水位：%s MiB\n' "$MEM_TCP_BUDGET_MIB"
  printf '  tcp_mem 页阈值：%s / %s / %s（low / pressure / high）\n' \
    "$TCP_MEM_LOW_PAGES" "$TCP_MEM_PRESSURE_PAGES" "$TCP_MEM_HIGH_PAGES"
  printf '  搜索策略：倍增探索；检测到综合评分回落后，二分回退至 1 MiB 粒度\n\n'

  BACKUP_DIR="$(create_backup "$iface")"
  TUNING_ACTIVE="1"
  trap cleanup_tuning_on_exit EXIT
  trap stop_tuning_on_signal INT TERM HUP
  pending_guard
  schedule_rollback "$BACKUP_DIR"

  section "第一阶段：倍增探索综合性能边界"
  for ((index=0; index<${#CANDIDATE_MIBS[@]}; index++)); do
    mib="${CANDIDATE_MIBS[$index]}"
    factor="${CANDIDATE_FACTORS[$index]}"
    candidate_count=$((candidate_count+1)); SEARCH_ROUNDS="$candidate_count"
    printf '\n[SEARCH] 第 %-3s 轮｜倍增探索｜缓存 %6s MiB｜约 %5s × BDP\n' "$SEARCH_ROUNDS" "$mib" "$factor"
    apply_candidate "$iface" "$mib"
    run_balanced_pair "candidate-${SEARCH_ROUNDS}-${mib}m" "$address" "候选 ${SEARCH_ROUNDS}（倍增探索）" yes
    record_pair_result candidate "bbr-${TUNING_QDISC}" "$mib" "$factor"
    if candidate_better_than_best; then
      PLATEAU_STEPS=0
      set_best_from_pair "candidate-${SEARCH_ROUNDS}" "$mib" "$factor"
      info "实测最优值更新：缓存 ${mib} MiB｜单连接 ${BEST_SINGLE_MBPS} Mbps｜多连接 ${BEST_MULTI_MBPS} Mbps｜评分 ${BEST_SCORE}"
    elif (( mib > BEST_BUFFER_MIB )) && candidate_regressed_from_best; then
      OVERSHOOT_DETECTED=1
      OVERSHOOT_MIB="$mib"
      warn "候选 ${mib} MiB 出现实测评分回落，开始区间回退；不认定为物理极限"
      break
    else
      PLATEAU_STEPS=$((PLATEAU_STEPS+1))
      info "候选 ${mib} MiB 未形成显著收益（连续 ${PLATEAU_STEPS} 档）"
      if (( PLATEAU_STEPS >= 2 )); then
        SEARCH_STOP_REASON="连续两档无显著评分收益，停止扩容；不能将路径限制误判为缓存不足"
        info "$SEARCH_STOP_REASON"
        break
      fi
    fi
  done

  if (( OVERSHOOT_DETECTED )) && [[ "$BEST_KIND" != "none" ]]; then
    lower="${BEST_BUFFER_MIB%.*}"
    upper="$OVERSHOOT_MIB"
    section "第二阶段：在 ${lower}～${upper} MiB 区间内回退精调"
    while (( upper - lower > 1 )); do
      midpoint=$(( (lower + upper) / 2 ))
      factor="$(candidate_factor "$midpoint")"
      candidate_count=$((candidate_count+1)); SEARCH_ROUNDS="$candidate_count"
      printf '\n[SEARCH] 第 %-3s 轮｜区间精调｜缓存 %6s MiB｜约 %5s × BDP\n' "$SEARCH_ROUNDS" "$midpoint" "$factor"
      apply_candidate "$iface" "$midpoint"
      run_balanced_pair "candidate-${SEARCH_ROUNDS}-${midpoint}m" "$address" "候选 ${SEARCH_ROUNDS}（区间精调）" yes
      record_pair_result candidate "bbr-${TUNING_QDISC}" "$midpoint" "$factor"
      if candidate_better_than_best; then
        set_best_from_pair "candidate-${SEARCH_ROUNDS}" "$midpoint" "$factor"
        lower="$midpoint"
        info "区间精调发现更优配置：${midpoint} MiB｜评分 ${BEST_SCORE}"
      elif candidate_regressed_from_best; then
        upper="$midpoint"
        info "${midpoint} MiB 位于性能边界外侧，缩小上界"
      else
        lower="$midpoint"
        info "${midpoint} MiB 与当前最优评分差异未越过经验阈值，继续逼近上界"
      fi
    done
    info "区间精调已收敛至 ${lower}～${upper} MiB；选定实测综合评分最优的 ${BEST_BUFFER_MIB} MiB"
  fi

  if [[ "$BEST_KIND" == "none" ]]; then
    cancel_rollback_for_backup "$BACKUP_DIR"
    restore_backup "$BACKUP_DIR"
    TUNING_ACTIVE="0"
    trap - INT TERM HUP
    die "未取得任何有效候选测试结果，已恢复调优前配置"
  fi

  section "最终复核：应用实测最优缓存 ${BEST_BUFFER_MIB} MiB"
  apply_candidate "$iface" "$BEST_BUFFER_MIB"
  run_balanced_pair "final-${BEST_BUFFER_MIB}m" "$address" "最优参数复核" yes
  record_pair_result final "bbr-${TUNING_QDISC}" "$BEST_BUFFER_MIB" "$BEST_FACTOR"
  set_final_from_pair
  FINAL_BUFFER_BYTES=$(( BEST_BUFFER_MIB * 1048576 ))

  if [[ "$FINAL_PASS" == "yes" && "$PAIR_ELIGIBLE" == "yes" ]]; then
    OUTCOME="optimized-runtime"
  else
    OUTCOME="best-effort-runtime"
  fi
  if (( PERSIST_FINAL )); then
    info "实测最优候选复核完成，写入持久化配置"
    write_persistent_config "$iface" "$BEST_BUFFER_MIB"
    if [[ "$OUTCOME" == "optimized-runtime" ]]; then
      OUTCOME="optimized-persistent"
    else
      OUTCOME="best-effort-persistent"
    fi
  fi
  trap - INT TERM HUP
  if (( AUTO_ROLLBACK_SECONDS > 0 )); then
    warn "实测最优参数已生效；请在 ${AUTO_ROLLBACK_SECONDS} 秒内通过独立 SSH 会话验证，然后执行 sudo $PROGRAM confirm"
  else
    warn "实测最优参数已生效；本次运行未启用定时安全回滚"
  fi

  if (( AUTO_ROLLBACK_SECONDS > 0 )); then
    cancel_rollback_for_backup "$BACKUP_DIR"
    schedule_rollback "$BACKUP_DIR"
    rm -f "$(pending_path "$BACKUP_DIR")/owner"
  fi
  capture_state "$iface" "${SESSION_DIR}/system-after.txt"
  write_comparison "$iface" "$FINAL_BUFFER_BYTES"
  append_history
  TUNING_ACTIVE="0"
  trap - EXIT
  if [[ "$FINAL_PASS" != "yes" ]]; then
    warn "最终配置未同时达到全部绝对门槛；仍已按所选方案的单连接/多连接综合评分采用本次实测最优候选"
  fi
  if (( QOS_DETECTED )); then
    warn "单连接与多连接吞吐差异显著；仅凭本次测试无法区分窗口、CPU、路径拥塞或单流策略限制"
  fi
  info "完整运行日志：$RUN_LOG"
  info "专业评估报告：$COMPARISON_FILE"
}
qdisc_command() {
  require_linux; require_root; validate_qdisc_options
  case "$REQUESTED_QDISC" in fq|fq_codel|cake) ;; *) die "单独切换队列需要 --qdisc fq、fq_codel 或 cake" ;; esac
  for cmd in ip tc sysctl modprobe awk mktemp tee; do have "$cmd" || die "服务器缺少命令：$cmd"; done
  init_session
  install_python3_if_needed
  local iface before
  iface="$(resolve_iface)"
  [[ -n "$iface" ]] && ip link show dev "$iface" >/dev/null 2>&1 || die "无法识别出口网卡"
  select_tuning_qdisc "$iface" || die "队列切换预检失败，未修改服务器参数"
  before="$(root_qdisc_kind "$iface")"
  capture_state "$iface" "${SESSION_DIR}/system-before.txt"
  section "出口队列切换"
  printf '  网卡：%s\n  原根队列：%s\n  目标：%s\n' "$iface" "$before" "$(qdisc_policy_summary)"
  printf '  本操作不修改 TCP 缓存、拥塞控制或系统默认队列。\n'
  QDISC_ONLY=1
  BACKUP_DIR="$(create_backup "$iface")"
  TUNING_ACTIVE=1
  trap cleanup_tuning_on_exit EXIT
  trap stop_tuning_on_signal INT TERM HUP
  pending_guard
  schedule_rollback "$BACKUP_DIR"
  apply_tuning_qdisc "$iface" || die "队列切换失败，正在恢复备份"
  if (( PERSIST_FINAL )); then write_qdisc_persistence "$iface"; fi
  capture_state "$iface" "${SESSION_DIR}/system-after.txt"
  {
    printf '出口队列调整报告\n'
    printf '时间：%s\n网卡：%s\n原根队列：%s\n当前根队列：%s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$iface" "$before" "$(root_qdisc_kind "$iface")"
    printf '队列策略：%s\n' "$(qdisc_policy_summary)"
    printf 'TCP 缓存与拥塞控制：未修改\n开机加载：%s\n' "$([[ "$PERSIST_FINAL" == 1 ]] && echo 已配置 || echo 未修改)"
    printf '原队列完整参数：%s/qdisc-original.json\n' "$BACKUP_DIR"
    printf '原配置与切换后状态：%s\n' "$SESSION_DIR"
    printf '安全回滚：%s 秒；验证业务后执行 bbr-tune confirm\n' "$AUTO_ROLLBACK_SECONDS"
  } >"${SESSION_DIR}/queue-comparison.txt"
  rm -f "$(pending_path "$BACKUP_DIR")/owner"
  TUNING_ACTIVE=0
  trap - EXIT INT TERM HUP
  info "队列已切换；请在 ${AUTO_ROLLBACK_SECONDS} 秒内验证代理业务后执行 bbr-tune confirm"
  info "操作报告：${SESSION_DIR}/queue-comparison.txt"
}

status_command() {
  require_linux
  for cmd in ip tc sysctl awk; do have "$cmd" || die "缺少命令：$cmd"; done
  local iface rmax wmax
  iface="$(resolve_iface)"
  detect_memory_limits
  rmax="$(sysctl_get net.core.rmem_max)"
  wmax="$(sysctl_get net.core.wmem_max)"
  section "当前服务器 TCP/BBR 状态"
  printf '  时间：%s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
  printf '  内核：%s\n' "$(uname -srmo)"
  printf '  出口网卡：%s\n' "$iface"
  printf '  拥塞控制算法：%s\n' "$(sysctl_get net.ipv4.tcp_congestion_control)"
  printf '  运行时 BBR 版本：%s（未知不表示 v1）\n' "$(cat /sys/module/tcp_bbr/version 2>/dev/null || echo 未知)"
  printf '  内核可用算法：%s\n' "$(sysctl_get net.ipv4.tcp_available_congestion_control)"
  printf '  系统默认队列：%s\n' "$(sysctl_get net.core.default_qdisc)"
  printf '  出口实际队列：%s\n' "$(root_qdisc_kind "$iface")"
  printf '  服务器物理总内存：%s\n' "$(format_mib "$MEM_TOTAL_MIB")"
  printf '  有效总内存：%s\n' "$(format_mib "$MEM_EFFECTIVE_MIB")"
  printf '  TCP 聚合内存预算：%s（有效总内存的 2/3）\n' "$(format_mib "$MEM_TCP_BUDGET_MIB")"
  printf '  单 socket 缓存上限：%s\n' "$(format_mib "$MEM_BUFFER_CAP_MIB")"
  printf '  接收缓存硬上限：%s\n' "$(format_bytes_mib "$rmax")"
  printf '  发送缓存硬上限：%s\n' "$(format_bytes_mib "$wmax")"
  printf '  tcp_rmem（最小/默认/最大）：%s\n' "$(sysctl_get net.ipv4.tcp_rmem)"
  printf '  tcp_wmem（最小/默认/最大）：%s\n' "$(sysctl_get net.ipv4.tcp_wmem)"
  printf '  tcp_mem（low/pressure/high）：%s\n' "$(sysctl_get net.ipv4.tcp_mem)"
  printf '\n队列详细统计\n------------\n'
  tc -s -d qdisc show dev "$iface" || true
}

history_snapshot_value() {
  local file="$1" key="$2" value
  if [[ -r "$file" ]]; then
    value="$(awk -v key="$key" 'index($0,key"=")==1 {print substr($0,length(key)+2); exit}' "$file")"
  fi
  printf '%s\n' "${value:-未记录}"
}

history_snapshot_qdisc() {
  local file="$1" value
  if [[ -r "$file" ]]; then
    value="$(awk '/^\[qdisc\]$/ {inside=1; next} /^\[/ {inside=0} inside && $1=="qdisc" && $4=="root" {print $2; exit}' "$file")"
  fi
  printf '%s\n' "${value:-未记录}"
}

history_compare_format_value() {
  local value="$1" format="$2"
  case "$format" in
    bytes)
      if [[ "$value" =~ ^[0-9]+$ ]]; then
        awk -v n="$value" 'BEGIN {printf "%.2f MiB (%s bytes)\n",n/1048576,n}'
      else printf '%s\n' "$value"; fi ;;
    mib)
      if [[ "$value" =~ ^[0-9]+$ ]]; then printf '%s MiB\n' "$value"
      else printf '%s\n' "$value"; fi ;;
    *) printf '%s\n' "$value" ;;
  esac
}

history_compare_row() {
  local label="$1" key="$2" current_file="$3" before_file="$4" after_file="$5" format="${6:-raw}"
  local current before selected marker=""
  if [[ "$format" == qdisc ]]; then
    current="$(history_snapshot_qdisc "$current_file")"
    before="$(history_snapshot_qdisc "$before_file")"
    selected="$(history_snapshot_qdisc "$after_file")"
  else
    current="$(history_snapshot_value "$current_file" "$key")"
    before="$(history_snapshot_value "$before_file" "$key")"
    selected="$(history_snapshot_value "$after_file" "$key")"
  fi
  current="$(history_compare_format_value "$current" "$format")"
  before="$(history_compare_format_value "$before" "$format")"
  selected="$(history_compare_format_value "$selected" "$format")"
  [[ "$selected" == "$current" || "$selected" == 未记录 ]] || marker='← 与当前不同'
  if (( ${#label} + ${#current} + ${#before} + ${#selected} <= 34 )); then
    printf '  %s：当前 %s｜测试前 %s｜历史 %s%s%s%s\n' \
      "$label" "$current" "$before" "$UI_YELLOW" "$selected" "$UI_RESET" "$marker"
  else
    printf '  %s\n' "$label"
    printf '    当前       %s\n' "$current"
    printf '    测试前     %s\n' "$before"
    printf '    选中历史   %s%s%s%s\n' "$UI_YELLOW" "$selected" "$UI_RESET" "$marker"
  fi
}

history_compare_command() (
  require_linux
  local session="$HISTORY_SESSION" before_file after_file current_file iface
  [[ "$session" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || { error "history-compare 需要有效的 --session 会话编号"; return 1; }
  [[ -d "${SESSION_ROOT}/${session}" && ! -L "${SESSION_ROOT}/${session}" ]] || { error "找不到历史会话：${session}"; return 1; }
  before_file="${SESSION_ROOT}/${session}/system-before.txt"
  after_file="${SESSION_ROOT}/${session}/system-after.txt"
  [[ -r "$before_file" || -r "$after_file" ]] || { error "该会话没有保存参数快照：${session}"; return 1; }
  iface="$(resolve_iface)"
  [[ -n "$iface" ]] || { error "无法识别当前出口网卡"; return 1; }
  detect_memory_limits
  current_file="$(mktemp)" || return 1
  trap 'rm -f "$current_file"' EXIT
  capture_state "$iface" "$current_file"
  section "历史会话 ${session} / 关键参数对比"
  printf '  当前＝现在生效；测试前＝这次测试的原始值；选中历史＝这次测试结束时的值。\n'
  printf '  ← 标出与当前不同的历史值；未记录表示当时没有保存。\n'
  printf '\n  TCP / BBR 参数\n'
  history_compare_row '拥塞控制算法' net.ipv4.tcp_congestion_control "$current_file" "$before_file" "$after_file"
  history_compare_row '接收缓存硬上限' net.core.rmem_max "$current_file" "$before_file" "$after_file" bytes
  history_compare_row '发送缓存硬上限' net.core.wmem_max "$current_file" "$before_file" "$after_file" bytes
  history_compare_row 'tcp_rmem（最小/默认/最大，bytes）' net.ipv4.tcp_rmem "$current_file" "$before_file" "$after_file"
  history_compare_row 'tcp_wmem（最小/默认/最大，bytes）' net.ipv4.tcp_wmem "$current_file" "$before_file" "$after_file"
  history_compare_row 'tcp_mem（low/pressure/high，页）' net.ipv4.tcp_mem "$current_file" "$before_file" "$after_file"
  printf '\n  队列与服务器条件（用于判断测试环境）\n'
  history_compare_row '系统默认队列' net.core.default_qdisc "$current_file" "$before_file" "$after_file"
  history_compare_row '出口实际队列' qdisc "$current_file" "$before_file" "$after_file" qdisc
  history_compare_row '出口网卡' interface "$current_file" "$before_file" "$after_file"
  history_compare_row '运行内核' kernel "$current_file" "$before_file" "$after_file"
  history_compare_row 'BBR 运行版本' bbr_runtime_version "$current_file" "$before_file" "$after_file"
  history_compare_row '内核可用算法' net.ipv4.tcp_available_congestion_control "$current_file" "$before_file" "$after_file"
  history_compare_row '物理总内存' memory_total_mib "$current_file" "$before_file" "$after_file" mib
  history_compare_row '有效总内存' memory_effective_mib "$current_file" "$before_file" "$after_file" mib
  history_compare_row 'TCP 聚合内存预算' memory_tcp_budget_mib "$current_file" "$before_file" "$after_file" mib
  history_compare_row '单 socket 缓存技术上限' memory_buffer_cap_mib "$current_file" "$before_file" "$after_file" mib
  printf '\n  应用历史记录时：采用历史缓存上限，保留当前队列和 TCP 缓存最小/默认值，\n'
  printf '  tcp_mem 会按当前内存重新计算；历史列是当时实测值，并非逐项原样写入。\n'
  printf '  还会启用 TCP 自动缓冲、SACK/DSACK 和窗口缩放。\n'
)

history_params_command() {
  local session="$HISTORY_SESSION" snapshot label
  [[ "$session" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || { error "history-params 需要有效的 --session 会话编号"; return 1; }
  [[ -d "${SESSION_ROOT}/${session}" && ! -L "${SESSION_ROOT}/${session}" ]] || { error "找不到历史会话：${session}"; return 1; }
  if (( HISTORY_PARAMS_AFTER )); then
    snapshot="${SESSION_ROOT}/${session}/system-after.txt"
    label="测试后"
  else
    snapshot="${SESSION_ROOT}/${session}/system-before.txt"
    label="测试前"
  fi
  [[ -r "$snapshot" ]] || { error "该历史会话没有保存${label}原始参数：${snapshot}"; return 1; }
  section "历史会话 ${session} / ${label}原始参数"
  cat -- "$snapshot"
  printf '\n  快照文件：%s\n' "$snapshot"
  printf '  这是当时保存的参数；当前生效参数请查看“当前状态”。\n'
}

history_candidate() {
  local session="$1" header record result_file state_file bytes line
  [[ "$session" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || { error "历史会话编号无效"; return 1; }
  [[ -r "$HISTORY_FILE" && -d "${SESSION_ROOT}/${session}" && ! -L "${SESSION_ROOT}/${session}" ]] || {
    error "找不到历史会话或历史索引：${session}"; return 1;
  }
  IFS= read -r header <"$HISTORY_FILE" || return 1
  [[ "$header" == *$'before_single_mbps\tafter_single_mbps'* ]] || { error "历史索引字段不受支持"; return 1; }
  record="$(awk -F '\t' -v wanted="$session" '
    NR>1 && $2==wanted {
      if (NF!=30) exit 2
      count++
      printf "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",$1,$3,$4,$18,$19,$21,$7,$10
    }
    END {if (count!=1) exit 1}
  ' "$HISTORY_FILE")" || { error "历史索引中缺少唯一且完整的会话：${session}"; return 1; }
  HISTORY_FIELDS=()
  while IFS= read -r line; do HISTORY_FIELDS+=("$line"); done <<<"$record"
  local mib="${HISTORY_FIELDS[3]}"
  [[ "$mib" =~ ^[0-9]{1,4}$ ]] && (( 10#$mib >= 1 && 10#$mib <= TCP_BUFFER_SYSCTL_MAX_MIB )) || {
    error "历史缓存值无效：${mib}"; return 1;
  }
  bytes=$(( 10#$mib * 1048576 ))
  result_file="${SESSION_ROOT}/${session}/results.tsv"
  state_file="${SESSION_ROOT}/${session}/system-after.txt"
  [[ -r "$result_file" && -r "$state_file" ]] || { error "历史会话缺少最终复核或生效状态记录，无法直接应用"; return 1; }
  awk -F '\t' -v mib="$((10#$mib))" '
    $1=="final" {count++; if ($6!=mib || ($3!="single" && $3!="multi")) invalid=1; seen[$3]=1}
    END {exit (invalid || count!=2 || !seen["single"] || !seen["multi"])}
  ' "$result_file" || { error "历史最终复核与汇总缓存值不一致，拒绝应用"; return 1; }
  grep -Fqx "net.core.rmem_max=${bytes}" "$state_file" &&
    grep -Fqx "net.core.wmem_max=${bytes}" "$state_file" || {
      error "历史生效状态与汇总缓存值不一致，拒绝应用"; return 1;
    }
}

apply_history_command() {
  require_linux; require_root
  [[ -n "$HISTORY_SESSION" ]] || die "apply-history 需要 --session 会话编号"
  [[ "$REQUESTED_QDISC" == auto || "$REQUESTED_QDISC" == keep ]] || die "应用历史参数时保留当前队列；单独切换队列请使用 qdisc 命令"
  history_candidate "$HISTORY_SESSION" || die "历史记录未通过校验"
  local historical_time="${HISTORY_FIELDS[0]}" historical_mib="${HISTORY_FIELDS[3]}"
  local historical_outcome="${HISTORY_FIELDS[4]}" iface buffer_bytes
  TARGET_MBPS="${HISTORY_FIELDS[1]}"; RTT_MS="${HISTORY_FIELDS[2]}"; STRATEGY="${HISTORY_FIELDS[5]}"
  is_number "$TARGET_MBPS" && is_number "$RTT_MS" || die "历史目标带宽或 RTT 无效"
  configure_strategy
  for cmd in ip tc sysctl modprobe awk mktemp tee; do have "$cmd" || die "服务器缺少命令：$cmd"; done
  iface="$(resolve_iface)"
  [[ -n "$iface" ]] && ip link show dev "$iface" >/dev/null 2>&1 || die "无法识别当前出口网卡"
  detect_memory_limits
  calculate_bdp
  (( 10#$historical_mib <= MEM_BUFFER_CAP_MIB )) || die "历史缓存 ${historical_mib} MiB 超过当前服务器上限 ${MEM_BUFFER_CAP_MIB} MiB"
  prepare_tcp_rules
  buffer_bytes=$(( 10#$historical_mib * 1048576 ))
  (( buffer_bytes >= TCP_RDEFAULT && buffer_bytes >= TCP_WDEFAULT )) || die "历史缓存低于当前 TCP 默认缓存，无法应用"
  REQUESTED_QDISC=keep
  section "应用历史测试参数"
  printf '  历史会话：%s（%s）\n' "$HISTORY_SESSION" "$historical_time"
  printf '  当时结论：%s；单连接 %s Mbps，多连接 %s Mbps\n' "$historical_outcome" "${HISTORY_FIELDS[6]}" "${HISTORY_FIELDS[7]}"
  printf '  待应用：BBR、TCP 自动缓冲及 %s MiB 缓存上限\n' "$historical_mib"
  printf '  当前网卡：%s；保留当前出口队列和整形设置\n' "$iface"
  printf '  TCP 聚合内存阈值按当前服务器内存重新计算\n'
  printf '  开机配置：%s；安全回滚：%s 秒\n' "$([[ "$PERSIST_FINAL" == 1 ]] && echo 写入 || echo 不写入)" "$AUTO_ROLLBACK_SECONDS"
  printf '  历史测速不会代表当前链路表现；应用后请从独立 SSH 会话验证业务。\n'
  if (( ! YES )); then
    [[ -t 0 ]] || die "非交互应用历史参数需要 --yes"
    local answer
    read -r -p '确认备份当前参数并应用？[y/N] ' answer || return 0
    [[ "$answer" =~ ^[Yy]$ ]] || return 0
  fi
  init_session
  select_tuning_qdisc "$iface" || die "无法验证当前队列布局，尚未修改 TCP 参数"
  ensure_bbr
  BACKUP_DIR="$(create_backup "$iface")"
  TUNING_ACTIVE=1
  trap cleanup_tuning_on_exit EXIT
  trap stop_tuning_on_signal INT TERM HUP
  pending_guard
  schedule_rollback "$BACKUP_DIR"
  apply_candidate "$iface" "$((10#$historical_mib))"
  if (( PERSIST_FINAL )); then write_persistent_config "$iface" "$((10#$historical_mib))"; fi
  capture_state "$iface" "${SESSION_DIR}/system-after.txt"
  {
    printf '历史参数应用记录\n来源会话：%s\n来源时间：%s\n' "$HISTORY_SESSION" "$historical_time"
    printf 'TCP 缓存上限：%s MiB\n当前出口网卡：%s\n当前队列：保留\n' "$historical_mib" "$iface"
    printf '开机配置：%s\n安全回滚：%s 秒\n' "$([[ "$PERSIST_FINAL" == 1 ]] && echo 已写入 || echo 未写入)" "$AUTO_ROLLBACK_SECONDS"
  } >"${SESSION_DIR}/history-application.txt"
  rm -f "$(pending_path "$BACKUP_DIR")/owner"
  TUNING_ACTIVE=0
  trap - EXIT INT TERM HUP
  info "历史 TCP 参数已应用；请验证业务后执行 sudo $PROGRAM confirm"
  info "本次备份：$BACKUP_DIR"
  info "应用记录：${SESSION_DIR}/history-application.txt"
}

history_command() {
  local header choice count selected action snapshot_choice
  if [[ ! -r "$HISTORY_FILE" ]]; then info "尚无历史测试记录；完成一次调优后即可在此对比"; return; fi
  IFS= read -r header <"$HISTORY_FILE" || header=""
  section "历史测试 / 按时间归档"
  if [[ "$header" == *$'before_single_mbps\tafter_single_mbps'* ]]; then
    awk -F '\t' '
      function strategy(s) {if(s=="speed")return "速度优先";if(s=="stable")return "稳定优先";if(s=="retrans")return "低重传优先";return "均衡"}
      NR>1 {
        printf "\n  %d) %s  /  %s\n", NR-1,$1,strategy($21)
        printf "  会话：%s\n",$2
        printf "  单连接：%s → %s Mbps（%s%%）\n",$6,$7,$8
        printf "  多连接：%s → %s Mbps（%s%%）\n",$9,$10,$11
        printf "  RTT：%s ms    缓存：%s MiB\n",$4,$18
        printf "  测试结论：%s\n",($19~/^optimized-/ ? "达到目标" : "最佳努力，未完全达标")
        printf "  报告：%s\n",$20
      }' "$HISTORY_FILE"
    printf '\n  历史结论仅反映当时测试；当前生效参数请查看“当前状态”。\n'
    if [[ -t 0 && -t 1 ]]; then
      count="$(awk 'END {print NR-1}' "$HISTORY_FILE")"
      (( count > 0 )) || return 0
      while true; do
        read -r -p '输入编号查看关键参数对比（0 返回）：' choice || return 0
        [[ "$choice" == 0 || -z "$choice" ]] && return 0
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( 10#$choice >= 1 && 10#$choice <= count )); then break; fi
        printf '请输入 0～%s 的编号\n' "$count"
      done
      selected="$(awk -F '\t' -v n="$choice" 'NR==n+1 {print $2}' "$HISTORY_FILE")"
      HISTORY_SESSION="$selected"
      history_compare_command || true
      while true; do
        printf '\n会话 %s\n' "$selected"
        printf '  1  重新查看关键参数对比\n  2  应用本次测试的 TCP 参数\n  3  查看完整原始快照\n  0  返回\n'
        read -r -p '请选择：' action || return 0
        case "$action" in
          1) history_compare_command || true ;;
          2)
            history_candidate "$selected" || continue
            local args=()
            if ui_yes_no '同时写入开机配置' n; then args+=(--persist); fi
            ui_execute 1 apply-history --session "$selected" ${args[@]+"${args[@]}"} || true
            ;;
          3)
            read -r -p '查看 1 测试前 / 2 测试后（0 返回）：' snapshot_choice || continue
            case "$snapshot_choice" in
              1) HISTORY_PARAMS_AFTER=0; history_params_command || true ;;
              2) HISTORY_PARAMS_AFTER=1; history_params_command || true ;;
              0|'') ;;
              *) printf '请输入 0～2 的编号\n' ;;
            esac
            ;;
          0|'') return 0 ;;
          *) printf '请输入 0～3 的编号\n' ;;
        esac
      done
    fi
  else
    warn "这是旧版历史记录；请按首行字段查看原文件：$HISTORY_FILE"
  fi
}

update_channel_base() {
  case "$1" in
    github) printf '%s\n' 'https://raw.githubusercontent.com/allen0039/vps_tools/main/bbr-tune' ;;
    gitee) printf '%s\n' 'https://gitee.com/allen0039/vps_tools/raw/main/bbr-tune' ;;
    *) return 1 ;;
  esac
}

update_channel_api() {
  case "$1" in
    github) printf '%s\n' 'https://api.github.com/repos/allen0039/vps_tools/commits/main' ;;
    gitee) printf '%s\n' 'https://gitee.com/api/v5/repos/allen0039/vps_tools/branches/main' ;;
    *) return 1 ;;
  esac
}

download_update_installer() {
  local url="$1" destination="$2"
  if have curl; then
    curl -fL --retry 3 --connect-timeout 15 --max-time 120 -H 'Cache-Control: no-cache' "$url" -o "$destination"
  elif have wget; then
    wget -T 30 -t 3 -O "$destination" "$url"
  else
    error "缺少 curl 或 wget，无法下载更新文件"
    return 1
  fi
}

update_command() (
  require_linux; require_root
  local base temp_dir installer nonce installed_version installed_path metadata api sha
  base="$(update_channel_base "$UPDATE_CHANNEL")" || { error "更新渠道只能是 github 或 gitee"; return 1; }
  api="$(update_channel_api "$UPDATE_CHANNEL")"
  nonce="$$-$RANDOM-$RANDOM"
  temp_dir="$(mktemp -d /tmp/bbr-tune-update.XXXXXX)" || { error "无法创建更新临时目录"; return 1; }
  trap 'rm -rf "$temp_dir"' EXIT
  installer="${temp_dir}/install.sh"
  metadata="${temp_dir}/commit.json"
  section "从 ${UPDATE_CHANNEL} 更新 BBR TUNE"
  download_update_installer "${api}?bbr_tune_refresh=${nonce}" "$metadata" || { error "无法查询所选渠道的最新提交"; return 1; }
  sha="$(grep -oEm1 '"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]{40}"' "$metadata" | head -n 1 | grep -oE '[0-9a-f]{40}' || true)"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { error "更新渠道未返回有效的提交编号"; return 1; }
  base="${base%/main/bbr-tune}/${sha}/bbr-tune"
  printf '  下载来源：%s\n' "$base"
  download_update_installer "${base}/install.sh?bbr_tune_refresh=${nonce}" "$installer" || { error "安装器下载失败，当前版本未修改"; return 1; }
  [[ -s "$installer" ]] && head -n 1 "$installer" | grep -q '^#!/usr/bin/env bash' && bash -n "$installer" || {
    error "下载的安装器无效，当前版本未修改"; return 1;
  }
  if BBR_TUNE_RAW_BASE="$base" BBR_TUNE_DOWNLOAD_NONCE="$nonce" bash "$installer" --install-only; then
    installed_path="${BBR_TUNE_INSTALL_PATH:-/usr/local/sbin/bbr-tune}"
    installed_version="$("$installed_path" --version 2>/dev/null)" || { error "安装器已执行，但无法读取安装后的版本：$installed_path"; return 1; }
    installed_version="${installed_version##* }"
    if [[ "$installed_version" == "$VERSION" ]]; then
      warn "安装后仍是版本 ${VERSION}；所选渠道尚未提供新版本，或下载内容仍被缓存"
    else
      info "已从 ${VERSION} 更新到 ${installed_version}；重新打开菜单即可使用新版本"
    fi
  else
    error "更新未完成，请检查上方错误"
    return 1
  fi
)

ui_init() {
  if [[ -t 1 && "${TERM:-dumb}" != dumb && -z "${NO_COLOR+x}" ]]; then
    UI_BLUE=$'\033[1;36m'; UI_GREEN=$'\033[1;32m'; UI_YELLOW=$'\033[1;33m'; UI_RED=$'\033[1;31m'; UI_RESET=$'\033[0m'
  else
    UI_BLUE=""; UI_GREEN=""; UI_YELLOW=""; UI_RED=""; UI_RESET=""
  fi
}

ui_title() {
  section "BBR TUNE  /  远程服务器网络调优"
  printf '  版本 %s    服务器 → 本地电脑\n' "$VERSION"
  printf '  仅修改服务器参数；本地只测速。\n'
  if [[ -f "${PENDING_LATEST}/armed" ]]; then
    printf '\n  %s[待确认]%s 当前参数仍受安全回滚保护，请验证后选择 4。\n' "$UI_YELLOW" "$UI_RESET"
  fi
  printf '\n'
}

ui_menu_options() {
  printf '  调优与记录\n'
  printf '    %s1%s  自动测试并选择 TCP 参数\n' "$UI_GREEN" "$UI_RESET"
  printf '    2  查看当前 TCP / BBR 状态\n'
  printf '    3  查看历史测试 / 关键参数对比 / 应用\n'
  printf '\n  参数管理\n'
  printf '    4  确认保留当前参数\n'
  printf '    5  恢复调优前参数\n'
  printf '    6  更改出口队列算法\n'
  printf '\n  工具\n'
  printf '    7  使用说明\n'
  printf '    8  BBRv3 内核管理\n'
  printf '    9  更新工具（GitHub / Gitee）\n'
  printf '    0  退出\n\n'
}

ui_read_text() {
  local label="$1" default="$2" value
  if [[ -n "$default" ]]; then read -r -p "${label} [${default}]：" value || return 1; else read -r -p "${label}：" value || return 1; fi
  printf '%s\n' "${value:-$default}"
}

ui_read_number() {
  local label="$1" default="$2" min="$3" max="$4" kind="${5:-number}" value
  while true; do
    value="$(ui_read_text "$label" "$default")" || return 1
    if [[ "$kind" == integer ]] && ! is_integer "$value"; then
      printf '请输入 %s～%s 的整数\n' "$min" "$max" >&2; continue
    fi
    if is_number "$value" && awk -v v="$value" -v lo="$min" -v hi="$max" 'BEGIN {exit !(v>=lo && v<=hi)}'; then
      printf '%s\n' "$value"; return 0
    fi
    printf '%s请输入 %s～%s 的数字%s\n' "$UI_RED" "$min" "$max" "$UI_RESET" >&2
  done
}

ui_yes_no() {
  local label="$1" default="$2" answer suffix
  [[ "$default" == "y" ]] && suffix="[Y/n]" || suffix="[y/N]"
  while true; do
    read -r -p "${label} ${suffix}：" answer || return 1
    answer="${answer:-$default}"
    case "$answer" in y|Y|yes|YES) return 0 ;; n|N|no|NO) return 1 ;; esac
  done
}

ui_execute() {
  local need_root="$1"; shift
  local cmd=(bash "$SCRIPT_PATH" "$@") rc
  section "执行操作"
  if [[ "$need_root" == "1" && $EUID -ne 0 ]]; then
    have sudo || { printf '%s需要 root，但未安装 sudo%s\n' "$UI_RED" "$UI_RESET"; return 1; }
    if sudo "${cmd[@]}"; then rc=0; else rc=$?; fi
  else
    if "${cmd[@]}"; then rc=0; else rc=$?; fi
  fi
  if (( rc == 0 )); then
    printf '\n%s[完成] 操作已结束%s\n' "$UI_GREEN" "$UI_RESET"
  else
    printf '\n%s[未完成] 请按上方错误说明处理；退出码 %s%s\n' "$UI_RED" "$rc" "$UI_RESET"
  fi
  return "$rc"
}

ui_update() {
  local choice channel base
  section "更新工具 / 选择下载渠道"
  printf '  当前版本：%s\n' "$VERSION"
  printf '    1  GitHub\n    2  Gitee\n    0  返回\n'
  while true; do
    read -r -p '请选择渠道：' choice || return 1
    case "$choice" in
      1) channel=github; break ;;
      2) channel=gitee; break ;;
      0|'') return 1 ;;
      *) printf '请输入 0～2 的编号\n' ;;
    esac
  done
  base="$(update_channel_base "$channel")"
  printf '\n  将从 %s 下载并安装最新版本。\n' "$base"
  printf '  更新完成后会重新打开主菜单。\n'
  ui_yes_no '确认更新工具' n || return 1
  ui_execute 1 update --channel "$channel"
}

ui_select_strategy() {
  local choice
  printf '\n调优方案（所有方案均测试单连接和多连接）\n' >&2
  printf '  1) 均衡：综合吞吐、波动和重传（默认）\n' >&2
  printf '  2) 速度优先：吞吐权重更高，仍保留双侧基线保护\n' >&2
  printf '  3) 稳定优先：优先较小吞吐波动与负载 RTT 增长\n' >&2
  printf '  4) 低重传优先：优先较低估算重传，不承诺零丢包\n' >&2
  while true; do
    read -r -p '请选择方案 [1]：' choice || return 1
    case "${choice:-1}" in
      1) echo balanced; return ;; 2) echo speed; return ;;
      3) echo stable; return ;; 4) echo retrans; return ;;
      *) printf '请输入 1～4\n' >&2 ;;
    esac
  done
}

ui_select_qdisc() {
  local mode="${1:-tune}" choice
  printf '\n出口队列算法\n' >&2
  if [[ "$mode" == tune ]]; then
    printf '  1) 自动：普通队列使用 fq，已有 CAKE 保留（默认）\n' >&2
    printf '  2) 保留：不修改任何现有队列\n' >&2
    printf '  3) fq：按连接公平调度\n  4) fq_codel：公平调度与主动队列管理\n' >&2
    printf '  5) CAKE：公平调度与可选出站带宽整形\n' >&2
  else
    printf '  1) fq：按连接公平调度\n  2) fq_codel：公平调度与主动队列管理\n' >&2
    printf '  3) CAKE：公平调度与可选出站带宽整形\n  0) 返回\n' >&2
  fi
  printf '  切换不代表一定提速；原配置不能安全恢复时会停止。\n' >&2
  printf '  从 CAKE 改为其他算法会取消原 CAKE 的带宽整形。\n' >&2
  while true; do
    read -r -p "请选择队列$([[ "$mode" == tune ]] && printf ' [1]')：" choice || return 1
    if [[ "$mode" == tune ]]; then
      case "${choice:-1}" in
        1) echo auto; return ;; 2) echo keep; return ;;
        3) echo fq; return ;; 4) echo fq_codel; return ;; 5) echo cake; return ;;
      esac
    else
      case "$choice" in
        0) return 1 ;; 1) echo fq; return ;; 2) echo fq_codel; return ;; 3) echo cake; return ;;
      esac
    fi
    printf '请选择列表中的编号\n' >&2
  done
}

ui_read_cake_bandwidth() {
  local value
  printf '\nCAKE 整形带宽是服务器出站限速，不等于下载测速目标。\n' >&2
  printf '留空：保留已有 CAKE 带宽，新建时不限速；0：明确取消 CAKE 限速。\n' >&2
  printf '仅单根队列可设置带宽；mq 子队列不设置整张网卡的总带宽。\n' >&2
  while true; do
    read -r -p 'CAKE 整形带宽 Mbps [留空]：' value || return 1
    if [[ -z "$value" ]] || { is_number "$value" && awk -v n="$value" 'BEGIN{exit !(n==0 || (n>=0.001 && n<=100000))}'; }; then
      printf '%s\n' "$value"; return
    fi
    printf '请输入 0 或 0.001～100000 的数字，或直接回车\n' >&2
  done
}

ui_qdisc() {
  local selected rate="" iface
  local args=()
  selected="$(ui_select_qdisc switch)" || return
  if [[ "$selected" == cake ]]; then rate="$(ui_read_cake_bandwidth)" || return; fi
  iface="$(ui_read_text '出口网卡（auto 为自动识别）' "$IFACE")" || return
  [[ -z "$rate" ]] || args+=(--cake-bandwidth-mbps "$rate")
  if ui_yes_no '将所选队列写入开机配置' n; then args+=(--persist); fi
  printf '\n  目标队列：%s\n  安全回滚：%s 秒\n' "$selected" "$AUTO_ROLLBACK_SECONDS"
  printf '  本操作可能短暂影响代理连接；建议保留备用 SSH 或云控制台。\n'
  ui_yes_no '备份并切换队列' n || return
  ui_execute 1 qdisc --iface "$iface" --qdisc "$selected" ${args[@]+"${args[@]}"}
}

ui_autotune() {
  local address bandwidth streams duration util retrans strategy selected_qdisc cake_rate=""
  local args=()
  address="$(guess_server_address 2>/dev/null || true)"
  printf '%s目标带宽说明%s\n' "$UI_YELLOW" "$UI_RESET"
  printf '  本工具测试“远程服务器 → 本地电脑”的下载方向。\n'
  printf '  建议填写：服务器出站带宽上限与本地下载带宽上限中的较小值。\n'
  printf '  例如服务器限速 200 Mbps、本地宽带 1000 Mbps，应填写 200。\n\n'
  strategy="$(ui_select_strategy)" || return
  selected_qdisc="$(ui_select_qdisc)" || return
  if [[ "$selected_qdisc" == cake ]]; then cake_rate="$(ui_read_cake_bandwidth)" || return; fi
  args+=(--qdisc "$selected_qdisc")
  [[ -z "$cake_rate" ]] || args+=(--cake-bandwidth-mbps "$cake_rate")
  bandwidth="$(ui_read_number "期望端到端下载带宽 Mbps" "1000" "1" "100000")" || return
  address="$(ui_read_text "服务器公网 IP 或域名" "$address")" || return
  [[ -n "$address" ]] || { printf '%s服务器地址不能为空%s\n' "$UI_RED" "$UI_RESET"; return; }
  streams="$(ui_read_number "多连接评估并发流" "8" "2" "64" integer)" || return
  duration="$(ui_read_number "每轮测试秒数" "15" "5" "300" integer)" || return
  util="$(ui_read_number "目标带宽利用率 %" "90" "1" "100")" || return
  retrans="$(ui_read_number "最大估算重传率 %" "1" "0" "100")" || return
  if ui_yes_no "最优参数通过复测后写入开机配置" "n"; then args+=(--persist); fi
  local selected_name
  case "$strategy" in balanced) selected_name="均衡" ;; speed) selected_name="速度优先" ;; stable) selected_name="稳定优先" ;; retrans) selected_name="低重传优先" ;; esac
  section "开始前确认"
  printf '  • 队列选择：%s；需切换时先验证内核支持和原配置恢复。\n' "$selected_qdisc"
  printf '  • RTT 由首轮 iperf3 自动测量。\n'
  printf '  • 每组参数依次执行单连接和 %s 连接测试，以所选方案评分选优。\n' "$streams"
  printf '  • 方案：%s；每种连接数默认复测 2 次，按中位数评价。\n' "$selected_name"
  printf '  • 扩容受 BDP/内存约束；连续两档无收益停止，回落则回退精调。\n'
  printf '  • 不改内核故障处理、VM、ARP、路由和连接超时策略。\n'
  printf '  • TCP 聚合缓存高水位按服务器有效总内存的 2/3 计算。\n'
  printf '  • 每轮等待本地连接 %s 秒；安全回滚固定为 %s 秒。\n' "$WAIT_SECONDS" "$AUTO_ROLLBACK_SECONDS"
  printf '  • 本地只执行测速命令，不修改任何本地 TCP 参数。\n\n'
  ui_yes_no "开始自动寻优" "n" || return
  ui_execute 1 autotune --strategy "$strategy" --bandwidth-mbps "$bandwidth" --server-address "$address" \
    --parallel "$streams" --duration "$duration" \
    --target-utilization "$util" --max-retrans-percent "$retrans" ${args[@]+"${args[@]}"}
}
kernel_command() {
  local canonical helper
  canonical="$(readlink -f "$SCRIPT_PATH" 2>/dev/null || printf '%s' "$SCRIPT_PATH")"
  if [[ -r "${canonical}-kernel" ]]; then helper="${canonical}-kernel"
  elif [[ -r "${canonical%/*}/bbr-kernel.sh" ]]; then helper="${canonical%/*}/bbr-kernel.sh"
  else die "缺少配套内核管理脚本，请重新运行一键安装更新"; fi
  grep -Fqx "KERNEL_HELPER_VERSION=\"${VERSION}\"" "$helper" || die "内核管理脚本版本不匹配，请重新安装完整版本"
  bash "$helper" "${KERNEL_ARGS[@]}"
}

menu() {
  [[ -t 0 && -t 1 ]] || { usage; return; }
  require_linux
  ui_init
  local choice restart_target
  while true; do
    ui_title
    ui_menu_options
    read -r -p "请选择：" choice || return
    case "$choice" in
      1) ui_autotune || true ;;
      2) ui_execute 0 status --iface "$IFACE" || true ;;
      3) ui_execute 1 history || true ;;
      4) ui_execute 1 confirm || true ;;
      5) ui_execute 1 rollback || true ;;
      6) ui_qdisc || true ;;
      7) usage ;;
      8) ui_execute 1 kernel menu || true ;;
      9)
        if ui_update; then
          restart_target="${BBR_TUNE_INSTALL_PATH:-/usr/local/sbin/bbr-tune}"
          if [[ -r "$restart_target" ]]; then exec bash "$restart_target" menu; fi
          warn "已完成更新；请重新运行 bbrtcp 打开新版菜单"
        fi
        ;;
      0) return ;;
      *) printf '%s无效选择%s\n' "$UI_RED" "$UI_RESET" ;;
    esac
    printf '\n按 Enter 返回主界面...'; read -r _ || true
  done
}

main() {
  parse_args "$@"
  ui_init
  if [[ "$COMMAND" == rollback && "${BBR_AUTO_ROLLBACK:-0}" == 1 ]]; then
    require_linux; require_root
    stop_expired_session
  fi
  case "$COMMAND" in autotune|qdisc|apply-history|confirm|rollback) acquire_operation_lock ;; esac
  case "$COMMAND" in
    menu) menu ;;
    autotune) autotune ;;
    qdisc) qdisc_command ;;
    kernel) kernel_command ;;
    status) status_command ;;
    history) history_command ;;
    history-compare) history_compare_command ;;
    history-params) history_params_command ;;
    apply-history) apply_history_command ;;
    update) update_command ;;
    confirm) confirm_tuning ;;
    rollback) rollback_command ;;
    help) usage ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
