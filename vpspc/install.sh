#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_ROOT="/opt/vps-audit"
CONFIG_DIR="/etc/vps-audit"
STATE_DIR="/var/lib/vps-audit"
REPORT_DIR="$STATE_DIR/reports"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_FILE="$CONFIG_DIR/config.json"
DATA_MARKER=".vps-audit-managed"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

die() {
  echo "错误: $*" >&2
  exit 1
}

need_root() {
  [[ "$(id -u)" -eq 0 ]] || die "请使用 sudo bash install.sh"
  [[ "$(uname -s)" == "Linux" ]] || die "交互安装器仅支持 Linux"
  command -v systemctl >/dev/null 2>&1 || die "需要 systemd"
}

ask() {
  local prompt="$1"
  local default_value="$2"
  local answer
  if [[ ! -t 0 ]]; then
    printf '%s' "$default_value"
    return
  fi
  read -r -p "$prompt [$default_value]: " answer
  printf '%s' "${answer:-$default_value}"
}

ask_yes_no() {
  local prompt="$1"
  local default_value="$2"
  local answer
  answer="$(ask "$prompt (yes/no)" "$default_value")"
  case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
    y|yes|是) return 0 ;;
    *) return 1 ;;
  esac
}

ask_secret() {
  local prompt="$1"
  local default_value="$2"
  local answer
  if [[ ! -t 0 ]]; then
    printf '%s' "$default_value"
    return
  fi
  read -r -s -p "$prompt${default_value:+ [$default_value]}: " answer
  echo >&2
  printf '%s' "${answer:-$default_value}"
}

install_os_packages() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' \
      || die "需要 Python 3.9 或更高版本"
    return
  fi
  echo "安装 Python 运行环境..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 ca-certificates
  else
    die "未识别包管理器，请先安装 Python 3.9+ 和 venv"
  fi
  python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' \
    || die "系统安装的 Python 版本低于 3.9"
}

existing_config_value() {
  local dotted_key="$1"
  local fallback="$2"
  if [[ ! -f "$CONFIG_FILE" ]]; then
    printf '%s' "$fallback"
    return
  fi
  python3 - "$CONFIG_FILE" "$dotted_key" "$fallback" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        value = json.load(handle)
    for key in sys.argv[2].split("."):
        value = value[key]
    if isinstance(value, bool):
        print("yes" if value else "no", end="")
    elif isinstance(value, list):
        print(value[0] if value else sys.argv[3], end="")
    else:
        print(value, end="")
except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
    print(sys.argv[3], end="")
PY
}

validate_storage_path() {
  local value="$1"
  local label="$2"
  [[ -n "$value" ]] || die "$label 不能为空"
  [[ "$value" == /* ]] || die "$label 必须是绝对路径，例如 /data/vps-audit"
  [[ "$value" =~ ^/[A-Za-z0-9._/+:=-]+$ ]] \
    || die "$label 只能包含字母、数字、/、点、下划线、加号、冒号、等号和连字符"
  [[ "/$value/" != *"/../"* ]] || die "$label 不能包含 .."

  local normalized
  normalized="$(python3 - "$value" <<'PY'
import os
import sys
print(os.path.normpath(sys.argv[1]), end="")
PY
)"
  case "$normalized" in
    /|/bin|/boot|/data|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib)
      die "$label 不能使用系统根目录或过宽的父目录: $normalized"
      ;;
    "$INSTALL_ROOT"|"$CONFIG_DIR")
      die "$label 不能与程序或配置目录相同: $normalized"
      ;;
  esac
  case "$normalized" in
    /home/*|/root/*)
      die "$label 不能放在用户主目录中；systemd 安全策略不会开放该位置"
      ;;
  esac
  printf '%s' "$normalized"
}

is_configured_storage_path() {
  local directory="$1"
  [[ -f "$CONFIG_FILE" ]] || return 1
  [[ "$directory" == "$(existing_config_value state_dir "")" \
    || "$directory" == "$(existing_config_value report_dir "")" ]]
}

prepare_managed_directory() {
  local directory="$1"
  local label="$2"
  if [[ -e "$directory" && ! -d "$directory" ]]; then
    die "$label 已存在但不是目录: $directory"
  fi
  if [[ -d "$directory" && ! -f "$directory/$DATA_MARKER" ]]; then
    local first_entry
    first_entry="$(find "$directory" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null || true)"
    if [[ -n "$first_entry" ]] && ! is_configured_storage_path "$directory"; then
      die "$label 已存在且包含其他文件。请换一个空目录，避免审计数据与现有数据混用: $directory"
    fi
    if [[ -n "$first_entry" ]]; then
      echo "沿用已有审计目录并补充安全标记: $directory" >&2
    fi
  fi
  # 安装器只允许 root 运行，因此 Linux 上新目录自然归 root:root 所有。
  install -d -m 0700 "$directory"
  if [[ "$(uname -s)" == "Linux" ]]; then
    chown root:root "$directory"
  fi
  : > "$directory/$DATA_MARKER"
  chmod 0600 "$directory/$DATA_MARKER"
}

detect_auth_log() {
  if [[ -f /var/log/auth.log ]]; then
    printf '%s' "/var/log/auth.log"
  elif [[ -f /var/log/secure ]]; then
    printf '%s' "/var/log/secure"
  else
    printf '%s' ""
  fi
}

copy_application() {
  install -d -m 0755 "$INSTALL_ROOT"
  cp -a "$SCRIPT_DIR/vps_audit" "$INSTALL_ROOT/"
  cp -a "$SCRIPT_DIR/pyproject.toml" "$SCRIPT_DIR/setup.py" "$INSTALL_ROOT/"
  if ! python3 -m venv "$INSTALL_ROOT/venv"; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv
      python3 -m venv "$INSTALL_ROOT/venv"
    else
      die "无法创建 Python venv，请先安装对应的 python3-venv 包"
    fi
  fi
  install -m 0755 "$SCRIPT_DIR/deploy/bin/vps-audit" "$INSTALL_ROOT/venv/bin/vps-audit"
  install -m 0755 "$SCRIPT_DIR/deploy/bin/vps-audit-runner" "$INSTALL_ROOT/venv/bin/vps-audit-runner"
}

write_runtime_config() {
  local auth_default timezone_default falco_default
  local auth_log auth_timezone falco_log subscription_log miaomiaowux_log miaomiaowux_timezone retention interval
  local state_dir report_dir
  local journal_enabled telegram_enabled telegram_chat min_severity cooldown include_ip
  local ai_enabled ai_model city_db asn_db install_geoip
  local sub_window sub_ip_count sub_region_count sub_city_count sub_asn_count travel_distance travel_speed

  auth_default="$(existing_config_value auth_logs "$(detect_auth_log)")"
  timezone_default="$(existing_config_value auth_timezone "$(date +%:z 2>/dev/null || echo +00:00)")"
  [[ "$timezone_default" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]] || timezone_default="+00:00"
  falco_default=""
  [[ -f /var/log/falco/events.json ]] && falco_default="/var/log/falco/events.json"
  falco_default="$(existing_config_value falco_logs "$falco_default")"
  local subscription_default
  subscription_default="$(existing_config_value subscription_logs "")"
  local miaomiaowux_default
  miaomiaowux_default="$(existing_config_value miaomiaowux_logs "")"
  [[ -f /opt/1panel/docker/compose/miaomiaowux/data/logs/mmwx.log ]] \
    && miaomiaowux_default="/opt/1panel/docker/compose/miaomiaowux/data/logs/mmwx.log"

  echo
  echo "配置本地审计数据存储"
  state_dir="$(ask "审计数据保存目录（直接回车使用默认值）" "$(existing_config_value state_dir "$STATE_DIR")")"
  state_dir="$(validate_storage_path "$state_dir" "审计数据保存目录")"
  report_dir="$(ask "报告保存目录（直接回车使用默认值）" "$(existing_config_value report_dir "$state_dir/reports")")"
  report_dir="$(validate_storage_path "$report_dir" "报告保存目录")"
  retention="$(ask "事件保存天数（直接回车使用默认值）" "$(existing_config_value retention_days 7)")"
  [[ "$retention" =~ ^[0-9]+$ ]] && (( retention >= 1 && retention <= 365 )) \
    || die "保留天数应为 1 到 365 的整数"
  prepare_managed_directory "$state_dir" "审计数据保存目录"
  prepare_managed_directory "$report_dir" "报告保存目录"

  echo
  echo "配置日志与巡查周期"
  auth_log="$(ask "SSH 登录日志路径（留空自动读取 journald）" "$auth_default")"
  journal_enabled="false"
  [[ -n "$auth_log" ]] || journal_enabled="true"
  auth_timezone="$(ask "日志时区偏移" "$timezone_default")"
  interval="$(ask "巡查间隔（分钟）" "$(existing_config_value scan_interval_minutes 5)")"
  falco_log="$(ask "Falco JSON 日志路径，留空则只审计登录" "$falco_default")"
  subscription_log="$(ask "妙妙屋 X 订阅访问 JSONL 路径，留空则不采集" "$subscription_default")"
  miaomiaowux_log="$(ask "妙妙屋 X 原生 mmwx.log 路径，留空则不采集" "$miaomiaowux_default")"
  miaomiaowux_timezone="$(ask "mmwx.log 时区偏移" "$(existing_config_value miaomiaowux_timezone +00:00)")"
  [[ "$auth_timezone" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]] || die "日志时区格式应为 +08:00"
  [[ "$interval" =~ ^[0-9]+$ ]] && (( interval >= 1 && interval <= 1440 )) \
    || die "巡查间隔应为 1 到 1440 的整数"
  if [[ -n "$auth_log" && ! -f "$auth_log" ]]; then
    echo "警告: $auth_log 当前不存在；服务会等待该日志出现。" >&2
  fi
  if [[ -n "$falco_log" && ! -f "$falco_log" ]]; then
    echo "警告: $falco_log 当前不存在；进程/网络审计在 Falco 写入后生效。" >&2
  fi
  if [[ -n "$subscription_log" && ! -f "$subscription_log" ]]; then
    echo "提示: $subscription_log 当前不存在；请让妙妙屋 X 或适配器按文档格式写入。" >&2
  fi
  if [[ -n "$miaomiaowux_log" && ! -f "$miaomiaowux_log" ]]; then
    echo "提示: $miaomiaowux_log 当前不存在；妙妙屋 X 原生日志采集暂不会产生事件。" >&2
  fi
  [[ "$miaomiaowux_timezone" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]] || die "mmwx.log 时区格式应为 +00:00"

  echo
  echo "配置个人订阅异地使用预警阈值"
  sub_window="$(ask "活跃 IP 统计窗口（分钟）" "$(existing_config_value rules.thresholds.subscription_window_minutes 15)")"
  sub_ip_count="$(ask "同订阅多少个不同 IP 时告警" "$(existing_config_value rules.thresholds.subscription_ip_count 10)")"
  sub_region_count="$(ask "同订阅跨多少个省/地区时告警" "$(existing_config_value rules.thresholds.subscription_region_count 3)")"
  sub_city_count="$(ask "同订阅跨多少个城市时告警" "$(existing_config_value rules.thresholds.subscription_city_count 5)")"
  sub_asn_count="$(ask "同订阅跨多少个 ASN/运营商时告警" "$(existing_config_value rules.thresholds.subscription_asn_count 4)")"
  travel_distance="$(ask "不可能旅行最小距离（km）" "$(existing_config_value rules.thresholds.impossible_travel_min_km 500)")"
  travel_speed="$(ask "不可能旅行速度阈值（km/h）" "$(existing_config_value rules.thresholds.impossible_travel_kmh 900)")"
  for value in "$sub_window" "$sub_ip_count" "$sub_region_count" "$sub_city_count" "$sub_asn_count" "$travel_distance" "$travel_speed"; do
    [[ "$value" =~ ^[0-9]+$ ]] || die "订阅审计阈值必须是正整数"
    (( value >= 1 )) || die "订阅审计阈值必须大于 0"
  done

  telegram_enabled="false"
  telegram_chat=""
  min_severity="high"
  cooldown="6"
  include_ip="false"
  if ask_yes_no "启用 Telegram Bot 推送" "$(existing_config_value telegram.enabled no)"; then
    telegram_enabled="true"
    local telegram_token telegram_token_default
    telegram_token_default=""
    [[ -s "$CONFIG_DIR/telegram.token" ]] && telegram_token_default="KEEP"
    telegram_token="$(ask_secret "Telegram Bot Token（输入 KEEP 保留已有值）" "$telegram_token_default")"
    [[ -n "$telegram_token" ]] || die "启用 Telegram 时 Bot Token 不能为空"
    telegram_chat="$(ask "Telegram Chat ID" "$(existing_config_value telegram.chat_id "")")"
    [[ -n "$telegram_chat" ]] || die "启用 Telegram 时 Chat ID 不能为空"
    min_severity="$(ask "最低推送等级 low/medium/high/critical" "$(existing_config_value telegram.minimum_severity high)")"
    cooldown="$(ask "同账号同规则冷却小时数" "$(existing_config_value telegram.cooldown_hours 6)")"
    case "$min_severity" in low|medium|high|critical) ;; *) die "无效的推送等级" ;; esac
    [[ "$cooldown" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "冷却时间必须是非负数字"
    if ask_yes_no "推送中显示完整来源 IP（默认只显示前两段）" "$(existing_config_value telegram.include_source_ip no)"; then
      include_ip="true"
    fi
    install -d -m 0700 "$CONFIG_DIR"
    if [[ "$telegram_token" != "KEEP" ]]; then
      printf '%s\n' "$telegram_token" > "$CONFIG_DIR/telegram.token"
    fi
    chmod 0600 "$CONFIG_DIR/telegram.token"
  fi

  city_db=""
  asn_db=""
  install_geoip="false"
  local detected_city detected_asn
  detected_city="$(existing_config_value geoip.city_db /var/lib/GeoIP/GeoLite2-City.mmdb)"
  detected_asn="$(existing_config_value geoip.asn_db /var/lib/GeoIP/GeoLite2-ASN.mmdb)"
  [[ -f "$detected_city" ]] || detected_city=""
  [[ -f "$detected_asn" ]] || detected_asn=""
  if [[ -n "$detected_city" || -n "$detected_asn" ]] || ask_yes_no "配置本地 MaxMind GeoIP 数据库" "no"; then
    city_db="$(ask "GeoLite2 City MMDB 路径，留空跳过" "$detected_city")"
    asn_db="$(ask "GeoLite2 ASN MMDB 路径，留空跳过" "$detected_asn")"
    if [[ -n "$city_db" || -n "$asn_db" ]]; then
      install_geoip="true"
    fi
  fi

  ai_enabled="false"
  ai_model=""
  if ask_yes_no "有新告警时启用 OpenAI AI 复核" "$(existing_config_value openai_review.enabled no)"; then
    ai_enabled="true"
    local openai_key openai_key_default
    openai_key_default=""
    [[ -s "$CONFIG_DIR/openai.key" ]] && openai_key_default="KEEP"
    openai_key="$(ask_secret "OpenAI API Key（输入 KEEP 保留已有值）" "$openai_key_default")"
    [[ -n "$openai_key" ]] || die "启用 AI 复核时 API Key 不能为空"
    ai_model="$(ask "OpenAI 模型 ID" "$(existing_config_value openai_review.model "")")"
    [[ -n "$ai_model" ]] || die "启用 AI 复核时模型 ID 不能为空"
    install -d -m 0700 "$CONFIG_DIR"
    if [[ "$openai_key" != "KEEP" ]]; then
      printf '%s\n' "$openai_key" > "$CONFIG_DIR/openai.key"
    fi
    chmod 0600 "$CONFIG_DIR/openai.key"
  fi

  install -d -m 0700 "$CONFIG_DIR"
  AUTH_LOG="$auth_log" AUTH_TIMEZONE="$auth_timezone" JOURNAL_ENABLED="$journal_enabled" FALCO_LOG="$falco_log" SUBSCRIPTION_LOG="$subscription_log" \
  MIAOMIAOWUX_LOG="$miaomiaowux_log" MIAOMIAOWUX_TIMEZONE="$miaomiaowux_timezone" \
  STATE_PATH="$state_dir" REPORT_PATH="$report_dir" RETENTION="$retention" INTERVAL_VALUE="$interval" \
  TELEGRAM_ENABLED="$telegram_enabled" TELEGRAM_CHAT="$telegram_chat" \
  MIN_SEVERITY="$min_severity" COOLDOWN="$cooldown" INCLUDE_IP="$include_ip" \
  AI_ENABLED="$ai_enabled" AI_MODEL="$ai_model" CITY_DB="$city_db" ASN_DB="$asn_db" \
  SUB_WINDOW="$sub_window" SUB_IP_COUNT="$sub_ip_count" SUB_REGION_COUNT="$sub_region_count" \
  SUB_CITY_COUNT="$sub_city_count" SUB_ASN_COUNT="$sub_asn_count" TRAVEL_DISTANCE="$travel_distance" TRAVEL_SPEED="$travel_speed" \
  python3 - "$CONFIG_FILE" <<'PY'
import json
import os
import sys

config = {
    "auth_logs": [os.environ["AUTH_LOG"]] if os.environ["AUTH_LOG"] else [],
    "auth_timezone": os.environ["AUTH_TIMEZONE"],
    "journal": {
        "enabled": os.environ["JOURNAL_ENABLED"] == "true",
        "units": ["ssh.service", "sshd.service"],
        "initial_since_hours": 24,
    },
    "falco_logs": [os.environ["FALCO_LOG"]] if os.environ["FALCO_LOG"] else [],
    "subscription_logs": [os.environ["SUBSCRIPTION_LOG"]] if os.environ["SUBSCRIPTION_LOG"] else [],
    "miaomiaowux_logs": [os.environ["MIAOMIAOWUX_LOG"]] if os.environ["MIAOMIAOWUX_LOG"] else [],
    "miaomiaowux_timezone": os.environ["MIAOMIAOWUX_TIMEZONE"],
    "state_dir": os.environ["STATE_PATH"],
    "report_dir": os.environ["REPORT_PATH"],
    "retention_days": int(os.environ["RETENTION"]),
    "scan_interval_minutes": int(os.environ["INTERVAL_VALUE"]),
    "rules": {
        "thresholds": {
            "subscription_window_minutes": int(os.environ["SUB_WINDOW"]),
            "subscription_ip_count": int(os.environ["SUB_IP_COUNT"]),
            "subscription_region_count": int(os.environ["SUB_REGION_COUNT"]),
            "subscription_city_count": int(os.environ["SUB_CITY_COUNT"]),
            "subscription_asn_count": int(os.environ["SUB_ASN_COUNT"]),
            "impossible_travel_min_km": int(os.environ["TRAVEL_DISTANCE"]),
            "impossible_travel_kmh": int(os.environ["TRAVEL_SPEED"]),
        }
    },
    "geoip": {"city_db": os.environ["CITY_DB"], "asn_db": os.environ["ASN_DB"]},
    "telegram": {
        "enabled": os.environ["TELEGRAM_ENABLED"] == "true",
        "token_file": "/etc/vps-audit/telegram.token",
        "chat_id": os.environ["TELEGRAM_CHAT"],
        "minimum_severity": os.environ["MIN_SEVERITY"],
        "cooldown_hours": float(os.environ["COOLDOWN"]),
        "include_source_ip": os.environ["INCLUDE_IP"] == "true",
        "max_findings": 8,
    },
    "openai_review": {
        "enabled": os.environ["AI_ENABLED"] == "true",
        "api_key_file": "/etc/vps-audit/openai.key",
        "model": os.environ["AI_MODEL"],
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(config, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
PY
  chmod 0600 "$CONFIG_FILE"

  if [[ "$install_geoip" == "true" ]]; then
    "$INSTALL_ROOT/venv/bin/pip" install --disable-pip-version-check --no-cache-dir 'geoip2>=4,<6'
  fi

  INTERVAL="$interval"
  CONFIGURED_STATE_DIR="$state_dir"
  CONFIGURED_REPORT_DIR="$report_dir"
}

install_systemd_units() {
  local interval="$1"
  local state_dir="$2"
  local report_dir="$3"
  SERVICE_TEMPLATE="$SCRIPT_DIR/deploy/systemd/vps-audit.service" SERVICE_OUTPUT="$SYSTEMD_DIR/vps-audit.service" \
  STATE_PATH="$state_dir" REPORT_PATH="$report_dir" python3 <<'PY'
import os
from pathlib import Path

template = Path(os.environ["SERVICE_TEMPLATE"]).read_text(encoding="utf-8")
template = template.replace("@STATE_DIR@", os.environ["STATE_PATH"])
template = template.replace("@REPORT_DIR@", os.environ["REPORT_PATH"])
Path(os.environ["SERVICE_OUTPUT"]).write_text(template, encoding="utf-8")
PY
  chmod 0644 "$SYSTEMD_DIR/vps-audit.service"
  sed "s/@INTERVAL@/$interval/g" "$SCRIPT_DIR/deploy/systemd/vps-audit.timer" > "$SYSTEMD_DIR/vps-audit.timer"
  chmod 0644 "$SYSTEMD_DIR/vps-audit.timer"
  systemctl daemon-reload
  systemctl enable --now vps-audit.timer
}

install_app() {
  need_root
  install_os_packages
  copy_application
  INTERVAL="5"
  write_runtime_config
  install_systemd_units "$INTERVAL" "$CONFIGURED_STATE_DIR" "$CONFIGURED_REPORT_DIR"
  echo
  echo "执行首次巡查..."
  if ! systemctl start vps-audit.service; then
    journalctl -u vps-audit.service -n 30 --no-pager || true
    die "首次巡查失败，请检查以上日志"
  fi
  if [[ "$(existing_config_value telegram.enabled no)" == "yes" ]] && ask_yes_no "发送 Telegram 测试消息" "yes"; then
    "$INSTALL_ROOT/venv/bin/vps-audit-runner" --config "$CONFIG_FILE" test-telegram
  fi
  echo
  echo "安装完成。"
  echo "状态: sudo bash install.sh status"
  echo "审计数据: $CONFIGURED_STATE_DIR（保留 $(existing_config_value retention_days 7) 天）"
  echo "报告: $CONFIGURED_REPORT_DIR/latest.md"
  echo "日志: journalctl -u vps-audit.service"
}

configure_app() {
  need_root
  [[ -x "$INSTALL_ROOT/venv/bin/vps-audit-runner" ]] || die "尚未安装"
  INTERVAL="5"
  write_runtime_config
  install_systemd_units "$INTERVAL" "$CONFIGURED_STATE_DIR" "$CONFIGURED_REPORT_DIR"
  systemctl start vps-audit.service
  echo "配置已更新。"
}

status_app() {
  need_root
  systemctl status vps-audit.timer --no-pager || true
  echo
  if [[ -x "$INSTALL_ROOT/venv/bin/vps-audit-runner" && -f "$CONFIG_FILE" ]]; then
    "$INSTALL_ROOT/venv/bin/vps-audit-runner" --config "$CONFIG_FILE" health
  fi
}

uninstall_app() {
  need_root
  local purge_state_dir=""
  local purge_report_dir=""
  if [[ "${1:-}" == "--purge" && -f "$CONFIG_FILE" ]]; then
    purge_state_dir="$(validate_storage_path "$(existing_config_value state_dir "$STATE_DIR")" "已配置的审计数据目录")"
    purge_report_dir="$(validate_storage_path "$(existing_config_value report_dir "$REPORT_DIR")" "已配置的报告目录")"
  fi
  systemctl disable --now vps-audit.timer >/dev/null 2>&1 || true
  systemctl stop vps-audit.service >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_DIR/vps-audit.service" "$SYSTEMD_DIR/vps-audit.timer"
  systemctl daemon-reload
  rm -rf "$INSTALL_ROOT"
  if [[ "${1:-}" == "--purge" ]]; then
    local deleted=()
    if [[ -n "$purge_report_dir" && -f "$purge_report_dir/$DATA_MARKER" ]]; then
      rm -rf -- "$purge_report_dir"
      deleted+=("$purge_report_dir")
    elif [[ -n "$purge_report_dir" ]]; then
      echo "安全保留未带管理标记的报告目录: $purge_report_dir" >&2
    fi
    if [[ -n "$purge_state_dir" && -f "$purge_state_dir/$DATA_MARKER" ]]; then
      rm -rf -- "$purge_state_dir"
      deleted+=("$purge_state_dir")
    elif [[ -n "$purge_state_dir" ]]; then
      echo "安全保留未带管理标记的审计数据目录: $purge_state_dir" >&2
    fi
    rm -rf -- "$CONFIG_DIR"
    echo "程序和配置已删除。"
    if (( ${#deleted[@]} > 0 )); then
      printf '已删除本地审计目录: %s\n' "${deleted[@]}"
    fi
  else
    echo "程序已卸载，配置和审计数据仍保留。使用 uninstall --purge 可一并删除。"
  fi
}

main() {
  case "${1:-install}" in
    install) install_app ;;
    configure) configure_app ;;
    status) status_app ;;
    uninstall) uninstall_app "${2:-}" ;;
    *)
      echo "用法: sudo bash install.sh [install|configure|status|uninstall [--purge]]"
      exit 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
