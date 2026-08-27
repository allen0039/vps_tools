#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_ROOT="/opt/vps-audit"
CONFIG_DIR="/etc/vps-audit"
STATE_DIR="/var/lib/vps-audit"
REPORT_DIR="$STATE_DIR/reports"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_FILE="$CONFIG_DIR/config.json"
DATA_MARKER=".vps-audit-managed"
SOURCE_MARKER=".vpspc-source-managed"
CLI_SHORTCUT="/usr/local/bin/vpspc"
CLI_SHORTCUT_MARKER="managed-by=vpspc"
FALCO_MANAGED_DIR="$CONFIG_DIR/managed"
FALCO_RULE_FILE="/etc/falco/rules.d/vps-audit-rules.yaml"
FALCO_OVERRIDE_DIR="$SYSTEMD_DIR/falco-modern-bpf.service.d"
FALCO_OVERRIDE_FILE="$FALCO_OVERRIDE_DIR/vps-audit.conf"
FALCO_LOG_DIR="/var/log/vps-audit"
FALCO_LOG_FILE="$FALCO_LOG_DIR/falco-events.json"
FALCO_LOGROTATE_FILE="/etc/logrotate.d/vps-audit-falco"
FALCO_REPO_LIST="/etc/apt/sources.list.d/falcosecurity.list"
FALCO_REPO_KEY="/usr/share/keyrings/falco-archive-keyring.gpg"
FALCO_REPO_URL="https://download.falco.org/packages/deb"
FALCO_KEY_URL="https://falco.org/repo/falcosecurity-packages.asc"
FALCO_ETC_DIR="/etc/falco"
FALCOCTL_ETC_DIR="/etc/falcoctl"
APT_LIST_CACHE_DIR="/var/lib/apt/lists"
APT_ARCHIVE_CACHE_DIR="/var/cache/apt/archives"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AI_TEST_REQUESTED="false"

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

select_node_reporting_mode() {
  local current_mode="${1:-controller_only}"
  local default_choice choice
  case "$current_mode" in
    node_reporting) default_choice="2" ;;
    *) default_choice="1" ;;
  esac
  echo "1. 仅主控监控" >&2
  echo "2. 允许节点轻量上报" >&2
  choice="$(ask "请选择采集模式" "$default_choice")"
  case "$choice" in
    1) printf 'controller_only' ;;
    2) printf 'node_reporting' ;;
    *) die "请选择 1 或 2" ;;
  esac
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

existing_config_list() {
  local dotted_key="$1"
  local fallback="${2:-}"
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
    if not isinstance(value, list):
        raise TypeError
    print(",".join(str(item) for item in value), end="")
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
    || "$directory" == "$(existing_config_value report_dir "")" \
    || "$directory" == "$(existing_config_value behavior_audit.archive_dir "")" ]]
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

detect_geoip_database() {
  local filename="$1"
  local configured="${2:-}"
  local state_dir="${3:-$STATE_DIR}"
  local candidate root
  for candidate in \
    "$configured" \
    "$state_dir/geoip/$filename" \
    "/usr/share/GeoIP/$filename" \
    "/usr/local/share/GeoIP/$filename" \
    "/var/lib/GeoIP/$filename" \
    "/opt/GeoIP/$filename"; do
    if [[ -n "$candidate" && -f "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  done
  for root in /usr/share/GeoIP /usr/local/share/GeoIP /var/lib/GeoIP /opt/GeoIP; do
    [[ -d "$root" ]] || continue
    candidate="$(find "$root" -maxdepth 3 -type f -name "$filename" -print -quit 2>/dev/null || true)"
    if [[ -n "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  done
}

install_maxmind_geoip_databases() {
  local destination="$1"
  local license_key
  license_key="$(ask_secret "MaxMind License Key（仅用于本次官方下载，不保存）" "")"
  [[ -n "$license_key" ]] || die "自动安装 GeoLite2 需要 MaxMind License Key"
  install -d -m 0700 "$destination"
  if ! printf '%s' "$license_key" \
    | python3 "$SCRIPT_DIR/vps_audit/maxmind_install.py" --destination "$destination" >&2; then
    license_key=""
    die "GeoLite2 自动安装失败；未修改已有数据库"
  fi
  license_key=""
}

configure_geoip_databases() {
  local state_dir="$1"
  local city_db asn_db configured_city configured_asn destination tab
  configured_city="$(existing_config_value geoip.city_db "")"
  configured_asn="$(existing_config_value geoip.asn_db "")"
  city_db="$(detect_geoip_database GeoLite2-City.mmdb "$configured_city" "$state_dir")"
  asn_db="$(detect_geoip_database GeoLite2-ASN.mmdb "$configured_asn" "$state_dir")"

  echo >&2
  echo "MaxMind GeoIP 地理位置数据库" >&2
  if [[ -n "$city_db" ]]; then
    echo "City 数据库：已自动检测 $city_db" >&2
  fi
  if [[ -n "$asn_db" ]]; then
    echo "ASN 数据库：已自动检测 $asn_db" >&2
  fi
  if [[ -z "$city_db" || -z "$asn_db" ]]; then
    echo "未检测到完整的 GeoLite2 City/ASN 数据库。它用于离线识别国家、省市、距离和运营商。" >&2
    echo "自动安装需要先在 MaxMind 创建免费账号并生成 License Key。" >&2
    if ask_yes_no "是否从 MaxMind 官方自动安装/补全 GeoLite2 数据库" "no"; then
      destination="$state_dir/geoip"
      install_maxmind_geoip_databases "$destination"
      city_db="$destination/GeoLite2-City.mmdb"
      asn_db="$destination/GeoLite2-ASN.mmdb"
      echo "GeoLite2 City/ASN 已安装到 $destination" >&2
    elif [[ -z "$city_db" && -z "$asn_db" ]]; then
      echo "已跳过 GeoIP 安装；IP 数量预警仍可用，异地风险识别将缺少省市和 ASN 信息。" >&2
    else
      echo "已跳过 GeoIP 补全；继续使用已检测到的数据库。" >&2
    fi
  fi
  tab="$(printf '\t')"
  printf '%s%s%s' "$city_db" "$tab" "$asn_db"
}

detect_service_read_access() {
  [[ -f "$CONFIG_FILE" ]] || return 0
  python3 - "$CONFIG_FILE" <<'PY'
import grp
import json
import os
import stat
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)

paths = []
for key in ("auth_logs", "falco_logs", "subscription_logs", "miaomiaowux_logs"):
    value = config.get(key, [])
    if isinstance(value, list):
        paths.extend(item for item in value if isinstance(item, str))
geoip = config.get("geoip", {})
if isinstance(geoip, dict):
    paths.extend(
        value for value in (geoip.get("city_db"), geoip.get("asn_db"))
        if isinstance(value, str)
    )

groups = set()
needs_capability = [False]

def group_name(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)

def require_access(path, owner_bit, group_bit, other_bit):
    try:
        info = os.stat(path)
    except OSError:
        return
    if info.st_uid == 0:
        if not info.st_mode & owner_bit:
            needs_capability[0] = True
        return
    if info.st_mode & other_bit:
        return
    if info.st_mode & group_bit:
        if info.st_gid != 0:
            groups.add(group_name(info.st_gid))
        return
    needs_capability[0] = True

for configured in paths:
    if not configured or not os.path.isabs(configured):
        continue
    resolved = os.path.realpath(configured)
    current = os.path.dirname(resolved)
    while current and current != "/":
        require_access(current, stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH)
        current = os.path.dirname(current)
    if os.path.exists(resolved):
        require_access(resolved, stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH)

journal = config.get("journal", {})
if isinstance(journal, dict) and journal.get("enabled"):
    try:
        groups.add(grp.getgrnam("systemd-journal").gr_name)
    except KeyError:
        pass

print(
    " ".join(sorted(groups))
    + "\t"
    + ("yes" if needs_capability[0] else "no"),
    end="",
)
PY
}

detect_host_timezone_offset() {
  local value
  value="$(date +%:z 2>/dev/null || true)"
  if [[ "$value" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]]; then
    printf '%s' "$value"
    return
  fi
  python3 <<'PY'
from datetime import datetime

value = datetime.now().astimezone().strftime("%z")
print(value[:3] + ":" + value[3:], end="")
PY
}

detect_miaomiaowux_log() {
  local configured="${1:-}"
  local candidate mount_source
  if [[ -n "$configured" && -f "$configured" ]]; then
    printf '%s' "$configured"
    return
  fi
  for candidate in \
    /opt/1panel/docker/compose/miaomiaowux/data/logs/mmwx.log \
    /opt/miaomiaowux/data/logs/mmwx.log \
    /var/lib/miaomiaowux/data/logs/mmwx.log; do
    if [[ -f "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  done
  if command -v docker >/dev/null 2>&1 \
    && docker inspect miaomiaowux >/dev/null 2>&1; then
    mount_source="$(docker inspect miaomiaowux \
      --format '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{println .Source}}{{end}}{{end}}' \
      2>/dev/null | head -n 1)"
    candidate="${mount_source%/}/logs/mmwx.log"
    if [[ -n "$mount_source" && -f "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  fi
  if [[ -d /opt/1panel/docker/compose ]]; then
    candidate="$(find /opt/1panel/docker/compose -maxdepth 5 -type f -name mmwx.log -print -quit 2>/dev/null || true)"
    [[ -n "$candidate" ]] && printf '%s' "$candidate"
  fi
}

detect_subscription_jsonl() {
  local configured="${1:-}"
  local candidate
  if [[ -n "$configured" && -f "$configured" ]]; then
    printf '%s' "$configured"
    return
  fi
  for candidate in \
    /var/log/vpspc/subscription-access.jsonl \
    /var/log/miaomiaowu/subscription-access.jsonl \
    /var/log/miaomiaowux/subscription-access.jsonl; do
    if [[ -f "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  done
}

infer_log_timezone_offset() {
  local log_path="$1"
  LOG_TIMEZONE_PATH="$log_path" python3 <<'PY'
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

path = Path(os.environ["LOG_TIMEZONE_PATH"])
try:
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - 262_144))
        text = handle.read().decode("utf-8", errors="replace")
    matches = re.findall(r'time="(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"', text)
    naive = datetime.strptime(matches[-1], "%Y-%m-%d %H:%M:%S")
    modified = path.stat().st_mtime
except (OSError, ValueError, IndexError):
    raise SystemExit(1)

best = None
for minutes in range(-12 * 60, 14 * 60 + 1, 15):
    observed = naive.replace(tzinfo=timezone(timedelta(minutes=minutes))).timestamp()
    difference = abs(modified - observed)
    if best is None or difference < best[0]:
        best = (difference, minutes)
if best is None or best[0] > 900:
    raise SystemExit(1)
minutes = best[1]
sign = "+" if minutes >= 0 else "-"
hours, remainder = divmod(abs(minutes), 60)
print(f"{sign}{hours:02d}:{remainder:02d}", end="")
PY
}

detect_miaomiaowux_timezone() {
  local log_path="$1"
  local configured="${2:-}"
  local value
  value="$(infer_log_timezone_offset "$log_path" 2>/dev/null || true)"
  if [[ "$value" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]]; then
    printf '%s' "$value"
    return
  fi
  if command -v docker >/dev/null 2>&1 \
    && docker inspect miaomiaowux >/dev/null 2>&1; then
    value="$(docker exec miaomiaowux date +%:z 2>/dev/null || true)"
    if [[ "$value" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]]; then
      printf '%s' "$value"
      return
    fi
  fi
  if [[ "$configured" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]]; then
    printf '%s' "$configured"
    return
  fi
  detect_host_timezone_offset
}

copy_application() {
  install -d -m 0755 "$INSTALL_ROOT"
  cp -a "$SCRIPT_DIR/vps_audit" "$INSTALL_ROOT/"
  cp -a "$SCRIPT_DIR/pyproject.toml" "$SCRIPT_DIR/setup.py" "$INSTALL_ROOT/"
  rm -rf -- "$INSTALL_ROOT/manager"
  install -d -m 0755 "$INSTALL_ROOT/manager"
  cp -a "$SCRIPT_DIR/vps_audit" "$SCRIPT_DIR/deploy" "$INSTALL_ROOT/manager/"
  cp -a "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/pyproject.toml" "$SCRIPT_DIR/setup.py" "$INSTALL_ROOT/manager/"
  chmod 0755 "$INSTALL_ROOT/manager/install.sh"
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
  install -m 0755 "$SCRIPT_DIR/deploy/bin/vps-audit-bot" "$INSTALL_ROOT/venv/bin/vps-audit-bot"
  install -m 0755 "$SCRIPT_DIR/deploy/bin/vpspc" "$INSTALL_ROOT/venv/bin/vpspc"
  install -m 0755 "$SCRIPT_DIR/deploy/bin/vps-audit-nodes" "$INSTALL_ROOT/venv/bin/vps-audit-nodes"
  install -m 0755 "$SCRIPT_DIR/deploy/bin/vps-audit-web" "$INSTALL_ROOT/venv/bin/vps-audit-web"
}

install_cli_shortcut() {
  check_cli_shortcut_available
  install -d -m 0755 "$(dirname -- "$CLI_SHORTCUT")"
  install -m 0755 "$SCRIPT_DIR/deploy/bin/vpspc" "$CLI_SHORTCUT"
}

check_cli_shortcut_available() {
  if [[ -e "$CLI_SHORTCUT" || -L "$CLI_SHORTCUT" ]]; then
    if [[ -L "$CLI_SHORTCUT" || ! -f "$CLI_SHORTCUT" ]] \
      || ! grep -Fxq "# $CLI_SHORTCUT_MARKER" "$CLI_SHORTCUT"; then
      die "快捷命令已存在且不属于 vpspc，拒绝覆盖: $CLI_SHORTCUT"
    fi
  fi
}

remove_cli_shortcut() {
  if [[ ! -L "$CLI_SHORTCUT" && -f "$CLI_SHORTCUT" ]] \
    && grep -Fxq "# $CLI_SHORTCUT_MARKER" "$CLI_SHORTCUT"; then
    rm -f -- "$CLI_SHORTCUT"
  elif [[ -e "$CLI_SHORTCUT" || -L "$CLI_SHORTCUT" ]]; then
    echo "安全保留不属于 vpspc 的快捷命令: $CLI_SHORTCUT" >&2
  fi
}

falco_is_installed() {
  command -v falco >/dev/null 2>&1 \
    || { command -v dpkg-query >/dev/null 2>&1 \
      && [[ "$(dpkg-query -W -f='${db:Status-Abbrev}' falco 2>/dev/null || true)" == "ii " ]]; }
}

falco_component_is_managed() {
  [[ -f "$FALCO_MANAGED_DIR/$1" ]]
}

mark_falco_component() {
  local component="$1"
  install -d -m 0700 "$FALCO_MANAGED_DIR" || return 1
  printf 'managed-by=vps-audit\n' > "$FALCO_MANAGED_DIR/$component" || return 1
  chmod 0600 "$FALCO_MANAGED_DIR/$component" || return 1
}

falco_target_available() {
  local path="$1"
  local component="$2"
  if [[ -e "$path" && ! -f "$FALCO_MANAGED_DIR/$component" ]]; then
    echo "Falco 安装回滚保护：不会覆盖已有文件 $path" >&2
    return 1
  fi
}

write_falco_snapshot() {
  local output="$1"
  FALCO_SNAPSHOT_OUTPUT="$output" FALCO_SNAPSHOT_RULE="$FALCO_RULE_FILE" \
  FALCO_SNAPSHOT_OVERRIDE="$FALCO_OVERRIDE_FILE" FALCO_SNAPSHOT_ROOTS="$FALCO_ETC_DIR:$FALCOCTL_ETC_DIR:$FALCO_OVERRIDE_DIR" \
  python3 <<'PY'
import hashlib
import os
from pathlib import Path

excluded = {os.environ["FALCO_SNAPSHOT_RULE"], os.environ["FALCO_SNAPSHOT_OVERRIDE"]}
files = []
for raw_root in os.environ["FALCO_SNAPSHOT_ROOTS"].split(":"):
    root = Path(raw_root)
    if not root.is_dir():
        continue
    for path in root.rglob("*"):
        if path.is_file() and str(path) not in excluded:
            files.append(path)
lines = []
for path in sorted(files, key=lambda item: str(item)):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {path}\n")
Path(os.environ["FALCO_SNAPSHOT_OUTPUT"]).write_text("".join(lines), encoding="utf-8")
PY
}

falco_has_external_changes() {
  local baseline="$FALCO_MANAGED_DIR/baseline.sha256"
  local current="$FALCO_MANAGED_DIR/current.sha256"
  [[ -f "$baseline" ]] || return 0
  write_falco_snapshot "$current" || return 0
  if cmp -s "$baseline" "$current"; then
    rm -f -- "$current"
    return 1
  fi
  rm -f -- "$current"
  return 0
}

remove_managed_falco_files() {
  local stop_service="${1:-yes}"
  if [[ "$stop_service" == "yes" ]]; then
    systemctl disable --now falco-modern-bpf.service >/dev/null 2>&1 || true
  fi

  if falco_component_is_managed service-override; then
    rm -f -- "$FALCO_OVERRIDE_FILE"
    rm -f -- "$FALCO_MANAGED_DIR/service-override"
    rmdir "$FALCO_OVERRIDE_DIR" >/dev/null 2>&1 || true
  fi
  if falco_component_is_managed rule; then
    rm -f -- "$FALCO_RULE_FILE"
    rm -f -- "$FALCO_MANAGED_DIR/rule"
  fi
  if falco_component_is_managed logrotate; then
    rm -f -- "$FALCO_LOGROTATE_FILE"
    rm -f -- "$FALCO_MANAGED_DIR/logrotate"
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ "$stop_service" != "yes" ]]; then
    systemctl enable --now falco-modern-bpf.service >/dev/null 2>&1 || true
    systemctl restart falco-modern-bpf.service >/dev/null 2>&1 || true
  fi

  if falco_component_is_managed log-directory; then
    rm -f -- "$FALCO_LOG_FILE" "$FALCO_LOG_DIR/.vps-audit-falco-managed"
    rm -f -- "$FALCO_MANAGED_DIR/log-directory"
    rmdir "$FALCO_LOG_DIR" >/dev/null 2>&1 || true
  fi
}

cleanup_falco_package_residue() {
  rm -f -- "$FALCO_ETC_DIR/config.d/engine-kind-falcoctl.yaml"
  FALCO_CLEANUP_BASELINE="$FALCO_MANAGED_DIR/baseline.sha256" \
  FALCO_CLEANUP_ROOTS="$FALCO_ETC_DIR:$FALCOCTL_ETC_DIR" python3 <<'PY'
import hashlib
import os
from pathlib import Path

roots = [Path(value).resolve() for value in os.environ["FALCO_CLEANUP_ROOTS"].split(":")]
baseline = Path(os.environ["FALCO_CLEANUP_BASELINE"])
if baseline.is_file():
    for line in baseline.read_text(encoding="utf-8").splitlines():
        try:
            expected, raw_path = line.split("  ", 1)
        except ValueError:
            continue
        path = Path(raw_path)
        try:
            resolved = path.resolve()
            allowed = any(resolved == root or root in resolved.parents for root in roots)
            if allowed and path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected:
                path.unlink()
        except OSError:
            pass
for root in roots:
    if not root.is_dir():
        continue
    for current, directories, _files in os.walk(root, topdown=False):
        for directory in directories:
            try:
                (Path(current) / directory).rmdir()
            except OSError:
                pass
    try:
        root.rmdir()
    except OSError:
        pass
PY
  if [[ -d "$APT_LIST_CACHE_DIR" ]]; then
    find "$APT_LIST_CACHE_DIR" -maxdepth 1 -type f -name 'download.falco.org_packages_deb_*' -delete 2>/dev/null || true
  fi
  if [[ -d "$APT_ARCHIVE_CACHE_DIR" ]]; then
    find "$APT_ARCHIVE_CACHE_DIR" -maxdepth 1 -type f -name 'falco_*.deb' -delete 2>/dev/null || true
  fi
}

rollback_falco_install() {
  local rollback_failed="false"
  echo "Falco 安装未完成，正在回滚本次创建的内容..." >&2
  remove_managed_falco_files
  if falco_component_is_managed package; then
    if command -v apt-get >/dev/null 2>&1 \
      && DEBIAN_FRONTEND=noninteractive apt-get purge -y falco >/dev/null 2>&1; then
      cleanup_falco_package_residue
      rm -f -- "$FALCO_MANAGED_DIR/package"
    else
      rollback_failed="true"
      echo "Falco 软件包回滚失败，已保留归属标记以便重试。" >&2
    fi
  fi
  if falco_component_is_managed falcoctl-mask; then
    systemctl unmask falcoctl-artifact-follow.service >/dev/null 2>&1 || true
    rm -f -- "$FALCO_MANAGED_DIR/falcoctl-mask"
  fi
  if falco_component_is_managed repository; then
    rm -f -- "$FALCO_REPO_LIST" "$FALCO_MANAGED_DIR/repository"
  fi
  if falco_component_is_managed repository-key; then
    rm -f -- "$FALCO_REPO_KEY" "$FALCO_MANAGED_DIR/repository-key"
  fi
  rm -f -- "$FALCO_MANAGED_DIR/current.sha256"
  if [[ "$rollback_failed" == "false" ]]; then
    rm -f -- "$FALCO_MANAGED_DIR/baseline.sha256"
  fi
  rmdir "$FALCO_MANAGED_DIR" >/dev/null 2>&1 || true
  if [[ "$rollback_failed" == "true" ]]; then
    return 1
  fi
  echo "Falco 回滚完成，其他服务和原有文件未改动。" >&2
}

install_managed_falco() {
  local retention="$1"
  local key_download key_binary falcoctl_state

  command -v apt-get >/dev/null 2>&1 \
    || { echo "Falco 自动安装当前支持 Debian/Ubuntu（apt）；本机将跳过。" >&2; return 1; }
  command -v curl >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates || return 1
  command -v gpg >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y gnupg || return 1

  install -d -m 0700 "$CONFIG_DIR" "$FALCO_MANAGED_DIR" || return 1
  falco_target_available "$FALCO_RULE_FILE" rule || return 1
  falco_target_available "$FALCO_OVERRIDE_FILE" service-override || return 1
  falco_target_available "$FALCO_LOGROTATE_FILE" logrotate || return 1

  if [[ ! -e "$FALCO_REPO_KEY" ]]; then
    mark_falco_component repository-key || return 1
    key_download="$(mktemp /tmp/vps-audit-falco-key.XXXXXX)" || return 1
    key_binary="${key_download}.gpg"
    if ! curl --fail --location --silent --show-error --retry 3 "$FALCO_KEY_URL" -o "$key_download"; then
      rm -f -- "$key_download" "$key_binary"
      return 1
    fi
    if ! gpg --batch --yes --dearmor -o "$key_binary" "$key_download"; then
      rm -f -- "$key_download" "$key_binary"
      return 1
    fi
    install -m 0644 "$key_binary" "$FALCO_REPO_KEY" || return 1
    rm -f -- "$key_download" "$key_binary"
  fi
  if [[ ! -e "$FALCO_REPO_LIST" ]]; then
    mark_falco_component repository || return 1
    printf 'deb [signed-by=%s] %s stable main\n' "$FALCO_REPO_KEY" "$FALCO_REPO_URL" > "$FALCO_REPO_LIST" || return 1
    chmod 0644 "$FALCO_REPO_LIST" || return 1
  fi

  apt-get update || return 1
  falcoctl_state="$(systemctl is-enabled falcoctl-artifact-follow.service 2>/dev/null || true)"
  if [[ "$falcoctl_state" != "masked" ]]; then
    mark_falco_component falcoctl-mask || return 1
  fi
  mark_falco_component package || return 1
  FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf FALCOCTL_ENABLED=no \
    DEBIAN_FRONTEND=noninteractive apt-get install -y falco || return 1
  falco_is_installed || return 1
  write_falco_snapshot "$FALCO_MANAGED_DIR/baseline.sha256" || return 1
  chmod 0600 "$FALCO_MANAGED_DIR/baseline.sha256" || return 1

  install -d -m 0755 "$(dirname -- "$FALCO_RULE_FILE")" "$FALCO_OVERRIDE_DIR" || return 1
  mark_falco_component rule || return 1
  install -m 0644 "$SCRIPT_DIR/deploy/falco/vps-audit-rules.yaml" "$FALCO_RULE_FILE" || return 1
  falco --validate "$FALCO_ETC_DIR/falco_rules.yaml" --validate "$FALCO_RULE_FILE" || return 1

  mark_falco_component service-override || return 1
  cat > "$FALCO_OVERRIDE_FILE" <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/falco -o engine.kind=modern_ebpf -o json_output=true -o json_include_output_property=true -o file_output.enabled=true -o file_output.keep_alive=false -o file_output.filename=$FALCO_LOG_FILE -o rules[0].disable.rule=* -o rules[1].enable.tag=vps_audit
EOF
  chmod 0644 "$FALCO_OVERRIDE_FILE" || return 1

  if [[ -d "$FALCO_LOG_DIR" && ! -f "$FALCO_LOG_DIR/.vps-audit-falco-managed" ]]; then
    [[ -z "$(find "$FALCO_LOG_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null || true)" ]] \
      || { echo "不会使用已有的非空日志目录 $FALCO_LOG_DIR" >&2; return 1; }
  fi
  mark_falco_component log-directory || return 1
  install -d -m 0700 "$FALCO_LOG_DIR" || return 1
  : > "$FALCO_LOG_DIR/.vps-audit-falco-managed" || return 1
  chmod 0600 "$FALCO_LOG_DIR/.vps-audit-falco-managed" || return 1
  : > "$FALCO_LOG_FILE" || return 1
  chmod 0600 "$FALCO_LOG_FILE" || return 1

  install -d -m 0755 "$(dirname -- "$FALCO_LOGROTATE_FILE")" || return 1
  mark_falco_component logrotate || return 1
  cat > "$FALCO_LOGROTATE_FILE" <<EOF
$FALCO_LOG_FILE {
    daily
    rotate $retention
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
EOF
  chmod 0644 "$FALCO_LOGROTATE_FILE" || return 1

  systemctl daemon-reload || return 1
  systemctl enable --now falco-modern-bpf.service || return 1
  systemctl restart falco-modern-bpf.service || return 1
  local _
  for _ in 1 2 3 4 5; do
    systemctl is-active --quiet falco-modern-bpf.service && break
    sleep 1
  done
  systemctl is-active --quiet falco-modern-bpf.service || return 1
  echo "Falco 已安装并运行，仅记录 vpspc 规则，JSON 日志: $FALCO_LOG_FILE"
}

uninstall_managed_falco() {
  [[ -d "$FALCO_MANAGED_DIR" ]] || return 0
  echo "清理本工具管理的 Falco 组件..."
  if falco_component_is_managed package && falco_has_external_changes; then
    echo "检测到 Falco 安装后新增或修改的外部配置；为避免影响其他服务，将保留 Falco 软件包和官方仓库。"
    remove_managed_falco_files no
    if falco_component_is_managed falcoctl-mask; then
      systemctl unmask falcoctl-artifact-follow.service >/dev/null 2>&1 || true
    fi
    rm -f -- "$FALCO_MANAGED_DIR/package" "$FALCO_MANAGED_DIR/falcoctl-mask"
    rm -f -- "$FALCO_MANAGED_DIR/repository" "$FALCO_MANAGED_DIR/repository-key"
    rm -f -- "$FALCO_MANAGED_DIR/baseline.sha256"
    rmdir "$FALCO_MANAGED_DIR" >/dev/null 2>&1 || true
    echo "vpspc 专属 Falco 规则、输出和日志已删除；共享 Falco 已恢复为默认启动方式。"
    return 0
  fi
  remove_managed_falco_files
  if falco_component_is_managed package; then
    if ! command -v apt-get >/dev/null 2>&1 \
      || ! DEBIAN_FRONTEND=noninteractive apt-get purge -y falco; then
      echo "Falco 软件包卸载失败；已保留归属标记，请修复 apt 后重试。" >&2
      return 1
    fi
    cleanup_falco_package_residue
    rm -f -- "$FALCO_MANAGED_DIR/package"
  fi
  if falco_component_is_managed falcoctl-mask; then
    systemctl unmask falcoctl-artifact-follow.service >/dev/null 2>&1 || true
    rm -f -- "$FALCO_MANAGED_DIR/falcoctl-mask"
  fi
  if falco_component_is_managed repository; then
    rm -f -- "$FALCO_REPO_LIST" "$FALCO_MANAGED_DIR/repository"
  fi
  if falco_component_is_managed repository-key; then
    rm -f -- "$FALCO_REPO_KEY" "$FALCO_MANAGED_DIR/repository-key"
  fi
  rm -f -- "$FALCO_MANAGED_DIR/baseline.sha256"
  rmdir "$FALCO_MANAGED_DIR" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo "本工具创建的 Falco 组件已清理；预先存在的 Falco 和其他服务未改动。"
}

create_settings_snapshot() {
  [[ -f "$CONFIG_FILE" ]] || return 0
  local rollback_root="$CONFIG_DIR/rollback"
  local snapshot="$rollback_root/latest"
  local staging="$rollback_root/.latest.new.$$"
  install -d -m 0700 "$rollback_root" "$staging"
  install -m 0600 "$CONFIG_FILE" "$staging/config.json"
  [[ -f "$CONFIG_DIR/telegram.token" ]] && install -m 0600 "$CONFIG_DIR/telegram.token" "$staging/telegram.token"
  [[ -f "$CONFIG_DIR/openai.key" ]] && install -m 0600 "$CONFIG_DIR/openai.key" "$staging/openai.key"
  [[ -f "$CONFIG_DIR/web.token" ]] && install -m 0600 "$CONFIG_DIR/web.token" "$staging/web.token"
  if [[ -d "$CONFIG_DIR/ai-providers" ]]; then
    cp -a "$CONFIG_DIR/ai-providers" "$staging/ai-providers"
    chmod 0700 "$staging/ai-providers"
    find "$staging/ai-providers" -type f -exec chmod 0600 {} +
  fi
  [[ -f "$SYSTEMD_DIR/vps-audit.service" ]] && install -m 0644 "$SYSTEMD_DIR/vps-audit.service" "$staging/vps-audit.service"
  [[ -f "$SYSTEMD_DIR/vps-audit.timer" ]] && install -m 0644 "$SYSTEMD_DIR/vps-audit.timer" "$staging/vps-audit.timer"
  [[ -f "$SYSTEMD_DIR/vps-audit-bot.service" ]] && install -m 0644 "$SYSTEMD_DIR/vps-audit-bot.service" "$staging/vps-audit-bot.service"
  [[ -f "$SYSTEMD_DIR/vps-audit-node-receiver.service" ]] && install -m 0644 "$SYSTEMD_DIR/vps-audit-node-receiver.service" "$staging/vps-audit-node-receiver.service"
  [[ -f "$SYSTEMD_DIR/vps-audit-web.service" ]] && install -m 0644 "$SYSTEMD_DIR/vps-audit-web.service" "$staging/vps-audit-web.service"
  falco_component_is_managed package && : > "$staging/falco-managed-before"
  find "$staging" -type d -exec chmod 0700 {} +
  find "$staging" -type f -exec chmod 0600 {} +
  rm -rf -- "$snapshot"
  mv "$staging" "$snapshot"
  echo "已保存上一次配置快照，可使用 install.sh rollback 恢复。"
}

rollback_settings_app() {
  need_root
  local snapshot="$CONFIG_DIR/rollback/latest"
  [[ -f "$snapshot/config.json" ]] || die "没有可用的上一次配置快照"

  if [[ ! -f "$snapshot/falco-managed-before" ]] && falco_component_is_managed package; then
    uninstall_managed_falco || die "回滚新增 Falco 组件失败"
  fi

  systemctl stop vps-audit-web.service vps-audit-node-receiver.service vps-audit-bot.service vps-audit.timer vps-audit.service >/dev/null 2>&1 || true
  install -d -m 0700 "$CONFIG_DIR"
  install -m 0600 "$snapshot/config.json" "$CONFIG_FILE"
  if [[ -f "$snapshot/telegram.token" ]]; then
    install -m 0600 "$snapshot/telegram.token" "$CONFIG_DIR/telegram.token"
  else
    rm -f -- "$CONFIG_DIR/telegram.token"
  fi
  if [[ -f "$snapshot/openai.key" ]]; then
    install -m 0600 "$snapshot/openai.key" "$CONFIG_DIR/openai.key"
  else
    rm -f -- "$CONFIG_DIR/openai.key"
  fi
  if [[ -f "$snapshot/web.token" ]]; then
    install -m 0600 "$snapshot/web.token" "$CONFIG_DIR/web.token"
  fi
  rm -rf -- "$CONFIG_DIR/ai-providers"
  if [[ -d "$snapshot/ai-providers" ]]; then
    cp -a "$snapshot/ai-providers" "$CONFIG_DIR/ai-providers"
    chmod 0700 "$CONFIG_DIR/ai-providers"
    find "$CONFIG_DIR/ai-providers" -type f -exec chmod 0600 {} +
  fi
  if [[ -f "$snapshot/vps-audit.service" ]]; then
    install -m 0644 "$snapshot/vps-audit.service" "$SYSTEMD_DIR/vps-audit.service"
  else
    rm -f -- "$SYSTEMD_DIR/vps-audit.service"
  fi
  if [[ -f "$snapshot/vps-audit.timer" ]]; then
    install -m 0644 "$snapshot/vps-audit.timer" "$SYSTEMD_DIR/vps-audit.timer"
  else
    rm -f -- "$SYSTEMD_DIR/vps-audit.timer"
  fi
  if [[ -f "$snapshot/vps-audit-bot.service" ]]; then
    install -m 0644 "$snapshot/vps-audit-bot.service" "$SYSTEMD_DIR/vps-audit-bot.service"
  else
    rm -f -- "$SYSTEMD_DIR/vps-audit-bot.service"
  fi
  if [[ -f "$snapshot/vps-audit-node-receiver.service" ]]; then
    install -m 0644 "$snapshot/vps-audit-node-receiver.service" "$SYSTEMD_DIR/vps-audit-node-receiver.service"
  else
    rm -f -- "$SYSTEMD_DIR/vps-audit-node-receiver.service"
  fi
  if [[ -f "$snapshot/vps-audit-web.service" ]]; then
    install -m 0644 "$snapshot/vps-audit-web.service" "$SYSTEMD_DIR/vps-audit-web.service"
  else
    rm -f -- "$SYSTEMD_DIR/vps-audit-web.service"
  fi
  systemctl daemon-reload
  if [[ -f "$SYSTEMD_DIR/vps-audit.timer" ]]; then
    systemctl enable --now vps-audit.timer
    if ! systemctl start vps-audit.service; then
      journalctl -u vps-audit.service -n 30 --no-pager || true
      die "配置文件已恢复，但首次巡查失败，请检查日志"
    fi
  fi
  configure_bot_service
  configure_node_receiver_service
  configure_web_service
  echo "已恢复上一次配置、密钥引用和 systemd 单元；审计事件数据未删除。"
}

write_runtime_config() {
  local auth_default timezone_default falco_default
  local auth_log auth_timezone falco_log subscription_log miaomiaowux_log miaomiaowux_timezone retention interval
  local state_dir report_dir
  local journal_enabled telegram_enabled telegram_chat min_severity cooldown include_ip
  local ai_enabled ai_model ai_provider_id ai_display_name ai_base_url ai_api_mode ai_timeout ai_key_file
  local city_db asn_db install_geoip geoip_selection tab
  local sub_window sub_ip_count sub_region_count sub_city_count sub_asn_count sub_device_count sub_shared_source_count
  local travel_distance travel_speed
  local monitor_mode monitor_users
  local telegram_bot_enabled telegram_admin_ids telegram_admin_default
  local falco_install_requested falco_skipped
  local node_reporting_mode node_public_base_url node_listen_host node_listen_port
  local web_enabled web_host web_port web_token web_token_file
  local behavior_enabled behavior_archive_dir behavior_retention behavior_incident_retention behavior_max_disk
  local node_window node_ip_count node_region_count node_city_count node_asn_count
  local behavior_connection_count behavior_destination_count behavior_account_count

  auth_default="$(existing_config_value auth_logs "$(detect_auth_log)")"
  timezone_default="$(existing_config_value auth_timezone "$(detect_host_timezone_offset)")"
  [[ "$timezone_default" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]] || timezone_default="+00:00"
  falco_default=""
  [[ -f "$FALCO_LOG_FILE" ]] && falco_default="$FALCO_LOG_FILE"
  [[ -f /var/log/falco/events.json ]] && falco_default="/var/log/falco/events.json"
  falco_default="$(existing_config_value falco_logs "$falco_default")"
  local subscription_default
  subscription_default="$(detect_subscription_jsonl "$(existing_config_value subscription_logs "")")"
  local miaomiaowux_default
  miaomiaowux_default="$(detect_miaomiaowux_log "$(existing_config_value miaomiaowux_logs "")")"

  echo
  echo "配置本地审计数据存储"
  state_dir="$(ask "审计数据保存目录（直接回车使用默认值）" "$(existing_config_value state_dir "$STATE_DIR")")"
  state_dir="$(validate_storage_path "$state_dir" "审计数据保存目录")"
  report_dir="$(ask "报告保存目录（直接回车使用默认值）" "$(existing_config_value report_dir "$state_dir/reports")")"
  report_dir="$(validate_storage_path "$report_dir" "报告保存目录")"
  retention="$(ask "事件保存天数（直接回车使用默认值）" "$(existing_config_value retention_days 7)")"
  if [[ ! "$retention" =~ ^[0-9]+$ ]] || (( retention < 1 || retention > 365 )); then
    die "保留天数应为 1 到 365 的整数"
  fi
  prepare_managed_directory "$state_dir" "审计数据保存目录"
  prepare_managed_directory "$report_dir" "报告保存目录"

  echo
  echo "配置 Web 管理台"
  web_enabled="false"
  web_host="$(existing_config_value web.listen_host 127.0.0.1)"
  web_port="$(existing_config_value web.listen_port 8787)"
  web_token_file="$(existing_config_value web.token_file "$CONFIG_DIR/web.token")"
  if ask_yes_no "启用 Web 管理台" "$(existing_config_value web.enabled no)"; then
    web_enabled="true"
    web_host="$(ask "Web 监听地址（公网建议放在 HTTPS 反代后）" "$web_host")"
    web_port="$(ask "Web 监听端口" "$web_port")"
    [[ "$web_port" =~ ^[0-9]+$ ]] && (( web_port >= 1 && web_port <= 65535 )) || die "Web 端口应为 1 到 65535"
    [[ "$web_host" != *$'\n'* && -n "$web_host" ]] || die "Web 监听地址无效"
    web_token_file="$CONFIG_DIR/web.token"
    local web_token_default
    web_token_default=""
    [[ -s "$web_token_file" ]] && web_token_default="KEEP"
    web_token="$(ask_secret "Web Token（输入 KEEP 保留，留空自动生成）" "$web_token_default")"
    if [[ "$web_token" == "KEEP" && -s "$web_token_file" ]]; then
      :
    else
      [[ -n "$web_token" ]] || web_token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
      install -d -m 0700 "$CONFIG_DIR"
      printf '%s\n' "$web_token" > "$web_token_file"
      chmod 0600 "$web_token_file"
    fi
  fi

  echo
  echo "配置主控 / 节点上报模式"
  node_reporting_mode="$(select_node_reporting_mode "$(existing_config_value node_reporting.mode controller_only)")"
  node_public_base_url="$(existing_config_value node_reporting.public_base_url "")"
  node_listen_host="$(existing_config_value node_reporting.listen_host "127.0.0.1")"
  node_listen_port="$(existing_config_value node_reporting.listen_port "8766")"
  behavior_enabled="false"
  behavior_archive_dir="$(existing_config_value behavior_audit.archive_dir "$state_dir/behavior-audit")"
  behavior_retention="$(existing_config_value behavior_audit.retention_days 7)"
  behavior_incident_retention="$(existing_config_value behavior_audit.incident_retention_days 30)"
  behavior_max_disk="$(existing_config_value behavior_audit.max_disk_mb 20480)"
  if [[ "$node_reporting_mode" == "node_reporting" ]]; then
    node_public_base_url="$(ask "节点访问的主控 HTTPS Base URL（例如 https://monitor.example.com）" "$node_public_base_url")"
    node_listen_host="$(ask "接收服务监听地址（反代部署建议 127.0.0.1）" "$node_listen_host")"
    node_listen_port="$(ask "接收服务监听端口" "$node_listen_port")"
    [[ "$node_public_base_url" =~ ^https:// ]] \
      || [[ "$node_public_base_url" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?$ ]] \
      || die "远程节点上报必须使用 HTTPS 公网地址"
    [[ "$node_listen_port" =~ ^[0-9]+$ ]] && (( node_listen_port >= 1 && node_listen_port <= 65535 )) \
      || die "节点接收端口应为 1 到 65535"
    echo "提示：接收服务本身使用 HTTP，请由 Nginx/Caddy 在该地址前终止 HTTPS。"
    echo
    echo "完整连接元数据审计可记录用户、节点、完整来源 IP/端口、目标域名或 IP/端口、协议和时间。"
    echo "它不解密 TLS，因此看不到 URL 路径、请求正文、密码、Cookie 或注册是否成功。"
    echo "管理员手动触发外部 AI 审计时，上述完整元数据会发送给当前 AI 供应商。"
    if ask_yes_no "启用完整连接元数据与行为规则审计" "$(existing_config_value behavior_audit.enabled no)"; then
      behavior_enabled="true"
      behavior_archive_dir="$(ask "完整连接与事件归档目录" "$behavior_archive_dir")"
      behavior_archive_dir="$(validate_storage_path "$behavior_archive_dir" "完整连接归档目录")"
      [[ "$behavior_archive_dir" != "$state_dir" && "$behavior_archive_dir" != "$report_dir" ]] \
        || die "完整连接归档目录不能与状态目录或报告目录完全相同"
      behavior_retention="$(ask "完整连接日志保存天数" "$behavior_retention")"
      behavior_incident_retention="$(ask "行为事件保存天数" "$behavior_incident_retention")"
      behavior_max_disk="$(ask "完整连接归档容量上限（MB）" "$behavior_max_disk")"
      [[ "$behavior_retention" =~ ^[0-9]+$ ]] && (( behavior_retention >= 1 && behavior_retention <= 365 )) \
        || die "完整连接日志保存天数应为 1 到 365"
      [[ "$behavior_incident_retention" =~ ^[0-9]+$ ]] && (( behavior_incident_retention >= 1 && behavior_incident_retention <= 3650 )) \
        || die "行为事件保存天数应为 1 到 3650"
      [[ "$behavior_max_disk" =~ ^[0-9]+$ ]] && (( behavior_max_disk >= 100 && behavior_max_disk <= 1048576 )) \
        || die "完整连接归档容量应为 100 到 1048576 MB"
      prepare_managed_directory "$behavior_archive_dir" "完整连接归档目录"
    fi
  fi

  falco_install_requested="false"
  falco_skipped="false"
  echo
  echo "Falco 可选行为审计"
  echo "Falco 使用 eBPF 观察普通 Linux 用户启动的进程和部分出站连接，"
  echo "可为疑似 Python/Node/浏览器自动化、注册机和短时大量连接提供证据。"
  echo "它只记录和预警，不会封禁、终止进程或修改妙妙屋 X。命令行日志可能包含敏感参数。"
  if falco_is_installed; then
    echo "已检测到 Falco；安装器不会覆盖或接管已有安装。"
  elif ask_yes_no "未检测到 Falco，是否安装 vpspc 管理的 Falco（modern eBPF）" "no"; then
    falco_install_requested="true"
    falco_default="$FALCO_LOG_FILE"
    echo "已选择安装；完成所有交互设置后自动安装，失败会回滚 Falco 组件。"
  else
    falco_skipped="true"
    echo "已跳过 Falco；SSH 和订阅多 IP 审计仍可正常使用。"
  fi

  echo
  echo "配置日志与巡查周期"
  journal_enabled="false"
  if [[ -n "$auth_default" ]]; then
    auth_log="$auth_default"
    echo "SSH 登录来源：已自动检测文件 $auth_log"
  else
    auth_log=""
    journal_enabled="true"
    echo "SSH 登录来源：未发现 auth.log/secure，自动使用 journald"
  fi
  auth_timezone="$timezone_default"
  echo "SSH/主机日志时区：已自动检测 $auth_timezone"
  interval="$(ask "巡查间隔（分钟）" "$(existing_config_value scan_interval_minutes 5)")"
  if [[ "$falco_install_requested" == "true" ]]; then
    falco_log="$FALCO_LOG_FILE"
    echo "Falco JSON 日志路径 [$falco_log]"
  elif [[ "$falco_skipped" == "true" ]]; then
    falco_log=""
  elif [[ -n "$falco_default" && -f "$falco_default" ]]; then
    falco_log="$falco_default"
    echo "Falco JSON 日志：已自动检测 $falco_log"
  else
    falco_log="$(ask "Falco JSON 日志路径，留空则不审计进程/网络行为" "$falco_default")"
  fi
  if [[ -n "$miaomiaowux_default" ]]; then
    miaomiaowux_log="$miaomiaowux_default"
    subscription_log="$subscription_default"
    miaomiaowux_timezone="$(detect_miaomiaowux_timezone "$miaomiaowux_log" "$(existing_config_value miaomiaowux_timezone "")")"
    echo "妙妙屋 X 日志：已自动检测原生日志 $miaomiaowux_log"
    echo "mmwx.log 时区：已根据现有配置、日志时间或容器时间自动检测 $miaomiaowux_timezone"
    if [[ -n "$subscription_log" ]]; then
      echo "通用订阅访问 JSONL：同时使用 $subscription_log"
    else
      echo "未配置额外通用 JSONL；这里不需要填写订阅 URL。"
    fi
  else
    if [[ -n "$subscription_default" ]]; then
      subscription_log="$subscription_default"
      echo "通用订阅访问 JSONL：已自动检测 $subscription_log"
    else
      subscription_log="$(ask "通用本地订阅访问 JSONL 文件，留空则不采集" "")"
    fi
    if [[ "$subscription_log" =~ ^https?:// ]]; then
      echo "提示: 已忽略订阅 URL；该项目只读取本地日志文件，不会请求或保存订阅内容。" >&2
      subscription_log=""
    fi
    miaomiaowux_log="$(ask "未自动发现 mmwx.log；如有本地文件请输入绝对路径，留空跳过" "")"
    if [[ -n "$miaomiaowux_log" ]]; then
      miaomiaowux_timezone="$(detect_miaomiaowux_timezone "$miaomiaowux_log" "")"
      echo "mmwx.log 时区：已自动检测 $miaomiaowux_timezone"
    else
      miaomiaowux_timezone="$(detect_host_timezone_offset)"
    fi
  fi
  [[ "$auth_timezone" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]] || die "日志时区格式应为 +08:00"
  if [[ ! "$interval" =~ ^[0-9]+$ ]] || (( interval < 1 || interval > 1440 )); then
    die "巡查间隔应为 1 到 1440 的整数"
  fi
  if [[ -n "$auth_log" && ! -f "$auth_log" ]]; then
    echo "警告: $auth_log 当前不存在；服务会等待该日志出现。" >&2
  fi
  if [[ -n "$falco_log" && ! -f "$falco_log" ]]; then
    echo "警告: $falco_log 当前不存在；进程/网络审计在 Falco 写入后生效。" >&2
  fi
  if [[ -n "$subscription_log" && ! -f "$subscription_log" ]]; then
    echo "提示: $subscription_log 当前不存在；请让面板或适配器按文档格式写入。" >&2
  fi
  if [[ -n "$miaomiaowux_log" && ! -f "$miaomiaowux_log" ]]; then
    echo "提示: $miaomiaowux_log 当前不存在；妙妙屋 X 原生日志采集暂不会产生事件。" >&2
  fi
  [[ "$miaomiaowux_timezone" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]] || die "mmwx.log 时区格式应为 +00:00"

  echo
  echo "配置多个订阅用户监测"
  monitor_mode="$(ask "订阅监测模式 all=全部日志用户 / allowlist=仅重点名单" "$(existing_config_value subscription_monitoring.mode all)")"
  case "$monitor_mode" in all|allowlist) ;; *) die "订阅监测模式只能是 all 或 allowlist" ;; esac
  monitor_users="$(ask "重点用户名或订阅 ID（多个用英文逗号分隔，可留空）" "$(existing_config_list subscription_monitoring.users "")")"
  if [[ "$monitor_mode" == "allowlist" && -z "${monitor_users//[[:space:],]/}" ]]; then
    echo "提示: 当前重点名单为空，保存后不会产生订阅用户告警；可稍后输入 vpspc 或通过 Telegram 添加。" >&2
  fi

  echo
  echo "配置个人订阅异地使用预警阈值"
  sub_window="$(ask "活跃 IP 统计窗口（分钟）" "$(existing_config_value rules.thresholds.subscription_window_minutes 15)")"
  sub_ip_count="$(ask "同订阅多少个不同 IP 时告警" "$(existing_config_value rules.thresholds.subscription_ip_count 10)")"
  sub_region_count="$(ask "同订阅跨多少个省/地区时告警" "$(existing_config_value rules.thresholds.subscription_region_count 3)")"
  sub_city_count="$(ask "同订阅跨多少个城市时告警" "$(existing_config_value rules.thresholds.subscription_city_count 5)")"
  sub_asn_count="$(ask "同订阅跨多少个 ASN/运营商时告警" "$(existing_config_value rules.thresholds.subscription_asn_count 4)")"
  sub_device_count="$(ask "同订阅多少个设备标识时告警（日志有 device_id 时生效）" "$(existing_config_value rules.thresholds.subscription_device_count 6)")"
  sub_shared_source_count="$(ask "同一来源拉取多少个不同订阅用户时提示聚合器/NAT" "$(existing_config_value rules.thresholds.subscription_shared_source_user_count 8)")"
  travel_distance="$(ask "不可能旅行最小距离（km）" "$(existing_config_value rules.thresholds.impossible_travel_min_km 500)")"
  travel_speed="$(ask "不可能旅行速度阈值（km/h）" "$(existing_config_value rules.thresholds.impossible_travel_kmh 900)")"
  for value in "$sub_window" "$sub_ip_count" "$sub_region_count" "$sub_city_count" "$sub_asn_count" "$sub_device_count" "$sub_shared_source_count" "$travel_distance" "$travel_speed"; do
    [[ "$value" =~ ^[0-9]+$ ]] || die "订阅审计阈值必须是正整数"
    (( value >= 1 )) || die "订阅审计阈值必须大于 0"
  done
  node_window="$(existing_config_value rules.thresholds.node_window_minutes 10)"
  node_ip_count="$(existing_config_value rules.thresholds.node_ip_count 5)"
  node_region_count="$(existing_config_value rules.thresholds.node_region_count 2)"
  node_city_count="$(existing_config_value rules.thresholds.node_city_count 3)"
  node_asn_count="$(existing_config_value rules.thresholds.node_asn_count 3)"
  behavior_connection_count="$(existing_config_value rules.thresholds.behavior_connection_count 200)"
  behavior_destination_count="$(existing_config_value rules.thresholds.behavior_unique_destination_count 30)"
  behavior_account_count="$(existing_config_value rules.thresholds.behavior_account_service_count 20)"
  if [[ "$behavior_enabled" == "true" ]]; then
    echo
    echo "配置单用户、单节点行为审计阈值"
    node_window="$(ask "节点行为统计窗口（分钟）" "$node_window")"
    node_ip_count="$(ask "单用户单节点多少个来源 IP 时告警" "$node_ip_count")"
    node_region_count="$(ask "单用户单节点跨多少个省/地区时告警" "$node_region_count")"
    node_city_count="$(ask "单用户单节点跨多少个城市时告警" "$node_city_count")"
    node_asn_count="$(ask "单用户单节点跨多少个 ASN 时告警" "$node_asn_count")"
    behavior_connection_count="$(ask "窗口内多少条连接视为连接爆发" "$behavior_connection_count")"
    behavior_destination_count="$(ask "窗口内多少个不同目标视为目标爆发" "$behavior_destination_count")"
    behavior_account_count="$(ask "窗口内多少条账号/认证类连接视为疑似自动化" "$behavior_account_count")"
  fi
  for value in "$node_window" "$node_ip_count" "$node_region_count" "$node_city_count" "$node_asn_count" \
    "$behavior_connection_count" "$behavior_destination_count" "$behavior_account_count"; do
    [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 1 )) || die "节点行为审计阈值必须是正整数"
  done

  telegram_enabled="false"
  telegram_chat=""
  min_severity="high"
  cooldown="6"
  include_ip="false"
  telegram_bot_enabled="false"
  telegram_admin_ids=""
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
    echo "Telegram 双向管理可以查看状态、维护多个订阅用户、修改检测阈值并立即巡查。"
    echo "它没有封禁能力；所有写操作还会校验发送者的 Telegram 用户 ID。"
    if ask_yes_no "启用 Telegram 双向交互管理" "$(existing_config_value telegram.bot_management_enabled no)"; then
      telegram_bot_enabled="true"
      telegram_admin_default="$(existing_config_list telegram.admin_user_ids "")"
      if [[ -z "$telegram_admin_default" && "$telegram_chat" =~ ^[0-9]+$ ]]; then
        telegram_admin_default="$telegram_chat"
      fi
      telegram_admin_ids="$(ask "允许管理的 Telegram 用户 ID（多个用英文逗号分隔；群组 ID 不能代替用户 ID）" "$telegram_admin_default")"
      telegram_admin_ids="${telegram_admin_ids//[[:space:]]/}"
      [[ "$telegram_admin_ids" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "管理员 Telegram 用户 ID 必须是一个或多个正整数"
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
  geoip_selection="$(configure_geoip_databases "$state_dir")"
  tab="$(printf '\t')"
  city_db="${geoip_selection%%"$tab"*}"
  asn_db="${geoip_selection#*"$tab"}"
  if [[ -n "$city_db" || -n "$asn_db" ]]; then
    install_geoip="true"
  fi

  ai_enabled="false"
  ai_model=""
  ai_provider_id=""
  ai_display_name=""
  ai_base_url=""
  ai_api_mode=""
  ai_timeout="30"
  ai_key_file=""
  AI_TEST_REQUESTED="false"
  if ask_yes_no "有新告警时启用 OpenAI 兼容 AI 复核" "$(existing_config_value openai_review.enabled no)"; then
    ai_enabled="true"
    local existing_ai_count
    existing_ai_count="$(python3 - "$CONFIG_FILE" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        ai = json.load(handle).get("openai_review", {})
    providers = ai.get("providers", {}) if isinstance(ai, dict) else {}
    count = len(providers) if isinstance(providers, dict) else 0
    if count == 0 and isinstance(ai, dict) and ai.get("model"):
        count = 1
    print(count)
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    print(0)
PY
)"
    if (( existing_ai_count > 0 )); then
      echo "已保留现有 $existing_ai_count 个 AI 供应商；可安装后使用 vpspc 管理或在 Telegram 中切换。"
    else
      ai_provider_id="$(ask "初始供应商 ID（小写字母/数字/._-）" "openai")"
      [[ "$ai_provider_id" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] || die "AI 供应商 ID 格式无效"
      ai_display_name="$(ask "供应商显示名称" "OpenAI")"
      ai_base_url="$(ask "OpenAI 兼容 Base URL" "https://api.openai.com/v1")"
      ai_api_mode="$(ask "接口模式 responses/chat_completions" "responses")"
      case "$ai_api_mode" in responses|chat_completions) ;; *) die "AI 接口模式无效" ;; esac
      ai_model="$(ask "模型名称" "")"
      [[ -n "$ai_model" ]] || die "启用 AI 复核时模型名称不能为空"
      ai_timeout="$(ask "AI 请求超时秒数" "30")"
      [[ "$ai_timeout" =~ ^[0-9]+$ ]] && (( ai_timeout >= 5 && ai_timeout <= 120 )) \
        || die "AI 请求超时应为 5 到 120 秒"
      ai_key_file="$CONFIG_DIR/ai-providers/$ai_provider_id.key"
      local ai_key ai_key_default
      ai_key_default=""
      [[ -s "$ai_key_file" ]] && ai_key_default="KEEP"
      ai_key="$(ask_secret "API Key（输入 KEEP 保留已有值）" "$ai_key_default")"
      [[ -n "$ai_key" ]] || die "启用 AI 复核时 API Key 不能为空"
      install -d -m 0700 "$CONFIG_DIR/ai-providers"
      if [[ "$ai_key" != "KEEP" ]]; then
        printf '%s\n' "$ai_key" > "$ai_key_file"
      fi
      chmod 0600 "$ai_key_file"
    fi
    if ask_yes_no "配置保存后手动测试当前 AI 模型" "no"; then
      AI_TEST_REQUESTED="true"
    fi
  fi

  if [[ "$install_geoip" == "true" ]]; then
    "$INSTALL_ROOT/venv/bin/pip" install --disable-pip-version-check --no-cache-dir 'geoip2>=4,<6'
  fi

  if [[ "$falco_install_requested" == "true" ]]; then
    if ! install_managed_falco "$retention"; then
      rollback_falco_install || die "Falco 自动安装失败且软件包回滚未完成，请修复 apt 后运行 install.sh destroy"
      falco_log=""
      echo "警告: Falco 自动安装失败，已完整回滚；继续以登录和订阅审计模式安装。" >&2
    fi
  fi

  install -d -m 0700 "$CONFIG_DIR"
  AUTH_LOG="$auth_log" AUTH_TIMEZONE="$auth_timezone" JOURNAL_ENABLED="$journal_enabled" FALCO_LOG="$falco_log" SUBSCRIPTION_LOG="$subscription_log" \
  MIAOMIAOWUX_LOG="$miaomiaowux_log" MIAOMIAOWUX_TIMEZONE="$miaomiaowux_timezone" \
  STATE_PATH="$state_dir" REPORT_PATH="$report_dir" RETENTION="$retention" INTERVAL_VALUE="$interval" \
  TELEGRAM_ENABLED="$telegram_enabled" TELEGRAM_CHAT="$telegram_chat" \
  MIN_SEVERITY="$min_severity" COOLDOWN="$cooldown" INCLUDE_IP="$include_ip" \
  TELEGRAM_BOT_ENABLED="$telegram_bot_enabled" TELEGRAM_ADMIN_IDS="$telegram_admin_ids" \
  AI_ENABLED="$ai_enabled" AI_PROVIDER_ID="$ai_provider_id" AI_DISPLAY_NAME="$ai_display_name" \
  AI_BASE_URL="$ai_base_url" AI_API_MODE="$ai_api_mode" AI_KEY_FILE="$ai_key_file" AI_MODEL="$ai_model" AI_TIMEOUT="$ai_timeout" \
  CITY_DB="$city_db" ASN_DB="$asn_db" \
  MONITOR_MODE="$monitor_mode" MONITOR_USERS="$monitor_users" \
  SUB_WINDOW="$sub_window" SUB_IP_COUNT="$sub_ip_count" SUB_REGION_COUNT="$sub_region_count" \
  SUB_CITY_COUNT="$sub_city_count" SUB_ASN_COUNT="$sub_asn_count" SUB_DEVICE_COUNT="$sub_device_count" \
  SUB_SHARED_SOURCE_COUNT="$sub_shared_source_count" \
  TRAVEL_DISTANCE="$travel_distance" TRAVEL_SPEED="$travel_speed" \
  NODE_REPORTING_MODE="$node_reporting_mode" NODE_PUBLIC_BASE_URL="$node_public_base_url" \
  NODE_LISTEN_HOST="$node_listen_host" NODE_LISTEN_PORT="$node_listen_port" \
  WEB_ENABLED="$web_enabled" WEB_HOST="$web_host" WEB_PORT="$web_port" WEB_TOKEN_FILE="$web_token_file" \
  BEHAVIOR_ENABLED="$behavior_enabled" BEHAVIOR_ARCHIVE_DIR="$behavior_archive_dir" \
  BEHAVIOR_RETENTION="$behavior_retention" BEHAVIOR_INCIDENT_RETENTION="$behavior_incident_retention" \
  BEHAVIOR_MAX_DISK="$behavior_max_disk" NODE_WINDOW="$node_window" NODE_IP_COUNT="$node_ip_count" \
  NODE_REGION_COUNT="$node_region_count" NODE_CITY_COUNT="$node_city_count" NODE_ASN_COUNT="$node_asn_count" \
  BEHAVIOR_CONNECTION_COUNT="$behavior_connection_count" BEHAVIOR_DESTINATION_COUNT="$behavior_destination_count" \
  BEHAVIOR_ACCOUNT_COUNT="$behavior_account_count" \
  python3 - "$CONFIG_FILE" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
existing = {}
try:
    with path.open(encoding="utf-8") as handle:
        existing = json.load(handle)
except (OSError, ValueError, json.JSONDecodeError):
    existing = {}
existing_ai = existing.get("openai_review", {})
if not isinstance(existing_ai, dict):
    existing_ai = {}
providers = existing_ai.get("providers", {})
if not isinstance(providers, dict):
    providers = {}
providers = dict(providers)
active_provider = str(existing_ai.get("active_provider", ""))
existing_node_reporting = existing.get("node_reporting", {})
if not isinstance(existing_node_reporting, dict):
    existing_node_reporting = {}
if not providers and existing_ai.get("model"):
    providers["legacy"] = {
        "display_name": "Legacy OpenAI",
        "base_url": str(existing_ai.get("base_url", "https://api.openai.com/v1")),
        "api_mode": str(existing_ai.get("api_mode", "responses")),
        "api_key_file": str(existing_ai.get("api_key_file", "/etc/vps-audit/openai.key")),
        "model": str(existing_ai["model"]),
        "timeout_seconds": int(existing_ai.get("timeout_seconds", 60)),
    }
    active_provider = "legacy"
new_provider_id = os.environ["AI_PROVIDER_ID"]
if new_provider_id:
    providers[new_provider_id] = {
        "display_name": os.environ["AI_DISPLAY_NAME"],
        "base_url": os.environ["AI_BASE_URL"],
        "api_mode": os.environ["AI_API_MODE"],
        "api_key_file": os.environ["AI_KEY_FILE"],
        "model": os.environ["AI_MODEL"],
        "timeout_seconds": int(os.environ["AI_TIMEOUT"]),
    }
    active_provider = new_provider_id

config = {
    "web": {
        "enabled": os.environ["WEB_ENABLED"] == "true",
        "listen_host": os.environ["WEB_HOST"],
        "listen_port": int(os.environ["WEB_PORT"]),
        "token_file": os.environ["WEB_TOKEN_FILE"],
    },
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
    "node_reporting": {
        "mode": os.environ["NODE_REPORTING_MODE"],
        "listen_host": os.environ["NODE_LISTEN_HOST"],
        "listen_port": int(os.environ["NODE_LISTEN_PORT"]),
        "public_base_url": os.environ["NODE_PUBLIC_BASE_URL"],
        "registry_file": str(existing_node_reporting.get("registry_file", "")),
        "inbox_file": str(existing_node_reporting.get("inbox_file", "")),
        "agent_asset_path": "/opt/vps-audit/manager/deploy/node/vpspc-node.py",
        "enrollment_ttl_minutes": int(existing_node_reporting.get("enrollment_ttl_minutes", 15)),
        "replay_window_seconds": int(existing_node_reporting.get("replay_window_seconds", 300)),
        "max_batch_events": int(existing_node_reporting.get("max_batch_events", 500)),
    },
    "behavior_audit": {
        "enabled": os.environ["BEHAVIOR_ENABLED"] == "true",
        "archive_dir": os.environ["BEHAVIOR_ARCHIVE_DIR"],
        "retention_days": int(os.environ["BEHAVIOR_RETENTION"]),
        "incident_retention_days": int(os.environ["BEHAVIOR_INCIDENT_RETENTION"]),
        "max_disk_mb": int(os.environ["BEHAVIOR_MAX_DISK"]),
        "max_analysis_events": 100000,
        "ai_include_full_metadata": True,
    },
    "subscription_monitoring": {
        "enabled": True,
        "mode": os.environ["MONITOR_MODE"],
        "users": [
            item.strip() for item in os.environ["MONITOR_USERS"].split(",") if item.strip()
        ],
    },
    "rules": {
        "thresholds": {
            "subscription_window_minutes": int(os.environ["SUB_WINDOW"]),
            "subscription_ip_count": int(os.environ["SUB_IP_COUNT"]),
            "subscription_region_count": int(os.environ["SUB_REGION_COUNT"]),
            "subscription_city_count": int(os.environ["SUB_CITY_COUNT"]),
            "subscription_asn_count": int(os.environ["SUB_ASN_COUNT"]),
            "subscription_device_count": int(os.environ["SUB_DEVICE_COUNT"]),
            "subscription_shared_source_user_count": int(os.environ["SUB_SHARED_SOURCE_COUNT"]),
            "impossible_travel_min_km": int(os.environ["TRAVEL_DISTANCE"]),
            "impossible_travel_kmh": int(os.environ["TRAVEL_SPEED"]),
            "node_window_minutes": int(os.environ["NODE_WINDOW"]),
            "node_ip_count": int(os.environ["NODE_IP_COUNT"]),
            "node_region_count": int(os.environ["NODE_REGION_COUNT"]),
            "node_city_count": int(os.environ["NODE_CITY_COUNT"]),
            "node_asn_count": int(os.environ["NODE_ASN_COUNT"]),
            "behavior_connection_count": int(os.environ["BEHAVIOR_CONNECTION_COUNT"]),
            "behavior_unique_destination_count": int(os.environ["BEHAVIOR_DESTINATION_COUNT"]),
            "behavior_account_service_count": int(os.environ["BEHAVIOR_ACCOUNT_COUNT"]),
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
        "bot_management_enabled": os.environ["TELEGRAM_BOT_ENABLED"] == "true",
        "admin_user_ids": [
            int(item) for item in os.environ["TELEGRAM_ADMIN_IDS"].split(",") if item
        ],
        "poll_timeout_seconds": 30,
    },
    "openai_review": {
        "enabled": os.environ["AI_ENABLED"] == "true",
        "active_provider": active_provider,
        "providers": providers,
    },
}
temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
with temporary.open("w", encoding="utf-8") as handle:
    json.dump(config, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PY
  chmod 0600 "$CONFIG_FILE"

  INTERVAL="$interval"
  CONFIGURED_STATE_DIR="$state_dir"
  CONFIGURED_REPORT_DIR="$report_dir"
  if [[ "$behavior_enabled" == "true" ]]; then
    CONFIGURED_BEHAVIOR_ARCHIVE_DIR="$behavior_archive_dir"
  else
    CONFIGURED_BEHAVIOR_ARCHIVE_DIR="$state_dir"
  fi
}

install_systemd_units() {
  local interval="$1"
  local state_dir="$2"
  local report_dir="$3"
  local behavior_archive_dir="$4"
  local service_read_access supplementary_groups requires_dac_read_search
  local supplementary_groups_directive capability_bounding_set_directive
  service_read_access="$(detect_service_read_access)"
  supplementary_groups="${service_read_access%%$'\t'*}"
  requires_dac_read_search="${service_read_access#*$'\t'}"
  supplementary_groups_directive=""
  if [[ -n "$supplementary_groups" ]]; then
    supplementary_groups_directive="SupplementaryGroups=$supplementary_groups"
  fi
  capability_bounding_set_directive="CapabilityBoundingSet="
  if [[ "$requires_dac_read_search" == "yes" ]]; then
    capability_bounding_set_directive="CapabilityBoundingSet=CAP_DAC_READ_SEARCH"
  fi
  SERVICE_TEMPLATE="$SCRIPT_DIR/deploy/systemd/vps-audit.service" SERVICE_OUTPUT="$SYSTEMD_DIR/vps-audit.service" \
  STATE_PATH="$state_dir" REPORT_PATH="$report_dir" BEHAVIOR_ARCHIVE_PATH="$behavior_archive_dir" SUPPLEMENTARY_GROUPS_DIRECTIVE="$supplementary_groups_directive" \
  CAPABILITY_BOUNDING_SET_DIRECTIVE="$capability_bounding_set_directive" python3 <<'PY'
import os
from pathlib import Path

template = Path(os.environ["SERVICE_TEMPLATE"]).read_text(encoding="utf-8")
template = template.replace("@STATE_DIR@", os.environ["STATE_PATH"])
template = template.replace("@REPORT_DIR@", os.environ["REPORT_PATH"])
template = template.replace("@BEHAVIOR_ARCHIVE_DIR@", os.environ["BEHAVIOR_ARCHIVE_PATH"])
template = template.replace("@SUPPLEMENTARY_GROUPS@", os.environ["SUPPLEMENTARY_GROUPS_DIRECTIVE"])
template = template.replace("@CAPABILITY_BOUNDING_SET@", os.environ["CAPABILITY_BOUNDING_SET_DIRECTIVE"])
Path(os.environ["SERVICE_OUTPUT"]).write_text(template, encoding="utf-8")
PY
  chmod 0644 "$SYSTEMD_DIR/vps-audit.service"
  sed "s/@INTERVAL@/$interval/g" "$SCRIPT_DIR/deploy/systemd/vps-audit.timer" > "$SYSTEMD_DIR/vps-audit.timer"
  chmod 0644 "$SYSTEMD_DIR/vps-audit.timer"
  STATE_PATH="$state_dir" BEHAVIOR_ARCHIVE_PATH="$behavior_archive_dir" BOT_TEMPLATE="$SCRIPT_DIR/deploy/systemd/vps-audit-bot.service" \
  BOT_OUTPUT="$SYSTEMD_DIR/vps-audit-bot.service" python3 <<'PY'
import os
from pathlib import Path

template = Path(os.environ["BOT_TEMPLATE"]).read_text(encoding="utf-8")
template = template.replace("@STATE_DIR@", os.environ["STATE_PATH"])
template = template.replace("@BEHAVIOR_ARCHIVE_DIR@", os.environ["BEHAVIOR_ARCHIVE_PATH"])
Path(os.environ["BOT_OUTPUT"]).write_text(template, encoding="utf-8")
PY
  chmod 0644 "$SYSTEMD_DIR/vps-audit-bot.service"
  STATE_PATH="$state_dir" BEHAVIOR_ARCHIVE_PATH="$behavior_archive_dir" RECEIVER_TEMPLATE="$SCRIPT_DIR/deploy/systemd/vps-audit-node-receiver.service" \
  RECEIVER_OUTPUT="$SYSTEMD_DIR/vps-audit-node-receiver.service" python3 <<'PY'
import os
from pathlib import Path

template = Path(os.environ["RECEIVER_TEMPLATE"]).read_text(encoding="utf-8")
template = template.replace("@STATE_DIR@", os.environ["STATE_PATH"])
template = template.replace("@BEHAVIOR_ARCHIVE_DIR@", os.environ["BEHAVIOR_ARCHIVE_PATH"])
Path(os.environ["RECEIVER_OUTPUT"]).write_text(template, encoding="utf-8")
PY
  chmod 0644 "$SYSTEMD_DIR/vps-audit-node-receiver.service"
  STATE_PATH="$state_dir" REPORT_PATH="$report_dir" BEHAVIOR_ARCHIVE_PATH="$behavior_archive_dir" WEB_TEMPLATE="$SCRIPT_DIR/deploy/systemd/vps-audit-web.service" WEB_OUTPUT="$SYSTEMD_DIR/vps-audit-web.service" python3 <<'PY'
import os
from pathlib import Path
template = Path(os.environ["WEB_TEMPLATE"]).read_text(encoding="utf-8")
template = template.replace("@STATE_DIR@", os.environ["STATE_PATH"])
template = template.replace("@REPORT_DIR@", os.environ["REPORT_PATH"])
template = template.replace("@BEHAVIOR_ARCHIVE_DIR@", os.environ["BEHAVIOR_ARCHIVE_PATH"])
Path(os.environ["WEB_OUTPUT"]).write_text(template, encoding="utf-8")
PY
  chmod 0644 "$SYSTEMD_DIR/vps-audit-web.service"
  systemctl daemon-reload
}

configure_bot_service() {
  if [[ -f "$CONFIG_FILE" && "$(existing_config_value telegram.bot_management_enabled no)" == "yes" \
    && -f "$SYSTEMD_DIR/vps-audit-bot.service" ]]; then
    systemctl enable vps-audit-bot.service
    systemctl restart vps-audit-bot.service
  else
    systemctl disable --now vps-audit-bot.service >/dev/null 2>&1 || true
  fi
}

configure_node_receiver_service() {
  if [[ -f "$CONFIG_FILE" && "$(existing_config_value node_reporting.mode controller_only)" == "node_reporting" \
    && -f "$SYSTEMD_DIR/vps-audit-node-receiver.service" ]]; then
    systemctl enable vps-audit-node-receiver.service
    systemctl restart vps-audit-node-receiver.service
  else
    systemctl disable --now vps-audit-node-receiver.service >/dev/null 2>&1 || true
  fi
}

configure_web_service() {
  if [[ -f "$CONFIG_FILE" && "$(existing_config_value web.enabled no)" == "yes" && -f "$SYSTEMD_DIR/vps-audit-web.service" ]]; then
    [[ -s "$(existing_config_value web.token_file "$CONFIG_DIR/web.token")" ]] \
      || die "Web 已启用，但找不到 Web Token 文件；请重新配置 Web Token"
    systemctl enable vps-audit-web.service
    if ! systemctl restart vps-audit-web.service; then
      journalctl -u vps-audit-web.service -n 30 --no-pager || true
      die "Web 管理台启动失败；请执行 systemctl status vps-audit-web.service 查看详情"
    fi
    if ! systemctl is-active --quiet vps-audit-web.service; then
      journalctl -u vps-audit-web.service -n 30 --no-pager || true
      die "Web 管理台未进入运行状态；请执行 systemctl status vps-audit-web.service 查看详情"
    fi
    echo "Web 管理台已启动：$(existing_config_value web.listen_host 127.0.0.1):$(existing_config_value web.listen_port 8787)"
    echo "如使用反代，请将后端指向上述地址；Web Token 可通过 vpspc 菜单查看。"
  else
    systemctl disable --now vps-audit-web.service >/dev/null 2>&1 || true
    echo "Web 管理台未启用。"
  fi
}

test_ai_if_requested() {
  if [[ "$AI_TEST_REQUESTED" == "true" ]]; then
    echo
    echo "测试当前 AI 供应商、模型与结构化输出..."
    "$INSTALL_ROOT/venv/bin/vps-audit-runner" --config "$CONFIG_FILE" test-ai \
      || die "AI 模型测试失败；可修正配置或使用 install.sh rollback 恢复"
  fi
}

run_initial_audit_and_enable_timer() {
  echo
  echo "执行首次巡查..."
  if ! systemctl start vps-audit.service; then
    journalctl -u vps-audit.service -n 30 --no-pager || true
    die "首次巡查失败；定时器未启用，请检查以上日志"
  fi
  systemctl enable --now vps-audit.timer
}

install_app() {
  need_root
  check_cli_shortcut_available
  install_os_packages
  copy_application
  create_settings_snapshot
  systemctl stop vps-audit-web.service vps-audit-node-receiver.service vps-audit-bot.service vps-audit.timer >/dev/null 2>&1 || true
  INTERVAL="5"
  write_runtime_config
  install_systemd_units "$INTERVAL" "$CONFIGURED_STATE_DIR" "$CONFIGURED_REPORT_DIR" "$CONFIGURED_BEHAVIOR_ARCHIVE_DIR"
  configure_web_service
  test_ai_if_requested
  run_initial_audit_and_enable_timer
  install_cli_shortcut
  configure_bot_service
  configure_node_receiver_service
  if [[ "$(existing_config_value telegram.enabled no)" == "yes" ]] && ask_yes_no "发送 Telegram 测试消息" "yes"; then
    "$INSTALL_ROOT/venv/bin/vps-audit-runner" --config "$CONFIG_FILE" test-telegram
  fi
  echo
  echo "安装完成。"
  echo "状态: sudo bash install.sh status"
  echo "交互管理: sudo vpspc（root 登录可直接输入 vpspc）"
  echo "审计数据: $CONFIGURED_STATE_DIR（保留 $(existing_config_value retention_days 7) 天）"
  echo "报告: $CONFIGURED_REPORT_DIR/latest.md"
  echo "日志: journalctl -u vps-audit.service"
}

configure_app() {
  need_root
  check_cli_shortcut_available
  [[ -x "$INSTALL_ROOT/venv/bin/vps-audit-runner" ]] || die "尚未安装"
  create_settings_snapshot
  systemctl stop vps-audit-web.service vps-audit-node-receiver.service vps-audit-bot.service vps-audit.timer >/dev/null 2>&1 || true
  INTERVAL="5"
  write_runtime_config
  install_systemd_units "$INTERVAL" "$CONFIGURED_STATE_DIR" "$CONFIGURED_REPORT_DIR" "$CONFIGURED_BEHAVIOR_ARCHIVE_DIR"
  configure_web_service
  test_ai_if_requested
  run_initial_audit_and_enable_timer
  install_cli_shortcut
  configure_bot_service
  configure_node_receiver_service
  echo "配置已更新。"
}

status_app() {
  need_root
  systemctl status vps-audit.timer --no-pager || true
  if [[ "$(existing_config_value telegram.bot_management_enabled no)" == "yes" ]]; then
    systemctl status vps-audit-bot.service --no-pager || true
  fi
  if [[ "$(existing_config_value node_reporting.mode controller_only)" == "node_reporting" ]]; then
    systemctl status vps-audit-node-receiver.service --no-pager || true
  fi
  if [[ "$(existing_config_value web.enabled no)" == "yes" ]]; then
    systemctl status vps-audit-web.service --no-pager || true
  fi
  echo
  if [[ -x "$INSTALL_ROOT/venv/bin/vps-audit-runner" && -f "$CONFIG_FILE" ]]; then
    "$INSTALL_ROOT/venv/bin/vps-audit-runner" --config "$CONFIG_FILE" health
  fi
  echo
  if falco_is_installed; then
    echo "Falco: 已安装"
    systemctl is-active falco-modern-bpf.service 2>/dev/null || true
    [[ -f "$FALCO_LOG_FILE" ]] && echo "Falco JSON: $FALCO_LOG_FILE"
  else
    echo "Falco: 未安装（可选，不影响 SSH/订阅审计）"
  fi
}

uninstall_app() {
  need_root
  local purge_state_dir=""
  local purge_report_dir=""
  local purge_behavior_dir=""
  if [[ "${1:-}" == "--purge" && -f "$CONFIG_FILE" ]]; then
    purge_state_dir="$(validate_storage_path "$(existing_config_value state_dir "$STATE_DIR")" "已配置的审计数据目录")"
    purge_report_dir="$(validate_storage_path "$(existing_config_value report_dir "$REPORT_DIR")" "已配置的报告目录")"
    if [[ "$(existing_config_value behavior_audit.enabled no)" == "yes" ]]; then
      purge_behavior_dir="$(validate_storage_path "$(existing_config_value behavior_audit.archive_dir "$STATE_DIR/behavior-audit")" "已配置的完整连接归档目录")"
    fi
  elif [[ "${1:-}" == "--purge" ]]; then
    [[ -f "$STATE_DIR/$DATA_MARKER" ]] && purge_state_dir="$STATE_DIR"
    [[ -f "$REPORT_DIR/$DATA_MARKER" ]] && purge_report_dir="$REPORT_DIR"
    [[ -f "$STATE_DIR/behavior-audit/$DATA_MARKER" ]] && purge_behavior_dir="$STATE_DIR/behavior-audit"
  fi
  if [[ "${1:-}" == "--purge" ]]; then
    uninstall_managed_falco || die "Falco 清理未完成；为便于重试，尚未删除 vpspc 配置"
  elif falco_component_is_managed package; then
    systemctl stop falco-modern-bpf.service >/dev/null 2>&1 || true
    echo "已停止本工具管理的 Falco；配置保留，重新安装 vpspc 后可恢复。"
  fi
  systemctl disable --now vps-audit-web.service vps-audit-node-receiver.service vps-audit-bot.service vps-audit.timer >/dev/null 2>&1 || true
  systemctl stop vps-audit.service >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_DIR/vps-audit.service" "$SYSTEMD_DIR/vps-audit.timer" "$SYSTEMD_DIR/vps-audit-bot.service" \
    "$SYSTEMD_DIR/vps-audit-node-receiver.service" "$SYSTEMD_DIR/vps-audit-web.service"
  systemctl daemon-reload
  remove_cli_shortcut
  rm -rf "$INSTALL_ROOT"
  if [[ "${1:-}" == "--purge" ]]; then
    local deleted=()
    if [[ -n "$purge_behavior_dir" && -f "$purge_behavior_dir/$DATA_MARKER" ]]; then
      rm -rf -- "$purge_behavior_dir"
      deleted+=("$purge_behavior_dir")
    elif [[ -n "$purge_behavior_dir" ]]; then
      echo "安全保留未带管理标记的完整连接归档目录: $purge_behavior_dir" >&2
    fi
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

destroy_app() {
  need_root
  local managed_source=""
  if [[ -f "$SCRIPT_DIR/$SOURCE_MARKER" ]]; then
    managed_source="$(validate_storage_path "$SCRIPT_DIR" "远程安装源码目录")"
  fi
  uninstall_app --purge
  if [[ -n "$managed_source" && -f "$managed_source/$SOURCE_MARKER" ]]; then
    rm -rf -- "$managed_source"
    echo "已删除远程安装源码目录: $managed_source"
  else
    echo "当前源码目录不是一键安装器管理的目录，已安全保留: $SCRIPT_DIR"
  fi
  echo "vpspc 创建的程序、配置、数据、日志和可选 Falco 组件已彻底清理。"
}

main() {
  case "${1:-install}" in
    install) install_app ;;
    configure) configure_app ;;
    status) status_app ;;
    rollback) rollback_settings_app ;;
    uninstall) uninstall_app "${2:-}" ;;
    destroy) destroy_app ;;
    *)
      echo "用法: sudo bash install.sh [install|configure|status|rollback|uninstall [--purge]|destroy]"
      exit 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
