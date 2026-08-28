#!/usr/bin/env bash
set -Eeuo pipefail

# Installs the only Docker-privileged component.  Web, Bot, receiver and the
# maintenance container receive neither /var/run/docker.sock nor a Docker CLI.
# This script copies a root-owned Compose snapshot so later maintenance calls
# cannot be redirected to an arbitrary user-provided project or path.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
CONFIG_DIR="/etc/vps-audit"
HELPER_DIR="/usr/local/lib/vpspc-updater"
SYSTEMD_DIR="/etc/systemd/system"

die() {
  echo "vpspc Docker helper: $*" >&2
  exit 1
}

[[ "$(id -u)" -eq 0 ]] || die "run this script with sudo"
[[ "$(uname -s)" == "Linux" ]] || die "only Linux Docker hosts are supported"
[[ "$PROJECT_ROOT" != "/" && "$PROJECT_ROOT" != "$HOME" && "$PROJECT_ROOT" != "$HOME"/* ]] \
  || die "the Compose project must not be / or a home directory"
[[ -f "$PROJECT_ROOT/compose.yml" && -f "$PROJECT_ROOT/docker/config.json" ]] \
  || die "compose.yml and docker/config.json are required"
command -v docker >/dev/null 2>&1 || die "Docker is required"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"

CONFIG_FILE="$PROJECT_ROOT/docker/config.json" PROJECT_ROOT="$PROJECT_ROOT" python3 <<'PY'
import json
import os
from pathlib import Path

config_path = Path(os.environ["CONFIG_FILE"])
project_root = Path(os.environ["PROJECT_ROOT"])
with config_path.open(encoding="utf-8") as handle:
    config = json.load(handle)
if not isinstance(config, dict):
    raise SystemExit("vpspc Docker helper: docker/config.json must be an object")
secrets = project_root / "docker" / "secrets"
if isinstance(config.get("web"), dict) and config["web"].get("enabled") and not (secrets / "web_token").is_file():
    raise SystemExit("vpspc Docker helper: docker/secrets/web_token is required when Web is enabled")
telegram = config.get("telegram")
if isinstance(telegram, dict) and telegram.get("bot_management_enabled") and not (secrets / "telegram_token").is_file():
    raise SystemExit("vpspc Docker helper: docker/secrets/telegram_token is required when Telegram management is enabled")
PY

install -d -m 0700 "$CONFIG_DIR/docker/secrets"
install -d -m 0755 "$HELPER_DIR/vps_audit/maintenance"
install -d -m 0700 /run/vpspc

install -m 0644 "$PROJECT_ROOT/compose.yml" "$CONFIG_DIR/docker-compose.yml"
install -m 0600 "$PROJECT_ROOT/docker/config.json" "$CONFIG_DIR/docker/config.json"
for secret in web_token telegram_token; do
  if [[ -f "$PROJECT_ROOT/docker/secrets/$secret" ]]; then
    install -m 0600 "$PROJECT_ROOT/docker/secrets/$secret" "$CONFIG_DIR/docker/secrets/$secret"
  fi
done

CONFIG_FILE="$CONFIG_DIR/docker/config.json" python3 <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["CONFIG_FILE"])
with path.open(encoding="utf-8") as handle:
    config = json.load(handle)
config["maintenance"] = {
    "deployment_mode": "docker",
    "updater_socket": "/run/vpspc-host/updater.sock",
    "updater_key_file": "/run/secrets/updater_key",
}
path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY

image="vpspc:local"
if [[ -f "$PROJECT_ROOT/.env" ]]; then
  candidate="$(sed -n 's/^AUDIT_IMAGE=//p' "$PROJECT_ROOT/.env" | tail -n 1)"
  [[ -z "$candidate" ]] || image="$candidate"
fi
printf 'AUDIT_IMAGE=%s\n' "$image" > "$CONFIG_DIR/docker.env"
chmod 0600 "$CONFIG_DIR/docker.env"

CONFIG_FILE="$CONFIG_DIR/docker/config.json" python3 <<'PY' > "$CONFIG_DIR/docker-maintenance.json"
import json
import os
from pathlib import Path

with Path(os.environ["CONFIG_FILE"]).open(encoding="utf-8") as handle:
    config = json.load(handle)
services = ["audit", "maintenance"]
if isinstance(config.get("web"), dict) and config["web"].get("enabled"):
    services.append("web")
telegram = config.get("telegram")
if isinstance(telegram, dict) and telegram.get("bot_management_enabled"):
    services.append("bot")
nodes = config.get("node_reporting")
if isinstance(nodes, dict) and nodes.get("mode") == "node_reporting":
    services.append("receiver")
print(json.dumps({"schema_version": 1, "project": "vpspc", "services": services}, separators=(",", ":")))
PY
chmod 0600 "$CONFIG_DIR/docker-maintenance.json"

python3 - <<'PY' > "$CONFIG_DIR/updater.key"
import secrets
print(secrets.token_hex(32))
PY
chmod 0600 "$CONFIG_DIR/updater.key"
install -m 0600 "$CONFIG_DIR/updater.key" "$CONFIG_DIR/docker/secrets/updater_key"

install -m 0755 "$PROJECT_ROOT/deploy/update/vpspc-host-updater.py" "$HELPER_DIR/vpspc-host-updater.py"
install -m 0644 "$PROJECT_ROOT/vps_audit/maintenance/__init__.py" "$HELPER_DIR/vps_audit/maintenance/__init__.py"
install -m 0644 "$PROJECT_ROOT/vps_audit/maintenance/ownership.py" "$HELPER_DIR/vps_audit/maintenance/ownership.py"
printf 'managed-by=vpspc\n' > "$HELPER_DIR/.vpspc-managed"
chmod 0600 "$HELPER_DIR/.vpspc-managed"
printf 'managed-by=vpspc\n' > "$CONFIG_DIR/.vpspc-managed"
chmod 0600 "$CONFIG_DIR/.vpspc-managed"

install -m 0644 "$PROJECT_ROOT/deploy/systemd/vps-audit-update-helper.service" \
  "$SYSTEMD_DIR/vps-audit-update-helper.service"
install -m 0644 "$PROJECT_ROOT/deploy/systemd/vps-audit-update-helper.socket" \
  "$SYSTEMD_DIR/vps-audit-update-helper.socket"

CONFIG_DIR="$CONFIG_DIR" HELPER_DIR="$HELPER_DIR" SYSTEMD_DIR="$SYSTEMD_DIR" python3 <<'PY'
import hashlib
import json
import os
from pathlib import Path

config = Path(os.environ["CONFIG_DIR"])
helper = Path(os.environ["HELPER_DIR"])
systemd = Path(os.environ["SYSTEMD_DIR"])

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

resources = [
    {"kind": "config", "path": str(config), "marker": ".vpspc-managed", "fingerprint": sha(config / ".vpspc-managed")},
    {"kind": "managed_directory", "path": str(helper), "marker": ".vpspc-managed", "fingerprint": sha(helper / ".vpspc-managed")},
]
for name in ("vps-audit-update-helper.service", "vps-audit-update-helper.socket"):
    path = systemd / name
    resources.append({"kind": "systemd_unit", "path": str(path), "marker": "managed-by=vpspc", "fingerprint": sha(path)})
payload = {"schema_version": 1, "install_mode": "docker", "resources": resources}
target = config / "ownership.json"
target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
os.chmod(target, 0o600)
PY

systemctl daemon-reload
systemctl enable --now vps-audit-update-helper.socket
echo "Docker maintenance helper is ready. Restart the managed Compose stack with:"
echo "  docker compose --env-file $CONFIG_DIR/docker.env -f $CONFIG_DIR/docker-compose.yml up -d"
