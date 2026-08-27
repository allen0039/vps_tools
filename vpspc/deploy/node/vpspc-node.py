#!/usr/bin/env python3
# managed-by=vpspc-node
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


AGENT_VERSION = "0.1.1"
AGENT_PROTOCOL = 1
MARKER = "managed-by=vpspc-node"
INSTALL_DIR = Path("/usr/local/lib/vpspc-node")
AGENT_PATH = INSTALL_DIR / "vpspc-node.py"
WRAPPER_PATH = Path("/usr/local/bin/vpspc-node")
CONFIG_DIR = Path("/etc/vpspc-node")
CONFIG_PATH = CONFIG_DIR / "config.json"
KEY_PATH = CONFIG_DIR / "node.key"
STATE_DIR = Path("/var/lib/vpspc-node")
STATE_PATH = STATE_DIR / "state.json"
SPOOL_PATH = STATE_DIR / "spool.jsonl"
SERVICE_PATH = Path("/etc/systemd/system/vpspc-node.service")
TIMER_PATH = Path("/etc/systemd/system/vpspc-node.timer")
COMMAND_SERVICE_PATH = Path("/etc/systemd/system/vpspc-node-command.service")
COMMAND_TIMER_PATH = Path("/etc/systemd/system/vpspc-node-command.timer")
MAINTENANCE_SERVICE_PATH = Path("/etc/systemd/system/vpspc-node-maintenance.service")
UPDATE_DOWNLOAD_PATH = STATE_DIR / "update-download.py"
UPDATE_BACKUP_PATH = STATE_DIR / "update-backup.py"
MAX_SPOOL_EVENTS = 10_000
MAX_SPOOL_BYTES = 10 * 1024 * 1024
MAX_BATCH_EVENTS = 500
MAX_UPDATE_ARTIFACT_BYTES = 50 * 1024 * 1024
SAFE_TASK_ID = re.compile(r"^task_[a-f0-9]{32}$")
SAFE_SHA256 = re.compile(r"^[a-f0-9]{64}$")
SAFE_RELEASE_VERSION = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
SAFE_RECEIPT_TOKEN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
XRAY_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"from\s+(?P<remote>\S+)\s+accepted\s+(?P<destination>\S+)"
    r"(?P<context>.*?)\s+email:\s+(?P<user>\S.*?)\s*$"
)


def _rooted(path: Path) -> Path:
    root = os.environ.get("VPSPC_NODE_TEST_ROOT", "")
    return Path(root) / path.relative_to("/") if root and path.is_absolute() else path


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_text(path: Path, value: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        temporary.write_text(value, encoding="utf-8")
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_bytes(path: Path, value: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        with temporary.open("wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_json(path: Path, value: Dict[str, Any], mode: int = 0o600) -> None:
    _atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n", mode)


def _load_json(path: Path, fallback: Dict[str, Any]) -> Dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
        if isinstance(value, dict):
            return value
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return dict(fallback)


def _controller_url(value: str) -> str:
    url = value.strip().rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("主控地址必须是纯 HTTP(S) Base URL")
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("远程主控必须使用 HTTPS")
    return url


def _request_json(
    method: str,
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str] | None = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request_headers = {"Content-Type": "application/json", "User-Agent": f"vpspc-node/{AGENT_VERSION}"}
    request_headers.update(headers or {})
    request = Request(url, data=body, headers=request_headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise RuntimeError("主控响应过大")
            value = json.loads(raw)
    except HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"主控返回 HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"无法连接主控: {exc}") from exc
    if not isinstance(value, dict) or not value.get("ok"):
        raise RuntimeError(str(value.get("error", "主控返回无效响应")) if isinstance(value, dict) else "主控返回无效响应")
    return value


def _sign(key: str, timestamp: str, nonce: str, body: bytes) -> str:
    digest = hashlib.sha256(body).hexdigest()
    message = f"{timestamp}\n{nonce}\n{digest}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _authenticated_request(
    config: Dict[str, Any], key: str, path: str, payload: Dict[str, Any]
) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = secrets.token_urlsafe(24)
    headers = {
        "X-VPSPC-Node": str(config["node_id"]),
        "X-VPSPC-Timestamp": timestamp,
        "X-VPSPC-Nonce": nonce,
        "X-VPSPC-Signature": _sign(key, timestamp, nonce, body),
    }
    request = Request(
        str(config["controller_url"]).rstrip("/") + path,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": f"vpspc-node/{AGENT_VERSION}", **headers},
        method="POST",
    )
    try:
        with urlopen(request, timeout=int(config.get("timeout_seconds", 30))) as response:
            value = json.loads(response.read(1_048_577))
    except HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"主控返回 HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"节点上报失败: {exc}") from exc
    if not isinstance(value, dict) or not value.get("ok"):
        raise RuntimeError(str(value.get("error", "主控拒绝上报")) if isinstance(value, dict) else "主控拒绝上报")
    return value


def _endpoint(value: str) -> Tuple[str, str, int | None]:
    network = "tcp"
    endpoint = value
    if endpoint.startswith("tcp:") or endpoint.startswith("udp:"):
        network, endpoint = endpoint.split(":", 1)
    port: int | None = None
    if endpoint.startswith("[") and "]:" in endpoint:
        host, raw_port = endpoint[1:].rsplit("]:", 1)
    elif endpoint.count(":") == 1:
        host, raw_port = endpoint.rsplit(":", 1)
    else:
        host, raw_port = endpoint, ""
    if raw_port.isdigit() and 1 <= int(raw_port) <= 65535:
        port = int(raw_port)
    return network, host.strip().rstrip("."), port


def parse_xray_access_line(line: str, source: str = "xray") -> Dict[str, Any] | None:
    match = XRAY_PATTERN.match(line.strip())
    if not match:
        return None
    user = match.group("user").strip()
    if not user or len(user) > 128 or any(ord(char) < 32 or ord(char) == 127 for char in user):
        return None
    try:
        network, source_host, source_port = _endpoint(match.group("remote"))
        source_ip = str(ipaddress.ip_address(source_host))
        destination_network, destination_host, destination_port = _endpoint(
            match.group("destination")
        )
    except ValueError:
        return None
    if not destination_host or len(destination_host) > 253:
        return None
    destination_ip = ""
    try:
        destination_ip = str(ipaddress.ip_address(destination_host))
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", destination_host):
            return None
    try:
        local_time = datetime.strptime(match.group("timestamp"), "%Y/%m/%d %H:%M:%S.%f")
    except ValueError:
        try:
            local_time = datetime.strptime(match.group("timestamp"), "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return None
    timestamp = _iso(local_time.astimezone())
    event_hash = hashlib.sha256((source + "\0" + line.strip()).encode("utf-8")).hexdigest()[:40]
    return {
        "timestamp": timestamp,
        "event_type": "proxy_connection",
        "user": user,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_host": "" if destination_ip else destination_host.lower(),
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "network": destination_network or network,
        "protocol": "xray",
        "inbound_tag": _inbound_tag(match.group("context")),
        "event_id": "evt_" + event_hash,
    }


def _inbound_tag(context: str) -> str:
    match = re.search(r"\[([^\]\s]+)\s*->", context)
    return match.group(1)[:64] if match else ""


def detect_xray_logs() -> List[str]:
    candidates = [
        Path("/var/log/xray/access.log"),
        Path("/var/log/Xray/access.log"),
        Path("/usr/local/etc/xray/access.log"),
        Path("/opt/xray/access.log"),
    ]
    return [str(path) for path in candidates if path.is_file()]


def _read_incremental(path: Path, state: Dict[str, Any], initial_bytes: int = 2_000_000) -> List[str]:
    try:
        info = path.stat()
    except OSError:
        return []
    key = str(path)
    previous = state.setdefault("files", {}).get(key, {})
    same_file = previous.get("inode") == info.st_ino and previous.get("device") == info.st_dev
    offset = int(previous.get("offset", 0)) if same_file else max(0, info.st_size - initial_bytes)
    if offset > info.st_size:
        offset = 0
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read()
        end = handle.tell()
    state["files"][key] = {"inode": info.st_ino, "device": info.st_dev, "offset": end}
    return data.decode("utf-8", errors="replace").splitlines()


def _load_spool() -> List[Dict[str, Any]]:
    path = _rooted(SPOOL_PATH)
    if not path.is_file():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
            except json.JSONDecodeError:
                continue
    return rows[-MAX_SPOOL_EVENTS:]


def _write_spool(events: Iterable[Dict[str, Any]]) -> None:
    rows = list(events)[-MAX_SPOOL_EVENTS:]
    encoded: List[str] = []
    size = 0
    for event in reversed(rows):
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        if size + len(line.encode("utf-8")) > MAX_SPOOL_BYTES:
            break
        encoded.append(line)
        size += len(line.encode("utf-8"))
    encoded.reverse()
    path = _rooted(SPOOL_PATH)
    if encoded:
        _atomic_text(path, "".join(encoded), 0o600)
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _managed_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    marker = path / ".managed-by-vpspc-node"
    _atomic_text(marker, MARKER + "\n", 0o600)


def _service_text() -> str:
    return f"""# {MARKER}
[Unit]
Description=VPSPC lightweight node reporter
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 {AGENT_PATH} run
TimeoutStartSec=90
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths={CONFIG_DIR} /var/log -/usr/local/etc/xray -/opt/xray
ReadWritePaths={STATE_DIR}
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
"""


def _timer_text(interval: int) -> str:
    return f"""# {MARKER}
[Unit]
Description=Run VPSPC node reporter every {interval} minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec={interval}min
RandomizedDelaySec=30s
AccuracySec=15s
Persistent=true
Unit=vpspc-node.service

[Install]
WantedBy=timers.target
"""


def _command_service_text() -> str:
    return f"""# {MARKER}
[Unit]
Description=VPSPC node maintenance command heartbeat
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 {AGENT_PATH} command-poll
TimeoutStartSec=45
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths={CONFIG_DIR}
ReadWritePaths={STATE_DIR}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
"""


def _command_timer_text() -> str:
    return f"""# {MARKER}
[Unit]
Description=Run VPSPC node maintenance heartbeat every 60 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
RandomizedDelaySec=5s
AccuracySec=5s
Persistent=true
Unit=vpspc-node-command.service

[Install]
WantedBy=timers.target
"""


def _maintenance_service_text() -> str:
    return f"""# {MARKER}
[Unit]
Description=VPSPC node maintenance executor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 {AGENT_PATH} maintenance-run
TimeoutStartSec=180
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths=/var/log -/usr/local/etc/xray -/opt/xray
ReadWritePaths={INSTALL_DIR} {WRAPPER_PATH} {CONFIG_DIR} {STATE_DIR} {SERVICE_PATH} {TIMER_PATH} {COMMAND_SERVICE_PATH} {COMMAND_TIMER_PATH} {MAINTENANCE_SERVICE_PATH}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
"""


def _write_installation(config: Dict[str, Any], key: str, interval: int) -> None:
    for directory in (_rooted(INSTALL_DIR), _rooted(CONFIG_DIR), _rooted(STATE_DIR)):
        _managed_dir(directory)
    source = Path(__file__).read_text(encoding="utf-8")
    _atomic_text(_rooted(AGENT_PATH), source, 0o755)
    wrapper = f"#!/bin/sh\n# {MARKER}\nexec /usr/bin/python3 {AGENT_PATH} \"$@\"\n"
    _atomic_text(_rooted(WRAPPER_PATH), wrapper, 0o755)
    _atomic_json(_rooted(CONFIG_PATH), config)
    _atomic_text(_rooted(KEY_PATH), key.strip() + "\n", 0o600)
    _atomic_text(_rooted(SERVICE_PATH), _service_text(), 0o644)
    _atomic_text(_rooted(TIMER_PATH), _timer_text(interval), 0o644)
    _atomic_text(_rooted(COMMAND_SERVICE_PATH), _command_service_text(), 0o644)
    _atomic_text(_rooted(COMMAND_TIMER_PATH), _command_timer_text(), 0o644)
    _atomic_text(_rooted(MAINTENANCE_SERVICE_PATH), _maintenance_service_text(), 0o644)


def install(controller: str, enroll_token: str, replace: bool, interval: int) -> Dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError("请使用 root 或 sudo 安装")
    if not 1 <= interval <= 1440:
        raise ValueError("上报间隔必须在 1 到 1440 分钟之间")
    controller_url = _controller_url(controller)
    existing = _load_json(_rooted(CONFIG_PATH), {})
    old_controller = str(existing.get("controller_url", "")).rstrip("/")
    replacing_existing = bool(old_controller and old_controller != controller_url)
    if replacing_existing and not replace:
        raise RuntimeError("节点已绑定其他主控；普通注册链接拒绝覆盖，请使用主控生成的覆盖注册链接")
    installation_id = str(existing.get("installation_id") or "install_" + uuid.uuid4().hex)
    payload = {
        "installation_id": installation_id,
        "node_name": socket.gethostname(),
        "agent_version": AGENT_VERSION,
        "agent_protocol": AGENT_PROTOCOL,
        "replace_existing": replacing_existing,
    }
    result = _request_json(
        "POST",
        controller_url + "/v1/node/enroll",
        payload,
        {"X-VPSPC-Enroll": enroll_token},
    )
    logs = list(existing.get("xray_logs", [])) if old_controller == controller_url else []
    if not logs:
        logs = detect_xray_logs()
    config = {
        "controller_url": controller_url,
        "node_id": result["node_id"],
        "installation_id": installation_id,
        "node_name": result.get("name") or socket.gethostname(),
        "xray_logs": logs,
        "interval_minutes": interval,
        "timeout_seconds": 30,
        "agent_version": AGENT_VERSION,
        "agent_protocol": AGENT_PROTOCOL,
        "behavior_audit_enabled": bool(result.get("behavior_audit", {}).get("enabled")),
    }
    _write_installation(config, str(result["credential"]), interval)
    if not os.environ.get("VPSPC_NODE_SKIP_SYSTEMCTL"):
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", "vpspc-node.timer"], check=True)
        subprocess.run(["systemctl", "enable", "--now", "vpspc-node-command.timer"], check=True)
        subprocess.run(["systemctl", "start", "vpspc-node.service"], check=True)
    return {"node_id": result["node_id"], "repaired": bool(result.get("repaired")), "logs": logs}


def _deduplicate(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique: Dict[str, Dict[str, Any]] = {}
    activity: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for event in events:
        if event.get("event_type") == "proxy_activity":
            key = (str(event.get("user")), str(event.get("source_ip")), str(event.get("protocol")))
            previous = activity.get(key)
            if not previous or str(previous.get("timestamp")) < str(event.get("timestamp")):
                activity[key] = event
        else:
            unique[str(event.get("event_id"))] = event
    for event in activity.values():
        unique[str(event["event_id"])] = event
    return sorted(unique.values(), key=lambda item: str(item.get("timestamp", "")))


def command_poll(claim: bool = True) -> Dict[str, Any]:
    """Send the independent 60-second command heartbeat.

    This deliberately does not read access logs.  If the controller assigns a
    task before a newer agent can execute it, retain that bounded task in the
    VPSPC-owned state directory rather than losing an already-claimed command.
    """

    config = _load_json(_rooted(CONFIG_PATH), {})
    if not config.get("controller_url") or not config.get("node_id"):
        raise RuntimeError("节点尚未注册")
    try:
        key = _rooted(KEY_PATH).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("节点密钥不可读") from exc
    if not key:
        raise RuntimeError("节点密钥不可读")

    result = _authenticated_request(
        config,
        key,
        "/v1/node/heartbeat",
        {
            "agent_version": AGENT_VERSION,
            "agent_protocol": AGENT_PROTOCOL,
            "claim": bool(claim),
        },
    )
    task = result.get("task")
    if task is not None and not isinstance(task, dict):
        raise RuntimeError("主控返回无效维护任务")
    if isinstance(task, dict):
        state = _load_json(_rooted(STATE_PATH), {"files": {}})
        state["pending_maintenance_task"] = task
        _atomic_json(_rooted(STATE_PATH), state)
        if not os.environ.get("VPSPC_NODE_SKIP_SYSTEMCTL"):
            subprocess.run(["systemctl", "start", "vpspc-node-maintenance.service"], check=False)
    return {"ok": True, "task": task}


def _node_credentials() -> Tuple[Dict[str, Any], str]:
    config = _load_json(_rooted(CONFIG_PATH), {})
    if not config.get("controller_url") or not config.get("node_id"):
        raise RuntimeError("节点尚未注册")
    try:
        key = _rooted(KEY_PATH).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("节点密钥不可读") from exc
    if not key:
        raise RuntimeError("节点密钥不可读")
    return config, key


def _validate_update_task(task: Dict[str, Any], node_id: str) -> Dict[str, Any]:
    if not isinstance(task, dict) or task.get("kind") != "node_update":
        raise ValueError("维护任务类型无效")
    if str(task.get("node_id", "")) != node_id:
        raise ValueError("维护任务不属于当前节点")
    task_id = str(task.get("task_id", ""))
    if not SAFE_TASK_ID.fullmatch(task_id):
        raise ValueError("维护任务 ID 无效")
    payload = task.get("payload")
    if not isinstance(payload, dict) or set(payload) != {"artifact_id", "sha256", "size", "version"}:
        raise ValueError("维护任务内容无效")
    sha256 = str(payload.get("sha256", ""))
    artifact_id = str(payload.get("artifact_id", ""))
    if not SAFE_SHA256.fullmatch(sha256) or artifact_id != "sha256-" + sha256:
        raise ValueError("维护任务校验和无效")
    size = payload.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_UPDATE_ARTIFACT_BYTES:
        raise ValueError("维护任务文件大小无效")
    version = str(payload.get("version", ""))
    if version != "edge" and not SAFE_RELEASE_VERSION.fullmatch(version):
        raise ValueError("维护任务版本无效")
    return {"task_id": task_id, **payload}


def _download_update_artifact(config: Dict[str, Any], payload: Dict[str, Any]) -> bytes:
    url = str(config["controller_url"]).rstrip("/") + "/assets/updates/" + str(payload["artifact_id"])
    request = Request(url, headers={"User-Agent": f"vpspc-node/{AGENT_VERSION}"}, method="GET")
    try:
        with urlopen(request, timeout=int(config.get("timeout_seconds", 30))) as response:
            if response.geturl() != url:
                raise RuntimeError("更新产物不允许重定向")
            content_type = str(response.headers.get("Content-Type", "")).lower()
            if not content_type.startswith("application/octet-stream"):
                raise RuntimeError("更新产物类型无效")
            content_length = response.headers.get("Content-Length")
            if content_length is None or int(content_length) != int(payload["size"]):
                raise RuntimeError("更新产物大小不匹配")
            chunks: List[bytes] = []
            received = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                received += len(chunk)
                if received > int(payload["size"]):
                    raise RuntimeError("更新产物大小不匹配")
                chunks.append(chunk)
    except (HTTPError, URLError, OSError, ValueError) as exc:
        raise RuntimeError(f"下载更新产物失败: {exc}") from exc
    artifact = b"".join(chunks)
    if len(artifact) != int(payload["size"]):
        raise RuntimeError("更新产物大小不匹配")
    if not hmac.compare_digest(hashlib.sha256(artifact).hexdigest(), str(payload["sha256"])):
        raise RuntimeError("更新产物校验失败")
    return artifact


def _report_task_status(
    config: Dict[str, Any], key: str, status: str, task_id: str, result: Dict[str, Any] | None = None
) -> None:
    payload: Dict[str, Any] = {"task_id": task_id, "status": status}
    if result is not None:
        payload["result"] = result
    _authenticated_request(config, key, "/v1/node/task-status", payload)


def _safe_report_task_status(
    config: Dict[str, Any], key: str, status: str, task_id: str, result: Dict[str, Any] | None = None
) -> None:
    try:
        _report_task_status(config, key, status, task_id, result)
    except RuntimeError:
        # The update outcome is authoritative even if the controller is briefly
        # unreachable. A later maintenance action can show the node as offline.
        pass


def _node_healthcheck(config: Dict[str, Any], key: str) -> None:
    if not os.environ.get("VPSPC_NODE_SKIP_SYSTEMCTL"):
        subprocess.run(["systemctl", "try-restart", "vpspc-node.service"], check=True)
    subprocess.run(
        [sys.executable, str(_rooted(AGENT_PATH)), "command-poll", "--no-claim"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=int(config.get("timeout_seconds", 30)) + 15,
    )


def _cleanup_update_files() -> None:
    for raw in (UPDATE_DOWNLOAD_PATH, UPDATE_BACKUP_PATH):
        try:
            _rooted(raw).unlink()
        except FileNotFoundError:
            pass


def execute_update_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """Atomically install a verified node agent and roll back on health failure."""

    config, key = _node_credentials()
    payload = _validate_update_task(task, str(config["node_id"]))
    backup = _rooted(UPDATE_BACKUP_PATH)
    replaced = False
    status = "failed"
    summary: Dict[str, Any] = {"stage": "preflight"}
    try:
        _safe_report_task_status(config, key, "downloading", payload["task_id"])
        artifact = _download_update_artifact(config, payload)
        candidate = _rooted(UPDATE_DOWNLOAD_PATH)
        _atomic_bytes(candidate, artifact, 0o700)
        subprocess.run([sys.executable, "-m", "py_compile", str(candidate)], check=True)
        if MARKER not in artifact.decode("utf-8", errors="ignore")[:4096]:
            raise RuntimeError("更新产物不是 VPSPC 节点探针")

        _safe_report_task_status(config, key, "installing", payload["task_id"])
        shutil.copy2(_rooted(AGENT_PATH), backup)
        os.chmod(backup, 0o700)
        os.replace(candidate, _rooted(AGENT_PATH))
        replaced = True

        _safe_report_task_status(config, key, "verifying", payload["task_id"])
        _node_healthcheck(config, key)
        status = "success"
        summary = {"stage": "verified", "version": payload["version"]}
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        summary = {"stage": "install" if replaced else "preflight", "error": str(exc)[:256]}
        if replaced and backup.is_file():
            try:
                os.replace(backup, _rooted(AGENT_PATH))
                _node_healthcheck(config, key)
                status = "rolled_back"
                summary["stage"] = "rolled_back"
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as rollback_exc:
                status = "failed"
                summary = {"stage": "rollback_failed", "error": str(rollback_exc)[:256]}
    finally:
        _cleanup_update_files()
    _safe_report_task_status(config, key, status, payload["task_id"], summary)
    return {"status": status, "task_id": payload["task_id"], "summary": summary}


def maintenance_run() -> Dict[str, Any]:
    state = _load_json(_rooted(STATE_PATH), {"files": {}})
    task = state.get("pending_maintenance_task")
    if not isinstance(task, dict):
        return {"ok": True, "task": None}
    if task.get("kind") == "node_update":
        result = execute_update_task(task)
        state = _load_json(_rooted(STATE_PATH), {"files": {}})
        if state.get("pending_maintenance_task", {}).get("task_id") == task.get("task_id"):
            state.pop("pending_maintenance_task", None)
            _atomic_json(_rooted(STATE_PATH), state)
        return {"ok": True, "task": result}
    if task.get("kind") == "node_destroy":
        result = execute_uninstall_task(task)
        return {"ok": True, "task": result}
    else:
        raise RuntimeError("不支持的维护任务")


def run_once() -> Dict[str, Any]:
    config = _load_json(_rooted(CONFIG_PATH), {})
    if not config.get("controller_url") or not config.get("node_id"):
        raise RuntimeError("节点尚未注册")
    try:
        key = _rooted(KEY_PATH).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("节点密钥不可读") from exc
    state = _load_json(_rooted(STATE_PATH), {"files": {}})
    behavior_audit_enabled = bool(
        state.get("behavior_audit_enabled", config.get("behavior_audit_enabled"))
    )
    new_events: List[Dict[str, Any]] = []
    parse_errors = 0
    for raw_path in config.get("xray_logs", []):
        path = Path(str(raw_path))
        for line in _read_incremental(path, state):
            event = parse_xray_access_line(line, str(path))
            if event:
                if behavior_audit_enabled:
                    new_events.append(event)
                else:
                    new_events.append(_connection_activity(event))
            elif " accepted " in line and " email: " in line:
                parse_errors += 1
    pending = _deduplicate([*_load_spool(), *new_events])
    sent = 0
    command = None
    remaining = list(pending)
    try:
        while remaining or sent == 0:
            batch = remaining[:MAX_BATCH_EVENTS]
            result = _authenticated_request(config, key, "/v1/node/events", {"events": batch})
            sent += len(batch)
            remaining = remaining[len(batch) :]
            if isinstance(result.get("command"), dict):
                command = result["command"]
            policy = result.get("behavior_audit")
            if isinstance(policy, dict) and isinstance(policy.get("enabled"), bool):
                state["behavior_audit_enabled"] = policy["enabled"]
            if not remaining:
                break
    except RuntimeError:
        _write_spool(remaining)
        _atomic_json(_rooted(STATE_PATH), state)
        raise
    _atomic_json(_rooted(STATE_PATH), state)
    _write_spool([])
    if isinstance(command, dict) and command.get("type") == "self_uninstall":
        _authenticated_request(
            config, key, "/v1/node/command-ack", {"command_id": str(command.get("id", ""))}
        )
        uninstall(purge=True, from_service=True)
    return {"ok": True, "sent": sent, "new": len(new_events), "parse_errors": parse_errors}


def _connection_activity(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in event.items()
        if key
        in {
            "timestamp",
            "user",
            "source_ip",
            "protocol",
            "event_id",
        }
    } | {"event_type": "proxy_activity"}


def configure_log(path: str) -> None:
    value = Path(path)
    if not value.is_absolute():
        raise ValueError("日志路径必须是绝对路径")
    config = _load_json(_rooted(CONFIG_PATH), {})
    logs = list(config.get("xray_logs", []))
    if str(value) not in logs:
        logs.append(str(value))
    config["xray_logs"] = logs
    _atomic_json(_rooted(CONFIG_PATH), config)


def _owned_file(path: Path) -> bool:
    try:
        return MARKER in path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False


def _owned_dir(path: Path) -> bool:
    marker = path / ".managed-by-vpspc-node"
    try:
        return marker.read_text(encoding="utf-8").strip() == MARKER
    except OSError:
        return False


NODE_OWNED_DIRECTORIES = (INSTALL_DIR, CONFIG_DIR, STATE_DIR)
NODE_OWNED_FILES = (
    WRAPPER_PATH,
    SERVICE_PATH,
    TIMER_PATH,
    COMMAND_SERVICE_PATH,
    COMMAND_TIMER_PATH,
    MAINTENANCE_SERVICE_PATH,
)


def _safe_owned_file(path: Path) -> bool:
    try:
        return path.lstat().st_mode & 0o170000 == 0o100000 and _owned_file(path)
    except OSError:
        return False


def _safe_owned_dir(path: Path) -> bool:
    try:
        return path.lstat().st_mode & 0o170000 == 0o040000 and _owned_dir(path)
    except OSError:
        return False


def preflight_node_removal() -> Dict[str, List[Path]]:
    """Resolve only the fixed VPSPC node footprint before removing anything."""

    directories: List[Path] = []
    files: List[Path] = []
    for raw in NODE_OWNED_DIRECTORIES:
        path = _rooted(raw)
        # Path.exists() follows symlinks and would skip a dangling one.  Treat
        # every directory entry as a retained resource unless it is exactly an
        # owned directory, so a malicious or accidental link cannot be hidden.
        if not os.path.lexists(path):
            continue
        if not _safe_owned_dir(path):
            raise ValueError("节点受管目录标记不匹配，已安全保留")
        directories.append(path)
    for raw in NODE_OWNED_FILES:
        path = _rooted(raw)
        if not os.path.lexists(path):
            continue
        if not _safe_owned_file(path):
            raise ValueError("节点受管文件标记不匹配，已安全保留")
        files.append(path)
    return {"directories": directories, "files": files}


def _validate_destroy_task(task: Dict[str, Any], node_id: str) -> Dict[str, str]:
    if not isinstance(task, dict) or task.get("kind") != "node_destroy":
        raise ValueError("维护任务类型无效")
    if str(task.get("node_id", "")) != node_id:
        raise ValueError("维护任务不属于当前节点")
    task_id = str(task.get("task_id", ""))
    if not SAFE_TASK_ID.fullmatch(task_id):
        raise ValueError("维护任务 ID 无效")
    payload = task.get("payload")
    if not isinstance(payload, dict) or set(payload) != {"receipt_token"}:
        raise ValueError("维护任务内容无效")
    receipt_token = str(payload.get("receipt_token", ""))
    if not SAFE_RECEIPT_TOKEN.fullmatch(receipt_token):
        raise ValueError("卸载回执凭据无效")
    return {"task_id": task_id, "receipt_token": receipt_token}


def _stop_node_units_for_removal() -> None:
    if os.environ.get("VPSPC_NODE_SKIP_SYSTEMCTL"):
        return
    subprocess.run(
        ["systemctl", "disable", "vpspc-node.timer", "vpspc-node-command.timer"], check=False
    )
    subprocess.run(
        ["systemctl", "stop", "vpspc-node.timer", "vpspc-node-command.timer", "vpspc-node.service"],
        check=False,
    )


def _remove_preflighted_paths(plan: Dict[str, List[Path]], keep: Iterable[Path] = ()) -> int:
    retained = {Path(value) for value in keep}
    removed = 0
    for path in plan["files"]:
        if path in retained:
            continue
        if _safe_owned_file(path):
            path.unlink()
            removed += 1
        else:
            raise RuntimeError("节点受管文件在清理前发生变化，已停止")
    for path in sorted(plan["directories"], key=lambda value: len(value.parts), reverse=True):
        if path in retained:
            continue
        if _safe_owned_dir(path):
            shutil.rmtree(path)
            removed += 1
        else:
            raise RuntimeError("节点受管目录在清理前发生变化，已停止")
    return removed


def _send_uninstall_receipt(
    config: Dict[str, Any], task: Dict[str, str], status: str, removed_paths_count: int
) -> bool:
    try:
        result = _request_json(
            "POST",
            str(config["controller_url"]).rstrip("/") + "/v1/node/uninstall-receipt",
            {
                "node_id": str(config["node_id"]),
                "task_id": task["task_id"],
                "status": status,
                "removed_paths_count": removed_paths_count,
            },
            {"Authorization": "Bearer " + task["receipt_token"]},
            timeout=int(config.get("timeout_seconds", 30)),
        )
        return bool(result.get("ok"))
    except RuntimeError:
        return False


def _remove_final_maintenance_unit() -> None:
    maintenance = _rooted(MAINTENANCE_SERVICE_PATH)
    if maintenance.exists() and _safe_owned_file(maintenance):
        maintenance.unlink()
    if not os.environ.get("VPSPC_NODE_SKIP_SYSTEMCTL"):
        subprocess.run(["systemctl", "daemon-reload"], check=False)


def execute_uninstall_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """Permanently remove only preflighted VPSPC node resources.

    A bearer receipt remains usable after the normal node credential/configuration
    is gone. It is the controller's final proof before it can delete itself.
    """

    if os.geteuid() != 0:
        raise PermissionError("请使用 root 或 sudo 执行节点彻底卸载")
    config, key = _node_credentials()
    try:
        receipt = _validate_destroy_task(task, str(config["node_id"]))
        plan = preflight_node_removal()
    except (ValueError, RuntimeError) as exc:
        task_id = str(task.get("task_id", ""))
        if SAFE_TASK_ID.fullmatch(task_id):
            _safe_report_task_status(
                config, key, "safely_retained", task_id, {"stage": "preflight", "error": str(exc)[:256]}
            )
        return {"status": "safely_retained", "summary": {"stage": "preflight"}}

    _safe_report_task_status(config, key, "installing", receipt["task_id"])
    removed = 0
    status = "failed"
    try:
        _stop_node_units_for_removal()
        removed = _remove_preflighted_paths(plan, keep={_rooted(MAINTENANCE_SERVICE_PATH)})
        status = "success" if _send_uninstall_receipt(config, receipt, "success", removed) else "failed"
    except (OSError, RuntimeError, ValueError) as exc:
        _send_uninstall_receipt(config, receipt, "failed", removed)
        status = "failed"
    finally:
        _remove_final_maintenance_unit()
    return {"status": status, "removed_paths_count": removed}


def uninstall(purge: bool = False, from_service: bool = False) -> None:
    if os.geteuid() != 0:
        raise PermissionError("请使用 root 或 sudo 卸载")
    if not os.environ.get("VPSPC_NODE_SKIP_SYSTEMCTL"):
        subprocess.run(["systemctl", "disable", "vpspc-node.timer", "vpspc-node-command.timer"], check=False)
        if not from_service:
            subprocess.run(
                ["systemctl", "stop", "vpspc-node.timer", "vpspc-node-command.timer", "vpspc-node.service"],
                check=False,
            )
    for raw in (SERVICE_PATH, TIMER_PATH, COMMAND_SERVICE_PATH, COMMAND_TIMER_PATH, WRAPPER_PATH):
        path = _rooted(raw)
        if _owned_file(path):
            path.unlink()
    install_dir = _rooted(INSTALL_DIR)
    if _owned_dir(install_dir):
        shutil.rmtree(install_dir)
    if purge:
        for raw in (CONFIG_DIR, STATE_DIR):
            path = _rooted(raw)
            if _owned_dir(path):
                shutil.rmtree(path)
    if not os.environ.get("VPSPC_NODE_SKIP_SYSTEMCTL"):
        subprocess.run(["systemctl", "daemon-reload"], check=False)


def status() -> Dict[str, Any]:
    config = _load_json(_rooted(CONFIG_PATH), {})
    state = _load_json(_rooted(STATE_PATH), {})
    return {
        "installed": bool(config.get("node_id")),
        "controller_url": config.get("controller_url"),
        "node_id": config.get("node_id"),
        "xray_logs": config.get("xray_logs", []),
        "spooled_events": len(_load_spool()),
        "tracked_files": len(state.get("files", {})) if isinstance(state.get("files", {}), dict) else 0,
        "pending_maintenance_task": bool(state.get("pending_maintenance_task")),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpspc-node")
    sub = parser.add_subparsers(dest="command", required=True)
    install_parser = sub.add_parser("install")
    install_parser.add_argument("--controller", required=True)
    install_parser.add_argument("--enroll-token", required=True)
    install_parser.add_argument("--replace", action="store_true")
    install_parser.add_argument("--interval", type=int, default=5)
    sub.add_parser("run")
    command_poll_parser = sub.add_parser("command-poll")
    command_poll_parser.add_argument("--no-claim", action="store_true")
    sub.add_parser("maintenance-run")
    sub.add_parser("status")
    configure = sub.add_parser("configure-log")
    configure.add_argument("path")
    uninstall_parser = sub.add_parser("uninstall")
    uninstall_parser.add_argument("--purge", action="store_true")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "install":
            print(json.dumps(install(args.controller, args.enroll_token, args.replace, args.interval), ensure_ascii=False))
        elif args.command == "run":
            print(json.dumps(run_once(), ensure_ascii=False))
        elif args.command == "command-poll":
            print(json.dumps(command_poll(claim=not args.no_claim), ensure_ascii=False))
        elif args.command == "maintenance-run":
            print(json.dumps(maintenance_run(), ensure_ascii=False))
        elif args.command == "status":
            print(json.dumps(status(), ensure_ascii=False, indent=2))
        elif args.command == "configure-log":
            configure_log(args.path)
            print("日志路径已保存。")
        else:
            uninstall(args.purge)
            print("VPSPC 节点采集器已卸载。")
        return 0
    except (OSError, ValueError, RuntimeError, PermissionError, json.JSONDecodeError) as exc:
        print(f"vpspc-node: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
