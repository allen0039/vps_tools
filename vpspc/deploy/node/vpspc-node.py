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
MAX_SPOOL_EVENTS = 10_000
MAX_SPOOL_BYTES = 10 * 1024 * 1024
MAX_BATCH_EVENTS = 500
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
        "behavior_audit_enabled": bool(result.get("behavior_audit", {}).get("enabled")),
    }
    _write_installation(config, str(result["credential"]), interval)
    if not os.environ.get("VPSPC_NODE_SKIP_SYSTEMCTL"):
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", "vpspc-node.timer"], check=True)
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


def uninstall(purge: bool = False, from_service: bool = False) -> None:
    if os.geteuid() != 0:
        raise PermissionError("请使用 root 或 sudo 卸载")
    if not os.environ.get("VPSPC_NODE_SKIP_SYSTEMCTL"):
        subprocess.run(["systemctl", "disable", "vpspc-node.timer"], check=False)
        if not from_service:
            subprocess.run(["systemctl", "stop", "vpspc-node.timer", "vpspc-node.service"], check=False)
    for raw in (SERVICE_PATH, TIMER_PATH, WRAPPER_PATH):
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
