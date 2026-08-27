from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shlex
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlsplit

from .behavior_audit import append_connections, classify_destination
from .models import parse_timestamp


REGISTRY_VERSION = 1
AGENT_VERSION = "0.1.0"
MAX_REQUEST_BYTES = 1_048_576
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
SAFE_NODE_ID = re.compile(r"^node_[a-f0-9]{24}$")
SAFE_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def signing_payload(timestamp: str, nonce: str, body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return f"{timestamp}\n{nonce}\n{digest}".encode("utf-8")


def sign_request(key: str, timestamp: str, nonce: str, body: bytes) -> str:
    return hmac.new(
        key.encode("utf-8"), signing_payload(timestamp, nonce, body), hashlib.sha256
    ).hexdigest()


def _atomic_json(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}.{threading.get_ident()}")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _clean_name(value: Any, label: str = "node name") -> str:
    name = str(value or "").strip()
    if not name or len(name) > 128 or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError(f"{label} must contain 1-128 printable characters")
    return name


class NodeRegistry:
    def __init__(self, path: Path, replay_window_seconds: int = 300):
        self.path = path
        self.lock_path = path.with_name(path.name + ".lock")
        self.replay_window_seconds = replay_window_seconds

    def _load(self) -> Dict[str, Any]:
        try:
            with self.path.open(encoding="utf-8") as handle:
                value = json.load(handle)
            if not isinstance(value, dict) or value.get("version") != REGISTRY_VERSION:
                raise ValueError("unsupported node registry format")
            if not isinstance(value.get("enrollments"), dict) or not isinstance(value.get("nodes"), dict):
                raise ValueError("invalid node registry structure")
            return value
        except FileNotFoundError:
            return {"version": REGISTRY_VERSION, "enrollments": {}, "nodes": {}}

    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock = self.lock_path.open("a+", encoding="utf-8")
        os.chmod(self.lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return lock

    @staticmethod
    def _expire_enrollments(state: Dict[str, Any], now: datetime) -> None:
        expired = []
        for digest, item in state["enrollments"].items():
            try:
                if parse_timestamp(str(item["expires_at"])) <= now:
                    expired.append(digest)
            except (KeyError, TypeError, ValueError):
                expired.append(digest)
        for digest in expired:
            state["enrollments"].pop(digest, None)

    def create_enrollment(
        self,
        name: str,
        allow_replace: bool = False,
        ttl_minutes: int = 15,
        now: datetime | None = None,
    ) -> Dict[str, Any]:
        display_name = _clean_name(name)
        if not 1 <= int(ttl_minutes) <= 1440:
            raise ValueError("enrollment TTL must be between 1 and 1440 minutes")
        current = now or _utc_now()
        token = secrets.token_urlsafe(32)
        record = {
            "name": display_name,
            "allow_replace": bool(allow_replace),
            "created_at": _iso(current),
            "expires_at": _iso(current + timedelta(minutes=int(ttl_minutes))),
        }
        with self._locked() as lock:
            state = self._load()
            self._expire_enrollments(state, current)
            state["enrollments"][_token_hash(token)] = record
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return {"token": token, **record}

    def inspect_enrollment(self, token: str, now: datetime | None = None) -> Dict[str, Any]:
        current = now or _utc_now()
        with self._locked() as lock:
            state = self._load()
            self._expire_enrollments(state, current)
            item = state["enrollments"].get(_token_hash(token))
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        if not isinstance(item, dict):
            raise ValueError("enrollment link is invalid, expired or already used")
        return dict(item)

    def enroll(
        self, token: str, payload: Dict[str, Any], now: datetime | None = None
    ) -> Dict[str, Any]:
        current = now or _utc_now()
        installation_id = str(payload.get("installation_id", "")).strip()
        if not SAFE_ID.fullmatch(installation_id):
            raise ValueError("installation_id is invalid")
        reported_name = str(payload.get("node_name", "")).strip()
        agent_version = str(payload.get("agent_version", "unknown"))[:64]
        with self._locked() as lock:
            state = self._load()
            self._expire_enrollments(state, current)
            digest = _token_hash(token)
            enrollment = state["enrollments"].get(digest)
            if not isinstance(enrollment, dict):
                raise ValueError("enrollment token is invalid, expired or already used")
            if payload.get("replace_existing") and not enrollment.get("allow_replace"):
                raise PermissionError("this enrollment token is not authorized to replace an existing controller")
            existing_id = next(
                (
                    node_id
                    for node_id, node in state["nodes"].items()
                    if node.get("installation_id") == installation_id and not node.get("revoked")
                ),
                None,
            )
            node_id = existing_id or f"node_{secrets.token_hex(12)}"
            credential = secrets.token_urlsafe(32)
            previous = state["nodes"].get(node_id, {})
            state["nodes"][node_id] = {
                "name": enrollment["name"] or reported_name or node_id,
                "reported_name": reported_name,
                "installation_id": installation_id,
                "credential": credential,
                "created_at": previous.get("created_at", _iso(current)),
                "registered_at": _iso(current),
                "last_seen": previous.get("last_seen"),
                "agent_version": agent_version,
                "revoked": False,
                "recent_nonces": [],
                "pending_command": previous.get("pending_command"),
            }
            state["enrollments"].pop(digest, None)
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return {
            "node_id": node_id,
            "credential": credential,
            "name": state["nodes"][node_id]["name"],
            "repaired": bool(existing_id),
            "allow_replace": bool(enrollment.get("allow_replace")),
        }

    def authenticate(
        self,
        node_id: str,
        timestamp: str,
        nonce: str,
        signature: str,
        body: bytes,
        now: datetime | None = None,
    ) -> Dict[str, Any]:
        current = now or _utc_now()
        if not SAFE_NODE_ID.fullmatch(node_id) or not SAFE_NONCE.fullmatch(nonce):
            raise PermissionError("invalid node authentication headers")
        try:
            request_time = datetime.fromtimestamp(int(timestamp), timezone.utc)
        except (TypeError, ValueError, OSError) as exc:
            raise PermissionError("invalid request timestamp") from exc
        if abs((current - request_time).total_seconds()) > self.replay_window_seconds:
            raise PermissionError("request timestamp is outside the replay window")
        with self._locked() as lock:
            state = self._load()
            node = state["nodes"].get(node_id)
            if not isinstance(node, dict) or node.get("revoked"):
                raise PermissionError("node credential is revoked or unknown")
            expected = sign_request(str(node["credential"]), timestamp, nonce, body)
            if not hmac.compare_digest(expected, signature):
                raise PermissionError("invalid request signature")
            recent = []
            for item in node.get("recent_nonces", []):
                if not isinstance(item, dict):
                    continue
                try:
                    seen_at = parse_timestamp(str(item.get("seen_at")))
                except (TypeError, ValueError):
                    continue
                if current - seen_at <= timedelta(seconds=self.replay_window_seconds):
                    recent.append(item)
            if any(item.get("nonce") == nonce for item in recent):
                raise PermissionError("request nonce has already been used")
            recent.append({"nonce": nonce, "seen_at": _iso(current)})
            node["recent_nonces"] = recent[-128:]
            node["last_seen"] = _iso(current)
            state["nodes"][node_id] = node
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        public = dict(node)
        public.pop("credential", None)
        public.pop("recent_nonces", None)
        return public

    def list_nodes(self) -> List[Dict[str, Any]]:
        with self._locked() as lock:
            state = self._load()
            result = []
            for node_id, node in sorted(state["nodes"].items()):
                item = dict(node)
                item["node_id"] = node_id
                item.pop("credential", None)
                item.pop("recent_nonces", None)
                result.append(item)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return result

    def revoke(self, node_id: str) -> None:
        with self._locked() as lock:
            state = self._load()
            node = state["nodes"].get(node_id)
            if not isinstance(node, dict):
                raise ValueError("node does not exist")
            node["revoked"] = True
            node["credential"] = secrets.token_urlsafe(32)
            node["pending_command"] = None
            state["nodes"][node_id] = node
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def delete(self, node_id: str) -> None:
        with self._locked() as lock:
            state = self._load()
            node = state["nodes"].get(node_id)
            if not isinstance(node, dict):
                raise ValueError("node does not exist")
            if not node.get("revoked"):
                raise ValueError("active node must be revoked or uninstalled before deletion")
            state["nodes"].pop(node_id, None)
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def request_uninstall(self, node_id: str) -> Dict[str, Any]:
        with self._locked() as lock:
            state = self._load()
            node = state["nodes"].get(node_id)
            if not isinstance(node, dict) or node.get("revoked"):
                raise ValueError("active node does not exist")
            command = {
                "id": uuid.uuid4().hex,
                "type": "self_uninstall",
                "created_at": _iso(_utc_now()),
            }
            node["pending_command"] = command
            state["nodes"][node_id] = node
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return command

    def acknowledge_command(self, node_id: str, command_id: str) -> None:
        with self._locked() as lock:
            state = self._load()
            node = state["nodes"].get(node_id)
            command = node.get("pending_command") if isinstance(node, dict) else None
            if not isinstance(command, dict) or command.get("id") != command_id:
                raise ValueError("pending command does not match")
            if command.get("type") != "self_uninstall":
                raise ValueError("unsupported command acknowledgement")
            node["pending_command"] = None
            node["revoked"] = True
            node["credential"] = secrets.token_urlsafe(32)
            node["uninstalled_at"] = _iso(_utc_now())
            state["nodes"][node_id] = node
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _validated_port(value: Any, label: str, required: bool = False) -> int | None:
    if value in (None, "") and not required:
        return None
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{label} is invalid")
    return port


def _validate_event(
    raw: Any, node_id: str, node_name: str, behavior_audit_enabled: bool = False
) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("node event must be an object")
    event_type = str(raw.get("event_type", ""))
    if event_type not in {"proxy_activity", "proxy_connection"}:
        raise ValueError("node event_type must be proxy_activity or proxy_connection")
    if event_type == "proxy_connection" and not behavior_audit_enabled:
        event_type = "proxy_activity"
    timestamp = str(raw.get("timestamp", ""))
    parse_timestamp(timestamp)
    user = str(raw.get("user", "")).strip()
    if not user or len(user) > 128 or any(ord(char) < 32 or ord(char) == 127 for char in user):
        raise ValueError("node event user is invalid")
    source_ip = str(raw.get("source_ip", "")).strip()
    ipaddress.ip_address(source_ip)
    event_id = str(raw.get("event_id", "")).strip()
    if not SAFE_ID.fullmatch(event_id):
        raise ValueError("node event_id is invalid")
    protocol = str(raw.get("protocol", "xray"))[:32]
    event = {
        "timestamp": timestamp,
        "event_type": event_type,
        "user": user,
        "source_ip": source_ip,
        "event_id": event_id,
        "protocol": protocol,
        "node_id": node_id,
        "node_name": node_name,
        "source": "remote_node",
    }
    if event_type == "proxy_connection":
        destination_host = str(raw.get("destination_host", "")).strip().lower().rstrip(".")
        destination_ip = str(raw.get("destination_ip", "")).strip()
        if destination_ip:
            destination_ip = str(ipaddress.ip_address(destination_ip))
        if destination_host and (
            len(destination_host) > 253
            or not re.fullmatch(r"[A-Za-z0-9._-]+", destination_host)
        ):
            raise ValueError("node event destination_host is invalid")
        if not destination_host and not destination_ip:
            raise ValueError("proxy_connection requires destination_host or destination_ip")
        network = str(raw.get("network", "tcp")).lower()
        if network not in {"tcp", "udp"}:
            raise ValueError("node event network is invalid")
        inbound_tag = str(raw.get("inbound_tag", "")).strip()
        if len(inbound_tag) > 64 or any(ord(char) < 32 for char in inbound_tag):
            raise ValueError("node event inbound_tag is invalid")
        event.update(
            {
                "source_port": _validated_port(raw.get("source_port"), "source_port"),
                "destination_host": destination_host,
                "destination_ip": destination_ip,
                "destination_port": _validated_port(
                    raw.get("destination_port"), "destination_port", required=True
                ),
                "destination_category": classify_destination(destination_host),
                "network": network,
                "inbound_tag": inbound_tag,
            }
        )
    return event


def append_inbox(path: Path, events: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    count = 0
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        with path.open("a", encoding="utf-8") as handle:
            os.chmod(path, 0o600)
            for event in events:
                json.dump(event, handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
                count += 1
            handle.flush()
            os.fsync(handle.fileno())
    return count


def build_bootstrap(public_base_url: str, token: str, allow_replace: bool) -> str:
    base = public_base_url.rstrip("/")
    replace_flag = " --replace" if allow_replace else ""
    asset_url = base + "/assets/vpspc-node.py"
    return f"""#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || {{ echo '请使用 root 或 sudo 执行' >&2; exit 1; }}
command -v python3 >/dev/null 2>&1 || {{ echo '需要 Python 3.9+' >&2; exit 1; }}
work_dir="$(mktemp -d /tmp/vpspc-node-install.XXXXXX)"
cleanup() {{ find "$work_dir" -depth -delete 2>/dev/null || true; }}
trap cleanup EXIT HUP INT TERM
agent="$work_dir/vpspc-node.py"
if command -v curl >/dev/null 2>&1; then
  curl --fail --location --silent --show-error {shlex.quote(asset_url)} --output "$agent"
elif command -v wget >/dev/null 2>&1; then
  wget -q --output-document="$agent" {shlex.quote(asset_url)}
else
  echo '需要 curl 或 wget' >&2
  exit 1
fi
python3 "$agent" install --controller {shlex.quote(base)} --enroll-token {shlex.quote(token)}{replace_flag}
"""


class NodeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: Tuple[str, int], handler, context: Dict[str, Any]):
        super().__init__(address, handler)
        self.context = context


class NodeRequestHandler(BaseHTTPRequestHandler):
    server_version = "VPSPCNodeReceiver/1"

    def log_message(self, format: str, *args: Any) -> None:
        # Never include enrollment paths, credentials or request headers in logs.
        sys.stderr.write(f"node-receiver: {self.client_address[0]} {args[1] if len(args) > 1 else '-'}\n")

    @property
    def context(self) -> Dict[str, Any]:
        return self.server.context  # type: ignore[attr-defined]

    def _behavior_audit_policy(self) -> Dict[str, Any]:
        policy = self.context.get("behavior_audit_policy")
        if not isinstance(policy, dict):
            return {"enabled": False, "archive_dir": ""}
        return {
            "enabled": bool(policy.get("enabled")),
            "archive_dir": str(policy.get("archive_dir", "")),
        }

    def _json(self, status: int, value: Dict[str, Any]) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _text(self, status: int, value: str, content_type: str = "text/plain; charset=utf-8") -> None:
        body = value.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> bytes:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if not 0 < size <= int(self.context["max_request_bytes"]):
            raise ValueError("request body size is invalid")
        body = self.rfile.read(size)
        if len(body) != size:
            raise ValueError("request body is incomplete")
        return body

    def _authenticate(self, body: bytes) -> Tuple[str, Dict[str, Any]]:
        node_id = self.headers.get("X-VPSPC-Node", "")
        node = self.context["registry"].authenticate(
            node_id,
            self.headers.get("X-VPSPC-Timestamp", ""),
            self.headers.get("X-VPSPC-Nonce", ""),
            self.headers.get("X-VPSPC-Signature", ""),
            body,
        )
        return node_id, node

    def do_GET(self) -> None:
        try:
            if self.path == "/assets/vpspc-node.py":
                asset = Path(self.context["agent_asset_path"])
                self._text(HTTPStatus.OK, asset.read_text(encoding="utf-8"), "text/x-python; charset=utf-8")
                return
            if self.path.startswith("/join/"):
                token = self.path[len("/join/") :]
                if not token or "/" in token or "?" in token:
                    raise ValueError("invalid enrollment link")
                item = self.context["registry"].inspect_enrollment(token)
                script = build_bootstrap(
                    self.context["public_base_url"], token, bool(item.get("allow_replace"))
                )
                self._text(HTTPStatus.OK, script, "text/x-shellscript; charset=utf-8")
                return
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
        except (OSError, ValueError) as exc:
            self._json(HTTPStatus.GONE, {"ok": False, "error": str(exc)})

    def do_POST(self) -> None:
        try:
            body = self._body()
            raw = json.loads(body)
            if not isinstance(raw, dict):
                raise ValueError("request JSON must be an object")
            if self.path == "/v1/node/enroll":
                token = self.headers.get("X-VPSPC-Enroll", "")
                result = self.context["registry"].enroll(token, raw)
                self._json(
                    HTTPStatus.OK,
                    {"ok": True, **result, "behavior_audit": self._behavior_audit_policy()},
                )
                return
            node_id, node = self._authenticate(body)
            if self.path == "/v1/node/events":
                rows = raw.get("events")
                if not isinstance(rows, list) or len(rows) > int(self.context["max_batch_events"]):
                    raise ValueError("events must be an array within the configured batch limit")
                policy = self._behavior_audit_policy()
                events = [
                    _validate_event(item, node_id, str(node["name"]), bool(policy["enabled"]))
                    for item in rows
                ]
                if policy["enabled"] and policy["archive_dir"]:
                    append_connections(Path(policy["archive_dir"]), events)
                accepted = append_inbox(Path(self.context["inbox_path"]), events) if events else 0
                response: Dict[str, Any] = {
                    "ok": True,
                    "accepted": accepted,
                    "behavior_audit": policy,
                }
                if isinstance(node.get("pending_command"), dict):
                    response["command"] = node["pending_command"]
                self._json(HTTPStatus.OK, response)
                return
            if self.path == "/v1/node/command-ack":
                command_id = str(raw.get("command_id", ""))
                self.context["registry"].acknowledge_command(node_id, command_id)
                self._json(HTTPStatus.OK, {"ok": True})
                return
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
        except PermissionError as exc:
            self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": str(exc)})
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})


def _paths(config: Dict[str, Any]) -> Dict[str, Any]:
    node_config = config["node_reporting"]
    state_dir = Path(config["state_dir"])
    return {
        "registry_path": Path(node_config.get("registry_file") or state_dir / "nodes.json"),
        "inbox_path": Path(node_config.get("inbox_file") or state_dir / "node-inbox.jsonl"),
        "agent_asset_path": str(node_config["agent_asset_path"]),
    }


def serve(config_path: str) -> None:
    from .runtime import load_runtime_config

    config = load_runtime_config(config_path)
    node_config = config["node_reporting"]
    if node_config["mode"] != "node_reporting":
        raise ValueError("node reporting mode is disabled")
    paths = _paths(config)
    registry = NodeRegistry(paths["registry_path"], int(node_config["replay_window_seconds"]))
    context = {
        **paths,
        "registry": registry,
        "public_base_url": node_config["public_base_url"],
        "max_batch_events": int(node_config["max_batch_events"]),
        "max_request_bytes": MAX_REQUEST_BYTES,
        "behavior_audit_policy": {
            "enabled": bool(config["behavior_audit"]["enabled"]),
            "archive_dir": str(config["behavior_audit"]["archive_dir"]),
        },
    }
    server = NodeHTTPServer(
        (str(node_config["listen_host"]), int(node_config["listen_port"])),
        NodeRequestHandler,
        context,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


def _load_admin(config_path: str) -> Tuple[Dict[str, Any], NodeRegistry]:
    from .runtime import load_runtime_config

    config = load_runtime_config(config_path)
    paths = _paths(config)
    registry = NodeRegistry(paths["registry_path"], int(config["node_reporting"]["replay_window_seconds"]))
    return config, registry


def create_install_command(
    config_path: str, name: str, replace: bool = False, ttl_minutes: int | None = None
) -> str:
    config, registry = _load_admin(config_path)
    if config["node_reporting"]["mode"] != "node_reporting":
        raise ValueError("请先通过完整重新配置启用节点上报模式")
    ttl = ttl_minutes or int(config["node_reporting"]["enrollment_ttl_minutes"])
    item = registry.create_enrollment(name, replace, ttl)
    base = str(config["node_reporting"]["public_base_url"]).rstrip("/")
    return f"curl -fsSL {shlex.quote(base + '/join/' + item['token'])} | sudo sh"


def list_registered_nodes(config_path: str) -> List[Dict[str, Any]]:
    return _load_admin(config_path)[1].list_nodes()


def revoke_registered_node(config_path: str, node_id: str) -> None:
    _load_admin(config_path)[1].revoke(node_id)


def delete_registered_node(config_path: str, node_id: str) -> None:
    _load_admin(config_path)[1].delete(node_id)


def request_registered_node_uninstall(config_path: str, node_id: str) -> Dict[str, Any]:
    return _load_admin(config_path)[1].request_uninstall(node_id)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vps-audit-nodes")
    parser.add_argument("--config", default="/etc/vps-audit/config.json")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    create = sub.add_parser("create-link")
    create.add_argument("--name", required=True)
    create.add_argument("--replace", action="store_true")
    create.add_argument("--ttl-minutes", type=int)
    sub.add_parser("list")
    revoke = sub.add_parser("revoke")
    revoke.add_argument("node_id")
    delete = sub.add_parser("delete")
    delete.add_argument("node_id")
    uninstall = sub.add_parser("uninstall")
    uninstall.add_argument("node_id")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "serve":
            serve(args.config)
            return 0
        config, registry = _load_admin(args.config)
        if args.command == "create-link":
            if config["node_reporting"]["mode"] != "node_reporting":
                raise ValueError("请先启用节点上报模式")
            print(create_install_command(args.config, args.name, args.replace, args.ttl_minutes))
        elif args.command == "list":
            print(json.dumps(registry.list_nodes(), ensure_ascii=False, indent=2))
        elif args.command == "revoke":
            registry.revoke(args.node_id)
            print("节点凭据已撤销。")
        elif args.command == "delete":
            registry.delete(args.node_id)
            print("已删除撤销节点的注册记录。")
        else:
            command = registry.request_uninstall(args.node_id)
            print(f"已排队固定自卸载命令：{command['id']}")
        return 0
    except (OSError, ValueError, PermissionError, json.JSONDecodeError) as exc:
        print(f"vps-audit-nodes: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
