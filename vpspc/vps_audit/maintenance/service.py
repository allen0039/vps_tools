"""Local maintenance service and its deliberately small Unix-socket API."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import threading
from typing import Any, Dict, Mapping, Optional

from vps_audit.maintenance.coordinator import MaintenanceCoordinator
from vps_audit.maintenance.helper_client import HostUpdaterClient
from vps_audit.maintenance.releases import GitHubReleaseSource
from vps_audit.maintenance.store import MaintenanceStore
from vps_audit.node_reporting import NodeRegistry
from vps_audit.runtime import load_runtime_config


SOCKET_PATH = Path("/run/vpspc/maintenance.sock")
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_NODE_IDS = 500
ALLOWED_START_ACTIONS = frozenset(
    {"controller_update", "node_update", "all_update", "node_destroy", "full_destroy"}
)


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read_limited(connection: socket.socket) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = connection.recv(8192)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_MESSAGE_BYTES:
            raise ValueError("maintenance request is too large")
        chunks.append(chunk)
    if not chunks:
        raise ValueError("maintenance request is empty")
    return b"".join(chunks)


def _clean_error(exc: BaseException) -> str:
    value = str(exc).replace("\r", " ").replace("\n", " ").strip()
    return (value or "maintenance request failed")[:240]


def build_coordinator(config_path: str) -> MaintenanceCoordinator:
    config = load_runtime_config(config_path)
    state_dir = Path(config["state_dir"])
    node_config = config["node_reporting"]
    registry_path = Path(node_config.get("registry_file") or state_dir / "nodes.json")
    maintenance = config.get("maintenance", {})
    deployment_mode = str(maintenance.get("deployment_mode", "native")) if isinstance(maintenance, Mapping) else "native"
    updater_socket = Path(str(maintenance.get("updater_socket", "/run/vpspc/updater.sock")))
    updater_key = Path(str(maintenance.get("updater_key_file", "/etc/vps-audit/updater.key")))
    return MaintenanceCoordinator(
        MaintenanceStore(state_dir / "maintenance.json"),
        NodeRegistry(registry_path, int(node_config["replay_window_seconds"])),
        GitHubReleaseSource(state_dir / "release-artifacts"),
        HostUpdaterClient(socket_path=updater_socket, key_path=updater_key),
        deployment_mode=deployment_mode,
    )


def _require_exact(value: Mapping[str, Any], expected: frozenset, label: str) -> None:
    if frozenset(value) != expected:
        raise ValueError(label + " fields are invalid")


def _start_request(body: Mapping[str, Any]) -> Dict[str, Any]:
    allowed = frozenset({"action", "channel", "version", "node_ids", "actor", "confirmation_id", "confirmation_code"})
    if not isinstance(body, Mapping) or not frozenset(body).issubset(allowed):
        raise ValueError("maintenance start fields are invalid")
    action = body.get("action")
    if action not in ALLOWED_START_ACTIONS:
        raise ValueError("unsupported maintenance action")
    actor = body.get("actor")
    if not isinstance(actor, str) or not actor.strip() or len(actor) > 128:
        raise ValueError("maintenance actor is invalid")
    node_ids = body.get("node_ids", [])
    if not isinstance(node_ids, list) or len(node_ids) > MAX_NODE_IDS or any(not isinstance(item, str) for item in node_ids):
        raise ValueError("node_ids must be an array with at most 500 node IDs")
    channel = body.get("channel")
    version = body.get("version")
    if action in {"controller_update", "node_update", "all_update"}:
        if channel not in {"stable", "edge"} or (version is not None and not isinstance(version, str)):
            raise ValueError("release channel or version is invalid")
    elif channel is not None or version is not None:
        raise ValueError("removal actions do not accept a release selection")
    if action in {"controller_update", "all_update", "full_destroy"} and node_ids:
        raise ValueError("this maintenance action does not accept node IDs")
    return {
        "action": action,
        "channel": channel,
        "version": version,
        "node_ids": list(node_ids),
        "actor": actor.strip(),
        "confirmation_id": body.get("confirmation_id"),
        "confirmation_code": body.get("confirmation_code"),
    }


class MaintenanceAPI:
    """Dispatch only fixed maintenance requests to one coordinator."""

    def __init__(self, coordinator: MaintenanceCoordinator):
        self.coordinator = coordinator

    def dispatch(self, raw: Mapping[str, Any]) -> Dict[str, Any]:
        _require_exact(raw, frozenset({"method", "path", "body"}), "maintenance request")
        method = raw.get("method")
        path = raw.get("path")
        body = raw.get("body")
        if method not in {"GET", "POST"} or not isinstance(path, str) or not isinstance(body, Mapping):
            raise ValueError("maintenance request is invalid")
        if method == "GET":
            if body:
                raise ValueError("GET maintenance requests cannot have a body")
            if path == "/v1/status":
                return {"ok": True, "status": self.coordinator.snapshot()}
            if path == "/v1/catalog":
                return {"ok": True, "catalog": self.coordinator.snapshot()["catalog"]}
            if path == "/v1/nodes":
                return {"ok": True, "nodes": self.coordinator.list_nodes()}
            if path == "/v1/job":
                return {"ok": True, "job": self.coordinator.public_job(self.coordinator.store.read_current_job())}
            raise ValueError("maintenance endpoint is invalid")
        if path == "/v1/check":
            _require_exact(body, frozenset(), "version check")
            return {"ok": True, "catalog": self.coordinator.check_versions(force=True)}
        if path == "/v1/start":
            request = _start_request(body)
            action = request["action"]
            if action == "controller_update":
                job = self.coordinator.start_controller_update(request["channel"], request["version"], request["actor"])
            elif action == "node_update":
                job = self.coordinator.start_node_update(request["channel"], request["version"], request["node_ids"], request["actor"])
            elif action == "all_update":
                job = self.coordinator.start_all_update(request["channel"], request["version"], request["actor"])
            else:
                confirmation_id = request["confirmation_id"]
                confirmation_code = request["confirmation_code"]
                if not isinstance(confirmation_id, str) or not isinstance(confirmation_code, str):
                    raise ValueError("removal requires a confirmation code")
                if action == "node_destroy":
                    job = self.coordinator.start_node_destroy(request["node_ids"], request["actor"], confirmation_id, confirmation_code)
                else:
                    job = self.coordinator.start_full_destroy(request["actor"], confirmation_id, confirmation_code)
            return {"ok": True, "job": self.coordinator.public_job(job)}
        if path == "/v1/confirmation":
            _require_exact(body, frozenset({"action"}), "confirmation")
            action = body.get("action")
            if not isinstance(action, str):
                raise ValueError("confirmation action is invalid")
            return {"ok": True, "confirmation": self.coordinator.issue_confirmation(action)}
        if path == "/v1/confirm-controller-destroy":
            _require_exact(body, frozenset({"confirmation_id", "confirmation_code"}), "controller confirmation")
            identifier, code = body.get("confirmation_id"), body.get("confirmation_code")
            if not isinstance(identifier, str) or not isinstance(code, str):
                raise ValueError("confirmation code is invalid")
            return {"ok": True, "job": self.coordinator.public_job(self.coordinator.confirm_controller_destroy(identifier, code))}
        if path == "/v1/cancel":
            _require_exact(body, frozenset(), "maintenance cancellation")
            return {"ok": True, "job": self.coordinator.public_job(self.coordinator.cancel_job())}
        if path == "/v1/preferences":
            allowed = frozenset({"version_check_enabled", "batch_size"})
            if not body or not frozenset(body).issubset(allowed):
                raise ValueError("maintenance preferences are invalid")
            enabled = body.get("version_check_enabled")
            batch_size = body.get("batch_size")
            if enabled is not None and not isinstance(enabled, bool):
                raise ValueError("version_check_enabled must be boolean")
            if batch_size is not None and (isinstance(batch_size, bool) or not isinstance(batch_size, int)):
                raise ValueError("batch_size must be an integer")
            return {"ok": True, "preferences": self.coordinator.set_preferences(version_check_enabled=enabled, batch_size=batch_size)}
        raise ValueError("maintenance endpoint is invalid")


class _ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def make_server(socket_path: Path, api: MaintenanceAPI) -> _ThreadingUnixServer:
    path = Path(socket_path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        status = path.lstat()
        if not stat.S_ISSOCK(status.st_mode):
            raise ValueError("maintenance socket path is unsafe")
        path.unlink()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            try:
                raw = json.loads(_read_limited(self.request).decode("utf-8"))
                if not isinstance(raw, Mapping):
                    raise ValueError("maintenance request must be an object")
                response: Dict[str, Any] = api.dispatch(raw)
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                response = {"ok": False, "error": _clean_error(exc)}
            payload = _json_bytes(response)
            if len(payload) > MAX_MESSAGE_BYTES:
                payload = _json_bytes({"ok": False, "error": "maintenance response is too large"})
            self.request.sendall(payload)

    server = _ThreadingUnixServer(str(path), Handler)
    os.chmod(path, 0o600)
    return server


def serve(config_path: str, socket_path: Path = SOCKET_PATH, coordinator: Optional[MaintenanceCoordinator] = None) -> None:
    api = MaintenanceAPI(coordinator or build_coordinator(config_path))
    server = make_server(socket_path, api)
    stop = threading.Event()

    def tick() -> None:
        while not stop.wait(1.0):
            try:
                api.coordinator.periodic_tick()
            except (OSError, RuntimeError, ValueError):
                # The current job retains a sanitized error when an operation
                # itself fails.  A transient catalog failure is represented in
                # its cache; never take down the local management API.
                pass

    worker = threading.Thread(target=tick, name="vpspc-maintenance-tick", daemon=True)
    worker.start()
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        stop.set()
        server.server_close()
        try:
            Path(socket_path).unlink()
        except FileNotFoundError:
            pass


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vps-audit-maintenance")
    parser.add_argument("--config", default="/etc/vps-audit/config.json")
    args = parser.parse_args(argv)
    try:
        serve(args.config)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print("vps-audit-maintenance: " + _clean_error(exc), file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
