"""Token-protected VPSPC Web management console."""

from __future__ import annotations

import argparse
import hmac
import json
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlsplit

from .behavior_audit import list_incidents, load_incident
from .maintenance.client import MaintenanceClient
from .runtime import health, load_runtime_config, review_behavior_incident, run_cycle
from .web_ui import PAGE


MAX_BODY_BYTES = 64 * 1024
MAX_NODE_IDS = 500
ALLOWED_MAINTENANCE_ACTIONS = frozenset(
    {"controller_update", "node_update", "all_update", "node_destroy", "full_destroy"}
)


def _read_token(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value or len(value) > 512:
        raise ValueError("Web token file is empty or invalid")
    return value


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _safe_error(error: BaseException) -> str:
    value = str(error).replace("\r", " ").replace("\n", " ").strip()
    return (value or "request failed")[:240]


def _validate_start_body(body: Mapping[str, Any]) -> Dict[str, Any]:
    allowed = frozenset({"action", "channel", "version", "node_ids", "confirmation_id", "confirmation_code"})
    if not isinstance(body, Mapping) or not frozenset(body).issubset(allowed):
        raise ValueError("maintenance start fields are invalid")
    action = body.get("action")
    if action not in ALLOWED_MAINTENANCE_ACTIONS:
        raise ValueError("unsupported maintenance action")
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
    result: Dict[str, Any] = {"action": action, "channel": channel, "version": version, "node_ids": node_ids, "actor": "web"}
    if action in {"node_destroy", "full_destroy"}:
        identifier = body.get("confirmation_id")
        code = body.get("confirmation_code")
        if not isinstance(identifier, str) or not isinstance(code, str):
            raise ValueError("removal requires a confirmation code")
        result["confirmation_id"] = identifier
        result["confirmation_code"] = code
    return result


def _validate_confirmation_body(body: Mapping[str, Any], *, controller: bool = False) -> Dict[str, str]:
    expected = frozenset({"confirmation_id", "confirmation_code"}) if controller else frozenset({"action"})
    if not isinstance(body, Mapping) or frozenset(body) != expected:
        raise ValueError("maintenance confirmation fields are invalid")
    if controller:
        identifier, code = body.get("confirmation_id"), body.get("confirmation_code")
        if not isinstance(identifier, str) or not isinstance(code, str):
            raise ValueError("confirmation code is invalid")
        return {"confirmation_id": identifier, "confirmation_code": code}
    action = body.get("action")
    if action not in {"node_destroy", "full_destroy", "controller_destroy"}:
        raise ValueError("confirmation action is invalid")
    return {"action": action}


def create_handler(config_path: str, maintenance_client: Optional[MaintenanceClient] = None):
    client = maintenance_client or MaintenanceClient()

    class Handler(BaseHTTPRequestHandler):
        server_version = "VPSPCWeb/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("vps-audit-web: " + (fmt % args) + "\n")

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(15)

        def _authorized(self) -> bool:
            supplied = self.headers.get("X-Web-Token", "")
            if not supplied:
                authorization = self.headers.get("Authorization", "")
                if authorization.lower().startswith("bearer "):
                    supplied = authorization[7:].strip()
            expected = _read_token(str(load_runtime_config(config_path)["web"]["token_file"]))
            return hmac.compare_digest(supplied, expected)

        def _send(self, status: int, value: Any, content_type: str = "application/json") -> None:
            body = value.encode("utf-8") if isinstance(value, str) else _json_bytes(value)
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> Dict[str, Any]:
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValueError("request body length is invalid") from exc
            if not 0 <= length <= MAX_BODY_BYTES:
                raise ValueError("request body is too large")
            try:
                value = json.loads((self.rfile.read(length) if length else b"{}").decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("request body must be valid JSON") from exc
            if not isinstance(value, dict):
                raise ValueError("request body must be an object")
            return value

        @staticmethod
        def _incident_identifier(path: str) -> str:
            identifier = path.rsplit("/", 1)[-1].upper()
            if not identifier or "/" in identifier or len(identifier) > 128:
                raise ValueError("incident identifier is invalid")
            return identifier

        def _maintenance(self, method: str, path: str, body: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
            return client.request(method, path, body)

        def do_GET(self) -> None:
            path = urlsplit(self.path).path.rstrip("/") or "/"
            if path == "/":
                self._send(200, PAGE, "text/html")
                return
            # Browsers request this automatically before the user has supplied
            # a Web Token.  Keep it empty and public so it cannot create a
            # misleading authorization error in the browser console.
            if path == "/favicon.ico":
                self._send(204, "", "image/x-icon")
                return
            try:
                if not self._authorized():
                    self._send(401, {"error": "unauthorized"})
                    return
                current = load_runtime_config(config_path)
                if path == "/api/health":
                    self._send(200, health(config_path))
                elif path == "/api/report":
                    report_path = Path(current["report_dir"]) / "latest.json"
                    self._send(200, json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {})
                elif path == "/api/incidents":
                    self._send(200, list_incidents(Path(current["behavior_audit"]["archive_dir"]), 100))
                elif path.startswith("/api/incidents/"):
                    self._send(200, load_incident(Path(current["behavior_audit"]["archive_dir"]), self._incident_identifier(path)))
                elif path == "/api/maintenance/status":
                    self._send(200, self._maintenance("GET", "/v1/status"))
                elif path == "/api/maintenance/catalog":
                    self._send(200, self._maintenance("GET", "/v1/catalog"))
                elif path == "/api/maintenance/nodes":
                    self._send(200, self._maintenance("GET", "/v1/nodes"))
                elif path == "/api/maintenance/job":
                    self._send(200, self._maintenance("GET", "/v1/job"))
                else:
                    self._send(404, {"error": "not found"})
            except (OSError, RuntimeError, ValueError, socket.timeout, json.JSONDecodeError) as exc:
                self._send(400, {"error": _safe_error(exc)})

        def do_POST(self) -> None:
            path = urlsplit(self.path).path.rstrip("/")
            try:
                if not self._authorized():
                    self._send(401, {"error": "unauthorized"})
                    return
                if path == "/api/run":
                    self._send(200, {"ok": True, "report": run_cycle(config_path)})
                    return
                if path.startswith("/api/incidents/") and path.endswith("/ai"):
                    body = self._read_json()
                    if frozenset(body) - {"question"}:
                        raise ValueError("AI review fields are invalid")
                    identifier = path.removesuffix("/ai").rsplit("/", 1)[-1].upper()
                    review = review_behavior_incident(config_path, identifier, str(body.get("question", ""))[:2000])
                    self._send(200, {"ok": True, "review": review})
                    return
                body = self._read_json()
                if path == "/api/maintenance/check":
                    if body:
                        raise ValueError("version check fields are invalid")
                    self._send(200, self._maintenance("POST", "/v1/check", {}))
                elif path == "/api/maintenance/start":
                    self._send(202, self._maintenance("POST", "/v1/start", _validate_start_body(body)))
                elif path == "/api/maintenance/confirmation":
                    self._send(200, self._maintenance("POST", "/v1/confirmation", _validate_confirmation_body(body)))
                elif path == "/api/maintenance/confirm-controller-destroy":
                    self._send(202, self._maintenance("POST", "/v1/confirm-controller-destroy", _validate_confirmation_body(body, controller=True)))
                elif path == "/api/maintenance/cancel":
                    if body:
                        raise ValueError("maintenance cancellation fields are invalid")
                    self._send(200, self._maintenance("POST", "/v1/cancel", {}))
                elif path == "/api/maintenance/preferences":
                    allowed = {"version_check_enabled", "batch_size"}
                    if not body or not set(body).issubset(allowed):
                        raise ValueError("maintenance preferences are invalid")
                    if "version_check_enabled" in body and not isinstance(body["version_check_enabled"], bool):
                        raise ValueError("version_check_enabled must be boolean")
                    if "batch_size" in body and (isinstance(body["batch_size"], bool) or not isinstance(body["batch_size"], int)):
                        raise ValueError("batch_size must be an integer")
                    self._send(200, self._maintenance("POST", "/v1/preferences", body))
                else:
                    self._send(404, {"error": "not found"})
            except (OSError, RuntimeError, ValueError, socket.timeout, json.JSONDecodeError) as exc:
                self._send(400, {"error": _safe_error(exc)})

    return Handler


def serve(config_path: str) -> None:
    config = load_runtime_config(config_path)
    web = config["web"]
    if not web.get("enabled"):
        raise ValueError("Web management is disabled in the runtime config")

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 16

    server = Server((str(web["listen_host"]), int(web["listen_port"])), create_handler(config_path))
    print(f"vps-audit-web listening on {web['listen_host']}:{web['listen_port']}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vps-audit-web")
    parser.add_argument("--config", default="/etc/vps-audit/config.json")
    args = parser.parse_args(argv)
    try:
        serve(args.config)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print("vps-audit-web: " + _safe_error(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
