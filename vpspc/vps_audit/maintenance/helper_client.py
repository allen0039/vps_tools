"""Small authenticated client for the VPSPC root maintenance helper.

This module intentionally exposes named operations instead of a generic
``execute`` method.  That keeps Web, Telegram, and the maintenance coordinator
from ever obtaining a route to arbitrary host commands or paths.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import time
from typing import Any, Dict, Mapping, Optional


UPDATER_KEY_PATH = Path("/etc/vps-audit/updater.key")
UPDATER_SOCKET_PATH = Path("/run/vpspc/updater.sock")
MAX_MESSAGE_BYTES = 64 * 1024


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signature(
    key: bytes, method: str, path: str, timestamp: int, nonce: str, body: Mapping[str, Any]
) -> str:
    message = b"\n".join(
        (
            method.encode("ascii"),
            path.encode("ascii"),
            str(timestamp).encode("ascii"),
            nonce.encode("ascii"),
            _canonical_json(body),
        )
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


class HostUpdaterClient:
    """Call only fixed HMAC-protected endpoints on the local Unix socket."""

    def __init__(
        self,
        socket_path: Path = UPDATER_SOCKET_PATH,
        key_path: Path = UPDATER_KEY_PATH,
        timeout_seconds: float = 900.0,
    ):
        self.socket_path = Path(socket_path)
        self.key_path = Path(key_path)
        self.timeout_seconds = float(timeout_seconds)
        if not 1.0 <= self.timeout_seconds <= 1800.0:
            raise ValueError("host updater timeout must be between 1 and 1800 seconds")

    def native_update(
        self, *, job_id: str, artifact_id: str, version: str, sha256: str
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/v1/native-update",
            {
                "action": "native-update",
                "job_id": job_id,
                "artifact_id": artifact_id,
                "version": version,
                "sha256": sha256,
            },
        )

    def restart_maintenance(self, *, job_id: str) -> Dict[str, Any]:
        """Ask the helper to restart only the native maintenance coordinator."""
        return self._request(
            "POST",
            "/v1/maintenance-restart",
            {"action": "maintenance-restart", "job_id": job_id},
        )

    def controller_destroy(self, *, job_id: str, confirmation_id: str) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/v1/controller-destroy",
            {
                "action": "controller-destroy",
                "job_id": job_id,
                "confirmation_id": confirmation_id,
            },
        )

    def docker_update(self, *, job_id: str, digest: str, version: str) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/v1/docker-update",
            {
                "action": "docker-update",
                "job_id": job_id,
                "digest": digest,
                "version": version,
            },
        )

    def docker_destroy(self, *, job_id: str, confirmation_id: str) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/v1/docker-destroy",
            {
                "action": "docker-destroy",
                "job_id": job_id,
                "confirmation_id": confirmation_id,
            },
        )

    def job_status(self, job_id: str) -> Dict[str, Any]:
        return self._request("GET", "/v1/jobs/" + job_id, {})

    def _request(self, method: str, path: str, body: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        if method not in {"GET", "POST"}:
            raise ValueError("host updater method is invalid")
        if not isinstance(path, str) or not path.startswith("/v1/") or "?" in path or "#" in path:
            raise ValueError("host updater path is invalid")
        request_body = dict(body or {})
        timestamp = int(time.time())
        nonce = secrets.token_hex(16)
        key = self._load_key()
        envelope = {
            "method": method,
            "path": path,
            "timestamp": timestamp,
            "nonce": nonce,
            "body": request_body,
        }
        envelope["signature"] = _signature(key, method, path, timestamp, nonce, request_body)
        raw = _canonical_json(envelope)
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("host updater request is too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(str(self.socket_path))
                connection.sendall(raw)
                connection.shutdown(socket.SHUT_WR)
                response = self._read_response(connection)
        except OSError as exc:
            raise RuntimeError("VPSPC host updater is unavailable") from exc
        try:
            value = json.loads(response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("VPSPC host updater returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeError("VPSPC host updater returned an invalid response")
        return value

    def _load_key(self) -> bytes:
        try:
            descriptor = os.open(self.key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o600:
                raise ValueError("host updater key is unsafe")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                value = handle.read(513).strip()
        except OSError as exc:
            raise RuntimeError("VPSPC host updater key is unavailable") from exc
        finally:
            if "descriptor" in locals() and descriptor >= 0:
                os.close(descriptor)
        if not 16 <= len(value) <= 512:
            raise RuntimeError("VPSPC host updater key is invalid")
        return value

    @staticmethod
    def _read_response(connection: socket.socket) -> bytes:
        chunks = []
        total = 0
        while True:
            chunk = connection.recv(8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MESSAGE_BYTES:
                raise RuntimeError("VPSPC host updater response is too large")
            chunks.append(chunk)
        if not chunks:
            raise RuntimeError("VPSPC host updater returned no response")
        return b"".join(chunks)
