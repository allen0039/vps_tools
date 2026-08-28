"""Fixed local client used by Telegram and Web maintenance surfaces."""

from __future__ import annotations

import json
from pathlib import Path
import socket
from typing import Any, Dict, Mapping, Optional

from .service import MAX_MESSAGE_BYTES, SOCKET_PATH


class MaintenanceClient:
    def __init__(self, socket_path: Path = SOCKET_PATH, timeout_seconds: float = 20.0):
        self.socket_path = Path(socket_path)
        self.timeout_seconds = float(timeout_seconds)
        if not 1.0 <= self.timeout_seconds <= 60.0:
            raise ValueError("maintenance client timeout must be between 1 and 60 seconds")

    def request(self, method: str, path: str, body: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        if method not in {"GET", "POST"} or not isinstance(path, str) or not path.startswith("/v1/"):
            raise ValueError("maintenance request is invalid")
        payload = {"method": method, "path": path, "body": dict(body or {})}
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise ValueError("maintenance request is too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(str(self.socket_path))
                connection.sendall(encoded)
                connection.shutdown(socket.SHUT_WR)
                response = self._read(connection)
        except OSError as exc:
            raise RuntimeError("VPSPC maintenance service is unavailable") from exc
        try:
            decoded = json.loads(response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("VPSPC maintenance service returned invalid JSON") from exc
        if not isinstance(decoded, dict) or not isinstance(decoded.get("ok"), bool):
            raise RuntimeError("VPSPC maintenance service returned an invalid response")
        if not decoded["ok"]:
            raise RuntimeError(str(decoded.get("error") or "maintenance request failed"))
        return decoded

    @staticmethod
    def _read(connection: socket.socket) -> bytes:
        chunks = []
        total = 0
        while True:
            chunk = connection.recv(8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MESSAGE_BYTES:
                raise RuntimeError("VPSPC maintenance service response is too large")
            chunks.append(chunk)
        if not chunks:
            raise RuntimeError("VPSPC maintenance service returned no response")
        return b"".join(chunks)


__all__ = ["MaintenanceClient"]
