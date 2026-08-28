#!/usr/bin/env python3
"""Small dependency-free Docker health probes for VPSPC services."""

from __future__ import annotations

import json
import socket
import stat
import sys
import time
from pathlib import Path


def _config(path: str) -> dict:
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("invalid config")
    return value


def _audit(config_path: str) -> bool:
    from vps_audit.runtime import health

    return health(config_path).get("status") == "healthy"


def _bot(config_path: str) -> bool:
    config = _config(config_path)
    path = Path(str(config["state_dir"])) / "bot-state.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        last_poll = float(value["last_poll_at"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False
    return time.time() - last_poll < max(90, int(config["telegram"].get("poll_timeout_seconds", 30)) * 3)


def _tcp(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if len(args) < 2:
        return 2
    mode, config_path = args[:2]
    try:
        if mode == "audit":
            return 0 if _audit(config_path) else 1
        if mode == "bot":
            return 0 if _bot(config_path) else 1
        config = _config(config_path)
        if mode == "web":
            return 0 if _tcp("127.0.0.1", int(config["web"]["listen_port"])) else 1
        if mode == "receiver":
            return 0 if _tcp("127.0.0.1", int(config["node_reporting"]["listen_port"])) else 1
        if mode == "maintenance":
            path = Path("/run/vpspc/maintenance.sock")
            return 0 if path.exists() and stat.S_ISSOCK(path.stat().st_mode) else 1
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
