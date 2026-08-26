from __future__ import annotations

import shlex
from datetime import datetime
from typing import Any, Dict, Iterable, Iterator


SUBSCRIPTION_MESSAGES = (
    "用户获取订阅",
    "subscribe_fetch",
)


def _timestamp(value: str, timezone_offset: str) -> str:
    normalized = value.replace(" ", "T", 1)
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid miaomiaowux timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return normalized + timezone_offset
    return parsed.isoformat()


def parse_miaomiaowux_line(line: str, timezone_offset: str = "+00:00") -> Dict[str, Any] | None:
    if not any(marker in line for marker in SUBSCRIPTION_MESSAGES):
        return None
    try:
        fields: Dict[str, str] = {}
        for token in shlex.split(line):
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
    except ValueError:
        return None
    username = fields.get("username") or fields.get("user")
    source_ip = fields.get("ip") or fields.get("source_ip")
    timestamp = fields.get("time")
    message = fields.get("msg", "")
    if not username or not source_ip or not timestamp or "用户获取订阅" not in message:
        return None
    return {
        "timestamp": _timestamp(timestamp, timezone_offset),
        "event_type": "subscription_access",
        "user": username,
        "source_ip": source_ip,
        "source": "miaomiaowux",
        "access_mode": "subscription_fetch",
    }


def parse_miaomiaowux_log(lines: Iterable[str], timezone_offset: str = "+00:00") -> Iterator[Dict[str, Any]]:
    for line in lines:
        event = parse_miaomiaowux_line(line, timezone_offset)
        if event:
            yield event
