from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


def _field(fields: Dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in fields and fields[name] not in (None, ""):
            return fields[name]
    return None


def _timestamp(raw: Dict[str, Any], fields: Dict[str, Any]) -> str:
    value = raw.get("time") or _field(fields, "evt.time.iso8601", "evt.time")
    if isinstance(value, (int, float)):
        seconds = value / 1_000_000_000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")
    if value:
        return str(value)
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_falco_event(raw: Dict[str, Any]) -> Dict[str, Any] | None:
    fields = raw.get("output_fields") or {}
    if not isinstance(fields, dict):
        return None
    user = _field(fields, "user.name", "user.loginname")
    uid = _field(fields, "user.uid")
    try:
        if uid is not None and (int(uid) < 1000 or int(uid) == 65534):
            return None
    except (TypeError, ValueError):
        pass
    if not user:
        return None
    event_name = str(_field(fields, "evt.type") or "").lower()
    rule = str(raw.get("rule", "")).lower()
    base: Dict[str, Any] = {"timestamp": _timestamp(raw, fields), "user": str(user)}
    if event_name in {"execve", "execveat"} or "user process start" in rule:
        base.update({
            "event_type": "process_start",
            "pid": _field(fields, "proc.pid"),
            "executable": _field(fields, "proc.exepath", "proc.name"),
            "command": _field(fields, "proc.cmdline"),
            "parent_executable": _field(fields, "proc.pexepath", "proc.pname"),
        })
        return {key: value for key, value in base.items() if value is not None}
    if event_name in {"connect", "sendto"} or "user outbound connection" in rule:
        base.update({
            "event_type": "network_connection",
            "pid": _field(fields, "proc.pid"),
            "destination_ip": _field(fields, "fd.rip", "fd.sip"),
            "destination_port": _field(fields, "fd.rport", "fd.sport"),
        })
        if not base.get("destination_ip"):
            return None
        return {key: value for key, value in base.items() if value is not None}
    return None
