from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


VALID_EVENT_TYPES = {
    "login_success",
    "login_failure",
    "subscription_access",
    "process_start",
    "network_connection",
}


def parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_type: str
    user: str
    data: Dict[str, Any]
    line_number: int = 0

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], line_number: int = 0) -> "Event":
        raw = dict(raw)
        if not raw.get("event_type") and (raw.get("subscription_id") or raw.get("user_id")):
            raw["event_type"] = "subscription_access"
        if not raw.get("user"):
            raw["user"] = raw.get("subscription_id") or raw.get("user_id")
        if not raw.get("source_ip") and raw.get("ip"):
            raw["source_ip"] = raw["ip"]
        missing = [key for key in ("timestamp", "event_type", "user") if not raw.get(key)]
        if missing:
            raise ValueError("missing required fields: " + ", ".join(missing))
        if raw["event_type"] not in VALID_EVENT_TYPES:
            raise ValueError(f"unsupported event_type: {raw['event_type']}")
        return cls(
            timestamp=parse_timestamp(str(raw["timestamp"])),
            event_type=str(raw["event_type"]),
            user=str(raw["user"]),
            data={key: value for key, value in raw.items() if key not in {"timestamp", "event_type", "user", "subscription_id", "user_id", "ip"}},
            line_number=line_number,
        )

    def iso_timestamp(self) -> str:
        return self.timestamp.isoformat().replace("+00:00", "Z")


@dataclass
class Finding:
    rule_id: str
    user: str
    severity: str
    score: int
    title: str
    summary: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "user": self.user,
            "severity": self.severity,
            "score": self.score,
            "title": self.title,
            "summary": self.summary,
            "evidence": self.evidence,
        }
