from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Iterable, Iterator


PREFIX = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+")
SUCCESS = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
FAILURE = re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")


def parse_sshd_message(message: str, timestamp: str) -> Dict[str, Any] | None:
    match = SUCCESS.search(message)
    event_type = "login_success"
    if not match:
        match = FAILURE.search(message)
        event_type = "login_failure"
    if not match:
        return None
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "user": match.group("user"),
        "source_ip": match.group("ip"),
        "source_port": int(match.group("port")),
        "method": match.group("method"),
    }


def parse_auth_log(lines: Iterable[str], year: int, timezone_offset: str = "+00:00") -> Iterator[Dict[str, Any]]:
    for line in lines:
        prefix = PREFIX.match(line)
        if not prefix:
            continue
        local = datetime.strptime(
            f"{year} {prefix.group('month')} {prefix.group('day')} {prefix.group('time')}",
            "%Y %b %d %H:%M:%S",
        )
        event = parse_sshd_message(line, local.isoformat() + timezone_offset)
        if event:
            yield event
