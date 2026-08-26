from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .models import Event


def read_events(paths: Iterable[str]) -> List[Event]:
    events: List[Event] = []
    errors: List[str] = []
    for path_value in paths:
        path = Path(path_value)
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict):
                        raise ValueError("event must be a JSON object")
                    events.append(Event.from_dict(raw, line_number))
                except (json.JSONDecodeError, ValueError) as exc:
                    errors.append(f"{path}:{line_number}: {exc}")
    if errors:
        preview = "\n".join(errors[:20])
        suffix = f"\n... and {len(errors) - 20} more" if len(errors) > 20 else ""
        raise ValueError(f"invalid input events:\n{preview}{suffix}")
    return sorted(events, key=lambda event: event.timestamp)


def write_json(path: str, value: object) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
