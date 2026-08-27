from __future__ import annotations

import fcntl
import gzip
import hashlib
import json
import os
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .models import parse_timestamp


ARCHIVE_MARKER = ".vpspc-behavior-audit"
ACCOUNT_SERVICE_SUFFIXES = (
    "accounts.google.com",
    "account.google.com",
    "auth.openai.com",
    "chatgpt.com",
    "login.microsoftonline.com",
    "account.microsoft.com",
    "appleid.apple.com",
    "idmsa.apple.com",
    "challenges.cloudflare.com",
    "hcaptcha.com",
    "arkoselabs.com",
    "recaptcha.net",
)
ACCOUNT_SERVICE_KEYWORDS = (
    "account",
    "accounts",
    "auth",
    "captcha",
    "challenge",
    "challenges",
    "hcaptcha",
    "login",
    "oauth",
    "register",
    "recaptcha",
    "signup",
    "sms",
    "verify",
)


def classify_destination(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host:
        return "unknown"
    if any(host == suffix or host.endswith("." + suffix) for suffix in ACCOUNT_SERVICE_SUFFIXES):
        return "account_service"
    labels = set(host.replace("-", ".").split("."))
    if labels.intersection(ACCOUNT_SERVICE_KEYWORDS):
        return "account_service"
    return "general"


def ensure_archive_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    marker = path / ARCHIVE_MARKER
    if not marker.exists():
        marker.write_text("managed-by=vpspc\n", encoding="utf-8")
        os.chmod(marker, 0o600)


def archive_file(path: Path, timestamp: datetime) -> Path:
    return path / f"connections-{timestamp.astimezone(timezone.utc).date().isoformat()}.jsonl"


def append_connections(path: Path, events: Iterable[Dict[str, Any]]) -> int:
    rows = [event for event in events if event.get("event_type") == "proxy_connection"]
    if not rows:
        return 0
    ensure_archive_directory(path)
    by_file: Dict[Path, List[Dict[str, Any]]] = {}
    for event in rows:
        timestamp = parse_timestamp(str(event["timestamp"]))
        by_file.setdefault(archive_file(path, timestamp), []).append(event)
    lock_path = path / ".archive.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        for destination, items in by_file.items():
            with destination.open("a", encoding="utf-8") as handle:
                os.chmod(destination, 0o600)
                for item in items:
                    json.dump(item, handle, ensure_ascii=False, separators=(",", ":"))
                    handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
    return len(rows)


def _archive_files(path: Path) -> List[Path]:
    return sorted(
        [*path.glob("connections-????-??-??.jsonl"), *path.glob("connections-????-??-??.jsonl.gz")],
        key=lambda item: item.name,
    )


def maintain_archive(
    path: Path,
    retention_days: int,
    incident_retention_days: int,
    max_disk_mb: int,
    now: datetime,
) -> Dict[str, int]:
    ensure_archive_directory(path)
    lock_path = path / ".archive.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return _maintain_archive_locked(
            path, retention_days, incident_retention_days, max_disk_mb, now
        )


def _maintain_archive_locked(
    path: Path,
    retention_days: int,
    incident_retention_days: int,
    max_disk_mb: int,
    now: datetime,
) -> Dict[str, int]:
    cutoff = now.astimezone(timezone.utc).date() - timedelta(days=retention_days - 1)
    removed = 0
    compressed = 0
    today_name = archive_file(path, now).name
    for item in _archive_files(path):
        raw_date = item.name[len("connections-") : len("connections-") + 10]
        try:
            item_date = datetime.strptime(raw_date, "%Y-%m-%d").date()
        except ValueError:
            continue
        if item_date < cutoff:
            item.unlink(missing_ok=True)
            removed += 1
        elif item.name.endswith(".jsonl") and item.name != today_name:
            compressed_path = item.with_suffix(item.suffix + ".gz")
            temporary = compressed_path.with_name(compressed_path.name + f".tmp.{os.getpid()}")
            with item.open("rb") as source, gzip.open(temporary, "wb", compresslevel=6) as target:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    target.write(chunk)
            os.chmod(temporary, 0o600)
            os.replace(temporary, compressed_path)
            item.unlink()
            compressed += 1
    limit = max_disk_mb * 1024 * 1024
    files = _archive_files(path)
    total = sum(item.stat().st_size for item in files)
    for item in files:
        if total <= limit:
            break
        size = item.stat().st_size
        item.unlink(missing_ok=True)
        total -= size
        removed += 1
    removed_incidents = 0
    incident_cutoff = now - timedelta(days=incident_retention_days)
    incident_dir = path / "incidents"
    incident_files = incident_dir.glob("INC-*.json") if incident_dir.is_dir() else []
    for item in incident_files:
        try:
            value = json.loads(item.read_text(encoding="utf-8"))
            generated_at = parse_timestamp(str(value["generated_at"]))
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            generated_at = datetime.fromtimestamp(item.stat().st_mtime, tz=timezone.utc)
        if generated_at < incident_cutoff:
            item.unlink(missing_ok=True)
            removed_incidents += 1
    return {
        "removed_files": removed,
        "removed_incidents": removed_incidents,
        "compressed_files": compressed,
        "archive_bytes": total,
    }


def read_recent_connections(
    path: Path, cutoff: datetime, now: datetime, max_events: int
) -> List[Dict[str, Any]]:
    if not path.is_dir():
        return []
    rows = deque(maxlen=max_events)
    first_date = cutoff.astimezone(timezone.utc).date()
    last_date = (now + timedelta(minutes=5)).astimezone(timezone.utc).date()
    for item in _archive_files(path):
        raw_date = item.name[len("connections-") : len("connections-") + 10]
        try:
            item_date = datetime.strptime(raw_date, "%Y-%m-%d").date()
        except ValueError:
            continue
        if not first_date <= item_date <= last_date:
            continue
        opener = gzip.open if item.suffix == ".gz" else open
        try:
            with opener(item, "rt", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        value = json.loads(line)
                        timestamp = parse_timestamp(str(value["timestamp"]))
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if (
                        isinstance(value, dict)
                        and value.get("event_type") == "proxy_connection"
                        and cutoff <= timestamp <= now + timedelta(minutes=5)
                    ):
                        rows.append(value)
        except OSError:
            continue
    return sorted(rows, key=lambda item: str(item.get("timestamp", "")))


def incident_id(finding: Dict[str, Any]) -> str:
    evidence = finding.get("evidence") or []
    seed = json.dumps(
        {
            "rule_id": finding.get("rule_id"),
            "user": finding.get("user"),
            "node": next(
                (item.get("node_id") for item in evidence if isinstance(item, dict) and item.get("node_id")),
                "",
            ),
            "last": evidence[-1].get("timestamp") if evidence and isinstance(evidence[-1], dict) else "",
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return "INC-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16].upper()


def save_incidents(path: Path, findings: Iterable[Dict[str, Any]], generated_at: str) -> List[Dict[str, Any]]:
    ensure_archive_directory(path)
    incident_dir = path / "incidents"
    incident_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(incident_dir, 0o700)
    saved: List[Dict[str, Any]] = []
    for finding in findings:
        if not str(finding.get("rule_id", "")).startswith(("NODE_", "BEHAVIOR_")):
            continue
        record = dict(finding)
        record["incident_id"] = incident_id(record)
        record["generated_at"] = generated_at
        destination = incident_dir / f"{record['incident_id']}.json"
        previous: Dict[str, Any] = {}
        try:
            previous = json.loads(destination.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        if previous.get("ai_reviews"):
            record["ai_reviews"] = previous["ai_reviews"]
        temporary = destination.with_name(destination.name + f".tmp.{os.getpid()}")
        temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        finding["incident_id"] = record["incident_id"]
        saved.append(record)
    return saved


def list_incidents(path: Path, limit: int = 20) -> List[Dict[str, Any]]:
    incident_dir = path / "incidents"
    result: List[Dict[str, Any]] = []
    incident_files = incident_dir.glob("INC-*.json") if incident_dir.is_dir() else []
    for item in incident_files:
        try:
            value = json.loads(item.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                result.append(value)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    result.sort(key=lambda item: str(item.get("generated_at", "")), reverse=True)
    return result[:limit]


def load_incident(path: Path, identifier: str) -> Dict[str, Any]:
    if not identifier.startswith("INC-") or not identifier[4:].isalnum() or len(identifier) != 20:
        raise ValueError("事件 ID 格式无效")
    destination = path / "incidents" / f"{identifier}.json"
    try:
        value = json.loads(destination.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("事件不存在或已过期") from exc
    if not isinstance(value, dict):
        raise ValueError("事件记录损坏")
    return value


def save_incident_ai_review(path: Path, identifier: str, review: Dict[str, Any], question: str) -> Dict[str, Any]:
    record = load_incident(path, identifier)
    reviews = record.setdefault("ai_reviews", [])
    reviews.append(
        {
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "question": question,
            "review": review,
        }
    )
    reviews[:] = reviews[-20:]
    destination = path / "incidents" / f"{identifier}.json"
    temporary = destination.with_name(destination.name + f".tmp.{os.getpid()}")
    temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)
    return record


def render_incident(record: Dict[str, Any], max_evidence: int = 20) -> str:
    evidence = list(record.get("evidence", []))
    nodes = sorted(
        {
            str(item.get("node_name") or item.get("node_id"))
            for item in evidence
            if isinstance(item, dict) and (item.get("node_name") or item.get("node_id"))
        }
    )
    lines = [
        f"事件：{record.get('incident_id', '-')}",
        f"等级：{record.get('severity', '-')} | 规则：{record.get('rule_id', '-')}",
        f"用户：{record.get('user', '-')}",
        f"节点：{', '.join(nodes) if nodes else '-'}",
        f"摘要：{record.get('summary', '-')}",
        "",
        f"连接证据（显示 {min(len(evidence), max_evidence)}/{len(evidence)}）：",
    ]
    for item in evidence[:max_evidence]:
        if not isinstance(item, dict):
            continue
        target = item.get("destination_host") or item.get("destination_ip") or "-"
        source = str(item.get("source_ip", "-"))
        if ":" in source and not source.startswith("["):
            source = f"[{source}]"
        if item.get("source_port"):
            source += f":{item['source_port']}"
        if ":" in str(target) and not str(target).startswith("["):
            target = f"[{target}]"
        transport = "/".join(
            str(value) for value in (item.get("network"), item.get("protocol")) if value
        ) or "-"
        lines.append(
            f"{item.get('timestamp', '-')} | {source} -> "
            f"{target}:{item.get('destination_port', '-')} | {transport} | "
            f"入站={item.get('inbound_tag') or '-'} | {item.get('destination_category', '-')}"
        )
    return "\n".join(lines)[:3900]


def render_ai_review(review: Dict[str, Any]) -> str:
    lines = [f"AI 审计结论：{review.get('overall_assessment', '-')}"]
    for case in review.get("cases", [])[:5]:
        if not isinstance(case, dict):
            continue
        lines.extend(
            [
                "",
                f"用户：{case.get('user', '-')}",
                f"判断：{case.get('assessment', '-')} | 置信度：{float(case.get('confidence', 0)):.0%}",
            ]
        )
        sections = (
            ("事实", case.get("facts", [])),
            ("可能的正常解释", case.get("benign_explanations", [])),
            ("缺失证据", case.get("missing_evidence", [])),
        )
        for label, values in sections:
            if isinstance(values, list) and values:
                lines.append(f"{label}：")
                lines.extend(f"- {str(item)}" for item in values[:8])
        lines.append(f"建议：{case.get('recommended_action', '-')}")
    lines.append("\n说明：AI 只提供人工复核意见，不会自动封禁。")
    return "\n".join(lines)[:3900]
