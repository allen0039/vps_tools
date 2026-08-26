from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .ai_review import review_with_openai
from .analyzer import SEVERITY_ORDER, analyze
from .config import DEFAULT_CONFIG
from .falco_parser import parse_falco_event
from .geoip import GeoIPEnricher
from .io import read_events
from .models import Event, parse_timestamp
from .miaomiaowux_parser import parse_miaomiaowux_line
from .report import render_markdown
from .ssh_parser import parse_auth_log, parse_sshd_message
from .telegram import build_alert_message, send_message


DEFAULT_RUNTIME_CONFIG: Dict[str, Any] = {
    "auth_logs": ["/var/log/auth.log", "/var/log/secure"],
    "auth_timezone": "+00:00",
    "journal": {
        "enabled": False,
        "units": ["ssh.service", "sshd.service"],
        "initial_since_hours": 24,
    },
    "falco_logs": [],
    "subscription_logs": [],
    "miaomiaowux_logs": [],
    "miaomiaowux_timezone": "+00:00",
    "state_dir": "/var/lib/vps-audit",
    "report_dir": "/var/lib/vps-audit/reports",
    "scan_interval_minutes": 5,
    "retention_days": 7,
    "initial_scan_bytes": 2_000_000,
    "subscription_monitoring": {
        "enabled": True,
        "mode": "all",
        "users": [],
    },
    "rules": DEFAULT_CONFIG,
    "geoip": {
        "city_db": "",
        "asn_db": "",
        "connection_type_db": "",
        "anonymous_ip_db": "",
    },
    "telegram": {
        "enabled": False,
        "token_file": "/etc/vps-audit/telegram.token",
        "chat_id": "",
        "minimum_severity": "high",
        "cooldown_hours": 6,
        "include_source_ip": False,
        "max_findings": 8,
        "bot_management_enabled": False,
        "admin_user_ids": [],
        "poll_timeout_seconds": 30,
    },
    "openai_review": {
        "enabled": False,
        "api_key_file": "/etc/vps-audit/openai.key",
        "model": "",
    },
}


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = json.loads(json.dumps(base))
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def normalize_runtime_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("runtime config root must be a JSON object")
    config = _merge(DEFAULT_RUNTIME_CONFIG, raw)
    severity = config["telegram"]["minimum_severity"]
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"invalid telegram.minimum_severity: {severity}")
    monitoring = config["subscription_monitoring"]
    if not isinstance(monitoring, dict):
        raise ValueError("subscription_monitoring must be an object")
    if monitoring.get("mode") not in {"all", "allowlist"}:
        raise ValueError("subscription_monitoring.mode must be all or allowlist")
    if not isinstance(monitoring.get("enabled"), bool):
        raise ValueError("subscription_monitoring.enabled must be boolean")
    users = monitoring.get("users")
    if not isinstance(users, list):
        raise ValueError("subscription_monitoring.users must be an array")
    normalized_users: List[str] = []
    for value in users:
        user = str(value).strip()
        if not user or len(user) > 128 or any(ord(char) < 32 for char in user):
            raise ValueError("subscription user identifiers must contain 1 to 128 printable characters")
        if user not in normalized_users:
            normalized_users.append(user)
    if len(normalized_users) > 500:
        raise ValueError("subscription_monitoring.users supports at most 500 users")
    monitoring["users"] = normalized_users
    telegram = config["telegram"]
    if not isinstance(telegram.get("enabled"), bool):
        raise ValueError("telegram.enabled must be boolean")
    if not isinstance(telegram.get("bot_management_enabled"), bool):
        raise ValueError("telegram.bot_management_enabled must be boolean")
    admin_ids = telegram.get("admin_user_ids")
    if not isinstance(admin_ids, list):
        raise ValueError("telegram.admin_user_ids must be an array")
    try:
        if any(isinstance(value, bool) for value in admin_ids):
            raise ValueError
        telegram["admin_user_ids"] = list(dict.fromkeys(int(value) for value in admin_ids))
    except (TypeError, ValueError) as exc:
        raise ValueError("telegram.admin_user_ids must contain numeric Telegram user IDs") from exc
    if len(telegram["admin_user_ids"]) > 32:
        raise ValueError("telegram.admin_user_ids supports at most 32 administrators")
    if any(value <= 0 for value in telegram["admin_user_ids"]):
        raise ValueError("telegram.admin_user_ids must contain positive Telegram user IDs")
    if telegram.get("bot_management_enabled"):
        if not telegram.get("enabled"):
            raise ValueError("Telegram management requires telegram.enabled")
        chat_id = str(telegram.get("chat_id", "")).strip()
        if not chat_id:
            raise ValueError("Telegram management requires telegram.chat_id")
        if not chat_id.lstrip("-").isdigit():
            raise ValueError("telegram.chat_id must be numeric")
        if not telegram["admin_user_ids"]:
            raise ValueError("Telegram management requires at least one administrator user ID")
    numeric_ranges = {
        "retention_days": (1.0, 365.0),
        "scan_interval_minutes": (1.0, 1440.0),
        "telegram.cooldown_hours": (0.0, 8760.0),
        "telegram.max_findings": (1.0, 50.0),
        "telegram.poll_timeout_seconds": (5.0, 50.0),
    }
    for key, (minimum, maximum) in numeric_ranges.items():
        if "." in key:
            section, child = key.split(".", 1)
            value = config[section][child]
        else:
            value = config[key]
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be numeric") from exc
        if not minimum <= number <= maximum:
            raise ValueError(f"{key} must be between {minimum:g} and {maximum:g}")
    return config


def load_runtime_config(path: str) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return normalize_runtime_config(raw)


def _atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def _atomic_text(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def _load_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"version": 1, "files": {}, "notifications": {}}
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("runtime state must be a JSON object")
    value.setdefault("files", {})
    value.setdefault("notifications", {})
    return value


def _read_incremental(path: Path, state: Dict[str, Any], initial_scan_bytes: int) -> List[str]:
    if not path.is_file():
        return []
    stat = path.stat()
    file_state = state["files"].get(str(path), {})
    same_file = file_state.get("inode") == stat.st_ino
    if same_file and int(file_state.get("offset", 0)) <= stat.st_size:
        offset = int(file_state.get("offset", 0))
        skip_partial = False
    else:
        offset = max(0, stat.st_size - initial_scan_bytes) if not file_state else 0
        skip_partial = offset > 0
    with path.open("rb") as handle:
        handle.seek(offset)
        if skip_partial:
            handle.readline()
        start = handle.tell()
        data = handle.read()
    last_newline = data.rfind(b"\n")
    if last_newline < 0:
        consumed = 0
        complete = b""
    else:
        consumed = last_newline + 1
        complete = data[:consumed]
    state["files"][str(path)] = {"inode": stat.st_ino, "offset": start + consumed}
    return complete.decode("utf-8", errors="replace").splitlines()


def _parse_auth_lines(lines: Iterable[str], timezone_offset: str, enricher: GeoIPEnricher) -> Tuple[List[Dict[str, Any]], int]:
    events: List[Dict[str, Any]] = []
    errors = 0
    now = datetime.now(timezone.utc)
    for line in lines:
        try:
            parsed = list(parse_auth_log([line], now.year, timezone_offset))
            for event in parsed:
                timestamp = parse_timestamp(str(event["timestamp"]))
                if timestamp > now + timedelta(days=7):
                    timestamp = timestamp.replace(year=timestamp.year - 1)
                    event["timestamp"] = timestamp.isoformat()
                event.update(enricher.enrich(str(event["source_ip"])))
                events.append(event)
        except (ValueError, OSError):
            errors += 1
    return events, errors


def _parse_falco_lines(lines: Iterable[str]) -> Tuple[List[Dict[str, Any]], int]:
    events: List[Dict[str, Any]] = []
    errors = 0
    for line in lines:
        try:
            raw = json.loads(line)
            if isinstance(raw, dict):
                event = parse_falco_event(raw)
                if event:
                    events.append(event)
        except (json.JSONDecodeError, ValueError, TypeError):
            errors += 1
    return events, errors


def _parse_subscription_lines(lines: Iterable[str], enricher: GeoIPEnricher) -> Tuple[List[Dict[str, Any]], int]:
    events: List[Dict[str, Any]] = []
    errors = 0
    for line in lines:
        try:
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError("subscription event must be an object")
            user = raw.get("user") or raw.get("subscription_id") or raw.get("user_id")
            timestamp = raw.get("timestamp")
            source_ip = raw.get("source_ip") or raw.get("ip")
            if not user or not timestamp or not source_ip:
                raise ValueError("subscription event requires timestamp, user/subscription_id and source_ip")
            parse_timestamp(str(timestamp))
            event = dict(raw)
            event["timestamp"] = str(timestamp)
            event["event_type"] = "subscription_access"
            event["user"] = str(user)
            event["source_ip"] = str(source_ip)
            event.pop("subscription_id", None)
            event.pop("user_id", None)
            event.pop("ip", None)
            geo = enricher.enrich(str(source_ip))
            for key, value in geo.items():
                event.setdefault(key, value)
            events.append(event)
        except (json.JSONDecodeError, ValueError, TypeError, OSError):
            errors += 1
    return events, errors


def _parse_miaomiaowux_lines(
    lines: Iterable[str], timezone_offset: str, enricher: GeoIPEnricher
) -> Tuple[List[Dict[str, Any]], int]:
    events: List[Dict[str, Any]] = []
    errors = 0
    for line in lines:
        try:
            event = parse_miaomiaowux_line(line, timezone_offset)
            if event:
                event.update(enricher.enrich(str(event["source_ip"])))
                events.append(event)
        except (ValueError, TypeError, OSError):
            errors += 1
    return events, errors


def _journal_command(config: Dict[str, Any], cursor: str | None) -> List[str]:
    command = ["journalctl", "--no-pager", "--output=json"]
    for unit in config.get("units", []):
        command.extend(["--unit", str(unit)])
    if cursor:
        command.append(f"--after-cursor={cursor}")
    else:
        command.append(f"--since=-{int(config.get('initial_since_hours', 24))} hours")
    return command


def _collect_journal(state: Dict[str, Any], config: Dict[str, Any], enricher: GeoIPEnricher) -> Tuple[List[Dict[str, Any]], int]:
    cursor = state.get("journal_cursor")
    process = subprocess.run(_journal_command(config, cursor), capture_output=True, text=True, check=False)
    if process.returncode != 0 and cursor:
        process = subprocess.run(_journal_command(config, None), capture_output=True, text=True, check=False)
    if process.returncode != 0:
        detail = process.stderr.strip() or "journalctl returned a non-zero status"
        raise RuntimeError(f"journal collection failed: {detail}")
    events: List[Dict[str, Any]] = []
    errors = 0
    last_cursor = None
    for line in process.stdout.splitlines():
        try:
            raw = json.loads(line)
            if not isinstance(raw, dict):
                continue
            if raw.get("__CURSOR"):
                last_cursor = str(raw["__CURSOR"])
            message = str(raw.get("MESSAGE", ""))
            micros = int(raw["__REALTIME_TIMESTAMP"])
            timestamp = datetime.fromtimestamp(micros / 1_000_000, timezone.utc).isoformat().replace("+00:00", "Z")
            event = parse_sshd_message(message, timestamp)
            if event:
                event.update(enricher.enrich(str(event["source_ip"])))
                events.append(event)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, OSError):
            errors += 1
    if last_cursor:
        state["journal_cursor"] = last_cursor
    return events, errors


def _load_retained(path: Path, cutoff: datetime) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    result: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                raw = json.loads(line)
                if isinstance(raw, dict) and parse_timestamp(str(raw["timestamp"])) >= cutoff:
                    result.append(raw)
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
    return result


def _merge_events(existing: Iterable[Dict[str, Any]], new: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique: Dict[str, Dict[str, Any]] = {}
    for event in list(existing) + list(new):
        key = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        unique[key] = event
    return sorted(unique.values(), key=lambda item: parse_timestamp(str(item["timestamp"])))


def _filter_monitored_events(events: Iterable[Event], config: Dict[str, Any]) -> List[Event]:
    monitoring = config["subscription_monitoring"]
    if not monitoring.get("enabled"):
        return [event for event in events if event.event_type != "subscription_access"]
    if monitoring.get("mode") == "all":
        return list(events)
    allowed = set(monitoring.get("users", []))
    return [
        event
        for event in events
        if event.event_type != "subscription_access" or event.user in allowed
    ]


def _write_events(path: Path, events: Iterable[Dict[str, Any]]) -> None:
    rendered = "".join(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n" for event in events)
    _atomic_text(path, rendered)


def _notification_candidates(report: Dict[str, Any], state: Dict[str, Any], config: Dict[str, Any], now: datetime) -> List[Dict[str, Any]]:
    telegram = config["telegram"]
    minimum = SEVERITY_ORDER[telegram["minimum_severity"]]
    cooldown = timedelta(hours=float(telegram["cooldown_hours"]))
    account_severity = {item["user"]: item["severity"] for item in report.get("users", [])}
    selected: List[Dict[str, Any]] = []
    for finding in report["findings"]:
        effective = max(
            SEVERITY_ORDER[finding["severity"]],
            SEVERITY_ORDER.get(account_severity.get(finding["user"], "low"), 1),
        )
        if effective < minimum:
            continue
        key = f"{finding['user']}|{finding['rule_id']}"
        last_value = state["notifications"].get(key)
        if last_value:
            try:
                if now - parse_timestamp(last_value) < cooldown:
                    continue
            except ValueError:
                pass
        finding = dict(finding)
        finding["notification_key"] = key
        selected.append(finding)
    return selected


def _read_secret(path: str, label: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"{label} file is empty: {path}")
    return value


def run_cycle(config_path: str) -> Dict[str, Any]:
    config = load_runtime_config(config_path)
    state_dir = Path(config["state_dir"])
    report_dir = Path(config["report_dir"])
    state_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    os.chmod(report_dir, 0o700)
    lock_path = state_dir / "run.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another audit cycle is already running")

        state_path = state_dir / "state.json"
        events_path = state_dir / "events.jsonl"
        state = _load_state(state_path)
        new_events: List[Dict[str, Any]] = []
        parse_errors = 0
        with GeoIPEnricher(config) as enricher:
            for value in config.get("auth_logs", []):
                lines = _read_incremental(Path(value), state, int(config["initial_scan_bytes"]))
                parsed, errors = _parse_auth_lines(lines, str(config["auth_timezone"]), enricher)
                new_events.extend(parsed)
                parse_errors += errors
            if config.get("journal", {}).get("enabled"):
                parsed, errors = _collect_journal(state, config["journal"], enricher)
                new_events.extend(parsed)
                parse_errors += errors
        for value in config.get("falco_logs", []):
            lines = _read_incremental(Path(value), state, int(config["initial_scan_bytes"]))
            parsed, errors = _parse_falco_lines(lines)
            new_events.extend(parsed)
            parse_errors += errors
        with GeoIPEnricher(config) as enricher:
            for value in config.get("subscription_logs", []):
                lines = _read_incremental(Path(value), state, int(config["initial_scan_bytes"]))
                parsed, errors = _parse_subscription_lines(lines, enricher)
                new_events.extend(parsed)
                parse_errors += errors
            for value in config.get("miaomiaowux_logs", []):
                lines = _read_incremental(Path(value), state, int(config["initial_scan_bytes"]))
                parsed, errors = _parse_miaomiaowux_lines(
                    lines, str(config["miaomiaowux_timezone"]), enricher
                )
                new_events.extend(parsed)
                parse_errors += errors

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=float(config["retention_days"]))
        events = _merge_events(_load_retained(events_path, cutoff), new_events)
        _write_events(events_path, events)
        analyzed_events = _filter_monitored_events(read_events([str(events_path)]), config)
        report = analyze(analyzed_events, config["rules"])
        report["runtime"] = {
            "generated_at": now.isoformat().replace("+00:00", "Z"),
            "new_event_count": len(new_events),
            "parse_error_count": parse_errors,
            "retention_days": config["retention_days"],
            "subscription_monitoring": {
                "enabled": bool(config["subscription_monitoring"].get("enabled")),
                "mode": config["subscription_monitoring"].get("mode"),
                "configured_user_count": len(config["subscription_monitoring"].get("users", [])),
            },
        }
        candidates = _notification_candidates(report, state, config, now)
        ai_result = None
        ai_error = None
        if candidates and config["openai_review"].get("enabled"):
            try:
                model = str(config["openai_review"].get("model", ""))
                if not model:
                    raise ValueError("openai_review.model is required when AI review is enabled")
                api_key = _read_secret(str(config["openai_review"]["api_key_file"]), "OpenAI API key")
                evidence_report = dict(report)
                evidence_report["findings"] = candidates
                ai_result = review_with_openai(evidence_report, model, api_key)
                report["ai_review"] = ai_result
            except (OSError, ValueError, RuntimeError) as exc:
                ai_error = str(exc)
                report["runtime"]["ai_error"] = ai_error

        _atomic_json(report_dir / "latest.json", report)
        _atomic_text(report_dir / "latest.md", render_markdown(report, ai_result))
        state["last_run"] = report["runtime"]
        state["last_summary"] = report["summary"]
        state.pop("last_error", None)
        _atomic_json(state_path, state)

        delivery_error = None
        if candidates and config["telegram"].get("enabled"):
            try:
                token = _read_secret(str(config["telegram"]["token_file"]), "Telegram token")
                message = build_alert_message(
                    report,
                    candidates,
                    bool(config["telegram"].get("include_source_ip")),
                    ai_result,
                    int(config["telegram"].get("max_findings", 8)),
                )
                send_message(token, str(config["telegram"]["chat_id"]), message)
            except (OSError, ValueError, RuntimeError) as exc:
                delivery_error = str(exc)
        if candidates and (not config["telegram"].get("enabled") or not delivery_error):
            for finding in candidates:
                state["notifications"][finding["notification_key"]] = now.isoformat().replace("+00:00", "Z")
        if delivery_error:
            state["last_error"] = delivery_error
        elif ai_error:
            state["last_error"] = ai_error
        _atomic_json(state_path, state)
        if delivery_error:
            raise RuntimeError(delivery_error)
        return report


def health(config_path: str) -> Dict[str, Any]:
    config = load_runtime_config(config_path)
    state = _load_state(Path(config["state_dir"]) / "state.json")
    status = "never_run"
    if state.get("last_error"):
        status = "degraded"
    elif state.get("last_run", {}).get("generated_at"):
        generated = parse_timestamp(state["last_run"]["generated_at"])
        stale_after = timedelta(minutes=max(15, int(config["scan_interval_minutes"]) * 3))
        status = "healthy" if datetime.now(timezone.utc) - generated <= stale_after else "stale"
    return {
        "status": status,
        "config": config_path,
        "state_dir": config["state_dir"],
        "telegram_enabled": bool(config["telegram"].get("enabled")),
        "telegram_management_enabled": bool(config["telegram"].get("bot_management_enabled")),
        "subscription_monitoring": config["subscription_monitoring"],
        "openai_review_enabled": bool(config["openai_review"].get("enabled")),
        "last_run": state.get("last_run"),
        "last_summary": state.get("last_summary"),
        "last_error": state.get("last_error"),
    }


def test_telegram(config_path: str) -> None:
    config = load_runtime_config(config_path)
    telegram = config["telegram"]
    if not telegram.get("enabled"):
        raise ValueError("Telegram is disabled in the runtime config")
    token = _read_secret(str(telegram["token_file"]), "Telegram token")
    send_message(token, str(telegram["chat_id"]), f"VPS Audit 测试成功 | {os.uname().nodename}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vps-audit-runner", description="Scheduled VPS audit collector and notifier")
    parser.add_argument("--config", default="/etc/vps-audit/config.json")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("run", help="run one collection and audit cycle")
    subparsers.add_parser("health", help="show last cycle status")
    subparsers.add_parser("test-telegram", help="send a Telegram test message")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "run":
            report = run_cycle(args.config)
            print(json.dumps({"ok": True, "summary": report["summary"], "runtime": report["runtime"]}, ensure_ascii=False))
        elif args.command == "health":
            print(json.dumps(health(args.config), ensure_ascii=False, indent=2))
        else:
            test_telegram(args.config)
            print("Telegram test message sent.")
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"vps-audit-runner: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
