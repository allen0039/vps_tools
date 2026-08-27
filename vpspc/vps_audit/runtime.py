from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlsplit

from .ai_review import review_with_provider, test_ai_provider as run_ai_provider_test
from .analyzer import SEVERITY_ORDER, analyze
from .behavior_audit import (
    load_incident,
    maintain_archive,
    read_recent_connections,
    save_incident_ai_review,
    save_incidents,
)
from .config import DEFAULT_CONFIG
from .falco_parser import parse_falco_event
from .geoip import GeoIPEnricher
from .models import Event, parse_timestamp
from .miaomiaowux_parser import parse_miaomiaowux_line
from .report import render_markdown
from .ssh_parser import parse_auth_log, parse_sshd_message
from .telegram import build_alert_message, send_message


DEFAULT_RUNTIME_CONFIG: Dict[str, Any] = {
    "web": {
        "enabled": False,
        "listen_host": "127.0.0.1",
        "listen_port": 8787,
        "token_file": "/etc/vps-audit/web.token",
    },
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
    "node_reporting": {
        "mode": "controller_only",
        "listen_host": "127.0.0.1",
        "listen_port": 8766,
        "public_base_url": "",
        "registry_file": "",
        "inbox_file": "",
        "agent_asset_path": "/opt/vps-audit/manager/deploy/node/vpspc-node.py",
        "enrollment_ttl_minutes": 15,
        "replay_window_seconds": 300,
        "max_batch_events": 500,
    },
    "behavior_audit": {
        "enabled": False,
        "archive_dir": "/var/lib/vps-audit/behavior-audit",
        "retention_days": 7,
        "incident_retention_days": 30,
        "max_disk_mb": 20480,
        "max_analysis_events": 100000,
        "ai_include_full_metadata": True,
    },
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
        "active_provider": "",
        "providers": {},
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


def _normalize_ai_review(config: Dict[str, Any], raw: Dict[str, Any]) -> None:
    raw_ai = raw.get("openai_review", {})
    if not isinstance(raw_ai, dict):
        raise ValueError("openai_review must be an object")
    ai = config.get("openai_review")
    if not isinstance(ai, dict):
        raise ValueError("openai_review must be an object")
    if not isinstance(ai.get("enabled"), bool):
        raise ValueError("openai_review.enabled must be boolean")
    providers = ai.get("providers", {})
    if not isinstance(providers, dict):
        raise ValueError("openai_review.providers must be an object")
    legacy_model = str(raw_ai.get("model", "")).strip()
    if not providers and legacy_model:
        providers = {
            "legacy": {
                "display_name": "Legacy OpenAI",
                "base_url": str(raw_ai.get("base_url", "https://api.openai.com/v1")),
                "api_mode": str(raw_ai.get("api_mode", "responses")),
                "api_key_file": str(raw_ai.get("api_key_file", "/etc/vps-audit/openai.key")),
                "model": legacy_model,
                "timeout_seconds": int(raw_ai.get("timeout_seconds", 60)),
            }
        }
    if len(providers) > 16:
        raise ValueError("openai_review.providers supports at most 16 providers")
    normalized: Dict[str, Dict[str, Any]] = {}
    for raw_id, raw_provider in providers.items():
        provider_id = str(raw_id).strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,31}", provider_id):
            raise ValueError("AI provider ID must use 1-32 lowercase letters, numbers, dots, underscores or hyphens")
        if not isinstance(raw_provider, dict):
            raise ValueError(f"AI provider {provider_id} must be an object")
        display_name = str(raw_provider.get("display_name", provider_id)).strip()
        if not display_name or len(display_name) > 64 or any(ord(char) < 32 for char in display_name):
            raise ValueError(f"AI provider {provider_id} display_name must contain 1-64 printable characters")
        base_url = str(raw_provider.get("base_url", "")).strip().rstrip("/")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or len(base_url) > 512
            or any(ord(char) < 32 or ord(char) == 127 for char in base_url)
        ):
            raise ValueError(f"AI provider {provider_id} base_url must be a plain HTTP(S) base URL")
        api_mode = str(raw_provider.get("api_mode", "chat_completions"))
        if api_mode not in {"responses", "chat_completions"}:
            raise ValueError(f"AI provider {provider_id} api_mode must be responses or chat_completions")
        model = str(raw_provider.get("model", "")).strip()
        if not model or len(model) > 128 or any(ord(char) < 32 for char in model):
            raise ValueError(f"AI provider {provider_id} model must contain 1-128 printable characters")
        api_key_file = str(raw_provider.get("api_key_file", "")).strip()
        if not api_key_file or not Path(api_key_file).is_absolute() or len(api_key_file) > 512:
            raise ValueError(f"AI provider {provider_id} api_key_file must be an absolute path")
        try:
            timeout_seconds = int(raw_provider.get("timeout_seconds", 30))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"AI provider {provider_id} timeout_seconds must be an integer") from exc
        if not 5 <= timeout_seconds <= 120:
            raise ValueError(f"AI provider {provider_id} timeout_seconds must be between 5 and 120")
        normalized[provider_id] = {
            "display_name": display_name,
            "base_url": base_url,
            "api_mode": api_mode,
            "api_key_file": api_key_file,
            "model": model,
            "timeout_seconds": timeout_seconds,
        }
    active = str(ai.get("active_provider", "")).strip()
    if not active and len(normalized) == 1:
        active = next(iter(normalized))
    if active and active not in normalized:
        raise ValueError("openai_review.active_provider does not exist in providers")
    if ai["enabled"] and not active:
        raise ValueError("AI review requires an active provider")
    config["openai_review"] = {
        "enabled": ai["enabled"],
        "active_provider": active,
        "providers": normalized,
    }


def normalize_runtime_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("runtime config root must be a JSON object")
    config = _merge(DEFAULT_RUNTIME_CONFIG, raw)
    _normalize_ai_review(config, raw)
    node_reporting = config.get("node_reporting")
    if not isinstance(node_reporting, dict):
        raise ValueError("node_reporting must be an object")
    if node_reporting.get("mode") not in {"controller_only", "node_reporting"}:
        raise ValueError("node_reporting.mode must be controller_only or node_reporting")
    listen_host = str(node_reporting.get("listen_host", "")).strip()
    if not listen_host or len(listen_host) > 255 or any(ord(char) < 32 for char in listen_host):
        raise ValueError("node_reporting.listen_host is invalid")
    node_reporting["listen_host"] = listen_host
    for key in ("registry_file", "inbox_file"):
        value = str(node_reporting.get(key, "")).strip()
        if value and (not Path(value).is_absolute() or len(value) > 512):
            raise ValueError(f"node_reporting.{key} must be empty or an absolute path")
        node_reporting[key] = value
    asset_path = str(node_reporting.get("agent_asset_path", "")).strip()
    if not asset_path or not Path(asset_path).is_absolute() or len(asset_path) > 512:
        raise ValueError("node_reporting.agent_asset_path must be an absolute path")
    node_reporting["agent_asset_path"] = asset_path
    public_base_url = str(node_reporting.get("public_base_url", "")).strip().rstrip("/")
    if public_base_url:
        public = urlsplit(public_base_url)
        if (
            public.scheme not in {"http", "https"}
            or not public.hostname
            or public.username
            or public.password
            or public.query
            or public.fragment
            or len(public_base_url) > 512
        ):
            raise ValueError("node_reporting.public_base_url must be a plain HTTP(S) base URL")
        if public.scheme != "https" and public.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("remote node reporting requires an HTTPS public_base_url")
    if node_reporting["mode"] == "node_reporting" and not public_base_url:
        raise ValueError("node reporting mode requires node_reporting.public_base_url")
    node_reporting["public_base_url"] = public_base_url
    behavior_audit = config.get("behavior_audit")
    if not isinstance(behavior_audit, dict):
        raise ValueError("behavior_audit must be an object")
    if not isinstance(behavior_audit.get("enabled"), bool):
        raise ValueError("behavior_audit.enabled must be boolean")
    archive_dir = str(behavior_audit.get("archive_dir", "")).strip()
    if not archive_dir or not Path(archive_dir).is_absolute() or len(archive_dir) > 512:
        raise ValueError("behavior_audit.archive_dir must be an absolute path")
    behavior_audit["archive_dir"] = archive_dir
    if not isinstance(behavior_audit.get("ai_include_full_metadata"), bool):
        raise ValueError("behavior_audit.ai_include_full_metadata must be boolean")
    web = config.get("web")
    if not isinstance(web, dict):
        raise ValueError("web must be an object")
    if not isinstance(web.get("enabled"), bool):
        raise ValueError("web.enabled must be boolean")
    web_host = str(web.get("listen_host", "")).strip()
    if not web_host or len(web_host) > 255 or any(ord(char) < 32 for char in web_host):
        raise ValueError("web.listen_host is invalid")
    token_file = str(web.get("token_file", "")).strip()
    if not token_file or not Path(token_file).is_absolute() or len(token_file) > 512:
        raise ValueError("web.token_file must be an absolute path")
    web["listen_host"] = web_host
    web["token_file"] = token_file
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
        "node_reporting.listen_port": (1.0, 65535.0),
        "web.listen_port": (1.0, 65535.0),
        "node_reporting.enrollment_ttl_minutes": (1.0, 1440.0),
        "node_reporting.replay_window_seconds": (30.0, 3600.0),
        "node_reporting.max_batch_events": (1.0, 5000.0),
        "behavior_audit.retention_days": (1.0, 365.0),
        "behavior_audit.incident_retention_days": (1.0, 3650.0),
        "behavior_audit.max_disk_mb": (100.0, 1048576.0),
        "behavior_audit.max_analysis_events": (1000.0, 1000000.0),
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


def _parse_proxy_activity_lines(
    lines: Iterable[str], enricher: GeoIPEnricher
) -> Tuple[List[Dict[str, Any]], int]:
    events: List[Dict[str, Any]] = []
    errors = 0
    for line in lines:
        try:
            raw = json.loads(line)
            if not isinstance(raw, dict) or raw.get("event_type") not in {
                "proxy_activity",
                "proxy_connection",
            }:
                raise ValueError("remote node event must be proxy_activity or proxy_connection")
            for key in ("timestamp", "user", "source_ip", "node_id", "event_id"):
                if not raw.get(key):
                    raise ValueError(f"remote node event requires {key}")
            parse_timestamp(str(raw["timestamp"]))
            event = dict(raw)
            event["timestamp"] = str(raw["timestamp"])
            event["user"] = str(raw["user"])
            event["source_ip"] = str(raw["source_ip"])
            geo = enricher.enrich(event["source_ip"])
            for key, value in geo.items():
                event.setdefault(key, value)
            events.append(event)
        except (json.JSONDecodeError, ValueError, TypeError, OSError):
            errors += 1
    return events, errors


def _connection_activity_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    latest: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    for event in events:
        if event.get("event_type") != "proxy_connection":
            continue
        key = (
            str(event.get("user", "")),
            str(event.get("node_id", "")),
            str(event.get("source_ip", "")),
            str(event.get("protocol", "")),
        )
        previous = latest.get(key)
        if previous and str(previous.get("timestamp", "")) >= str(event.get("timestamp", "")):
            continue
        activity = {
            key_name: value
            for key_name, value in event.items()
            if key_name
            in {
                "timestamp",
                "user",
                "source_ip",
                "protocol",
                "node_id",
                "node_name",
                "source",
                "country",
                "region",
                "city",
                "asn",
                "isp",
                "network_type",
                "lat",
                "lon",
            }
        }
        activity["event_type"] = "proxy_activity"
        activity["event_id"] = "activity_" + hashlib.sha256(
            "\0".join(key).encode("utf-8")
        ).hexdigest()[:32]
        latest[key] = activity
    return list(latest.values())


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


def _load_retained(path: Path, cutoff: datetime) -> Tuple[List[Dict[str, Any]], bool]:
    if not path.exists():
        return [], False
    result: List[Dict[str, Any]] = []
    needs_rewrite = False
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                raw = json.loads(line)
                if isinstance(raw, dict) and parse_timestamp(str(raw["timestamp"])) >= cutoff:
                    result.append(raw)
                else:
                    needs_rewrite = True
            except (json.JSONDecodeError, KeyError, ValueError):
                needs_rewrite = True
    return result, needs_rewrite


def _merge_events(existing: Iterable[Dict[str, Any]], new: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique: Dict[str, Dict[str, Any]] = {}
    for source in (existing, new):
        for event in source:
            key = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            unique[key] = event
    return sorted(unique.values(), key=lambda item: parse_timestamp(str(item["timestamp"])))


def _filter_monitored_events(events: Iterable[Event], config: Dict[str, Any]) -> List[Event]:
    monitoring = config["subscription_monitoring"]
    if not monitoring.get("enabled"):
        return [
            event
            for event in events
            if event.event_type not in {"subscription_access", "proxy_activity", "proxy_connection"}
        ]
    if monitoring.get("mode") == "all":
        return list(events)
    allowed = set(monitoring.get("users", []))
    return [
        event
        for event in events
        if event.event_type not in {"subscription_access", "proxy_activity", "proxy_connection"} or event.user in allowed
    ]


def _claim_node_inbox(path: Path) -> Path | None:
    processing = path.with_name(path.name + ".processing")
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if processing.is_file():
            return processing
        try:
            if path.stat().st_size <= 0:
                return None
        except FileNotFoundError:
            return None
        os.replace(path, processing)
        path.touch(mode=0o600)
        os.chmod(path, 0o600)
        return processing


def _write_events(path: Path, events: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            for event in events:
                json.dump(event, handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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
        evidence = finding.get("evidence") or []
        node_id = next(
            (
                str(item.get("node_id"))
                for item in evidence
                if isinstance(item, dict) and item.get("node_id")
            ),
            "",
        )
        key = f"{finding['user']}|{finding['rule_id']}|{node_id}"
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


def _selected_ai_provider(config: Dict[str, Any], provider_id: str | None = None) -> Tuple[str, Dict[str, Any]]:
    ai = config["openai_review"]
    selected = provider_id or str(ai.get("active_provider", ""))
    providers = ai.get("providers", {})
    if not selected or selected not in providers:
        raise ValueError("未配置可用的 AI 供应商")
    return selected, providers[selected]


def test_configured_ai_provider(config_path: str, provider_id: str | None = None) -> Dict[str, Any]:
    config = load_runtime_config(config_path)
    selected, provider = _selected_ai_provider(config, provider_id)
    api_key = _read_secret(str(provider["api_key_file"]), f"AI provider {selected} API key")
    result = run_ai_provider_test(provider, api_key)
    result["provider_id"] = selected
    result["display_name"] = provider["display_name"]
    return result


def review_behavior_incident(
    config_path: str, incident_id: str, question: str = ""
) -> Dict[str, Any]:
    config = load_runtime_config(config_path)
    if not config["behavior_audit"]["enabled"]:
        raise ValueError("完整连接元数据审计未启用")
    if not config["behavior_audit"]["ai_include_full_metadata"]:
        raise ValueError("当前配置不允许将完整连接元数据发送给 AI")
    provider_id, provider = _selected_ai_provider(config)
    api_key = _read_secret(str(provider["api_key_file"]), f"AI provider {provider_id} API key")
    archive = Path(str(config["behavior_audit"]["archive_dir"]))
    incident = load_incident(archive, incident_id)
    user = str(incident.get("user", "unknown"))
    report = {
        "summary": {"event_count": len(incident.get("evidence", [])), "finding_count": 1},
        "users": [
            {
                "user": user,
                "risk_score": int(incident.get("score", 0)),
                "severity": incident.get("severity", "medium"),
                "finding_count": 1,
            }
        ],
        "findings": [incident],
        "policy": {
            "automatic_enforcement": False,
            "note": "管理员主动发起完整连接元数据审计；不包含 TLS 解密内容。",
        },
    }
    review = review_with_provider(report, provider, api_key, redact=False, question=question)
    save_incident_ai_review(archive, incident_id, review, question)
    review["provider_id"] = provider_id
    review["model"] = provider["model"]
    return review


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
        inbox_value = str(config["node_reporting"].get("inbox_file", "")).strip()
        inbox_path = Path(inbox_value) if inbox_value else state_dir / "node-inbox.jsonl"
        processing_inbox = _claim_node_inbox(inbox_path)
        now = datetime.now(timezone.utc)
        behavior_config = config["behavior_audit"]
        behavior_archive = Path(str(behavior_config["archive_dir"]))
        behavior_events: List[Dict[str, Any]] = []
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
            if processing_inbox:
                with processing_inbox.open(encoding="utf-8") as handle:
                    parsed, errors = _parse_proxy_activity_lines(handle, enricher)
                new_events.extend(parsed)
                parse_errors += errors

            if behavior_config["enabled"]:
                behavior_cutoff = now - timedelta(
                    minutes=int(config["rules"]["thresholds"]["node_window_minutes"])
                )
                archived = read_recent_connections(
                    behavior_archive,
                    behavior_cutoff,
                    now,
                    int(behavior_config["max_analysis_events"]),
                )
                raw_connections = [
                    *archived,
                    *(event for event in new_events if event.get("event_type") == "proxy_connection"),
                ]
                unique_connections: Dict[str, Dict[str, Any]] = {}
                for event in raw_connections:
                    event_id = str(event.get("event_id", ""))
                    if not event_id:
                        continue
                    enriched = dict(event)
                    for key, value in enricher.enrich(str(event.get("source_ip", ""))).items():
                        enriched.setdefault(key, value)
                    unique_connections[event_id] = enriched
                behavior_events = sorted(
                    unique_connections.values(), key=lambda item: str(item.get("timestamp", ""))
                )

        cutoff = now - timedelta(days=float(config["retention_days"]))
        retained_events, needs_rewrite = _load_retained(events_path, cutoff)
        persistent_new_events = [
            event for event in new_events if event.get("event_type") != "proxy_connection"
        ]
        persistent_new_events.extend(_connection_activity_events(behavior_events))
        events = _merge_events(retained_events, persistent_new_events)
        if not events_path.exists() or needs_rewrite or events != retained_events:
            _write_events(events_path, events)
        event_models = [Event.from_dict(event, index) for index, event in enumerate(events, 1)]
        event_models.extend(
            Event.from_dict(event, len(event_models) + index)
            for index, event in enumerate(behavior_events, 1)
        )
        analyzed_events = _filter_monitored_events(event_models, config)
        report = analyze(analyzed_events, config["rules"])
        generated_at = now.isoformat().replace("+00:00", "Z")
        if behavior_config["enabled"]:
            save_incidents(behavior_archive, report["findings"], generated_at)
            archive_status = maintain_archive(
                behavior_archive,
                int(behavior_config["retention_days"]),
                int(behavior_config["incident_retention_days"]),
                int(behavior_config["max_disk_mb"]),
                now,
            )
        else:
            archive_status = {
                "removed_files": 0,
                "removed_incidents": 0,
                "compressed_files": 0,
                "archive_bytes": 0,
            }
        report["runtime"] = {
            "generated_at": generated_at,
            "new_event_count": len(new_events),
            "parse_error_count": parse_errors,
            "retention_days": config["retention_days"],
            "subscription_monitoring": {
                "enabled": bool(config["subscription_monitoring"].get("enabled")),
                "mode": config["subscription_monitoring"].get("mode"),
                "configured_user_count": len(config["subscription_monitoring"].get("users", [])),
            },
            "node_reporting": {
                "mode": config["node_reporting"]["mode"],
                "received_event_count": sum(
                    1
                    for event in new_events
                    if event.get("event_type") in {"proxy_activity", "proxy_connection"}
                ),
            },
            "behavior_audit": {
                "enabled": bool(behavior_config["enabled"]),
                "analyzed_connection_count": len(behavior_events),
                **archive_status,
            },
        }
        candidates = _notification_candidates(report, state, config, now)
        coverage_candidates = _notification_candidates(
            {"findings": report.get("coverage_warnings", []), "users": []},
            state,
            config,
            now,
        )
        delivery_candidates = candidates + coverage_candidates
        ai_result = None
        ai_error = None
        if candidates and config["openai_review"].get("enabled"):
            try:
                provider_id, provider = _selected_ai_provider(config)
                api_key = _read_secret(str(provider["api_key_file"]), f"AI provider {provider_id} API key")
                evidence_report = dict(report)
                evidence_report["findings"] = candidates
                ai_result = review_with_provider(evidence_report, provider, api_key)
                report["ai_review"] = ai_result
                report["runtime"]["ai_provider"] = provider_id
                report["runtime"]["ai_model"] = provider["model"]
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
        if delivery_candidates and config["telegram"].get("enabled"):
            try:
                token = _read_secret(str(config["telegram"]["token_file"]), "Telegram token")
                message = build_alert_message(
                    report,
                    delivery_candidates,
                    bool(config["telegram"].get("include_source_ip")),
                    ai_result,
                    int(config["telegram"].get("max_findings", 8)),
                )
                send_message(token, str(config["telegram"]["chat_id"]), message)
            except (OSError, ValueError, RuntimeError) as exc:
                delivery_error = str(exc)
        if delivery_candidates and (not config["telegram"].get("enabled") or not delivery_error):
            for finding in delivery_candidates:
                state["notifications"][finding["notification_key"]] = now.isoformat().replace("+00:00", "Z")
        if delivery_error:
            state["last_error"] = delivery_error
        elif ai_error:
            state["last_error"] = ai_error
        _atomic_json(state_path, state)
        if delivery_error:
            raise RuntimeError(delivery_error)
        if processing_inbox:
            try:
                processing_inbox.unlink()
            except FileNotFoundError:
                pass
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
        "node_reporting": {
            "mode": config["node_reporting"]["mode"],
            "public_base_url": config["node_reporting"].get("public_base_url", ""),
        },
        "web": {
            "enabled": bool(config["web"].get("enabled")),
            "listen_host": config["web"].get("listen_host"),
            "listen_port": int(config["web"].get("listen_port", 8787)),
        },
        "openai_review_enabled": bool(config["openai_review"].get("enabled")),
        "openai_active_provider": config["openai_review"].get("active_provider", ""),
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
    test_ai = subparsers.add_parser("test-ai", help="test an OpenAI-compatible AI provider")
    test_ai.add_argument("--provider", help="provider ID; defaults to active_provider")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "run":
            report = run_cycle(args.config)
            print(json.dumps({"ok": True, "summary": report["summary"], "runtime": report["runtime"]}, ensure_ascii=False))
        elif args.command == "health":
            print(json.dumps(health(args.config), ensure_ascii=False, indent=2))
        elif args.command == "test-telegram":
            test_telegram(args.config)
            print("Telegram test message sent.")
        else:
            print(json.dumps(test_configured_ai_provider(args.config, args.provider), ensure_ascii=False))
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"vps-audit-runner: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
