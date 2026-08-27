from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

from .models import parse_timestamp


_DETAIL_FIELDS = ("country", "region", "city", "asn", "isp", "network_type")


def query_active_subscription_ips(
    config: Dict[str, Any], user: str, now: datetime | None = None
) -> Dict[str, Any]:
    """Return unique subscription-fetch or proxy-activity IPs in the active window."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    window_minutes = int(config["rules"]["thresholds"]["subscription_window_minutes"])
    cutoff = current - timedelta(minutes=window_minutes)
    future_limit = current + timedelta(minutes=5)
    path = Path(config["state_dir"]) / "events.jsonl"
    by_ip: Dict[str, Dict[str, Any]] = {}
    parse_error_count = 0
    try:
        handle = path.open("r", encoding="utf-8")
    except OSError:
        handle = None
    if handle is not None:
        with handle:
            for line in handle:
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("event must be an object")
                    event_type = str(event.get("event_type", ""))
                    if event_type not in {"subscription_access", "proxy_activity"} or str(event.get("user", "")) != user:
                        continue
                    timestamp = parse_timestamp(str(event["timestamp"]))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    parse_error_count += 1
                    continue
                if timestamp < cutoff or timestamp > future_limit:
                    continue
                source_ip = str(event.get("source_ip", "")).strip()
                if not source_ip:
                    continue
                try:
                    ipaddress.ip_address(source_ip)
                except ValueError:
                    parse_error_count += 1
                    continue
                existing = by_ip.get(source_ip)
                if existing is None:
                    existing = {
                        "source_ip": source_ip,
                        "last_seen": timestamp,
                        "access_count": 0,
                        "devices": set(),
                        "evidence_types": set(),
                        "nodes": set(),
                    }
                    by_ip[source_ip] = existing
                existing["access_count"] += 1
                existing["evidence_types"].add(event_type)
                node_name = str(event.get("node_name") or event.get("node_id") or "").strip()
                if node_name:
                    existing["nodes"].add(node_name)
                device_id = str(event.get("device_id", "")).strip()
                if device_id:
                    existing["devices"].add(device_id)
                if timestamp >= existing["last_seen"]:
                    existing["last_seen"] = timestamp
                    for field in _DETAIL_FIELDS:
                        value = event.get(field)
                        if value not in (None, ""):
                            existing[field] = value
                else:
                    for field in _DETAIL_FIELDS:
                        value = event.get(field)
                        if field not in existing and value not in (None, ""):
                            existing[field] = value

    items = []
    for item in by_ip.values():
        item = dict(item)
        item["last_seen"] = item["last_seen"].isoformat().replace("+00:00", "Z")
        item["device_count"] = len(item.pop("devices"))
        item["evidence_types"] = sorted(item["evidence_types"])
        item["nodes"] = sorted(item["nodes"])
        items.append(item)
    items.sort(key=lambda item: item["last_seen"], reverse=True)
    return {
        "user": user,
        "window_minutes": window_minutes,
        "generated_at": current.isoformat().replace("+00:00", "Z"),
        "ip_count": len(items),
        "ips": items,
        "parse_error_count": parse_error_count,
        "includes_proxy_activity": any(
            "proxy_activity" in item.get("evidence_types", []) for item in items
        ),
    }


def mask_ip(value: str) -> str:
    if "." in value:
        parts = value.split(".")
        if len(parts) == 4:
            return ".".join(parts[:2] + ["*", "*"])
    if ":" in value:
        return ":".join(value.split(":")[:2]) + ":..."
    return "[已脱敏]"


def render_active_ip_query(
    result: Dict[str, Any], include_source_ip: bool, max_items: int = 30
) -> str:
    lines = [
        f"用户：{result['user']}",
        f"最近 {result['window_minutes']} 分钟活跃 IP：{result['ip_count']} 个",
        (
            "说明：包含节点实际连接与订阅拉取的活跃证据，不是严格并发连接数。"
            if result.get("includes_proxy_activity")
            else "说明：这是订阅访问活跃窗口，不是严格 TCP/节点同时在线数。"
        ),
    ]
    ips = list(result.get("ips", []))
    if not ips:
        lines.extend(["", "窗口内未发现该用户的订阅访问 IP。"])
        return "\n".join(lines)
    lines.append("")
    for index, item in enumerate(ips[:max_items], 1):
        source_ip = str(item["source_ip"])
        shown_ip = source_ip if include_source_ip else mask_ip(source_ip)
        location = "/".join(
            _safe_text(item[field]) for field in ("country", "region", "city") if item.get(field)
        ) or "位置未知"
        network = []
        if item.get("asn"):
            network.append(f"ASN {item['asn']}")
        if item.get("isp"):
            network.append(_safe_text(item["isp"]))
        if item.get("network_type"):
            network.append(_safe_text(item["network_type"]))
        lines.append(f"{index}. {shown_ip} | {location}")
        if network:
            lines.append("   " + " | ".join(network))
        detail = f"最近：{item['last_seen']} | 访问记录：{item['access_count']}"
        if item.get("device_count"):
            detail += f" | 设备标识：{item['device_count']}"
        if item.get("nodes"):
            detail += " | 节点：" + ", ".join(_safe_text(value, 40) for value in item["nodes"][:3])
        lines.append("   " + detail)
    if len(ips) > max_items:
        lines.append(f"……另有 {len(ips) - max_items} 个 IP，请缩短窗口或在 VPS 本机查看。")
    if not include_source_ip:
        lines.extend(["", "Telegram 当前按配置隐藏完整 IP；可在推送参数中切换。"])
    return "\n".join(lines)


def _safe_text(value: Any, limit: int = 80) -> str:
    rendered = "".join(char if 32 <= ord(char) < 127 or ord(char) >= 160 else "?" for char in str(value))
    return rendered if len(rendered) <= limit else rendered[: limit - 3] + "..."
