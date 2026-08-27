from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from datetime import timedelta
from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple

from .models import Event, Finding


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _haversine_km(first: Dict[str, Any], second: Dict[str, Any]) -> float | None:
    try:
        lat1, lon1 = math.radians(float(first["lat"])), math.radians(float(first["lon"]))
        lat2, lon2 = math.radians(float(second["lat"])), math.radians(float(second["lon"]))
    except (KeyError, TypeError, ValueError):
        return None
    delta_lat, delta_lon = lat2 - lat1, lon2 - lon1
    value = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    return 6371.0 * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))


def _event_evidence(event: Event, fields: Sequence[str]) -> Dict[str, Any]:
    evidence: Dict[str, Any] = {"timestamp": event.iso_timestamp(), "source_line": event.line_number}
    for field in fields:
        if field in event.data:
            evidence[field] = event.data[field]
    return evidence


def _max_unique_window(
    events: Sequence[Event], minutes: int, key: Callable[[Event], Any]
) -> Tuple[List[Event], set[Any]]:
    best_events: List[Event] = []
    best_values: set[Any] = set()
    values = [key(event) for event in events]
    counts: Dict[Any, int] = defaultdict(int)
    left = 0
    for right, current in enumerate(events):
        current_value = values[right]
        if current_value not in (None, ""):
            counts[current_value] += 1
        while current.timestamp - events[left].timestamp > timedelta(minutes=minutes):
            old_value = values[left]
            if old_value not in (None, ""):
                counts[old_value] -= 1
                if counts[old_value] == 0:
                    del counts[old_value]
            left += 1
        if len(counts) > len(best_values):
            best_events = list(events[left : right + 1])
            best_values = set(counts)
    return best_events, best_values


def _max_count_window(events: Sequence[Event], minutes: int) -> List[Event]:
    best_left = 0
    best_right = -1
    left = 0
    for right, current in enumerate(events):
        while current.timestamp - events[left].timestamp > timedelta(minutes=minutes):
            left += 1
        if right - left > best_right - best_left:
            best_left, best_right = left, right
    return list(events[best_left : best_right + 1])


def _login_findings(user: str, events: Sequence[Event], config: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    thresholds = config["thresholds"]
    trusted = config.get("trusted", {})
    trusted_ips = set(trusted.get("ips", []))
    trusted_asns = {str(value) for value in trusted.get("asns", [])}
    successes = [event for event in events if event.event_type == "login_success"]
    failures = [event for event in events if event.event_type == "login_failure"]

    filtered_successes = [event for event in successes if event.data.get("source_ip") not in trusted_ips]
    ip_window, ips = _max_unique_window(
        filtered_successes,
        int(thresholds["multi_ip_window_minutes"]),
        lambda event: event.data.get("source_ip"),
    )
    if len(ips) >= int(thresholds["multi_ip_count"]):
        findings.append(Finding(
            "AUTH_MULTI_IP", user, "medium", 35, "短时多来源 IP 登录",
            f"{thresholds['multi_ip_window_minutes']} 分钟窗口内出现 {len(ips)} 个来源 IP。",
            [_event_evidence(event, ("source_ip", "city", "region", "country", "asn", "network_type")) for event in ip_window],
        ))

    asn_window, asns = _max_unique_window(
        [event for event in filtered_successes if str(event.data.get("asn", "")) not in trusted_asns],
        int(thresholds["multi_ip_window_minutes"]),
        lambda event: str(event.data.get("asn", "")),
    )
    if len(asns) >= int(thresholds["multi_asn_count"]):
        findings.append(Finding(
            "AUTH_ASN_CHURN", user, "high", 50, "短时跨多个网络运营商登录",
            f"同一窗口内来源跨 {len(asns)} 个 ASN，单纯多设备通常不能解释该变化。",
            [_event_evidence(event, ("source_ip", "asn", "isp", "city", "country")) for event in asn_window],
        ))

    for previous, current in zip(successes, successes[1:]):
        first_geo = previous.data.get("geo") or previous.data
        second_geo = current.data.get("geo") or current.data
        distance = _haversine_km(first_geo, second_geo)
        hours = (current.timestamp - previous.timestamp).total_seconds() / 3600
        if distance is None or hours <= 0:
            continue
        speed = distance / hours
        if distance >= float(thresholds["impossible_travel_min_km"]) and speed >= float(thresholds["impossible_travel_kmh"]):
            findings.append(Finding(
                "AUTH_IMPOSSIBLE_TRAVEL", user, "high", 60, "不可能旅行",
                f"两次登录相距约 {distance:.0f} km，间隔 {hours:.2f} 小时，推算速度 {speed:.0f} km/h。",
                [
                    _event_evidence(previous, ("source_ip", "city", "region", "country", "asn", "lat", "lon")),
                    _event_evidence(current, ("source_ip", "city", "region", "country", "asn", "lat", "lon")),
                ],
            ))

    by_ip: Dict[str, List[Event]] = defaultdict(list)
    for event in failures:
        by_ip[str(event.data.get("source_ip", "unknown"))].append(event)
    for source_ip, ip_events in by_ip.items():
        burst = _max_count_window(ip_events, int(thresholds["failed_login_window_minutes"]))
        if len(burst) >= int(thresholds["failed_login_count"]):
            findings.append(Finding(
                "AUTH_FAILURE_BURST", user, "medium", 30, "登录失败突增",
                f"来源 {source_ip} 在 {thresholds['failed_login_window_minutes']} 分钟内失败 {len(burst)} 次。",
                [_event_evidence(burst[0], ("source_ip", "method")), _event_evidence(burst[-1], ("source_ip", "method"))],
            ))

    risky = [event for event in successes if str(event.data.get("network_type", "")).lower() in {"hosting", "datacenter", "vpn", "tor"}]
    if risky:
        types = sorted({str(event.data.get("network_type")).lower() for event in risky})
        findings.append(Finding(
            "AUTH_ANON_OR_HOSTING", user, "low", 15, "代理或机房网络来源",
            f"成功登录来源包含 {', '.join(types)}；该信号可由合法 VPN 或云主机产生，不能单独定性。",
            [_event_evidence(event, ("source_ip", "network_type", "asn", "isp")) for event in risky[:10]],
        ))
    return findings


def _behavior_findings(user: str, events: Sequence[Event], config: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    thresholds = config["thresholds"]
    process_events = [event for event in events if event.event_type == "process_start"]
    network_events = [event for event in events if event.event_type == "network_connection"]

    indicator_hits: List[Tuple[Event, List[str]]] = []
    for event in process_events:
        haystack = " ".join(str(event.data.get(field, "")) for field in ("executable", "command", "parent_executable")).lower()
        categories = [
            category
            for category, needles in config.get("automation_indicators", {}).items()
            if any(str(needle).lower() in haystack for needle in needles)
        ]
        if categories:
            indicator_hits.append((event, categories))
    categories = {category for _, matched in indicator_hits for category in matched}
    if len(categories) >= 2:
        findings.append(Finding(
            "PROC_AUTOMATION_STACK", user, "high", 55, "疑似批量账号自动化工具链",
            f"进程命令同时命中 {len(categories)} 类独立特征：{', '.join(sorted(categories))}。",
            [dict(_event_evidence(event, ("pid", "executable", "command", "parent_executable")), indicators=matched) for event, matched in indicator_hits[:10]],
        ))
    elif indicator_hits:
        findings.append(Finding(
            "PROC_AUTOMATION_HINT", user, "low", 15, "发现浏览器自动化特征",
            "仅命中一类自动化特征，可能是测试或运维任务，需结合网络行为复核。",
            [dict(_event_evidence(event, ("pid", "executable", "command")), indicators=matched) for event, matched in indicator_hits[:10]],
        ))

    by_fingerprint: Dict[str, List[Event]] = defaultdict(list)
    for event in process_events:
        command = str(event.data.get("command") or event.data.get("executable") or "")
        if command:
            fingerprint = hashlib.sha256(command.encode("utf-8")).hexdigest()[:12]
            by_fingerprint[fingerprint].append(event)
    for fingerprint, grouped in by_fingerprint.items():
        burst = _max_count_window(grouped, int(thresholds["repeat_process_window_minutes"]))
        if len(burst) >= int(thresholds["repeat_process_count"]):
            findings.append(Finding(
                "PROC_REPEAT_BURST", user, "medium", 30, "同一命令高频启动",
                f"命令指纹 {fingerprint} 在 {thresholds['repeat_process_window_minutes']} 分钟内启动 {len(burst)} 次。",
                [_event_evidence(burst[0], ("pid", "executable", "command")), _event_evidence(burst[-1], ("pid", "executable", "command"))],
            ))

    window, destinations = _max_unique_window(
        network_events,
        int(thresholds["network_burst_window_minutes"]),
        lambda event: event.data.get("destination_host") or event.data.get("destination_ip"),
    )
    if len(destinations) >= int(thresholds["network_burst_unique_destinations"]):
        findings.append(Finding(
            "NET_DESTINATION_BURST", user, "medium", 35, "短时连接大量不同目标",
            f"{thresholds['network_burst_window_minutes']} 分钟内连接 {len(destinations)} 个不同目标。",
            [_event_evidence(event, ("pid", "destination_host", "destination_ip", "destination_port")) for event in window[:20]],
        ))
    return findings


def _subscription_findings(user: str, events: Sequence[Event], config: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    thresholds = config["thresholds"]
    accesses = [event for event in events if event.event_type == "subscription_access"]
    if not accesses:
        return findings
    trusted_ips = set(config.get("trusted", {}).get("ips", []))
    accesses = [event for event in accesses if event.data.get("source_ip") not in trusted_ips]
    window_minutes = int(thresholds["subscription_window_minutes"])

    ip_window, ips = _max_unique_window(accesses, window_minutes, lambda event: event.data.get("source_ip"))
    if len(ips) >= int(thresholds["subscription_ip_count"]):
        findings.append(Finding(
            "SUB_ACTIVE_IPS", user, "high", 55, "同一订阅短时活跃 IP 过多",
            f"同一订阅在 {window_minutes} 分钟窗口内出现 {len(ips)} 个不同来源 IP；这是活跃窗口近似值，不等同于严格并发连接数。",
            [_event_evidence(event, ("source_ip", "region", "city", "country", "asn", "network_type", "device_id", "session_id")) for event in ip_window[:20]],
        ))

    dimensions = [
        ("region", "subscription_region_count", "SUB_MULTI_REGION", "跨省/地区访问", 45),
        ("city", "subscription_city_count", "SUB_MULTI_CITY", "跨城市访问", 35),
        ("asn", "subscription_asn_count", "SUB_MULTI_ASN", "跨多个网络运营商访问", 45),
    ]
    for field, threshold_key, rule_id, title, score in dimensions:
        dimension_window, values = _max_unique_window(
            accesses,
            window_minutes,
            lambda event, name=field: str(event.data.get(name, "")).strip(),
        )
        threshold = int(thresholds[threshold_key])
        if len(values) >= threshold:
            label = "省/地区" if field == "region" else "城市" if field == "city" else "ASN"
            findings.append(Finding(
                rule_id, user, "high" if score >= 45 else "medium", score, title,
                f"同一订阅在 {window_minutes} 分钟窗口内覆盖 {len(values)} 个不同{label}：{', '.join(sorted(values)[:10])}。",
                [_event_evidence(event, ("source_ip", "region", "city", "country", "asn", "network_type", "device_id", "session_id")) for event in dimension_window[:20]],
            ))
    device_window, devices = _max_unique_window(
        accesses,
        window_minutes,
        lambda event: str(event.data.get("device_id", "")).strip(),
    )
    if len(devices) >= int(thresholds["subscription_device_count"]):
        findings.append(Finding(
            "SUB_MULTI_DEVICE", user, "medium", 35, "同一订阅短时设备标识过多",
            f"同一订阅在 {window_minutes} 分钟窗口内出现 {len(devices)} 个不同设备标识；设备标识由上游日志提供，缺失时本规则不生效。",
            [_event_evidence(event, ("source_ip", "region", "city", "asn", "device_id", "session_id")) for event in device_window[:20]],
        ))
    for previous, current in zip(accesses, accesses[1:]):
        distance = _haversine_km(previous.data.get("geo") or previous.data, current.data.get("geo") or current.data)
        hours = (current.timestamp - previous.timestamp).total_seconds() / 3600
        if distance is None or hours <= 0:
            continue
        speed = distance / hours
        if distance >= float(thresholds["impossible_travel_min_km"]) and speed >= float(thresholds["impossible_travel_kmh"]):
            findings.append(Finding(
                "SUB_IMPOSSIBLE_TRAVEL", user, "high", 50, "订阅访问出现不可能旅行",
                f"连续访问相距约 {distance:.0f} km，间隔 {hours:.2f} 小时，推算速度 {speed:.0f} km/h。",
                [
                    _event_evidence(previous, ("source_ip", "region", "city", "country", "asn", "lat", "lon", "device_id")),
                    _event_evidence(current, ("source_ip", "region", "city", "country", "asn", "lat", "lon", "device_id")),
                ],
            ))
    return findings


def _subscription_coverage_warnings(events: Sequence[Event], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    accesses = [event for event in events if event.event_type == "subscription_access"]
    by_source: Dict[str, List[Event]] = defaultdict(list)
    for event in accesses:
        source_ip = str(event.data.get("source_ip", "")).strip()
        if source_ip:
            by_source[source_ip].append(event)
    warnings: List[Dict[str, Any]] = []
    window_minutes = int(config["thresholds"]["subscription_window_minutes"])
    threshold = int(config["thresholds"]["subscription_shared_source_user_count"])
    for source_ip, source_events in by_source.items():
        window, users = _max_unique_window(source_events, window_minutes, lambda event: event.user)
        if len(users) < threshold:
            continue
        warnings.append({
            "rule_id": "SUB_SHARED_FETCH_SOURCE",
            "user": "订阅可见性",
            "severity": "medium",
            "score": 0,
            "title": "同一来源短时拉取多个用户订阅",
            "summary": (
                f"来源 {source_ip} 在 {window_minutes} 分钟内拉取 {len(users)} 个不同订阅用户；"
                "这可能是 Sub-Store/监控器/NAT。源站此时可能只能看到聚合出口，不能据此还原终端 IP。"
            ),
            "evidence": [
                _event_evidence(event, ("source_ip", "user_agent", "device_id", "session_id"))
                for event in window[:20]
            ],
        })
    return warnings


def analyze(events: Iterable[Event], config: Dict[str, Any]) -> Dict[str, Any]:
    all_events = sorted(events, key=lambda event: event.timestamp)
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for event in all_events:
        grouped[event.user].append(event)
    trusted_users = set(config.get("trusted", {}).get("users", []))
    findings: List[Finding] = []
    for user, user_events in grouped.items():
        if user in trusted_users:
            continue
        findings.extend(_login_findings(user, user_events, config))
        findings.extend(_subscription_findings(user, user_events, config))
        findings.extend(_behavior_findings(user, user_events, config))
    coverage_warnings = _subscription_coverage_warnings(all_events, config)

    per_user: Dict[str, List[Finding]] = defaultdict(list)
    for finding in findings:
        per_user[finding.user].append(finding)
    users = []
    for user, user_findings in per_user.items():
        # Repeated hits preserve their evidence but do not masquerade as
        # independent signals when calculating the account risk score.
        score_by_rule: Dict[str, int] = {}
        for item in user_findings:
            score_by_rule[item.rule_id] = max(score_by_rule.get(item.rule_id, 0), item.score)
        score = min(100, sum(score_by_rule.values()))
        severity = "critical" if score >= 85 else "high" if score >= 60 else "medium" if score >= 30 else "low"
        users.append({
            "user": user,
            "risk_score": score,
            "severity": severity,
            "finding_count": len(user_findings),
            "recommended_action": "人工复核并临时限制会话" if score >= 60 else "持续观察并向用户验证" if score >= 30 else "记录观察",
        })
    users.sort(key=lambda item: item["risk_score"], reverse=True)
    findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.score), reverse=True)
    return {
        "summary": {
            "event_count": sum(len(items) for items in grouped.values()),
            "user_count": len(grouped),
            "flagged_user_count": len(users),
            "finding_count": len(findings),
        },
        "users": users,
        "findings": [finding.as_dict() for finding in findings],
        "coverage_warnings": coverage_warnings,
        "policy": {
            "automatic_enforcement": False,
            "note": "检测结果是调查线索，不是共享账号或滥用行为的最终证明。",
        },
    }
