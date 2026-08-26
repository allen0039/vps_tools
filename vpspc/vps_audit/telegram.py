from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _mask_address(value: str) -> str:
    if "." in value:
        parts = value.split(".")
        if len(parts) == 4:
            return ".".join(parts[:2] + ["*", "*"])
    if ":" in value:
        return ":".join(value.split(":")[:2]) + ":..."
    return "[masked]"


def _evidence_line(evidence: Dict[str, Any], include_source_ip: bool) -> str:
    parts: List[str] = []
    if evidence.get("timestamp"):
        parts.append(str(evidence["timestamp"]))
    if evidence.get("source_ip"):
        source_ip = str(evidence["source_ip"])
        parts.append(source_ip if include_source_ip else _mask_address(source_ip))
    location = "/".join(str(evidence[key]) for key in ("country", "region", "city") if evidence.get(key))
    if location:
        parts.append(location)
    if evidence.get("asn"):
        parts.append(f"ASN {evidence['asn']}")
    if evidence.get("network_type"):
        parts.append(str(evidence["network_type"]))
    if evidence.get("executable"):
        parts.append(Path(str(evidence["executable"])).name)
    if evidence.get("indicators"):
        parts.append("特征=" + ",".join(str(item) for item in evidence["indicators"]))
    return " | ".join(parts)


def _safe_summary(finding: Dict[str, Any], include_source_ip: bool) -> str:
    summary = str(finding.get("summary", ""))
    if include_source_ip:
        return summary
    for evidence in finding.get("evidence", []):
        for key in ("source_ip", "destination_ip"):
            if evidence.get(key):
                raw = str(evidence[key])
                summary = summary.replace(raw, _mask_address(raw))
    return summary


def build_alert_message(
    report: Dict[str, Any],
    findings: Iterable[Dict[str, Any]],
    include_source_ip: bool = False,
    ai_review: Dict[str, Any] | None = None,
    max_findings: int = 8,
) -> str:
    all_findings = list(findings)
    selected = all_findings[:max_findings]
    affected = sorted({item["user"] for item in selected})
    user_scores = {item["user"]: item for item in report.get("users", [])}
    lines = [
        f"VPS 用户巡查告警 | {socket.gethostname()}",
        f"涉及账号：{', '.join(affected)}",
    ]
    for user in affected:
        risk = user_scores.get(user)
        if risk:
            lines.append(f"{user}: {risk['severity']} / {risk['risk_score']} 分")
    lines.append("")
    for finding in selected:
        lines.append(f"[{finding['severity'].upper()}] {finding['user']} - {finding['title']}")
        lines.append(_safe_summary(finding, include_source_ip))
        if finding.get("evidence"):
            evidence = _evidence_line(finding["evidence"][0], include_source_ip)
            if evidence:
                lines.append("证据：" + evidence)
        lines.append("")
    remaining = len(all_findings) - len(selected)
    if remaining > 0:
        lines.append(f"另有 {remaining} 条告警，请查看 VPS 本地报告。")
        lines.append("")
    if ai_review:
        lines.append("AI 复核：" + str(ai_review.get("overall_assessment", "未提供总体意见")))
        for case in ai_review.get("cases", [])[:3]:
            lines.append(f"{case.get('user')}: {case.get('assessment')} ({float(case.get('confidence', 0)):.0%})")
            lines.append("建议：" + str(case.get("recommended_action", "人工复核")))
    lines.append("处置原则：告警是调查线索，永久封禁前必须人工核对原始日志。")
    rendered = "\n".join(lines).strip()
    return rendered[:3900]


def api_request(token: str, method: str, payload: Dict[str, Any], timeout: int = 20) -> Dict[str, Any]:
    url = f"https://api.telegram.org/bot{token}/{method}"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Telegram API error {exc.code}: {detail[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Telegram connection failed: {exc.reason}") from exc
    if not isinstance(result, dict):
        raise RuntimeError("Telegram returned an invalid response")
    if not result.get("ok"):
        raise RuntimeError("Telegram rejected the message: " + json.dumps(result, ensure_ascii=False))
    return result


def send_message(
    token: str,
    chat_id: str,
    text: str,
    timeout: int = 20,
    reply_markup: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return api_request(token, "sendMessage", payload, timeout)


def get_updates(token: str, offset: int | None, timeout: int = 30) -> List[Dict[str, Any]]:
    payload: Dict[str, Any] = {
        "timeout": timeout,
        "allowed_updates": ["message", "callback_query"],
    }
    if offset is not None:
        payload["offset"] = offset
    result = api_request(token, "getUpdates", payload, timeout + 10)
    updates = result.get("result", [])
    if not isinstance(updates, list):
        raise RuntimeError("Telegram getUpdates returned an invalid result")
    return [item for item in updates if isinstance(item, dict)]


def answer_callback_query(token: str, callback_query_id: str, text: str = "") -> None:
    payload: Dict[str, Any] = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text[:180]
    api_request(token, "answerCallbackQuery", payload)
