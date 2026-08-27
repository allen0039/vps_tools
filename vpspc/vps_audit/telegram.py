from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class TelegramTransientError(RuntimeError):
    """A temporary network or server failure that is safe to retry."""


DEFAULT_COMMANDS: List[Dict[str, str]] = [
    {"command": "menu", "description": "打开管理菜单"},
    {"command": "vpspc", "description": "打开 VPSPC 管理菜单"},
    {"command": "status", "description": "查看运行状态"},
    {"command": "web", "description": "管理 Web 与 Token"},
    {"command": "nodes", "description": "管理节点与部署命令"},
    {"command": "users", "description": "管理订阅用户"},
    {"command": "discover", "description": "从日志发现用户"},
    {"command": "ips", "description": "查询用户活跃 IP"},
    {"command": "incidents", "description": "查看行为事件"},
    {"command": "incident", "description": "查看事件详情"},
    {"command": "incidentai", "description": "AI 复核事件"},
    {"command": "ask", "description": "向 AI 追问事件"},
    {"command": "thresholds", "description": "查看检测参数"},
    {"command": "set", "description": "修改检测参数"},
    {"command": "ai", "description": "管理 AI 供应商"},
    {"command": "aiuse", "description": "切换 AI 供应商"},
    {"command": "aimodel", "description": "修改 AI 模型名"},
    {"command": "aitest", "description": "测试当前 AI 模型"},
    {"command": "aion", "description": "启用 AI 复核"},
    {"command": "aioff", "description": "暂停 AI 复核"},
    {"command": "run", "description": "立即执行一次巡查"},
    {"command": "help", "description": "查看帮助"},
    {"command": "mode", "description": "切换全部或重点用户"},
    {"command": "monitor", "description": "启用或暂停订阅监测"},
    {"command": "adduser", "description": "添加重点用户"},
    {"command": "deluser", "description": "删除重点用户"},
]


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
    target = evidence.get("destination_host") or evidence.get("destination_ip")
    if target:
        destination = str(target)
        if evidence.get("destination_port"):
            destination += f":{evidence['destination_port']}"
        parts.append("目标=" + destination)
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


def _finding_nodes(finding: Dict[str, Any], limit: int = 5) -> List[str]:
    nodes: List[str] = []
    for evidence in finding.get("evidence", []):
        value = str(evidence.get("node_name") or evidence.get("node_id") or "").strip()
        value = "".join(
            char if 32 <= ord(char) < 127 or ord(char) >= 160 else "?" for char in value
        )
        if value and value not in nodes:
            nodes.append(value[:80])
        if len(nodes) >= limit:
            break
    return nodes


def _finding_targets(finding: Dict[str, Any], limit: int = 5) -> List[str]:
    counts: Dict[str, int] = {}
    for evidence in finding.get("evidence", []):
        target = evidence.get("destination_host") or evidence.get("destination_ip")
        if not target:
            continue
        rendered = str(target)
        if evidence.get("destination_port"):
            rendered += f":{evidence['destination_port']}"
        counts[rendered] = counts.get(rendered, 0) + 1
    return [
        target if count == 1 else f"{target} ({count})"
        for target, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


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
        nodes = _finding_nodes(finding)
        if nodes:
            lines.append("涉及节点：" + ", ".join(nodes))
        if finding.get("incident_id"):
            lines.append("事件 ID：" + str(finding["incident_id"]))
        if str(finding.get("rule_id", "")).startswith("BEHAVIOR_"):
            targets = _finding_targets(finding)
            if targets:
                lines.append("主要目标：" + ", ".join(targets))
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
        if exc.code == 429 or exc.code >= 500:
            raise TelegramTransientError(f"Telegram temporary API error {exc.code}") from exc
        raise RuntimeError(f"Telegram API error {exc.code}: {detail[:500]}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise TelegramTransientError(f"Telegram connection temporarily failed: {reason}") from exc
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


def set_my_commands(
    token: str, commands: Iterable[Dict[str, str]] | None = None, timeout: int = 20
) -> Dict[str, Any]:
    selected = list(commands or DEFAULT_COMMANDS)
    if len(selected) > 100:
        raise ValueError("Telegram command list cannot contain more than 100 commands")
    return api_request(token, "setMyCommands", {"commands": selected}, timeout)


def set_chat_menu_button(token: str, timeout: int = 20) -> Dict[str, Any]:
    return api_request(token, "setChatMenuButton", {"menu_button": {"type": "commands"}}, timeout)


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


def edit_message_text(
    token: str,
    chat_id: str,
    message_id: int,
    text: str,
    reply_markup: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return api_request(token, "editMessageText", payload)
