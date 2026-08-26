from __future__ import annotations

import json
import os
import hashlib
import secrets
import urllib.error
import urllib.request
from typing import Any, Dict, Tuple


SYSTEM_PROMPT = """你是 VPS 安全审计复核员。只能依据输入中的结构化规则证据判断，不能补充不存在的事实。
特别注意：多设备、家庭宽带、移动网络、VPN、远程服务器都可能造成 IP 变化；单个弱信号不能定性。
请区分“可证实事实”“合理解释”“仍需补充的证据”。禁止建议仅凭 AI 结果永久封号。"""


REVIEW_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "overall_assessment": {"type": "string"},
        "cases": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "user": {"type": "string"},
                    "assessment": {"type": "string", "enum": ["likely_abuse", "needs_review", "likely_benign"]},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "facts": {"type": "array", "items": {"type": "string"}},
                    "benign_explanations": {"type": "array", "items": {"type": "string"}},
                    "missing_evidence": {"type": "array", "items": {"type": "string"}},
                    "recommended_action": {"type": "string"},
                },
                "required": ["user", "assessment", "confidence", "facts", "benign_explanations", "missing_evidence", "recommended_action"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["overall_assessment", "cases"],
    "additionalProperties": False,
}


def _redact_for_ai(report: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    salt = secrets.token_bytes(16)
    users = sorted({item["user"] for item in report.get("users", [])})
    aliases = {user: f"account-{index:03d}" for index, user in enumerate(users, 1)}

    def token(value: Any, prefix: str) -> str:
        digest = hashlib.sha256(salt + str(value).encode("utf-8")).hexdigest()[:12]
        return f"{prefix}-{digest}"

    def redact(value: Any, key: str = "") -> Any:
        if key == "user" and isinstance(value, str):
            return aliases.get(value, "account-unknown")
        if key in {"source_ip", "destination_ip"}:
            return token(value, "ip")
        if key == "destination_host":
            return token(value, "host")
        if key == "command":
            return "[redacted; matched indicators are retained separately]"
        if key in {"lat", "lon", "source_line"}:
            return None
        if isinstance(value, dict):
            return {child_key: redact(child, child_key) for child_key, child in value.items() if child_key not in {"lat", "lon", "source_line"}}
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    bundle = redact({
        "summary": report["summary"],
        "users": report["users"],
        "findings": report["findings"],
        "policy": report["policy"],
    })
    reverse_aliases = {alias: user for user, alias in aliases.items()}
    return bundle, reverse_aliases


def review_with_openai(report: Dict[str, Any], model: str, api_key: str | None = None) -> Dict[str, Any]:
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise ValueError("OPENAI_API_KEY is required for --ai-review")
    evidence_bundle, reverse_aliases = _redact_for_ai(report)
    payload = {
        "model": model,
        "store": False,
        "instructions": SYSTEM_PROMPT,
        "input": "复核以下规则引擎证据并输出审计意见：\n" + json.dumps(evidence_bundle, ensure_ascii=False),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "vps_audit_review",
                "strict": True,
                "schema": REVIEW_SCHEMA,
            }
        },
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API error {exc.code}: {detail}") from exc
    output_text = result.get("output_text")
    if not output_text:
        for item in result.get("output", []):
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    output_text = content.get("text")
                    break
    if not output_text:
        raise RuntimeError("OpenAI response did not contain output_text")
    review = json.loads(output_text)
    for case in review.get("cases", []):
        case["user"] = reverse_aliases.get(case.get("user", ""), case.get("user", "unknown"))
    return review
