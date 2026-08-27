from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, Tuple


SYSTEM_PROMPT = """你是 VPS 安全审计复核员。只能依据输入中的结构化规则证据判断，不能补充不存在的事实。
特别注意：多设备、家庭宽带、移动网络、VPN、远程服务器和订阅聚合器都可能造成 IP 变化或隐藏真实来源；单个弱信号不能定性。
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

    replacements: Dict[str, str] = {}

    def collect(value: Any, key: str = "") -> None:
        if key in {"source_ip", "destination_ip"} and value:
            replacements[str(value)] = token(value, "ip")
        elif key == "destination_host" and value:
            replacements[str(value)] = token(value, "host")
        elif key == "command" and value:
            replacements[str(value)] = "[redacted command]"
        if isinstance(value, dict):
            for child_key, child in value.items():
                collect(child, child_key)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(report)

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
            return {
                child_key: redact(child, child_key)
                for child_key, child in value.items()
                if child_key not in {"lat", "lon", "source_line"}
            }
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, str):
            rendered = value
            for raw, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
                rendered = rendered.replace(raw, replacement)
            return rendered
        return value

    bundle = redact({
        "summary": report["summary"],
        "users": report["users"],
        "findings": report["findings"],
        "policy": report["policy"],
    })
    reverse_aliases = {alias: user for user, alias in aliases.items()}
    return bundle, reverse_aliases


def _endpoint(provider: Dict[str, Any]) -> str:
    suffix = "responses" if provider["api_mode"] == "responses" else "chat/completions"
    return str(provider["base_url"]).rstrip("/") + "/" + suffix


def _post_json(provider: Dict[str, Any], api_key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    request = urllib.request.Request(
        _endpoint(provider),
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "vps-user-audit/0.5.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=int(provider.get("timeout_seconds", 30))) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        if api_key:
            detail = detail.replace(api_key, "[redacted]")
        raise RuntimeError(f"AI provider HTTP {exc.code}: {detail[:500]}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(f"AI provider connection failed: {reason}") from exc
    if not isinstance(result, dict):
        raise RuntimeError("AI provider returned a non-object response")
    return result


def _extract_output_text(result: Dict[str, Any], api_mode: str) -> str:
    if api_mode == "chat_completions":
        try:
            content = result["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("AI chat completion did not contain message content") from exc
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            text = "".join(
                str(item.get("text", "")) for item in content if isinstance(item, dict)
            )
            if text:
                return text
        raise RuntimeError("AI chat completion returned unsupported message content")
    output_text = result.get("output_text")
    if isinstance(output_text, str) and output_text:
        return output_text
    for item in result.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text" and content.get("text"):
                return str(content["text"])
    raise RuntimeError("AI response did not contain output_text")


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuntimeError(f"AI review field {field} must be an array of strings")
    return value[:50]


def _validate_review(value: Any, aliases: Iterable[str]) -> Dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("overall_assessment"), str):
        raise RuntimeError("AI review must contain overall_assessment")
    cases = value.get("cases")
    if not isinstance(cases, list) or len(cases) > 100:
        raise RuntimeError("AI review cases must be an array with at most 100 items")
    allowed = set(aliases)
    normalized_cases = []
    for case in cases:
        if not isinstance(case, dict):
            raise RuntimeError("AI review case must be an object")
        alias = case.get("user")
        assessment = case.get("assessment")
        confidence = case.get("confidence")
        if alias not in allowed:
            raise RuntimeError("AI review referenced an unknown account alias")
        if assessment not in {"likely_abuse", "needs_review", "likely_benign"}:
            raise RuntimeError("AI review returned an invalid assessment")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise RuntimeError("AI review confidence must be between 0 and 1")
        recommended = case.get("recommended_action")
        if not isinstance(recommended, str):
            raise RuntimeError("AI review recommended_action must be a string")
        normalized_cases.append({
            "user": alias,
            "assessment": assessment,
            "confidence": float(confidence),
            "facts": _string_list(case.get("facts"), "facts"),
            "benign_explanations": _string_list(case.get("benign_explanations"), "benign_explanations"),
            "missing_evidence": _string_list(case.get("missing_evidence"), "missing_evidence"),
            "recommended_action": recommended,
        })
    return {"overall_assessment": value["overall_assessment"], "cases": normalized_cases}


def _parse_review_json(text: str) -> Any:
    candidate = text.strip()
    if candidate.startswith("```") and candidate.endswith("```"):
        first_newline = candidate.find("\n")
        if first_newline != -1:
            candidate = candidate[first_newline + 1 : -3].strip()
    return json.loads(candidate)


def review_with_provider(
    report: Dict[str, Any],
    provider: Dict[str, Any],
    api_key: str,
    *,
    redact: bool = True,
    question: str = "",
) -> Dict[str, Any]:
    if not api_key:
        raise ValueError("AI provider API key is required")
    if redact:
        evidence_bundle, reverse_aliases = _redact_for_ai(report)
    else:
        evidence_bundle = {
            "summary": report["summary"],
            "users": report["users"],
            "findings": report["findings"],
            "policy": report["policy"],
        }
        reverse_aliases = {
            str(item["user"]): str(item["user"])
            for item in report.get("users", [])
            if item.get("user")
        }
    user_prompt = "复核以下规则引擎证据并输出审计意见：\n" + json.dumps(evidence_bundle, ensure_ascii=False)
    if question:
        user_prompt += "\n\n管理员追加问题：" + question[:1000]
    if provider["api_mode"] == "responses":
        payload = {
            "model": provider["model"],
            "store": False,
            "instructions": SYSTEM_PROMPT,
            "input": user_prompt,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "vps_audit_review",
                    "strict": True,
                    "schema": REVIEW_SCHEMA,
                }
            },
        }
    else:
        payload = {
            "model": provider["model"],
            "messages": [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT + "\n必须只返回符合以下 JSON Schema 的 JSON 对象：\n" + json.dumps(REVIEW_SCHEMA, ensure_ascii=False),
                },
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "stream": False,
        }
    result = _post_json(provider, api_key, payload)
    try:
        raw_review = _parse_review_json(_extract_output_text(result, str(provider["api_mode"])))
    except json.JSONDecodeError as exc:
        raise RuntimeError("AI provider returned invalid JSON") from exc
    review = _validate_review(raw_review, reverse_aliases)
    for case in review["cases"]:
        case["user"] = reverse_aliases[case["user"]]
    return review


def test_ai_provider(provider: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    synthetic_report = {
        "summary": {"event_count": 1, "finding_count": 1, "flagged_user_count": 1},
        "users": [{"user": "connectivity-test", "risk_score": 30, "severity": "medium", "finding_count": 1}],
        "findings": [{
            "rule_id": "AI_CONNECTIVITY_TEST",
            "user": "connectivity-test",
            "severity": "medium",
            "score": 30,
            "title": "模型连通性测试",
            "summary": "这是无真实用户数据的合成测试。",
            "evidence": [{"timestamp": "2026-01-01T00:00:00Z", "indicators": ["synthetic_test"]}],
        }],
        "policy": "仅测试 OpenAI 兼容接口、模型和结构化输出，不执行任何处置。",
    }
    started = time.monotonic()
    review_with_provider(synthetic_report, provider, api_key)
    return {
        "ok": True,
        "model": str(provider["model"]),
        "api_mode": str(provider["api_mode"]),
        "latency_ms": round((time.monotonic() - started) * 1000),
    }


def review_with_openai(
    report: Dict[str, Any],
    model: str,
    api_key: str | None = None,
    base_url: str | None = None,
    api_mode: str = "responses",
) -> Dict[str, Any]:
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise ValueError("OPENAI_API_KEY is required for --ai-review")
    provider = {
        "base_url": base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        "api_mode": api_mode,
        "model": model,
        "timeout_seconds": 60,
    }
    return review_with_provider(report, provider, key)
