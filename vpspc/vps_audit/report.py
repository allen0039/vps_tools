from __future__ import annotations

from typing import Any, Dict, List


def render_markdown(report: Dict[str, Any], ai_review: Dict[str, Any] | None = None) -> str:
    summary = report["summary"]
    lines: List[str] = [
        "# VPS 用户行为巡查报告",
        "",
        f"- 事件数：{summary['event_count']}",
        f"- 用户数：{summary['user_count']}",
        f"- 命中用户：{summary['flagged_user_count']}",
        f"- 规则告警：{summary['finding_count']}",
    ]
    if report.get("runtime"):
        runtime = report["runtime"]
        lines.extend([
            f"- 生成时间：{runtime.get('generated_at', '-')}",
            f"- 本轮新增事件：{runtime.get('new_event_count', 0)}",
            f"- 本轮解析错误：{runtime.get('parse_error_count', 0)}",
        ])
        if runtime.get("ai_error"):
            lines.append(f"- AI 复核错误：{runtime['ai_error']}")
    lines.extend([
        "",
        "> 规则命中是调查线索，不是封号结论。高风险用户也应先核对原始日志和用户解释。",
        "",
        "## 风险用户",
        "",
        "| 用户 | 分数 | 等级 | 命中数 | 建议 |",
        "| --- | ---: | --- | ---: | --- |",
    ])
    if report["users"]:
        for user in report["users"]:
            lines.append(f"| {user['user']} | {user['risk_score']} | {user['severity']} | {user['finding_count']} | {user['recommended_action']} |")
    else:
        lines.append("| - | 0 | - | 0 | 未发现达到阈值的异常 |")
    lines.extend(["", "## 证据", ""])
    for finding in report["findings"]:
        lines.extend([
            f"### [{finding['severity']}] {finding['user']}：{finding['title']}",
            "",
            finding["summary"],
            "",
            "```json",
            _compact_json(finding["evidence"]),
            "```",
            "",
        ])
    if report.get("coverage_warnings"):
        lines.extend(["## 观测范围警告", ""])
        for warning in report["coverage_warnings"]:
            lines.extend([
                f"### [{warning['severity']}] {warning['title']}",
                "",
                warning["summary"],
                "",
                "```json",
                _compact_json(warning["evidence"]),
                "```",
                "",
            ])
    if ai_review:
        lines.extend(["## AI 复核", "", ai_review.get("overall_assessment", ""), ""])
        for case in ai_review.get("cases", []):
            lines.extend([
                f"### {case['user']}：{case['assessment']}（置信度 {case['confidence']:.0%}）",
                "",
                f"建议：{case['recommended_action']}",
                "",
                "已证实事实：" + "；".join(case["facts"]),
                "",
                "可能的正常解释：" + "；".join(case["benign_explanations"]),
                "",
                "待补证据：" + "；".join(case["missing_evidence"]),
                "",
            ])
    return "\n".join(lines).rstrip() + "\n"


def _compact_json(value: object) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, indent=2)
