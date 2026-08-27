from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

from .ai_review import review_with_openai
from .analyzer import analyze
from .config import load_config
from .io import read_events, write_json
from .report import render_markdown
from .ssh_parser import parse_auth_log


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vps-audit", description="Evidence-first VPS user behavior audit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize = subparsers.add_parser("normalize-auth", help="convert OpenSSH auth.log to JSONL")
    normalize.add_argument("input", help="auth.log path")
    normalize.add_argument("--year", type=int, required=True, help="year missing from syslog lines")
    normalize.add_argument("--timezone", default="+00:00", help="source timezone offset, e.g. +08:00")
    normalize.add_argument("--output", default="-", help="output JSONL path or - for stdout")

    inspect = subparsers.add_parser("analyze", help="analyze normalized JSONL events")
    inspect.add_argument("inputs", nargs="+", help="one or more JSONL event files")
    inspect.add_argument("--config", help="JSON config override")
    inspect.add_argument("--json-output", default="audit-report.json")
    inspect.add_argument("--markdown-output", default="audit-report.md")
    inspect.add_argument("--ai-review", action="store_true", help="send only the evidence bundle to OpenAI Responses API")
    inspect.add_argument("--model", default=os.environ.get("OPENAI_MODEL"), help="OpenAI model; defaults to OPENAI_MODEL")
    inspect.add_argument(
        "--base-url",
        default=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        help="OpenAI-compatible API base URL; defaults to OPENAI_BASE_URL",
    )
    inspect.add_argument(
        "--api-mode",
        choices=["responses", "chat_completions"],
        default=os.environ.get("OPENAI_API_MODE", "responses"),
        help="OpenAI-compatible API style",
    )
    return parser


def _normalize(args: argparse.Namespace) -> int:
    with Path(args.input).open("r", encoding="utf-8", errors="replace") as source:
        output_lines = [json.dumps(item, ensure_ascii=False) for item in parse_auth_log(source, args.year, args.timezone)]
    rendered = "\n".join(output_lines) + ("\n" if output_lines else "")
    if args.output == "-":
        sys.stdout.write(rendered)
    else:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered, encoding="utf-8")
    return 0


def _analyze(args: argparse.Namespace) -> int:
    events = read_events(args.inputs)
    report = analyze(events, load_config(args.config))
    ai_result = None
    if args.ai_review:
        if not args.model:
            raise ValueError("--model or OPENAI_MODEL is required for --ai-review")
        ai_result = review_with_openai(report, args.model, base_url=args.base_url, api_mode=args.api_mode)
        report["ai_review"] = ai_result
    write_json(args.json_output, report)
    markdown_path = Path(args.markdown_output)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(render_markdown(report, ai_result), encoding="utf-8")
    print(f"Analyzed {report['summary']['event_count']} events; flagged {report['summary']['flagged_user_count']} users.")
    print(f"JSON: {args.json_output}")
    print(f"Markdown: {args.markdown_output}")
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return _normalize(args) if args.command == "normalize-auth" else _analyze(args)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
