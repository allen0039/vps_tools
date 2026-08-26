import json
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vps_audit.falco_parser import parse_falco_event
from vps_audit.miaomiaowux_parser import parse_miaomiaowux_line
from vps_audit.runtime import _collect_journal, _notification_candidates, _parse_miaomiaowux_lines, _parse_subscription_lines, run_cycle
from vps_audit.telegram import build_alert_message


class RuntimeTests(unittest.TestCase):
    def _config(self, directory: Path, auth_log: Path) -> Path:
        config = {
            "auth_logs": [str(auth_log)],
            "auth_timezone": "+00:00",
            "falco_logs": [],
            "state_dir": str(directory / "state"),
            "report_dir": str(directory / "reports"),
            "retention_days": 7,
            "telegram": {"enabled": False, "minimum_severity": "medium", "cooldown_hours": 6},
            "openai_review": {"enabled": False},
        }
        path = directory / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return path

    def test_cycle_reads_appends_and_does_not_duplicate(self):
        now = datetime.now(timezone.utc)
        prefix = now.strftime("%b %d")
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            auth_log = directory / "auth.log"
            auth_log.write_text(
                f"{prefix} 01:00:00 vps sshd[1]: Accepted publickey for alice from 198.51.100.1 port 50001 ssh2\n",
                encoding="utf-8",
            )
            config = self._config(directory, auth_log)
            first = run_cycle(str(config))
            self.assertEqual(first["summary"]["event_count"], 1)
            self.assertEqual(first["runtime"]["new_event_count"], 1)
            self.assertEqual(stat.S_IMODE((directory / "state").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((directory / "reports").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((directory / "reports" / "latest.json").stat().st_mode), 0o600)

            with auth_log.open("a", encoding="utf-8") as handle:
                for index in range(2, 5):
                    handle.write(
                        f"{prefix} 01:0{index}:00 vps sshd[{index}]: Accepted publickey for alice "
                        f"from 198.51.100.{index} port {50000 + index} ssh2\n"
                    )
            second = run_cycle(str(config))
            self.assertEqual(second["summary"]["event_count"], 4)
            self.assertEqual(second["runtime"]["new_event_count"], 3)
            self.assertIn("AUTH_MULTI_IP", {finding["rule_id"] for finding in second["findings"]})

            third = run_cycle(str(config))
            self.assertEqual(third["summary"]["event_count"], 4)
            self.assertEqual(third["runtime"]["new_event_count"], 0)

    def test_allowlist_filters_subscription_report_but_retains_normalized_events(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            subscription_log = directory / "subscriptions.jsonl"
            rows = []
            for user, suffix in (("alice", 1), ("alice", 2), ("bob", 3), ("bob", 4)):
                rows.append(
                    json.dumps(
                        {
                            "timestamp": f"2026-08-26T01:0{suffix}:00Z",
                            "subscription_id": user,
                            "source_ip": f"198.51.100.{suffix}",
                        }
                    )
                )
            subscription_log.write_text("\n".join(rows) + "\n", encoding="utf-8")
            config = directory / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "auth_logs": [],
                        "subscription_logs": [str(subscription_log)],
                        "state_dir": str(directory / "state"),
                        "report_dir": str(directory / "reports"),
                        "subscription_monitoring": {"mode": "allowlist", "users": ["alice"]},
                        "rules": {"thresholds": {"subscription_ip_count": 2}},
                        "telegram": {"enabled": False},
                        "openai_review": {"enabled": False},
                    }
                ),
                encoding="utf-8",
            )
            report = run_cycle(str(config))
            self.assertEqual(report["summary"]["event_count"], 2)
            self.assertEqual({item["user"] for item in report["findings"]}, {"alice"})
            retained = (directory / "state" / "events.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(retained), 4)
            self.assertEqual(report["runtime"]["subscription_monitoring"]["configured_user_count"], 1)

    def test_falco_event_parser(self):
        raw = {
            "time": "2026-08-26T02:00:00Z",
            "rule": "VPS Audit User Process Start",
            "output_fields": {
                "evt.type": "execve",
                "user.name": "alice",
                "user.uid": 1001,
                "proc.pid": 42,
                "proc.exepath": "/usr/bin/python3",
                "proc.cmdline": "python3 task.py --headless --threads 10",
            },
        }
        event = parse_falco_event(raw)
        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "process_start")
        self.assertEqual(event["user"], "alice")

    def test_journal_collector_tracks_cursor(self):
        raw = {
            "__CURSOR": "s=cursor-1",
            "__REALTIME_TIMESTAMP": "1787706000000000",
            "MESSAGE": "Accepted publickey for alice from 198.51.100.9 port 50009 ssh2",
        }
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(raw) + "\n", stderr="")

        class NoopEnricher:
            def enrich(self, _source_ip):
                return {}

        state = {}
        with patch("vps_audit.runtime.subprocess.run", return_value=completed) as run:
            events, errors = _collect_journal(
                state,
                {"units": ["ssh.service", "sshd.service"], "initial_since_hours": 24},
                NoopEnricher(),
            )
        self.assertEqual(errors, 0)
        self.assertEqual(events[0]["user"], "alice")
        self.assertEqual(state["journal_cursor"], "s=cursor-1")
        self.assertIn("--since=-24 hours", run.call_args.args[0])

    def test_telegram_message_masks_ip_and_omits_command(self):
        report = {"users": [{"user": "alice", "severity": "high", "risk_score": 70}]}
        findings = [{
            "user": "alice",
            "severity": "high",
            "title": "疑似批量账号自动化工具链",
            "summary": "来源 198.51.100.24 的进程和网络行为交叉命中。",
            "evidence": [{
                "timestamp": "2026-08-26T02:00:00Z",
                "source_ip": "198.51.100.24",
                "executable": "/usr/bin/python3",
                "command": "python3 secret.py --api-key SECRET",
                "indicators": ["browser_automation", "bulk_behavior"],
            }],
        }]
        message = build_alert_message(report, findings)
        self.assertIn("198.51.*.*", message)
        self.assertNotIn("198.51.100.24", message)
        self.assertNotIn("SECRET", message)
        self.assertNotIn("secret.py", message)

    def test_high_account_score_promotes_medium_findings_to_notification(self):
        report = {
            "users": [{"user": "alice", "severity": "high", "risk_score": 65}],
            "findings": [
                {"user": "alice", "rule_id": "AUTH_MULTI_IP", "severity": "medium"},
                {"user": "alice", "rule_id": "PROC_REPEAT_BURST", "severity": "medium"},
            ],
        }
        config = {"telegram": {"minimum_severity": "high", "cooldown_hours": 6}}
        candidates = _notification_candidates(report, {"notifications": {}}, config, datetime.now(timezone.utc))
        self.assertEqual(len(candidates), 2)

    def test_subscription_adapter_accepts_subscription_id(self):
        class NoopEnricher:
            def enrich(self, _source_ip):
                return {"region": "Guangdong", "city": "Guangzhou"}

        lines = [json.dumps({
            "timestamp": "2026-08-26T01:00:00Z",
            "subscription_id": "personal-plan-001",
            "source_ip": "198.51.100.9",
            "device_id": "device-a",
        })]
        events, errors = _parse_subscription_lines(lines, NoopEnricher())
        self.assertEqual(errors, 0)
        self.assertEqual(events[0]["event_type"], "subscription_access")
        self.assertEqual(events[0]["user"], "personal-plan-001")
        self.assertEqual(events[0]["region"], "Guangdong")

    def test_miaomiaowux_native_log_parser_supports_ipv4_and_ipv6(self):
        ipv4 = 'time="2026-08-26 09:04:22" level="INFO " msg="用户获取订阅" username=alice ip=198.51.100.9'
        ipv6 = 'time="2026-08-26 09:04:23" level="INFO " msg="用户获取订阅" username=alice ip=2001:db8::9'
        first = parse_miaomiaowux_line(ipv4, "+00:00")
        second = parse_miaomiaowux_line(ipv6, "+00:00")
        self.assertEqual(first["source_ip"], "198.51.100.9")
        self.assertEqual(second["source_ip"], "2001:db8::9")
        self.assertEqual(first["timestamp"], "2026-08-26T09:04:22+00:00")

    def test_miaomiaowux_runtime_adapter_ignores_unrelated_logs(self):
        class NoopEnricher:
            def enrich(self, _source_ip):
                return {}

        lines = [
            'time="2026-08-26 09:04:22" level="INFO " msg="用户获取订阅" username=alice ip=198.51.100.9',
            'time="2026-08-26 09:05:00" level="INFO " msg="TCPing succeeded"',
        ]
        events, errors = _parse_miaomiaowux_lines(lines, "+00:00", NoopEnricher())
        self.assertEqual(errors, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "miaomiaowux")


if __name__ == "__main__":
    unittest.main()
