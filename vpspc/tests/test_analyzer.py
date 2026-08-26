import json
import tempfile
import unittest
from pathlib import Path

from vps_audit.ai_review import _redact_for_ai
from vps_audit.analyzer import analyze
from vps_audit.config import load_config
from vps_audit.io import read_events
from vps_audit.ssh_parser import parse_auth_log, parse_sshd_message


ROOT = Path(__file__).resolve().parents[1]


class AnalyzerTests(unittest.TestCase):
    def test_example_detects_cross_network_and_automation(self):
        report = analyze(
            read_events([str(ROOT / "examples" / "events.jsonl")]),
            load_config(str(ROOT / "examples" / "config.json")),
        )
        rule_ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("AUTH_MULTI_IP", rule_ids)
        self.assertIn("AUTH_ASN_CHURN", rule_ids)
        self.assertIn("AUTH_IMPOSSIBLE_TRAVEL", rule_ids)
        self.assertIn("PROC_AUTOMATION_STACK", rule_ids)
        self.assertIn("NET_DESTINATION_BURST", rule_ids)
        self.assertEqual(report["users"][0]["risk_score"], 100)

    def test_normal_user_is_not_flagged(self):
        raw = {
            "timestamp": "2026-08-26T01:00:00Z",
            "event_type": "login_success",
            "user": "bob",
            "source_ip": "198.51.100.1",
            "network_type": "residential",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(json.dumps(raw) + "\n", encoding="utf-8")
            report = analyze(read_events([str(path)]), load_config())
        self.assertEqual(report["summary"]["flagged_user_count"], 0)

    def test_repeated_same_rule_does_not_stack_score(self):
        rows = [
            {"timestamp": "2026-08-26T01:00:00Z", "event_type": "login_success", "user": "traveler", "source_ip": "198.51.100.1", "asn": 64511, "network_type": "residential", "lat": 23.1291, "lon": 113.2644},
            {"timestamp": "2026-08-26T01:10:00Z", "event_type": "login_success", "user": "traveler", "source_ip": "198.51.100.2", "asn": 64511, "network_type": "residential", "lat": 39.9042, "lon": 116.4074},
            {"timestamp": "2026-08-26T01:20:00Z", "event_type": "login_success", "user": "traveler", "source_ip": "198.51.100.3", "asn": 64511, "network_type": "residential", "lat": 1.3521, "lon": 103.8198},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            report = analyze(read_events([str(path)]), load_config())
        self.assertEqual(report["users"][0]["risk_score"], 60)
        self.assertEqual(report["summary"]["finding_count"], 2)

    def test_ai_bundle_redacts_sensitive_values(self):
        report = analyze(
            read_events([str(ROOT / "examples" / "events.jsonl")]),
            load_config(str(ROOT / "examples" / "config.json")),
        )
        bundle, aliases = _redact_for_ai(report)
        serialized = json.dumps(bundle)
        self.assertNotIn("198.51.100.11", serialized)
        self.assertNotIn("signup.py", serialized)
        self.assertEqual(aliases["account-001"], "alice")

    def test_auth_log_parser(self):
        lines = (ROOT / "examples" / "auth.log").read_text(encoding="utf-8").splitlines()
        events = list(parse_auth_log(lines, 2026, "+08:00"))
        self.assertEqual([event["event_type"] for event in events], ["login_success", "login_failure", "login_failure"])
        self.assertEqual(events[0]["user"], "alice")
        self.assertEqual(events[1]["user"], "admin")

    def test_journal_message_parser(self):
        event = parse_sshd_message(
            "Accepted publickey for alice from 198.51.100.9 port 50009 ssh2",
            "2026-08-26T01:00:00Z",
        )
        self.assertEqual(event["event_type"], "login_success")
        self.assertEqual(event["source_ip"], "198.51.100.9")

    def test_subscription_ten_ips_and_multiple_regions_alert(self):
        rows = []
        regions = [("Guangdong", "Guangzhou"), ("Beijing", "Beijing"), ("Shanghai", "Shanghai")]
        for index in range(10):
            region, city = regions[index % len(regions)]
            rows.append({
                "timestamp": f"2026-08-26T01:{index:02d}:00Z",
                "event_type": "subscription_access",
                "user": "personal-plan-001",
                "source_ip": f"198.51.100.{index + 1}",
                "region": region,
                "city": city,
                "asn": 64510 + (index % 4),
            })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subscription.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            report = analyze(read_events([str(path)]), load_config())
        rule_ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("SUB_ACTIVE_IPS", rule_ids)
        self.assertIn("SUB_MULTI_REGION", rule_ids)
        self.assertIn("SUB_MULTI_ASN", rule_ids)
        self.assertEqual(report["users"][0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
