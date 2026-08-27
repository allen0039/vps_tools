import json
import tempfile
import unittest
from pathlib import Path

from vps_audit.ai_review import _redact_for_ai
from vps_audit.analyzer import analyze
from vps_audit.behavior_audit import classify_destination
from vps_audit.config import load_config
from vps_audit.io import read_events
from vps_audit.report import render_markdown
from vps_audit.ssh_parser import parse_auth_log, parse_sshd_message


ROOT = Path(__file__).resolve().parents[1]


class AnalyzerTests(unittest.TestCase):
    def _analyze_rows(self, rows, thresholds=None):
        config = load_config()
        config["thresholds"].update(thresholds or {})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
            )
            return analyze(read_events([str(path)]), config)

    @staticmethod
    def _connection(index, user="user-a", node="node-a", destination="example.com"):
        return {
            "timestamp": f"2026-08-27T01:{index // 60:02d}:{index % 60:02d}Z",
            "event_type": "proxy_connection",
            "user": user,
            "source_ip": f"198.51.{index // 250}.{index % 250 + 1}",
            "source_port": 40000 + index,
            "destination_host": destination,
            "destination_port": 443,
            "destination_category": classify_destination(destination),
            "network": "tcp",
            "node_id": node,
            "node_name": node,
            "protocol": "xray",
            "event_id": f"evt_{index:016d}_{user}_{node}",
        }

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
                "device_id": f"device-{index + 1}",
            })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subscription.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            report = analyze(read_events([str(path)]), load_config())
        rule_ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("SUB_ACTIVE_IPS", rule_ids)
        self.assertIn("SUB_MULTI_REGION", rule_ids)
        self.assertIn("SUB_MULTI_ASN", rule_ids)
        self.assertIn("SUB_MULTI_DEVICE", rule_ids)
        self.assertEqual(report["users"][0]["severity"], "critical")

    def test_shared_subscription_fetch_source_is_coverage_warning_only(self):
        rows = [
            {
                "timestamp": f"2026-08-26T01:{index:02d}:00Z",
                "event_type": "subscription_access",
                "user": f"subscriber-{index}",
                "source_ip": "198.51.100.88",
                "user_agent": "Sub-Store",
            }
            for index in range(8)
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subscription.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            report = analyze(read_events([str(path)]), load_config())

        self.assertEqual(report["summary"]["flagged_user_count"], 0)
        self.assertEqual(report["summary"]["finding_count"], 0)
        self.assertEqual(
            [item["rule_id"] for item in report["coverage_warnings"]],
            ["SUB_SHARED_FETCH_SOURCE"],
        )
        self.assertIn("不能据此还原终端 IP", report["coverage_warnings"][0]["summary"])
        self.assertIn("## 观测范围警告", render_markdown(report))

    def test_shared_subscription_fetch_source_below_threshold_is_quiet(self):
        rows = [
            {
                "timestamp": f"2026-08-26T01:0{index}:00Z",
                "event_type": "subscription_access",
                "user": f"subscriber-{index}",
                "source_ip": "198.51.100.88",
            }
            for index in range(7)
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subscription.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            report = analyze(read_events([str(path)]), load_config())

        self.assertEqual(report["coverage_warnings"], [])

    def test_node_ip_window_isolated_by_user_and_node(self):
        split_users = [
            self._connection(index, user="user-a" if index < 4 else "user-b")
            for index in range(8)
        ]
        report = self._analyze_rows(split_users)
        self.assertNotIn("NODE_ACTIVE_IPS", {item["rule_id"] for item in report["findings"]})

        split_nodes = [
            self._connection(index, node="node-a" if index < 4 else "node-b")
            for index in range(8)
        ]
        report = self._analyze_rows(split_nodes)
        self.assertNotIn("NODE_ACTIVE_IPS", {item["rule_id"] for item in report["findings"]})

        report = self._analyze_rows([self._connection(index) for index in range(5)])
        finding = next(item for item in report["findings"] if item["rule_id"] == "NODE_ACTIVE_IPS")
        self.assertEqual(finding["user"], "user-a")
        self.assertTrue(all(item["node_id"] == "node-a" for item in finding["evidence"]))

    def test_node_region_and_account_automation_rules_use_connection_metadata(self):
        regional = [self._connection(0), self._connection(1)]
        regional[0].update({"region": "Guangdong", "city": "Guangzhou"})
        regional[1].update({"region": "Beijing", "city": "Beijing"})
        report = self._analyze_rows(regional)
        self.assertIn("NODE_MULTI_REGION", {item["rule_id"] for item in report["findings"]})

        domains = ["accounts.google.com", "auth.openai.com", "login.microsoftonline.com"]
        automated = [
            self._connection(index, destination=domains[index % len(domains)])
            for index in range(20)
        ]
        report = self._analyze_rows(automated)
        automation = next(
            item for item in report["findings"] if item["rule_id"] == "BEHAVIOR_ACCOUNT_AUTOMATION"
        )
        self.assertIn("不代表已确认注册成功", automation["summary"])
        self.assertIn("destination_host", automation["evidence"][0])

    def test_general_connection_burst_is_not_mislabeled_as_account_automation(self):
        rows = [self._connection(index, destination=f"cdn-{index}.example.com") for index in range(200)]
        report = self._analyze_rows(rows)
        rule_ids = {item["rule_id"] for item in report["findings"]}
        self.assertIn("BEHAVIOR_CONNECTION_BURST", rule_ids)
        self.assertNotIn("BEHAVIOR_ACCOUNT_AUTOMATION", rule_ids)


if __name__ == "__main__":
    unittest.main()
