import gzip
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vps_audit.behavior_audit import (
    ARCHIVE_MARKER,
    append_connections,
    list_incidents,
    load_incident,
    maintain_archive,
    read_recent_connections,
    render_ai_review,
    render_incident,
    save_incident_ai_review,
    save_incidents,
)


def connection(timestamp: str, event_id: str) -> dict:
    return {
        "timestamp": timestamp,
        "event_type": "proxy_connection",
        "user": "user-a",
        "source_ip": "198.51.100.9",
        "source_port": 54321,
        "destination_host": "accounts.google.com",
        "destination_ip": "",
        "destination_port": 443,
        "destination_category": "account_service",
        "network": "tcp",
        "inbound_tag": "vless-in",
        "protocol": "xray",
        "node_id": "node_1234567890abcdef12345678",
        "node_name": "vmiss hk",
        "event_id": event_id,
    }


class BehaviorAuditTests(unittest.TestCase):
    def test_connection_archive_rotates_reads_and_retains_private_files(self):
        now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "audit"
            rows = [
                connection("2026-08-26T12:00:00Z", "evt_1111111111111111"),
                connection("2026-08-27T11:59:00Z", "evt_2222222222222222"),
            ]
            self.assertEqual(append_connections(archive, rows), 2)
            status = maintain_archive(archive, 7, 30, 100, now)
            self.assertEqual(status["compressed_files"], 1)
            self.assertTrue((archive / "connections-2026-08-26.jsonl.gz").is_file())
            with gzip.open(archive / "connections-2026-08-26.jsonl.gz", "rt", encoding="utf-8") as handle:
                self.assertIn("accounts.google.com", handle.read())
            recent = read_recent_connections(
                archive, now - timedelta(minutes=5), now, max_events=100
            )
            self.assertEqual([item["event_id"] for item in recent], ["evt_2222222222222222"])
            self.assertTrue((archive / ARCHIVE_MARKER).is_file())
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((archive / "connections-2026-08-27.jsonl").stat().st_mode),
                0o600,
            )

            append_connections(
                archive,
                [
                    connection(
                        f"2026-08-27T11:59:0{index}Z", f"evt_recent_{index:08d}"
                    )
                    for index in range(5)
                ],
            )
            bounded = read_recent_connections(
                archive, now - timedelta(minutes=5), now, max_events=2
            )
            self.assertEqual(
                [item["event_id"] for item in bounded],
                ["evt_recent_00000003", "evt_recent_00000004"],
            )

    def test_capacity_limit_can_remove_current_day_file(self):
        now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "audit"
            append_connections(
                archive,
                [connection("2026-08-27T11:00:00Z", "evt_4444444444444444")],
            )
            current = archive / "connections-2026-08-27.jsonl"
            with current.open("ab") as handle:
                handle.write(os.urandom(1_100_000))
            status = maintain_archive(archive, 7, 30, 1, now)
            self.assertLessEqual(status["archive_bytes"], 1024 * 1024)
            self.assertFalse(current.exists())

    def test_incidents_preserve_ai_reviews_and_expire_independently(self):
        now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)
        finding = {
            "rule_id": "BEHAVIOR_ACCOUNT_AUTOMATION",
            "user": "user-a",
            "severity": "high",
            "score": 60,
            "title": "疑似批量账号注册或认证自动化",
            "summary": "fixture",
            "evidence": [connection("2026-08-27T11:59:00Z", "evt_3333333333333333")],
        }
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "audit"
            saved = save_incidents(archive, [finding], "2026-08-27T12:00:00Z")[0]
            identifier = saved["incident_id"]
            save_incident_ai_review(
                archive,
                identifier,
                {"overall_assessment": "needs review", "cases": []},
                "是否存在自动化？",
            )
            save_incidents(archive, [finding], "2026-08-27T12:01:00Z")
            self.assertEqual(len(load_incident(archive, identifier)["ai_reviews"]), 1)
            self.assertEqual(list_incidents(archive)[0]["incident_id"], identifier)
            self.assertIn("198.51.100.9", render_incident(load_incident(archive, identifier)))

            old = archive / "incidents" / "INC-0000000000000000.json"
            old.write_text(
                json.dumps({"generated_at": "2026-07-01T00:00:00Z"}), encoding="utf-8"
            )
            status = maintain_archive(archive, 7, 30, 100, now)
            self.assertEqual(status["removed_incidents"], 1)
            self.assertFalse(old.exists())

    def test_ai_review_renderer_keeps_review_dimensions(self):
        rendered = render_ai_review(
            {
                "overall_assessment": "需要人工复核",
                "cases": [{
                    "user": "user-a",
                    "assessment": "needs_review",
                    "confidence": 0.75,
                    "facts": ["短时连接较多"],
                    "benign_explanations": ["客户端重试"],
                    "missing_evidence": ["没有 TLS 正文"],
                    "recommended_action": "核对用户用途",
                }],
            }
        )
        self.assertIn("置信度：75%", rendered)
        self.assertIn("可能的正常解释", rendered)
        self.assertIn("不会自动封禁", rendered)


if __name__ == "__main__":
    unittest.main()
