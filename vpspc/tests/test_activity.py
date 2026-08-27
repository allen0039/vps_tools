import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from vps_audit.activity import query_active_subscription_ips, render_active_ip_query
from vps_audit.runtime import normalize_runtime_config


class ActivityTests(unittest.TestCase):
    def test_query_deduplicates_recent_ips_and_keeps_location(self):
        now = datetime(2026, 8, 27, 1, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir()
            rows = [
                {
                    "timestamp": "2026-08-27T01:10:00Z",
                    "event_type": "subscription_access",
                    "user": "alice",
                    "source_ip": "198.51.100.1",
                    "country": "CN",
                    "region": "Guangdong",
                    "city": "Guangzhou",
                    "asn": 64511,
                    "isp": "Example ISP",
                    "device_id": "phone",
                },
                {
                    "timestamp": "2026-08-27T01:22:00Z",
                    "event_type": "subscription_access",
                    "user": "alice",
                    "source_ip": "198.51.100.1",
                    "city": "Guangzhou",
                    "device_id": "laptop",
                },
                {
                    "timestamp": "2026-08-27T01:24:00Z",
                    "event_type": "proxy_activity",
                    "user": "alice",
                    "source_ip": "198.51.100.1",
                    "node_name": "edge-1",
                },
                {
                    "timestamp": "2026-08-27T01:25:00Z",
                    "event_type": "subscription_access",
                    "user": "alice",
                    "source_ip": "203.0.113.8",
                    "country": "CN",
                    "region": "Beijing",
                    "city": "Beijing",
                },
                {
                    "timestamp": "2026-08-27T00:30:00Z",
                    "event_type": "subscription_access",
                    "user": "alice",
                    "source_ip": "192.0.2.9",
                },
                {
                    "timestamp": "2026-08-27T01:29:00Z",
                    "event_type": "subscription_access",
                    "user": "bob",
                    "source_ip": "192.0.2.10",
                },
                {
                    "timestamp": "2026-08-27T01:29:00Z",
                    "event_type": "subscription_access",
                    "user": "alice",
                    "source_ip": "not-an-ip\nspoofed",
                },
            ]
            (state / "events.jsonl").write_text(
                "{broken\n" + "\n".join(json.dumps(row) for row in rows) + "\n",
                encoding="utf-8",
            )
            config = normalize_runtime_config(
                {
                    "state_dir": str(state),
                    "rules": {"thresholds": {"subscription_window_minutes": 30}},
                }
            )
            result = query_active_subscription_ips(config, "alice", now)

        self.assertEqual(result["ip_count"], 2)
        self.assertEqual(result["ips"][0]["source_ip"], "203.0.113.8")
        first_ip = next(item for item in result["ips"] if item["source_ip"] == "198.51.100.1")
        self.assertEqual(first_ip["access_count"], 3)
        self.assertEqual(first_ip["device_count"], 2)
        self.assertEqual(first_ip["region"], "Guangdong")
        self.assertEqual(first_ip["asn"], 64511)
        self.assertEqual(first_ip["nodes"], ["edge-1"])
        self.assertTrue(result["includes_proxy_activity"])
        self.assertGreaterEqual(result["parse_error_count"], 1)

    def test_render_masks_telegram_ip_and_marks_non_concurrent_semantics(self):
        result = {
            "user": "alice",
            "window_minutes": 15,
            "ip_count": 1,
            "ips": [{
                "source_ip": "198.51.100.9",
                "country": "CN",
                "region": "Shanghai",
                "city": "Shanghai",
                "asn": 64512,
                "last_seen": "2026-08-27T01:29:00Z",
                "access_count": 1,
                "device_count": 0,
            }],
        }
        rendered = render_active_ip_query(result, include_source_ip=False)
        self.assertIn("198.51.*.*", rendered)
        self.assertNotIn("198.51.100.9", rendered)
        self.assertIn("不是严格 TCP/节点同时在线数", rendered)
        self.assertIn("CN/Shanghai/Shanghai", rendered)


if __name__ == "__main__":
    unittest.main()
