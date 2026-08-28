import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from vps_audit.web import create_handler
from http.server import ThreadingHTTPServer


class WebTests(unittest.TestCase):
    def test_api_requires_token_and_reads_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = root / "web.token"
            token.write_text("test-token\n", encoding="utf-8")
            report_dir = root / "reports"
            report_dir.mkdir()
            (report_dir / "latest.json").write_text(json.dumps({"summary": {"event_count": 2}}), encoding="utf-8")
            config = root / "config.json"
            config.write_text(json.dumps({
                "web": {"enabled": True, "listen_host": "127.0.0.1", "listen_port": 8787, "token_file": str(token)},
                "state_dir": str(root / "state"), "report_dir": str(report_dir), "behavior_audit": {"enabled": False, "archive_dir": str(root / "archive"), "retention_days": 7, "incident_retention_days": 30, "max_disk_mb": 100, "max_analysis_events": 1000, "ai_include_full_metadata": True},
                "subscription_monitoring": {"enabled": True, "mode": "all", "users": []}, "openai_review": {"enabled": False, "active_provider": "", "providers": {}},
                "telegram": {"enabled": False, "bot_management_enabled": False, "admin_user_ids": [], "minimum_severity": "high"},
            }), encoding="utf-8")
            server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(str(config)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection(*server.server_address, timeout=3)
                connection.request("GET", "/")
                self.assertEqual(connection.getresponse().status, 200)
                connection.close()
                connection = HTTPConnection(*server.server_address, timeout=3)
                connection.request("GET", "/favicon.ico")
                self.assertEqual(connection.getresponse().status, 204)
                connection.close()
                connection = HTTPConnection(*server.server_address, timeout=3)
                connection.request("GET", "/api/report")
                self.assertEqual(connection.getresponse().status, 401)
                connection.close()
                connection = HTTPConnection(*server.server_address, timeout=3)
                connection.request("GET", "/api/report", headers={"X-Web-Token": "test-token"})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())["summary"]["event_count"], 2)
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
