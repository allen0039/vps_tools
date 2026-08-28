from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from vps_audit.web import create_handler
from vps_audit.web_ui import PAGE


class FakeMaintenance:
    def __init__(self):
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path == "/v1/status":
            return {"ok": True, "status": {"controller_version": "0.6.0", "nodes": [], "preferences": {}, "catalog": {}}}
        if path == "/v1/start":
            return {"ok": True, "job": {"id": "job_12345678", "status": "nodes_queued"}}
        raise AssertionError((method, path, body))


class WebMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        token = root / "web.token"
        token.write_text("test-token\n", encoding="utf-8")
        self.config = root / "config.json"
        self.config.write_text(
            json.dumps(
                {
                    "web": {"enabled": True, "listen_host": "127.0.0.1", "listen_port": 8787, "token_file": str(token)},
                    "state_dir": str(root / "state"),
                    "report_dir": str(root / "reports"),
                    "behavior_audit": {"enabled": False, "archive_dir": str(root / "archive")},
                    "subscription_monitoring": {"enabled": True, "mode": "all", "users": []},
                    "openai_review": {"enabled": False, "active_provider": "", "providers": {}},
                    "telegram": {"enabled": False, "bot_management_enabled": False, "admin_user_ids": [], "minimum_severity": "high"},
                }
            ),
            encoding="utf-8",
        )
        self.maintenance = FakeMaintenance()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(str(self.config), self.maintenance))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, payload=None, token=True):
        connection = HTTPConnection(*self.server.server_address, timeout=3)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Web-Token"] = "test-token"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        value = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, value

    def test_maintenance_api_requires_token_and_forwards_exact_node_ids(self):
        status, _ = self.request("POST", "/api/maintenance/start", {}, token=False)
        self.assertEqual(status, 401)

        status, result = self.request("POST", "/api/maintenance/start", {"action": "shell", "command": "id"})
        self.assertEqual(status, 400)
        self.assertIn("fields are invalid", result["error"])

        selected = ["node_1234567890abcdef12345678", "node_abcdefabcdefabcdefabcdef"]
        status, result = self.request(
            "POST",
            "/api/maintenance/start",
            {"action": "node_update", "channel": "stable", "version": None, "node_ids": selected},
        )
        self.assertEqual(status, 202)
        self.assertEqual(result["job"]["status"], "nodes_queued")
        forwarded = self.maintenance.calls[-1]
        self.assertEqual(forwarded[0:2], ("POST", "/v1/start"))
        self.assertEqual(forwarded[2]["node_ids"], selected)
        self.assertEqual(forwarded[2]["actor"], "web")

    def test_web_shell_contains_update_and_destroy_views(self):
        connection = HTTPConnection(*self.server.server_address, timeout=3)
        connection.request("GET", "/")
        response = connection.getresponse()
        page = response.read().decode("utf-8")
        connection.close()
        self.assertEqual(response.status, 200)
        self.assertIn("更新管理", page)
        self.assertIn("彻底卸载", page)
        self.assertIn('type="checkbox"', page)

    def test_embedded_management_javascript_has_valid_syntax(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable for JavaScript syntax validation")
        match = re.search(r"<script>(.*)</script>", PAGE, flags=re.DOTALL)
        self.assertIsNotNone(match)
        checked = subprocess.run(
            [node, "--check"],
            input=match.group(1),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
