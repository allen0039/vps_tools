from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from vps_audit.maintenance.client import MaintenanceClient
from vps_audit.maintenance.service import MaintenanceAPI, make_server

from tests.test_maintenance_coordinator import (
    FakeHostUpdater,
    FakeReleases,
    MaintenanceCoordinator,
    MaintenanceStore,
    NodeRegistry,
    release_fixture,
)


class MaintenanceServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.server_path = root / "maintenance.sock"
        self.coordinator = MaintenanceCoordinator(
            MaintenanceStore(root / "maintenance.json"),
            NodeRegistry(root / "nodes.json"),
            FakeReleases(release_fixture()),
            FakeHostUpdater(),
            controller_version="0.6.0",
        )
        self.server = make_server(self.server_path, MaintenanceAPI(self.coordinator))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = MaintenanceClient(self.server_path, timeout_seconds=2)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_status_check_and_fixed_start_schema(self):
        status = self.client.request("GET", "/v1/status")
        self.assertEqual(status["status"]["controller_version"], "0.6.0")

        checked = self.client.request("POST", "/v1/check", {})
        self.assertEqual(checked["catalog"]["stable"]["version"], "v0.7.0")

        with self.assertRaisesRegex(RuntimeError, "unsupported maintenance action"):
            self.client.request("POST", "/v1/start", {"action": "shell", "actor": "web"})
        with self.assertRaisesRegex(RuntimeError, "fields are invalid"):
            self.client.request("POST", "/v1/start", {"action": "controller_update", "actor": "web", "command": "id"})

    def test_preferences_require_known_types(self):
        result = self.client.request("POST", "/v1/preferences", {"version_check_enabled": False, "batch_size": 4})
        self.assertFalse(result["preferences"]["version_check_enabled"])
        self.assertEqual(result["preferences"]["batch_size"], 4)
        with self.assertRaisesRegex(RuntimeError, "batch_size"):
            self.client.request("POST", "/v1/preferences", {"batch_size": True})


if __name__ == "__main__":
    unittest.main()
