"""Cross-component lifecycle checks using the real coordinator and stores.

The harness is intentionally filesystem-only.  It proves orchestration never
reaches controller destruction after an unsuccessful node receipt and keeps
foreign node-product sentinels byte-for-byte intact.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from vps_audit.maintenance.coordinator import MaintenanceCoordinator
from vps_audit.maintenance.models import ReleaseManifest, VersionCatalog
from vps_audit.maintenance.store import MaintenanceStore
from vps_audit.node_reporting import NodeRegistry


NOW = datetime(2026, 8, 28, 8, 0, tzinfo=timezone.utc)


def release_manifest() -> ReleaseManifest:
    return ReleaseManifest.from_dict(
        {
            "schema_version": 1,
            "version": "v0.7.0",
            "channel": "stable",
            "source_revision": "a" * 40,
            "controller_protocol": 1,
            "node_protocol": 1,
            "config_schema_min": 1,
            "config_schema_max": 1,
            "controller_upgrade_from": "v0.1.0",
            "controller_downgrade_from": "v1.0.0",
            "node_upgrade_from": "v0.1.0",
            "node_downgrade_from": "v1.0.0",
            "artifacts": {
                "controller": {"name": "controller.tar.gz", "url": "https://github.com/allen0039/vps_tools/releases/download/v0.7.0/controller.tar.gz", "sha256": "b" * 64, "size": 1},
                "node": {"name": "node.py", "url": "https://github.com/allen0039/vps_tools/releases/download/v0.7.0/node.py", "sha256": "c" * 64, "size": 1},
            },
            "docker_digest": "sha256:" + "d" * 64,
        }
    )


class ReleaseSource:
    def __init__(self) -> None:
        self.manifest = release_manifest()

    def resolve(self, channel, version):
        if channel != "stable" or version not in {None, self.manifest.version}:
            raise ValueError("release is unavailable")
        return self.manifest

    def download(self, artifact):
        return Path("/tmp") / artifact.name

    def fetch_catalog(self, *, checked_at=None):
        return VersionCatalog(
            checked_at=(checked_at or NOW).isoformat().replace("+00:00", "Z"),
            stable=self.manifest,
            edge=None,
            releases=(self.manifest,),
        )


class Host:
    def __init__(self) -> None:
        self.native_calls = []
        self.destroy_calls = []
        self.restart_calls = []
        self.jobs = {}

    def job_status(self, job_id):
        return copy.deepcopy(self.jobs.get(job_id, {"status": "unknown"}))

    def native_update(self, **kwargs):
        self.native_calls.append(copy.deepcopy(kwargs))
        result = {"status": "success", "version": "v0.7.0"}
        self.jobs[kwargs["job_id"]] = copy.deepcopy(result)
        return result

    def restart_maintenance(self, **kwargs):
        self.restart_calls.append(copy.deepcopy(kwargs))
        return {"status": "accepted"}

    def controller_destroy(self, **kwargs):
        self.destroy_calls.append(copy.deepcopy(kwargs))
        return {"status": "success", "removed_paths_count": 1}


class MaintenanceLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.store = MaintenanceStore(root / "state" / "maintenance.json")
        self.registry = NodeRegistry(root / "state" / "nodes.json")
        self.host = Host()
        self.coordinator = MaintenanceCoordinator(
            self.store,
            self.registry,
            ReleaseSource(),
            self.host,
            controller_version="0.6.0",
            clock=lambda: NOW,
        )

    def enroll(self, name: str, *, online: bool = True):
        enrollment = self.registry.create_enrollment(name, now=NOW)
        node = self.registry.enroll(
            enrollment["token"],
            {"installation_id": "install_" + name.replace(" ", "_") + "_12345678", "node_name": name, "agent_version": "0.6.0"},
            now=NOW,
        )
        if online:
            self.registry.record_command_heartbeat(node["node_id"], "0.6.0", 1, NOW)
        return node

    def finish_all_active(self, job, results):
        for node_id in job["result"]["active_node_ids"]:
            task = self.store.claim_node_task(node_id, NOW)
            self.assertIsNotNone(task)
            self.store.record_node_task_status(node_id, task["task_id"], results[node_id], {"stage": results[node_id]}, NOW)

    def test_update_all_skips_offline_and_reports_node_rollback(self):
        healthy = self.enroll("vmiss hk")
        failing = self.enroll("oracle jp")
        offline = self.enroll("offline us", online=False)
        job = self.coordinator.start_all_update("stable", None, "web")
        job = self.coordinator.advance_current_job()
        self.assertEqual(job["status"], "controller_restart_pending")
        job = self.coordinator.advance_current_job()
        self.assertEqual(job["status"], "nodes_running")
        self.finish_all_active(job, {healthy["node_id"]: "success", failing["node_id"]: "rolled_back"})
        final = self.coordinator.advance_current_job()
        self.assertEqual(final["status"], "completed_with_failures")
        self.assertNotIn(offline["node_id"], self.store.node_results(final["id"]))
        self.assertEqual(final["result"]["nodes"][failing["node_id"]]["status"], "rolled_back")
        self.assertEqual(len(self.host.native_calls), 1)

    def test_failed_node_destroy_keeps_controller_and_third_party_sentinels(self):
        first = self.enroll("vmiss hk")
        second = self.enroll("oracle jp")
        root = Path(self.temporary.name)
        sentinels = {
            root / "third-party" / "xray" / "access.log": b"xray\n",
            root / "third-party" / "miaomiaowux" / "config.json": b"{}\n",
            root / "third-party" / "systemd" / "xrayagent.service": b"[Service]\n",
        }
        for path, payload in sentinels.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        before = {path: path.read_bytes() for path in sentinels}

        confirmation = self.coordinator.issue_confirmation("full_destroy")
        job = self.coordinator.start_full_destroy("tg:1", confirmation["id"], confirmation["code"])
        self.finish_all_active(job, {first["node_id"]: "success", second["node_id"]: "failed"})
        final = self.coordinator.advance_current_job()

        self.assertEqual(final["status"], "blocked_before_controller_destroy")
        self.assertEqual(self.host.destroy_calls, [])
        self.assertEqual({path: path.read_bytes() for path in sentinels}, before)


if __name__ == "__main__":
    unittest.main()
