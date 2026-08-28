from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from vps_audit.maintenance.coordinator import MaintenanceCoordinator
from vps_audit.maintenance.models import ReleaseManifest, VersionCatalog
from vps_audit.maintenance.store import MaintenanceStore
from vps_audit.node_reporting import NodeRegistry


def release_fixture() -> ReleaseManifest:
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
                "controller": {
                    "name": "vpspc-controller-v0.7.0.tar.gz",
                    "url": "https://github.com/allen0039/vps_tools/releases/download/v0.7.0/vpspc-controller-v0.7.0.tar.gz",
                    "sha256": "b" * 64,
                    "size": 123,
                },
                "node": {
                    "name": "vpspc-node-v0.7.0.py",
                    "url": "https://github.com/allen0039/vps_tools/releases/download/v0.7.0/vpspc-node-v0.7.0.py",
                    "sha256": "c" * 64,
                    "size": 456,
                },
            },
            "docker_digest": "sha256:" + "d" * 64,
        }
    )


class FakeReleases:
    def __init__(self, manifest: ReleaseManifest):
        self.manifest = manifest
        self.downloaded = []

    def fetch_catalog(self, *, checked_at=None):
        return VersionCatalog(
            checked_at=(checked_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
            stable=self.manifest,
            edge=None,
            releases=(self.manifest,),
        )

    def resolve(self, channel, version):
        if channel != "stable" or version not in {None, self.manifest.version}:
            raise ValueError("release is unavailable")
        return self.manifest

    def download(self, artifact):
        self.downloaded.append(artifact.name)
        return Path("/tmp") / artifact.name


class FakeHostUpdater:
    def __init__(self, controller_result=None):
        self.controller_result = controller_result or {"status": "success", "version": "v0.7.0"}
        self.native_calls = []
        self.destroy_calls = []
        self.restart_calls = []
        self.jobs = {}

    def native_update(self, **kwargs):
        self.native_calls.append(kwargs)
        result = copy.deepcopy(self.controller_result)
        self.jobs[kwargs["job_id"]] = result
        return result

    def job_status(self, job_id):
        return copy.deepcopy(self.jobs.get(job_id, {"status": "unknown"}))

    def restart_maintenance(self, **kwargs):
        self.restart_calls.append(kwargs)
        return {"status": "accepted"}

    def controller_destroy(self, **kwargs):
        self.destroy_calls.append(kwargs)
        return {"status": "success", "removed_paths_count": 4}


class MaintenanceCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.now = datetime(2026, 8, 28, 8, 0, tzinfo=timezone.utc)
        self.store = MaintenanceStore(self.root / "maintenance.json")
        self.registry = NodeRegistry(self.root / "nodes.json")
        self.releases = FakeReleases(release_fixture())
        self.host = FakeHostUpdater()
        self.coordinator = MaintenanceCoordinator(
            self.store,
            self.registry,
            self.releases,
            self.host,
            controller_version="0.6.0",
            clock=lambda: self.now,
        )
        self.store.set_batch_size(1)

    def enroll(self, name: str, version="0.6.0", online=True):
        enrollment = self.registry.create_enrollment(name, now=self.now)
        node = self.registry.enroll(
            enrollment["token"],
            {"installation_id": "install_" + name.replace(" ", "_") + "_12345678", "node_name": name, "agent_version": version},
            now=self.now,
        )
        if online:
            self.registry.record_command_heartbeat(node["node_id"], version, 1, self.now)
        return node

    def finish_active(self, node_id: str, status: str):
        task = self.store.claim_node_task(node_id, self.now)
        self.assertIsNotNone(task)
        self.store.record_node_task_status(node_id, task["task_id"], status, {"stage": status}, self.now)

    def test_node_update_continues_after_rollback_and_reports_names(self):
        first = self.enroll("vmiss hk")
        second = self.enroll("oracle jp")
        third = self.enroll("us west")

        job = self.coordinator.start_node_update("stable", None, [first["node_id"], second["node_id"], third["node_id"]], "tg:1")
        self.assertEqual(job["status"], "nodes_running")
        self.finish_active(first["node_id"], "success")
        self.coordinator.advance_current_job()
        self.finish_active(second["node_id"], "rolled_back")
        self.coordinator.advance_current_job()
        self.finish_active(third["node_id"], "success")
        final = self.coordinator.advance_current_job()

        self.assertEqual(final["status"], "completed_with_failures")
        failures = final["result"]["failures"]
        self.assertEqual([(item["node_name"], item["status"]) for item in failures], [("oracle jp", "rolled_back")])
        self.assertEqual(self.releases.downloaded.count("vpspc-node-v0.7.0.py"), 3)

    def test_offline_node_is_reported_as_skipped_without_a_task(self):
        online = self.enroll("online")
        offline = self.enroll("offline", online=False)
        job = self.coordinator.start_node_update("stable", None, [online["node_id"], offline["node_id"]], "web")
        self.assertEqual(job["result"]["nodes"][offline["node_id"]]["status"], "skipped")
        tasks = self.store.node_results(job["id"])
        self.assertEqual(set(tasks), {online["node_id"]})

    def test_full_destroy_never_calls_helper_when_one_node_fails(self):
        first = self.enroll("vmiss hk")
        second = self.enroll("oracle jp")
        confirmation = self.coordinator.issue_confirmation("full_destroy")
        job = self.coordinator.start_full_destroy("tg:1", confirmation["id"], confirmation["code"])
        first_active = job["result"]["active_node_ids"][0]
        self.finish_active(first_active, "success")
        next_batch = self.coordinator.advance_current_job()
        second_active = next_batch["result"]["active_node_ids"][0]
        self.finish_active(second_active, "failed")
        final = self.coordinator.advance_current_job()

        self.assertEqual(final["status"], "blocked_before_controller_destroy")
        self.assertEqual(self.host.destroy_calls, [])

    def test_all_update_starts_controller_then_online_nodes(self):
        node = self.enroll("vmiss hk")
        job = self.coordinator.start_all_update("stable", None, "web")
        self.assertEqual(job["status"], "controller_queued")
        restarting = self.coordinator.advance_current_job()
        self.assertEqual(restarting["status"], "controller_restart_pending")
        self.assertEqual(self.host.restart_calls, [{"job_id": job["id"]}])
        running = self.coordinator.advance_current_job()
        self.assertEqual(running["status"], "nodes_running")
        self.assertEqual(len(self.host.native_calls), 1)
        self.finish_active(node["node_id"], "success")
        self.assertEqual(self.coordinator.advance_current_job()["status"], "success")

    def test_confirmation_is_one_time_and_controller_destroy_requires_second_step(self):
        node = self.enroll("vmiss hk")
        initial = self.coordinator.issue_confirmation("full_destroy")
        job = self.coordinator.start_full_destroy("tg:1", initial["id"], initial["code"])
        self.finish_active(node["node_id"], "success")
        awaiting = self.coordinator.advance_current_job()
        self.assertEqual(awaiting["status"], "awaiting_controller_confirmation")
        final_code = self.coordinator.issue_confirmation("controller_destroy")
        queued = self.coordinator.confirm_controller_destroy(final_code["id"], final_code["code"])
        self.assertEqual(queued["status"], "controller_destroy_queued")
        final = self.coordinator.advance_current_job()
        self.assertEqual(final["status"], "controller_destroy_running")
        self.assertEqual(self.host.destroy_calls[0]["job_id"], job["id"])


if __name__ == "__main__":
    unittest.main()
