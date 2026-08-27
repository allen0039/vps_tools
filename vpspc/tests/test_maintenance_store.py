import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vps_audit.maintenance.store import MaintenanceStore


NOW = datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc)


def job(job_id: str = "job_12345678", status: str = "created"):
    return {
        "id": job_id,
        "kind": "node_update",
        "status": status,
        "actor": "telegram:1001",
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "updated_at": NOW.isoformat().replace("+00:00", "Z"),
        "targets": ["node_aaaaaaaaaaaaaaaaaaaaaaaa"],
        "results": {},
    }


class MaintenanceStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state" / "maintenance.json"
        self.store = MaintenanceStore(self.path)

    def test_store_keeps_only_current_job_and_consumes_terminal_result(self):
        self.store.begin_job(job())
        with self.assertRaisesRegex(RuntimeError, "already running"):
            self.store.begin_job(job("job_87654321"))

        updated = self.store.update_job("job_12345678", status="success", result={"ok": True}, now=NOW)
        self.assertEqual(updated["result"], {"ok": True})
        self.assertEqual(self.store.consume_terminal_job(), updated)
        self.assertIsNone(self.store.read_current_job())

    def test_confirmation_is_six_digits_hashed_single_use_and_expires(self):
        issued = self.store.issue_confirmation("destroy_all", now=NOW)
        self.assertRegex(issued.code, r"^[0-9]{6}$")
        self.assertEqual(issued.expires_at, (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"))

        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertNotIn(issued.code, json.dumps(raw))
        self.assertNotIn("code", raw["confirmation"])
        self.assertTrue(self.store.consume_confirmation(issued.id, issued.code, "destroy_all", NOW))
        self.assertFalse(self.store.consume_confirmation(issued.id, issued.code, "destroy_all", NOW))

    def test_confirmation_rejects_wrong_action_and_expired_code(self):
        issued = self.store.issue_confirmation("destroy_all", now=NOW)
        self.assertFalse(self.store.consume_confirmation(issued.id, issued.code, "controller_destroy", NOW))
        self.assertFalse(self.store.consume_confirmation(
            issued.id, issued.code, "destroy_all", NOW + timedelta(minutes=5, seconds=1)
        ))

    def test_preferences_have_safe_defaults_and_validate_range(self):
        self.assertEqual(self.store.load_preferences(), {"version_check_enabled": True, "batch_size": 3})
        self.assertFalse(self.store.set_version_check_enabled(False)["version_check_enabled"])
        self.assertEqual(self.store.set_batch_size(10)["batch_size"], 10)
        for value in (0, 11, "invalid"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store.set_batch_size(value)

    def test_expire_removes_unread_terminal_job_and_old_catalog(self):
        terminal = job(status="success")
        terminal["created_at"] = (NOW - timedelta(hours=25)).isoformat().replace("+00:00", "Z")
        terminal["updated_at"] = terminal["created_at"]
        self.store.begin_job(terminal)
        self.store.save_catalog({"checked_at": (NOW - timedelta(hours=25)).isoformat().replace("+00:00", "Z")})
        self.store.expire(NOW)
        self.assertIsNone(self.store.read_current_job())
        self.assertIsNone(self.store.read_catalog())

    def test_short_tasks_are_claimed_only_by_the_target_before_expiry(self):
        node_a = {"node_id": "node_" + "a" * 24, "name": "vmiss hk"}
        node_b = {"node_id": "node_" + "b" * 24, "name": "vmiss sg"}
        created = self.store.create_node_tasks(
            "job_12345678",
            [node_a],
            {"kind": "node_update", "artifact_id": "sha256-" + "a" * 64},
            NOW,
            ttl_seconds=120,
        )
        self.assertEqual(created[0]["node_id"], node_a["node_id"])
        self.assertIsNone(self.store.claim_node_task(node_b["node_id"], NOW))
        self.assertIsNone(self.store.claim_node_task(node_a["node_id"], NOW + timedelta(seconds=121)))
        self.assertEqual(
            self.store.node_results("job_12345678")[node_a["node_id"]]["status"], "expired"
        )

        fresh = self.store.create_node_tasks(
            "job_87654321", [node_a], {"kind": "node_update"}, NOW, ttl_seconds=120
        )
        claimed = self.store.claim_node_task(node_a["node_id"], NOW + timedelta(seconds=30))
        self.assertEqual(claimed["task_id"], fresh[0]["task_id"])
        self.assertEqual(claimed["job_id"], "job_87654321")

    def test_task_cancellation_status_updates_and_results_are_bounded(self):
        node_a = {"node_id": "node_" + "a" * 24, "name": "vmiss hk"}
        node_b = {"node_id": "node_" + "b" * 24, "name": "vmiss sg"}
        tasks = self.store.create_node_tasks(
            "job_12345678", [node_a, node_b], {"kind": "node_update"}, NOW
        )
        claimed = self.store.claim_node_task(node_a["node_id"], NOW)
        cancelled = self.store.cancel_unclaimed_node_tasks("job_12345678", NOW)
        self.assertEqual([item["node_id"] for item in cancelled], [node_b["node_id"]])
        self.assertEqual(self.store.node_results("job_12345678")[node_a["node_id"]]["status"], "claimed")
        self.assertEqual(self.store.node_results("job_12345678")[node_b["node_id"]]["status"], "cancelled")

        self.store.record_node_task_status(
            node_a["node_id"], claimed["task_id"], "downloading", now=NOW
        )
        self.store.record_node_task_status(
            node_a["node_id"], claimed["task_id"], "installing", now=NOW
        )
        finished = self.store.record_node_task_status(
            node_a["node_id"], claimed["task_id"], "rolled_back", result={"error": "health check"}, now=NOW
        )
        self.assertEqual(finished["result"], {"error": "health check"})
        with self.assertRaisesRegex(RuntimeError, "terminal"):
            self.store.record_node_task_status(
                node_a["node_id"], claimed["task_id"], "success", now=NOW
            )
        with self.assertRaisesRegex(PermissionError, "does not belong"):
            self.store.record_node_task_status(
                node_b["node_id"], tasks[0]["task_id"], "success", now=NOW
            )

    def test_consuming_a_terminal_job_also_removes_its_task_history(self):
        node = {"node_id": "node_" + "a" * 24, "name": "vmiss hk"}
        self.store.begin_job(job())
        self.store.create_node_tasks("job_12345678", [node], {"kind": "node_update"}, NOW)
        self.store.update_job("job_12345678", status="success", now=NOW)

        self.store.consume_terminal_job()

        self.assertEqual(self.store.node_results("job_12345678"), {})

    def test_uninstall_receipt_hashes_the_token_and_is_single_use(self):
        node_id = "node_" + "a" * 24
        task_id = "task_" + "b" * 32
        issued = self.store.issue_uninstall_receipt(node_id, task_id, NOW, ttl_seconds=120)
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertNotIn(issued["token"], json.dumps(raw))
        self.assertEqual(len(raw["uninstall_receipts"]), 1)

        self.assertIsNone(
            self.store.consume_uninstall_receipt(
                issued["token"], node_id, task_id, NOW + timedelta(seconds=121)
            )
        )
        issued = self.store.issue_uninstall_receipt(node_id, task_id, NOW, ttl_seconds=120)
        receipt = self.store.consume_uninstall_receipt(issued["token"], node_id, task_id, NOW)
        self.assertEqual(receipt["node_id"], node_id)
        self.assertEqual(receipt["task_id"], task_id)
        self.assertIsNone(self.store.consume_uninstall_receipt(issued["token"], node_id, task_id, NOW))


if __name__ == "__main__":
    unittest.main()
