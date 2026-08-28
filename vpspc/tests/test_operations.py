import tempfile
import unittest
from pathlib import Path

from vps_audit.operations import OperationStore


class OperationStoreTests(unittest.TestCase):
    def test_queue_claim_complete_and_dedupe_by_update_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = OperationStore(Path(temporary) / "operations.json")
            first = store.enqueue(
                update_id=99,
                actor_id=123,
                chat_id="-100500",
                message_id=77,
                value="/run",
            )
            duplicate = store.enqueue(
                update_id=99,
                actor_id=123,
                chat_id="-100500",
                message_id=77,
                value="/run",
            )
            self.assertEqual(first["id"], duplicate["id"])
            claimed = store.claim_next()
            self.assertEqual(claimed["status"], "running")
            finished = store.complete(claimed["id"], success=True, text="done")
            self.assertEqual(finished["status"], "success")
            self.assertIn("done", store.read(claimed["id"])["result"]["text"])

    def test_restart_marks_running_job_failed_without_replaying_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = OperationStore(Path(temporary) / "operations.json")
            item = store.enqueue(
                update_id=100,
                actor_id=123,
                chat_id="-100500",
                message_id=None,
                value="/run",
            )
            store.claim_next()
            self.assertEqual(store.recover_running(), 1)
            recovered = store.read(item["id"])
            self.assertEqual(recovered["status"], "failed")
            self.assertIn("未自动重试", recovered["result"]["text"])
            self.assertIsNone(store.claim_next())


if __name__ == "__main__":
    unittest.main()
