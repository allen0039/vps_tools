import json
import tempfile
import unittest
from pathlib import Path

from vps_audit.bot import _authorized, _handle
from vps_audit.runtime import load_runtime_config


class BotTests(unittest.TestCase):
    def _config(self, root: Path) -> Path:
        path = root / "config.json"
        path.write_text(
            json.dumps(
                {
                    "state_dir": str(root / "state"),
                    "report_dir": str(root / "reports"),
                    "telegram": {
                        "enabled": True,
                        "chat_id": "-100500",
                        "bot_management_enabled": True,
                        "admin_user_ids": [12345],
                    },
                    "openai_review": {"enabled": False},
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_authorization_requires_configured_chat_and_sender(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = load_runtime_config(str(self._config(Path(temporary))))
            self.assertTrue(_authorized(config, {"id": -100500}, 12345))
            self.assertFalse(_authorized(config, {"id": -100500}, 99999))
            self.assertFalse(_authorized(config, {"id": -100999}, 12345))

    def test_commands_manage_multiple_users_and_thresholds(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            pending = {}
            _handle(str(path), 12345, "/mode allowlist", pending)
            _handle(str(path), 12345, "/adduser alice", pending)
            _handle(str(path), 12345, "/adduser bob", pending)
            _handle(str(path), 12345, "/set subscription_ip_count 11", pending)
            config = load_runtime_config(str(path))
            self.assertEqual(config["subscription_monitoring"]["mode"], "allowlist")
            self.assertEqual(config["subscription_monitoring"]["users"], ["alice", "bob"])
            self.assertEqual(config["rules"]["thresholds"]["subscription_ip_count"], 11)

    def test_button_prompt_uses_per_admin_pending_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            pending = {}
            response, keyboard = _handle(str(path), 12345, "prompt:adduser", pending)
            self.assertIn("请发送", response)
            self.assertIsNone(keyboard)
            _handle(str(path), 12345, "carol", pending)
            self.assertNotIn("12345", pending)
            self.assertEqual(load_runtime_config(str(path))["subscription_monitoring"]["users"], ["carol"])


if __name__ == "__main__":
    unittest.main()
