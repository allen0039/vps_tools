import json
import stat
import tempfile
import unittest
from pathlib import Path

from vps_audit.runtime import load_runtime_config, normalize_runtime_config
from vps_audit.settings import (
    add_monitored_user,
    remove_monitored_user,
    set_monitoring_mode,
    set_telegram_option,
    set_threshold,
)


class SettingsTests(unittest.TestCase):
    def _config(self, root: Path) -> Path:
        path = root / "config.json"
        path.write_text(
            json.dumps(
                {
                    "state_dir": str(root / "state"),
                    "report_dir": str(root / "reports"),
                    "telegram": {"enabled": False},
                    "openai_review": {"enabled": False},
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_old_config_defaults_to_monitoring_all_subscription_users(self):
        config = normalize_runtime_config({})
        self.assertEqual(config["subscription_monitoring"], {"enabled": True, "mode": "all", "users": []})
        self.assertFalse(config["telegram"]["bot_management_enabled"])

    def test_atomic_multi_user_and_threshold_updates(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            set_monitoring_mode(str(path), "allowlist")
            add_monitored_user(str(path), "alice")
            add_monitored_user(str(path), "bob")
            add_monitored_user(str(path), "alice")
            set_threshold(str(path), "subscription_ip_count", 12)
            set_telegram_option(str(path), "cooldown_hours", 2.5)
            config = load_runtime_config(str(path))
            self.assertEqual(config["subscription_monitoring"]["users"], ["alice", "bob"])
            self.assertEqual(config["rules"]["thresholds"]["subscription_ip_count"], 12)
            self.assertEqual(config["telegram"]["cooldown_hours"], 2.5)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((path.parent / "config.json.lock").stat().st_mode), 0o600)
            remove_monitored_user(str(path), "alice")
            self.assertEqual(load_runtime_config(str(path))["subscription_monitoring"]["users"], ["bob"])

    def test_invalid_update_does_not_replace_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            before = path.read_text(encoding="utf-8")
            with self.assertRaises(ValueError):
                set_threshold(str(path), "subscription_ip_count", 1)
            self.assertEqual(path.read_text(encoding="utf-8"), before)

    def test_bot_management_requires_chat_and_admin_user_id(self):
        with self.assertRaisesRegex(ValueError, "administrator"):
            normalize_runtime_config(
                {
                    "telegram": {
                        "enabled": True,
                        "chat_id": "-100123",
                        "bot_management_enabled": True,
                        "admin_user_ids": [],
                    }
                }
            )


if __name__ == "__main__":
    unittest.main()
