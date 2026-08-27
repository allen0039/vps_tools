import json
import stat
import tempfile
import unittest
from pathlib import Path

from vps_audit.runtime import load_runtime_config, normalize_runtime_config
from vps_audit.settings import (
    add_monitored_user,
    remove_ai_provider,
    remove_monitored_user,
    set_active_ai_provider,
    set_ai_enabled,
    set_ai_provider_model,
    set_monitoring_mode,
    set_telegram_option,
    set_threshold,
    upsert_ai_provider,
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

    def test_legacy_single_provider_config_is_migrated_in_memory(self):
        config = normalize_runtime_config(
            {
                "openai_review": {
                    "enabled": True,
                    "api_key_file": "/etc/vps-audit/openai.key",
                    "model": "legacy-model",
                }
            }
        )
        self.assertEqual(config["openai_review"]["active_provider"], "legacy")
        self.assertEqual(config["openai_review"]["providers"]["legacy"]["api_mode"], "responses")
        self.assertNotIn("model", config["openai_review"])

    def test_multiple_ai_providers_can_be_switched_and_updated(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            upsert_ai_provider(
                str(path),
                "openai",
                "OpenAI",
                "https://api.openai.com/v1",
                "responses",
                str(Path(temporary) / "openai.key"),
                "model-a",
                30,
            )
            upsert_ai_provider(
                str(path),
                "vendor",
                "Vendor",
                "https://vendor.example/v1",
                "chat_completions",
                str(Path(temporary) / "vendor.key"),
                "model-b",
                45,
            )
            set_active_ai_provider(str(path), "vendor")
            set_ai_provider_model(str(path), "vendor", "model-c")
            set_ai_enabled(str(path), True)
            config = load_runtime_config(str(path))
            self.assertEqual(config["openai_review"]["active_provider"], "vendor")
            self.assertEqual(config["openai_review"]["providers"]["vendor"]["model"], "model-c")
            self.assertTrue(config["openai_review"]["enabled"])
            remove_ai_provider(str(path), "vendor")
            config = load_runtime_config(str(path))
            self.assertEqual(config["openai_review"]["active_provider"], "openai")

    def test_ai_provider_rejects_credentialed_or_invalid_url(self):
        with self.assertRaisesRegex(ValueError, "plain HTTP"):
            normalize_runtime_config(
                {
                    "openai_review": {
                        "enabled": False,
                        "providers": {
                            "bad": {
                                "display_name": "Bad",
                                "base_url": "https://user:pass@example.com/v1",
                                "api_mode": "chat_completions",
                                "api_key_file": "/etc/vps-audit/bad.key",
                                "model": "model",
                            }
                        },
                    }
                }
            )

        with self.assertRaisesRegex(ValueError, "plain HTTP"):
            normalize_runtime_config(
                {
                    "openai_review": {
                        "enabled": False,
                        "active_provider": "vendor",
                        "providers": {
                            "vendor": {
                                "base_url": "https://vendor.example/v1\ninvalid",
                                "api_key_file": "/etc/vps-audit/vendor.key",
                                "model": "model-a",
                            }
                        },
                    }
                }
            )


if __name__ == "__main__":
    unittest.main()
