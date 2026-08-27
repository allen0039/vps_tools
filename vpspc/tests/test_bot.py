import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vps_audit.bot import _DISCOVERY_CACHE, _authorized, _handle, _update_context, run_bot
from vps_audit.runtime import load_runtime_config
from vps_audit.settings import upsert_ai_provider
from vps_audit.telegram import TelegramTransientError


class BotTests(unittest.TestCase):
    def _config(self, root: Path) -> Path:
        token_file = root / "telegram.token"
        token_file.write_text("test-token\n", encoding="utf-8")
        path = root / "config.json"
        path.write_text(
            json.dumps(
                {
                    "state_dir": str(root / "state"),
                    "report_dir": str(root / "reports"),
                    "telegram": {
                        "enabled": True,
                        "token_file": str(token_file),
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

    def test_discovered_users_are_paginated_and_can_be_toggled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            state = root / "state"
            state.mkdir()
            events = []
            for index in range(18):
                events.append(
                    json.dumps(
                        {
                            "timestamp": f"2026-08-27T00:{index:02d}:00Z",
                            "event_type": "subscription_access",
                            "user": f"user-{index:02d}",
                            "source_ip": "198.51.100.1",
                        }
                    )
                )
            (state / "events.jsonl").write_text("\n".join(events) + "\n", encoding="utf-8")
            _DISCOVERY_CACHE.clear()
            response, keyboard = _handle(str(path), 12345, "discover:0", {})
            self.assertIn("发现 18 个", response)
            callbacks = [button["callback_data"] for row in keyboard["inline_keyboard"] for button in row]
            self.assertIn("discover:1", callbacks)
            add_callback = next(value for value in callbacks if value.startswith("discover:add:"))
            response, keyboard = _handle(str(path), 12345, add_callback, {})
            self.assertIn("第 1/3 页", response)
            selected = load_runtime_config(str(path))["subscription_monitoring"]["users"]
            self.assertEqual(len(selected), 1)
            callbacks = [button["callback_data"] for row in keyboard["inline_keyboard"] for button in row]
            remove_callback = next(value for value in callbacks if value.startswith("discover:remove:"))
            _handle(str(path), 12345, remove_callback, {})
            self.assertEqual(load_runtime_config(str(path))["subscription_monitoring"]["users"], [])

    def test_polling_timeout_retries_without_exiting_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            with patch(
                "vps_audit.bot.get_updates",
                side_effect=[TelegramTransientError("timeout"), []],
            ) as get_updates_mock, patch("vps_audit.bot.time.sleep") as sleep_mock:
                run_bot(str(path), once=True)
            self.assertEqual(get_updates_mock.call_count, 2)
            sleep_mock.assert_called_once_with(1.0)

    def test_callback_context_includes_message_id_for_in_place_updates(self):
        chat, sender_id, value, callback_id, message_id = _update_context(
            {
                "callback_query": {
                    "id": "callback-1",
                    "from": {"id": 12345},
                    "data": "discover:0",
                    "message": {"message_id": 77, "chat": {"id": -100500}},
                }
            }
        )
        self.assertEqual(chat["id"], -100500)
        self.assertEqual(sender_id, 12345)
        self.assertEqual(value, "discover:0")
        self.assertEqual(callback_id, "callback-1")
        self.assertEqual(message_id, 77)

    def test_ai_providers_can_be_switched_and_tested_from_telegram(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            for provider_id in ("first", "second"):
                key_file = root / f"{provider_id}.key"
                key_file.write_text("secret\n", encoding="utf-8")
                upsert_ai_provider(
                    str(path),
                    provider_id,
                    provider_id.title(),
                    f"https://{provider_id}.example/v1",
                    "chat_completions",
                    str(key_file),
                    f"{provider_id}-model",
                    15,
                )
            response, keyboard = _handle(str(path), 12345, "ai:use:second", {})
            self.assertIn("已切换", response)
            self.assertEqual(load_runtime_config(str(path))["openai_review"]["active_provider"], "second")
            with patch(
                "vps_audit.bot.test_configured_ai_provider",
                return_value={
                    "display_name": "Second",
                    "model": "second-model",
                    "api_mode": "chat_completions",
                    "latency_ms": 321,
                },
            ):
                response, keyboard = _handle(str(path), 12345, "ai:test", {})
            self.assertIn("321 ms", response)
            callback_values = [
                button["callback_data"] for row in keyboard["inline_keyboard"] for button in row
            ]
            self.assertIn("ai:use:first", callback_values)

    def test_active_ip_query_selects_added_user_and_masks_ip(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            _handle(str(path), 12345, "/adduser alice", {})
            response, keyboard = _handle(str(path), 12345, "activeips:0", {})
            self.assertIn("请选择", response)
            callback = next(
                button["callback_data"]
                for row in keyboard["inline_keyboard"]
                for button in row
                if button["callback_data"].startswith("activeips:user:")
            )
            with patch(
                "vps_audit.bot.query_active_subscription_ips",
                return_value={
                    "user": "alice",
                    "window_minutes": 15,
                    "ip_count": 1,
                    "ips": [{
                        "source_ip": "198.51.100.9",
                        "country": "CN",
                        "region": "Guangdong",
                        "city": "Guangzhou",
                        "last_seen": "2026-08-27T01:29:00Z",
                        "access_count": 1,
                        "device_count": 0,
                    }],
                },
            ):
                response, keyboard = _handle(str(path), 12345, callback, {})
            self.assertIn("活跃 IP：1 个", response)
            self.assertIn("198.51.*.*", response)
            self.assertNotIn("198.51.100.9", response)
            self.assertTrue(any(
                button["callback_data"].startswith("activeips:user:")
                for row in keyboard["inline_keyboard"] for button in row
            ))

    def test_active_ip_command_rejects_user_not_in_focus_list(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            with self.assertRaisesRegex(ValueError, "已经添加"):
                _handle(str(path), 12345, "/ips outsider", {})


if __name__ == "__main__":
    unittest.main()
