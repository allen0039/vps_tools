import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vps_audit.behavior_audit import save_incidents
from vps_audit.bot import _DISCOVERY_CACHE, _apply_pending, _authorized, _handle, _update_context, run_bot
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

    def test_web_menu_can_view_and_regenerate_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            web_token = root / "web.token"
            web_token.write_text("old-web-token\n", encoding="utf-8")
            data = json.loads(path.read_text(encoding="utf-8"))
            data["web"] = {
                "enabled": True,
                "listen_host": "127.0.0.1",
                "listen_port": 18381,
                "token_file": str(web_token),
            }
            path.write_text(json.dumps(data), encoding="utf-8")
            response, keyboard = _handle(str(path), 12345, "menu:web", {})
            self.assertIn("18381", response)
            callbacks = [
                button["callback_data"]
                for row in keyboard["inline_keyboard"]
                for button in row
            ]
            self.assertIn("web:show", callbacks)
            response, _ = _handle(str(path), 12345, "web:show", {})
            self.assertIn("old-web-token", response)
            response, keyboard = _handle(str(path), 12345, "web:regenerate", {})
            self.assertIn("确认", response)
            with patch(
                "vps_audit.bot.subprocess.run",
                side_effect=[
                    subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 0, stdout="active\n"),
                ],
            ):
                response, _ = _handle(str(path), 12345, "web:regenerate:yes", {})
            self.assertIn("已重新生成", response)
            self.assertNotEqual(web_token.read_text(encoding="utf-8").strip(), "old-web-token")

    def test_nodes_menu_generates_named_deployment_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["node_reporting"] = {
                "mode": "node_reporting",
                "public_base_url": "https://monitor.example.com",
                "registry_file": str(root / "nodes.json"),
                "inbox_file": str(root / "node-inbox.jsonl"),
                "agent_asset_path": str(root / "node.py"),
            }
            Path(data["node_reporting"]["agent_asset_path"]).write_text("# agent\n", encoding="utf-8")
            path.write_text(json.dumps(data), encoding="utf-8")
            response, keyboard = _handle(str(path), 12345, "/nodes", {})
            self.assertIn("已注册节点：0", response)
            callbacks = [
                button["callback_data"]
                for row in keyboard["inline_keyboard"]
                for button in row
            ]
            self.assertIn("prompt:node:normal", callbacks)
            pending = {}
            response, _ = _handle(str(path), 12345, "prompt:node:normal", pending)
            self.assertEqual(
                response,
                "请发送 被控端 名称，例如：服务商+地区。发送 /cancel 可取消。",
            )
            response, _ = _handle(str(path), 12345, "vmiss hk", pending)
            self.assertIn("curl -fsSL", response)

    def test_maintenance_menu_selects_named_online_nodes_and_starts_update(self):
        class Maintenance:
            def __init__(self):
                self.calls = []
                self.snapshot = {
                    "controller_version": "0.6.0",
                    "deployment_mode": "native",
                    "update_available": True,
                    "preferences": {"version_check_enabled": True, "batch_size": 3},
                    "online_node_count": 1,
                    "catalog": {
                        "stable": {"version": "v0.7.0"},
                        "edge": {"version": "edge"},
                        "releases": [{"version": "v0.7.0"}],
                    },
                    "nodes": [{"node_id": "node_1234567890abcdef12345678", "name": "vmiss hk", "online": True}],
                }

            def request(self, method, path, body=None):
                self.calls.append((method, path, body))
                if path == "/v1/status":
                    return {"status": self.snapshot}
                if path == "/v1/nodes":
                    return {"nodes": self.snapshot["nodes"]}
                if path == "/v1/start":
                    return {"job": {"kind": body["action"], "status": "nodes_running", "result": {"nodes": {}}}}
                raise AssertionError((method, path, body))

        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            maintenance = Maintenance()
            pending = {}
            with patch("vps_audit.bot._maintenance_client", return_value=maintenance):
                response, keyboard = _handle(str(path), 12345, "/maintenance", pending)
                labels = [button["text"] for row in keyboard["inline_keyboard"] for button in row]
                self.assertIn("检测到可用更新", labels)
                self.assertIn("主控当前版本：0.6.0", response)

                _handle(str(path), 12345, "maint:nodes", pending)
                response, keyboard = _handle(
                    str(path), 12345, "maint:toggle:node_1234567890abcdef12345678", pending
                )
                self.assertIn("已选 1", response)
                self.assertIn("✅ vmiss hk", json.dumps(keyboard, ensure_ascii=False))
                _handle(str(path), 12345, "maint:nodes:done", pending)
                _handle(str(path), 12345, "maint:pick:stable", pending)
                response, keyboard = _handle(str(path), 12345, "maint:start", pending)
            self.assertIn("维护任务已提交", response)
            start = next(item for item in maintenance.calls if item[1] == "/v1/start")
            self.assertEqual(start[2]["action"], "node_update")
            self.assertEqual(start[2]["node_ids"], ["node_1234567890abcdef12345678"])

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

    def test_slow_callback_is_queued_before_audit_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            update = {
                "update_id": 55,
                "callback_query": {
                    "id": "callback-55",
                    "from": {"id": 12345},
                    "data": "menu:run",
                    "message": {"message_id": 77, "chat": {"id": -100500}},
                },
            }
            with patch("vps_audit.bot.get_updates", return_value=[update]), patch(
                "vps_audit.bot.answer_callback_query"
            ) as acknowledge, patch("vps_audit.bot.edit_message_text") as edit, patch(
                "vps_audit.bot._run_audit"
            ) as audit:
                run_bot(str(path), once=True)
            acknowledge.assert_called_once()
            audit.assert_not_called()
            self.assertIn("任务已提交", edit.call_args.args[3])
            state = json.loads((root / "state" / "bot-operations.json").read_text(encoding="utf-8"))
            self.assertEqual(state["jobs"][0]["status"], "queued")

    def test_maintenance_selection_persists_before_background_submission(self):
        class Maintenance:
            snapshot = {
                "controller_version": "0.6.0",
                "deployment_mode": "native",
                "update_available": False,
                "preferences": {"version_check_enabled": True, "batch_size": 3},
                "online_node_count": 0,
                "catalog": {"stable": {"version": "v0.7.0"}, "edge": None, "releases": []},
                "nodes": [],
            }

            def request(self, method, path, body=None):
                self.calls.append((method, path, body))
                if path == "/v1/status":
                    return {"status": self.snapshot}
                raise AssertionError((method, path, body))

            def __init__(self):
                self.calls = []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            state_path = root / "state" / "bot-state.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps({
                    "pending": {
                        "12345": {
                            "action": "maintenance_update",
                            "kind": "controller_update",
                            "node_ids": [],
                            "created_at": 1_700_000_000,
                        }
                    }
                }),
                encoding="utf-8",
            )
            update = {
                "update_id": 57,
                "callback_query": {
                    "id": "callback-57",
                    "from": {"id": 12345},
                    "data": "maint:pick:stable",
                    "message": {"message_id": 77, "chat": {"id": -100500}},
                },
            }
            maintenance = Maintenance()
            with patch("vps_audit.bot.get_updates", return_value=[update]), patch(
                "vps_audit.bot.answer_callback_query"
            ), patch("vps_audit.bot.edit_message_text"), patch(
                "vps_audit.bot._maintenance_client", return_value=maintenance
            ):
                run_bot(str(path), once=True)

            saved = json.loads(state_path.read_text(encoding="utf-8"))
            entry = saved["pending"]["12345"]
            self.assertEqual(entry["channel"], "stable")
            self.assertIsNone(entry["version"])
            operations = json.loads((root / "state" / "bot-operations.json").read_text(encoding="utf-8"))
            self.assertEqual(operations["jobs"], [])

    def test_maintenance_check_is_queued_outside_the_polling_loop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            update = {
                "update_id": 58,
                "callback_query": {
                    "id": "callback-58",
                    "from": {"id": 12345},
                    "data": "maint:check",
                    "message": {"message_id": 78, "chat": {"id": -100500}},
                },
            }
            with patch("vps_audit.bot.get_updates", return_value=[update]), patch(
                "vps_audit.bot.answer_callback_query"
            ), patch("vps_audit.bot.edit_message_text") as edit, patch(
                "vps_audit.bot._maintenance_client", side_effect=AssertionError("must run in worker")
            ):
                run_bot(str(path), once=True)

            self.assertIn("任务已提交", edit.call_args.args[3])
            state = json.loads((root / "state" / "bot-operations.json").read_text(encoding="utf-8"))
            self.assertEqual(state["jobs"][0]["value"], "maint:check")
            self.assertEqual(state["jobs"][0]["status"], "queued")

    def test_maintenance_submission_queues_the_selected_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            state_path = root / "state" / "bot-state.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps({
                    "pending": {
                        "12345": {
                            "action": "maintenance_update",
                            "kind": "node_update",
                            "channel": "stable",
                            "version": None,
                            "node_ids": ["node_1234567890abcdef12345678"],
                            "created_at": 1_700_000_000,
                        }
                    }
                }),
                encoding="utf-8",
            )
            update = {
                "update_id": 59,
                "callback_query": {
                    "id": "callback-59",
                    "from": {"id": 12345},
                    "data": "maint:start",
                    "message": {"message_id": 79, "chat": {"id": -100500}},
                },
            }
            with patch("vps_audit.bot.get_updates", return_value=[update]), patch(
                "vps_audit.bot.answer_callback_query"
            ), patch("vps_audit.bot.edit_message_text"), patch(
                "vps_audit.bot._maintenance_client", side_effect=AssertionError("must run in worker")
            ):
                run_bot(str(path), once=True)

            saved = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertNotIn("12345", saved["pending"])
            operations = json.loads((root / "state" / "bot-operations.json").read_text(encoding="utf-8"))
            self.assertEqual(operations["jobs"][0]["value"], "maint:start")
            self.assertEqual(operations["jobs"][0]["pending"]["12345"]["channel"], "stable")
            self.assertEqual(
                operations["jobs"][0]["pending"]["12345"]["node_ids"],
                ["node_1234567890abcdef12345678"],
            )

    def test_malformed_update_is_skipped_without_exiting(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            malformed = {"update_id": 56, "message": {"from": {"id": None}, "chat": {"id": -100500}}}
            with patch("vps_audit.bot.get_updates", return_value=[malformed]), patch(
                "vps_audit.bot.send_message"
            ):
                run_bot(str(path), once=True)

    def test_expired_pending_prompt_does_not_apply_a_later_message(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            pending = {"12345": {"action": "adduser", "created_at": 0}}
            self.assertIsNone(_apply_pending(str(path), pending, 12345, "late-user"))
            self.assertEqual(load_runtime_config(str(path))["subscription_monitoring"]["users"], [])

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

    def test_behavior_incident_list_detail_ai_and_question_flow(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            raw = json.loads(path.read_text(encoding="utf-8"))
            archive = root / "behavior-audit"
            raw["behavior_audit"] = {
                "enabled": True,
                "archive_dir": str(archive),
                "ai_include_full_metadata": True,
            }
            path.write_text(json.dumps(raw), encoding="utf-8")
            record = save_incidents(
                archive,
                [{
                    "rule_id": "BEHAVIOR_ACCOUNT_AUTOMATION",
                    "user": "user-a",
                    "severity": "high",
                    "score": 60,
                    "title": "疑似批量账号注册或认证自动化",
                    "summary": "fixture",
                    "evidence": [{
                        "timestamp": "2026-08-27T01:00:00Z",
                        "source_ip": "198.51.100.9",
                        "destination_host": "accounts.google.com",
                        "destination_port": 443,
                        "destination_category": "account_service",
                        "node_id": "node_1234567890abcdef12345678",
                        "node_name": "vmiss hk",
                    }],
                }],
                "2026-08-27T01:01:00Z",
            )[0]
            identifier = record["incident_id"]

            response, keyboard = _handle(str(path), 12345, "/incidents", {})
            self.assertIn(identifier, response)
            callbacks = [button["callback_data"] for row in keyboard["inline_keyboard"] for button in row]
            detail_callback = next(item for item in callbacks if item.startswith("incident:view:"))
            response, keyboard = _handle(str(path), 12345, detail_callback, {})
            self.assertIn("198.51.100.9", response)
            self.assertIn("accounts.google.com:443", response)
            self.assertNotIn("incident:ai:", json.dumps(keyboard))

            key_file = root / "audit.key"
            key_file.write_text("secret\n", encoding="utf-8")
            upsert_ai_provider(
                str(path), "audit", "Audit AI", "https://ai.example/v1", "responses",
                str(key_file), "audit-model", 15,
            )
            _, keyboard = _handle(str(path), 12345, f"/incident {identifier}", {})
            callbacks = [button["callback_data"] for row in keyboard["inline_keyboard"] for button in row]
            self.assertIn(f"incident:ai:{identifier}", callbacks)
            pending = {}
            response, no_keyboard = _handle(
                str(path), 12345, f"incident:ask:{identifier}", pending
            )
            self.assertIn("请发送", response)
            self.assertIsNone(no_keyboard)
            with patch(
                "vps_audit.bot.review_behavior_incident",
                return_value={"overall_assessment": "需要复核", "cases": []},
            ) as review:
                response, _ = _handle(str(path), 12345, "请判断是否为客户端重试", pending)
            self.assertIn("需要复核", response)
            review.assert_called_once_with(
                str(path), identifier, "请判断是否为客户端重试"
            )


if __name__ == "__main__":
    unittest.main()
