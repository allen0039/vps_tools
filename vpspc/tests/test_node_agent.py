import importlib.util
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


AGENT_PATH = Path(__file__).resolve().parents[1] / "deploy" / "node" / "vpspc-node.py"
SPEC = importlib.util.spec_from_file_location("vpspc_node_agent", AGENT_PATH)
agent = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(agent)


class NodeAgentTests(unittest.TestCase):
    def test_xray_parser_supports_ipv4_and_ipv6(self):
        ipv4 = agent.parse_xray_access_line(
            "2026/08/27 12:01:02.123456 from tcp:198.51.100.9:54321 "
            "accepted tcp:example.com:443 [in -> direct] email: panel-user-1"
        )
        ipv6 = agent.parse_xray_access_line(
            "2026/08/27 12:01:03 from tcp:[2001:db8::9]:54321 "
            "accepted tcp:example.com:443 email: panel-user-2"
        )
        self.assertEqual(ipv4["source_ip"], "198.51.100.9")
        self.assertEqual(ipv6["source_ip"], "2001:db8::9")
        self.assertEqual(ipv4["event_type"], "proxy_connection")
        self.assertEqual(ipv4["source_port"], 54321)
        self.assertEqual(ipv4["destination_host"], "example.com")
        self.assertEqual(ipv4["destination_port"], 443)
        self.assertEqual(ipv4["inbound_tag"], "in")

    def test_normal_link_refuses_different_controller_before_enrollment(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            config = Path(temporary) / "etc" / "vpspc-node" / "config.json"
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps({
                "controller_url": "https://old.example.com",
                "installation_id": "install_12345678",
            }), encoding="utf-8")
            with patch.dict(os.environ, env, clear=False), patch.object(agent.os, "geteuid", return_value=0), patch.object(agent, "_request_json") as request:
                with self.assertRaisesRegex(RuntimeError, "覆盖注册链接"):
                    agent.install("https://new.example.com", "token", False, 5)
            request.assert_not_called()

    def test_replace_link_rebinds_and_managed_purge_preserves_unrelated_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            root = Path(temporary)
            existing = root / "etc" / "vpspc-node" / "config.json"
            existing.parent.mkdir(parents=True)
            existing.write_text(json.dumps({
                "controller_url": "https://old.example.com",
                "installation_id": "install_12345678",
                "xray_logs": ["/var/log/xray/access.log"],
            }), encoding="utf-8")
            response = {
                "ok": True,
                "node_id": "node_1234567890abcdef12345678",
                "credential": "private-node-key",
                "name": "edge",
                "repaired": False,
            }
            with patch.dict(os.environ, env, clear=False), patch.object(agent.os, "geteuid", return_value=0), patch.object(agent, "_request_json", return_value=response) as request:
                result = agent.install("https://new.example.com", "token", True, 5)
                written = json.loads(existing.read_text(encoding="utf-8"))
                self.assertEqual(written["controller_url"], "https://new.example.com")
                self.assertEqual(result["node_id"], response["node_id"])
                self.assertTrue(request.call_args.args[2]["replace_existing"])
                unrelated = root / "unrelated.txt"
                unrelated.write_text("preserve", encoding="utf-8")
                agent.uninstall(purge=True)
                self.assertTrue(unrelated.is_file())
                self.assertFalse((root / "etc" / "vpspc-node").exists())
                self.assertFalse((root / "usr" / "local" / "lib" / "vpspc-node").exists())

    def test_activity_dedup_keeps_latest_user_ip_pair(self):
        rows = [
            {"event_type": "proxy_activity", "user": "u", "source_ip": "198.51.100.1", "protocol": "xray", "timestamp": "2026-08-27T01:00:00Z", "event_id": "event_11111111"},
            {"event_type": "proxy_activity", "user": "u", "source_ip": "198.51.100.1", "protocol": "xray", "timestamp": "2026-08-27T01:01:00Z", "event_id": "event_22222222"},
        ]
        result = agent._deduplicate(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["event_id"], "event_22222222")

    def test_run_once_stores_dynamic_policy_in_state_without_rewriting_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            config = {
                "controller_url": "https://monitor.example.com",
                "node_id": "node_1234567890abcdef12345678",
                "installation_id": "install_12345678",
                "node_name": "edge",
                "xray_logs": [],
                "interval_minutes": 5,
                "timeout_seconds": 30,
                "agent_version": "test",
                "behavior_audit_enabled": False,
            }
            with patch.dict(os.environ, env, clear=False), patch.object(
                agent, "_authenticated_request", return_value={
                    "ok": True,
                    "accepted": 0,
                    "behavior_audit": {"enabled": True},
                }
            ):
                agent._write_installation(config, "private-node-key", 5)
                config_path = Path(temporary) / "etc" / "vpspc-node" / "config.json"
                original_config = config_path.read_bytes()
                result = agent.run_once()

            state_path = Path(temporary) / "var" / "lib" / "vpspc-node" / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(result["sent"], 0)
            self.assertEqual(config_path.read_bytes(), original_config)
            self.assertTrue(state["behavior_audit_enabled"])

    def test_command_poll_uses_60_second_heartbeat_and_keeps_log_state_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            config = {
                "controller_url": "https://monitor.example.com",
                "node_id": "node_1234567890abcdef12345678",
                "installation_id": "install_12345678",
                "node_name": "edge",
                "xray_logs": [],
                "interval_minutes": 5,
                "timeout_seconds": 30,
                "agent_version": "test",
            }
            with patch.dict(os.environ, env, clear=False), patch.object(
                agent, "_authenticated_request", return_value={"ok": True}
            ) as request:
                agent._write_installation(config, "private-node-key", 5)
                result = agent.command_poll()

            self.assertEqual(result, {"ok": True, "task": None})
            self.assertEqual(request.call_args.args[2], "/v1/node/heartbeat")
            self.assertEqual(request.call_args.args[3], {
                "agent_version": agent.AGENT_VERSION,
                "agent_protocol": agent.AGENT_PROTOCOL,
                "claim": True,
            })
            root = Path(temporary)
            command_timer = (root / "etc" / "systemd" / "system" / "vpspc-node-command.timer").read_text()
            command_service = (root / "etc" / "systemd" / "system" / "vpspc-node-command.service").read_text()
            self.assertIn("OnUnitActiveSec=60s", command_timer)
            self.assertIn("command-poll", command_service)
            self.assertNotIn("/var/log", command_service)
            self.assertFalse((root / "var" / "lib" / "vpspc-node" / "spool.jsonl").exists())

    def test_update_replaces_agent_reports_success_and_removes_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            config = {
                "controller_url": "https://monitor.example.com",
                "node_id": "node_1234567890abcdef12345678",
                "installation_id": "install_12345678",
                "node_name": "edge",
                "xray_logs": [],
                "interval_minutes": 5,
                "timeout_seconds": 30,
                "agent_version": "test",
            }
            replacement = AGENT_PATH.read_bytes().replace(b'AGENT_VERSION = "0.1.1"', b'AGENT_VERSION = "0.2.0"')
            task = {
                "task_id": "task_" + "a" * 32,
                "node_id": config["node_id"],
                "kind": "node_update",
                "payload": {
                    "artifact_id": "sha256-" + hashlib.sha256(replacement).hexdigest(),
                    "sha256": hashlib.sha256(replacement).hexdigest(),
                    "size": len(replacement),
                    "version": "v0.2.0",
                },
            }
            with patch.dict(os.environ, env, clear=False), patch.object(
                agent, "_download_update_artifact", return_value=replacement
            ), patch.object(agent, "_node_healthcheck"), patch.object(agent, "_report_task_status") as report:
                agent._write_installation(config, "private-node-key", 5)
                result = agent.execute_update_task(task)

            installed = (Path(temporary) / "usr" / "local" / "lib" / "vpspc-node" / "vpspc-node.py")
            self.assertEqual(result["status"], "success")
            self.assertIn(b'AGENT_VERSION = "0.2.0"', installed.read_bytes())
            self.assertFalse((Path(temporary) / "var" / "lib" / "vpspc-node" / "update-backup.py").exists())
            self.assertEqual(report.call_args_list[-1].args[2], "success")

    def test_failed_healthcheck_restores_previous_agent_and_reports_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            config = {
                "controller_url": "https://monitor.example.com",
                "node_id": "node_1234567890abcdef12345678",
                "installation_id": "install_12345678",
                "node_name": "edge",
                "xray_logs": [],
                "interval_minutes": 5,
                "timeout_seconds": 30,
                "agent_version": "test",
            }
            replacement = AGENT_PATH.read_bytes().replace(b'AGENT_VERSION = "0.1.1"', b'AGENT_VERSION = "0.2.0"')
            task = {
                "task_id": "task_" + "b" * 32,
                "node_id": config["node_id"],
                "kind": "node_update",
                "payload": {
                    "artifact_id": "sha256-" + hashlib.sha256(replacement).hexdigest(),
                    "sha256": hashlib.sha256(replacement).hexdigest(),
                    "size": len(replacement),
                    "version": "v0.2.0",
                },
            }
            with patch.dict(os.environ, env, clear=False), patch.object(
                agent, "_download_update_artifact", return_value=replacement
            ), patch.object(agent, "_node_healthcheck", side_effect=[RuntimeError("auth failed"), None]), patch.object(
                agent, "_report_task_status"
            ) as report:
                agent._write_installation(config, "private-node-key", 5)
                installed = Path(temporary) / "usr" / "local" / "lib" / "vpspc-node" / "vpspc-node.py"
                before = installed.read_bytes()
                result = agent.execute_update_task(task)

            self.assertEqual(result["status"], "rolled_back")
            self.assertEqual(installed.read_bytes(), before)
            self.assertEqual(report.call_args_list[-1].args[2], "rolled_back")

    def test_remote_destroy_removes_only_vpspc_and_preserves_node_services(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            root = Path(temporary)
            config = {
                "controller_url": "https://monitor.example.com",
                "node_id": "node_1234567890abcdef12345678",
                "installation_id": "install_12345678",
                "node_name": "edge",
                "xray_logs": ["/var/log/xray/access.log"],
                "interval_minutes": 5,
                "timeout_seconds": 30,
            }
            sentinels = {
                root / "etc" / "systemd" / "system" / "xrayagent.service": b"third-party service\n",
                root / "var" / "log" / "xray" / "access.log": b"third-party log\n",
                root / "opt" / "miaomiaowux" / "config.json": b'{"third_party": true}\n',
            }
            for path, content in sentinels.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            task = {
                "task_id": "task_" + "c" * 32,
                "node_id": config["node_id"],
                "kind": "node_destroy",
                "payload": {"receipt_token": "receipt-token"},
            }
            with patch.dict(os.environ, env, clear=False), patch.object(
                agent.os, "geteuid", return_value=0
            ), patch.object(agent, "_send_uninstall_receipt", return_value=True) as receipt:
                agent._write_installation(config, "private-node-key", 5)
                result = agent.execute_uninstall_task(task)

            self.assertEqual(result["status"], "success")
            for path, content in sentinels.items():
                self.assertEqual(path.read_bytes(), content)
            self.assertFalse((root / "etc" / "vpspc-node").exists())
            self.assertFalse((root / "var" / "lib" / "vpspc-node").exists())
            self.assertFalse((root / "usr" / "local" / "lib" / "vpspc-node").exists())
            self.assertFalse((root / "etc" / "systemd" / "system" / "vpspc-node-maintenance.service").exists())
            self.assertEqual(receipt.call_args.args[2], "success")

    def test_destroy_marker_mismatch_deletes_nothing_and_reports_safely_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            root = Path(temporary)
            config = {
                "controller_url": "https://monitor.example.com",
                "node_id": "node_1234567890abcdef12345678",
                "installation_id": "install_12345678",
                "node_name": "edge",
                "xray_logs": [],
                "interval_minutes": 5,
                "timeout_seconds": 30,
            }
            task = {
                "task_id": "task_" + "d" * 32,
                "node_id": config["node_id"],
                "kind": "node_destroy",
                "payload": {"receipt_token": "receipt-token"},
            }
            with patch.dict(os.environ, env, clear=False), patch.object(
                agent.os, "geteuid", return_value=0
            ), patch.object(agent, "_report_task_status") as report:
                agent._write_installation(config, "private-node-key", 5)
                marker = root / "var" / "lib" / "vpspc-node" / ".managed-by-vpspc-node"
                marker.write_text("managed by another tool\n", encoding="utf-8")
                before = {
                    path.relative_to(root): path.read_bytes()
                    for path in root.rglob("*") if path.is_file()
                }
                result = agent.execute_uninstall_task(task)

            after = {
                path.relative_to(root): path.read_bytes()
                for path in root.rglob("*") if path.is_file()
            }
            self.assertEqual(result["status"], "safely_retained")
            self.assertEqual(after, before)
            self.assertEqual(report.call_args.args[2], "safely_retained")

    def test_destroy_dangling_owned_path_is_safely_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            root = Path(temporary)
            config = {
                "controller_url": "https://monitor.example.com",
                "node_id": "node_1234567890abcdef12345678",
                "installation_id": "install_12345678",
                "node_name": "edge",
                "xray_logs": [],
                "interval_minutes": 5,
                "timeout_seconds": 30,
            }
            task = {
                "task_id": "task_" + "e" * 32,
                "node_id": config["node_id"],
                "kind": "node_destroy",
                "payload": {"receipt_token": "receipt-token"},
            }
            with patch.dict(os.environ, env, clear=False), patch.object(
                agent.os, "geteuid", return_value=0
            ), patch.object(agent, "_report_task_status") as report:
                agent._write_installation(config, "private-node-key", 5)
                dangling = root / "usr" / "local" / "bin" / "vpspc-node"
                dangling.unlink()
                dangling.symlink_to("/not-a-vpspc-target")
                result = agent.execute_uninstall_task(task)

            self.assertEqual(result["status"], "safely_retained")
            self.assertTrue(dangling.is_symlink())
            self.assertEqual(report.call_args.args[2], "safely_retained")

    def test_fixed_remote_uninstall_acknowledges_then_purges_managed_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"VPSPC_NODE_TEST_ROOT": temporary, "VPSPC_NODE_SKIP_SYSTEMCTL": "1"}
            config = {
                "controller_url": "https://monitor.example.com",
                "node_id": "node_1234567890abcdef12345678",
                "installation_id": "install_12345678",
                "node_name": "edge",
                "xray_logs": [],
                "interval_minutes": 5,
                "timeout_seconds": 30,
                "agent_version": "test",
            }
            command = {"id": "command_12345678", "type": "self_uninstall"}
            with patch.dict(os.environ, env, clear=False), patch.object(
                agent.os, "geteuid", return_value=0
            ), patch.object(
                agent,
                "_authenticated_request",
                side_effect=[
                    {"ok": True, "accepted": 0, "command": command},
                    {"ok": True},
                ],
            ) as request:
                agent._write_installation(config, "private-node-key", 5)
                result = agent.run_once()
            self.assertEqual(result["sent"], 0)
            self.assertEqual(request.call_args_list[0].args[2], "/v1/node/events")
            self.assertEqual(request.call_args_list[1].args[2], "/v1/node/command-ack")
            self.assertEqual(
                request.call_args_list[1].args[3], {"command_id": command["id"]}
            )
            root = Path(temporary)
            self.assertFalse((root / "etc" / "vpspc-node").exists())
            self.assertFalse((root / "var" / "lib" / "vpspc-node").exists())
            self.assertFalse((root / "usr" / "local" / "lib" / "vpspc-node").exists())
            self.assertFalse(
                (root / "etc" / "systemd" / "system" / "vpspc-node.service").exists()
            )


if __name__ == "__main__":
    unittest.main()
