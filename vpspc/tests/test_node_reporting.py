import http.client
import hashlib
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from vps_audit.node_reporting import (
    NodeRegistry,
    NodeHTTPServer,
    NodeRequestHandler,
    _validate_event,
    build_bootstrap,
    sign_request,
)
from vps_audit.maintenance.releases import GitHubReleaseSource
from vps_audit.maintenance.store import MaintenanceStore
from vps_audit.runtime import normalize_runtime_config, run_cycle


class NodeReportingTests(unittest.TestCase):
    def test_old_config_defaults_to_controller_only(self):
        config = normalize_runtime_config({"telegram": {"enabled": False}, "openai_review": {"enabled": False}})
        self.assertEqual(config["node_reporting"]["mode"], "controller_only")
        self.assertEqual(config["node_reporting"]["listen_host"], "127.0.0.1")

    def test_remote_mode_requires_https_public_url(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            normalize_runtime_config({
                "node_reporting": {
                    "mode": "node_reporting",
                    "public_base_url": "http://monitor.example.com",
                }
            })

    def test_enrollment_is_single_use_and_repairs_same_installation(self):
        now = datetime(2026, 8, 27, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            registry = NodeRegistry(Path(temporary) / "nodes.json")
            first_link = registry.create_enrollment("edge-1", ttl_minutes=15, now=now)
            first = registry.enroll(
                first_link["token"],
                {"installation_id": "install_12345678", "node_name": "host", "agent_version": "test"},
                now,
            )
            with self.assertRaisesRegex(ValueError, "already used"):
                registry.enroll(
                    first_link["token"],
                    {"installation_id": "install_12345678", "node_name": "host"},
                    now,
                )
            repair_link = registry.create_enrollment("edge-1", ttl_minutes=15, now=now)
            repaired = registry.enroll(
                repair_link["token"],
                {"installation_id": "install_12345678", "node_name": "host", "agent_version": "new"},
                now,
            )
            self.assertEqual(repaired["node_id"], first["node_id"])
            self.assertTrue(repaired["repaired"])
            self.assertNotEqual(repaired["credential"], first["credential"])

    def test_expired_enrollment_is_rejected(self):
        now = datetime(2026, 8, 27, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            registry = NodeRegistry(Path(temporary) / "nodes.json")
            link = registry.create_enrollment("edge", ttl_minutes=1, now=now)
            with self.assertRaisesRegex(ValueError, "expired"):
                registry.inspect_enrollment(link["token"], now + timedelta(minutes=2))

    def test_normal_enrollment_cannot_be_promoted_to_replace(self):
        now = datetime(2026, 8, 27, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            registry = NodeRegistry(Path(temporary) / "nodes.json")
            link = registry.create_enrollment("edge", allow_replace=False, now=now)
            with self.assertRaisesRegex(PermissionError, "not authorized"):
                registry.enroll(link["token"], {
                    "installation_id": "install_abcdefgh",
                    "node_name": "host",
                    "replace_existing": True,
                }, now)
            self.assertEqual(registry.inspect_enrollment(link["token"], now)["name"], "edge")

    def test_node_record_must_be_revoked_before_deletion(self):
        now = datetime(2026, 8, 27, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            registry = NodeRegistry(Path(temporary) / "nodes.json")
            link = registry.create_enrollment("edge", now=now)
            node = registry.enroll(
                link["token"],
                {"installation_id": "install_abcdefgh", "node_name": "host"},
                now,
            )
            with self.assertRaisesRegex(ValueError, "revoked"):
                registry.delete(node["node_id"])
            registry.revoke(node["node_id"])
            registry.delete(node["node_id"])
            self.assertEqual(registry.list_nodes(), [])

    def test_hmac_authentication_rejects_replay(self):
        now = datetime(2026, 8, 27, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            registry = NodeRegistry(Path(temporary) / "nodes.json", replay_window_seconds=300)
            link = registry.create_enrollment("edge", now=now)
            node = registry.enroll(
                link["token"],
                {"installation_id": "install_abcdefgh", "node_name": "host"},
                now,
            )
            body = b'{"events":[]}'
            timestamp = str(int(now.timestamp()))
            nonce = "nonce_1234567890123456"
            signature = sign_request(node["credential"], timestamp, nonce, body)
            authenticated = registry.authenticate(
                node["node_id"], timestamp, nonce, signature, body, now
            )
            self.assertEqual(authenticated["name"], "edge")
            with self.assertRaisesRegex(PermissionError, "already been used"):
                registry.authenticate(node["node_id"], timestamp, nonce, signature, body, now)

    def test_authentication_discards_malformed_historical_nonces(self):
        now = datetime(2026, 8, 27, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            registry_path = Path(temporary) / "nodes.json"
            registry = NodeRegistry(registry_path, replay_window_seconds=300)
            link = registry.create_enrollment("edge", now=now)
            node = registry.enroll(
                link["token"],
                {"installation_id": "install_abcdefgh", "node_name": "host"},
                now,
            )
            state = json.loads(registry_path.read_text(encoding="utf-8"))
            state["nodes"][node["node_id"]]["recent_nonces"] = [
                {"nonce": "old_nonce_12345678", "seen_at": "not-a-timestamp"},
                None,
            ]
            registry_path.write_text(json.dumps(state), encoding="utf-8")
            body = b'{"events":[]}'
            timestamp = str(int(now.timestamp()))
            nonce = "nonce_1234567890123456"
            signature = sign_request(node["credential"], timestamp, nonce, body)
            authenticated = registry.authenticate(
                node["node_id"], timestamp, nonce, signature, body, now
            )
            self.assertEqual(authenticated["name"], "edge")

    def test_bootstrap_only_contains_replace_for_authorized_link(self):
        normal = build_bootstrap("https://monitor.example.com", "one-time-token", False)
        replacement = build_bootstrap("https://monitor.example.com", "one-time-token", True)
        self.assertNotIn("--replace", normal)
        self.assertIn("--replace", replacement)
        self.assertNotIn("node.key", normal)

    def test_command_heartbeat_defines_online_window_without_event_upload(self):
        now = datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            registry = NodeRegistry(Path(temporary) / "nodes.json")
            link = registry.create_enrollment("vmiss hk", now=now)
            node = registry.enroll(
                link["token"],
                {"installation_id": "install_heartbeat123", "node_name": "host"},
                now,
            )

            registry.record_command_heartbeat(node["node_id"], "0.2.0", 2, now)

            self.assertEqual(
                [item["node_id"] for item in registry.list_online_nodes(now + timedelta(seconds=119))],
                [node["node_id"]],
            )
            self.assertEqual(registry.list_online_nodes(now + timedelta(seconds=121)), [])
            listed = registry.list_nodes()[0]
            self.assertEqual(listed["agent_version"], "0.2.0")
            self.assertEqual(listed["agent_protocol"], 2)
            self.assertEqual(listed["last_seen"], None)

    def test_registry_v1_loads_with_offline_command_defaults_then_writes_v2(self):
        now = datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc)
        node_id = "node_" + "a" * 24
        legacy = {
            "version": 1,
            "enrollments": {},
            "nodes": {
                node_id: {
                    "name": "legacy hk",
                    "reported_name": "legacy",
                    "installation_id": "install_legacy123",
                    "credential": "credential",
                    "created_at": "2026-08-27T08:00:00Z",
                    "registered_at": "2026-08-27T08:00:00Z",
                    "last_seen": None,
                    "agent_version": "0.1.0",
                    "revoked": False,
                    "recent_nonces": [],
                    "pending_command": None,
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nodes.json"
            path.write_text(json.dumps(legacy), encoding="utf-8")
            registry = NodeRegistry(path)

            node = registry.list_nodes()[0]
            self.assertIsNone(node["command_last_seen"])
            self.assertEqual(node["agent_protocol"], 1)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["version"], 1)

            registry.record_command_heartbeat(node_id, "0.2.0", 2, now)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["version"], 2)

    def test_runtime_claims_remote_inbox_and_emits_node_rule(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir()
            inbox = state / "node-inbox.jsonl"
            rows = []
            for index in range(2):
                rows.append({
                    "timestamp": (now + timedelta(seconds=index)).isoformat().replace("+00:00", "Z"),
                    "event_type": "proxy_activity",
                    "user": "panel-user-1",
                    "source_ip": f"198.51.100.{index + 1}",
                    "node_id": "node_1234567890abcdef12345678",
                    "node_name": "edge",
                    "event_id": f"event_1234567890abcdef{index}",
                    "protocol": "xray",
                })
            inbox.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            config = root / "config.json"
            config.write_text(json.dumps({
                "auth_logs": [],
                "state_dir": str(state),
                "report_dir": str(root / "reports"),
                "node_reporting": {"inbox_file": str(inbox)},
                "rules": {"thresholds": {"node_ip_count": 2}},
                "telegram": {"enabled": False},
                "openai_review": {"enabled": False},
            }), encoding="utf-8")
            report = run_cycle(str(config))
            self.assertIn("NODE_ACTIVE_IPS", {item["rule_id"] for item in report["findings"]})
            self.assertEqual(report["runtime"]["node_reporting"]["received_event_count"], 2)
            self.assertFalse(Path(str(inbox) + ".processing").exists())

    def test_runtime_keeps_claimed_inbox_when_audit_fails(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir()
            inbox = state / "node-inbox.jsonl"
            inbox.write_text(
                json.dumps(
                    {
                        "timestamp": now.isoformat().replace("+00:00", "Z"),
                        "event_type": "proxy_activity",
                        "user": "panel-user-1",
                        "source_ip": "198.51.100.10",
                        "node_id": "node_1234567890abcdef12345678",
                        "node_name": "edge",
                        "event_id": "event_1234567890abcdef",
                        "protocol": "xray",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "auth_logs": [],
                        "state_dir": str(state),
                        "report_dir": str(root / "reports"),
                        "node_reporting": {"inbox_file": str(inbox)},
                        "telegram": {"enabled": False},
                        "openai_review": {"enabled": False},
                    }
                ),
                encoding="utf-8",
            )
            with patch("vps_audit.runtime.analyze", side_effect=RuntimeError("fixture failure")):
                with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                    run_cycle(str(config))
            processing = Path(str(inbox) + ".processing")
            self.assertTrue(processing.is_file())
            self.assertIn("panel-user-1", processing.read_text(encoding="utf-8"))

    def test_ingest_event_schema_drops_unneeded_destination(self):
        event = _validate_event({
            "timestamp": "2026-08-27T01:00:00Z",
            "event_type": "proxy_activity",
            "user": "user-1",
            "source_ip": "198.51.100.9",
            "event_id": "event_1234567890",
            "protocol": "xray",
            "destination": "secret.example.com",
        }, "node_1234567890abcdef12345678", "edge")
        self.assertNotIn("destination", event)
        self.assertEqual(event["source"], "remote_node")

    def test_full_connection_requires_enabled_policy_and_keeps_complete_metadata(self):
        raw = {
            "timestamp": "2026-08-27T01:00:00Z",
            "event_type": "proxy_connection",
            "user": "user-a",
            "source_ip": "198.51.100.9",
            "source_port": 54321,
            "destination_host": "Accounts.Google.Com.",
            "destination_port": 443,
            "network": "tcp",
            "inbound_tag": "vless-in",
            "event_id": "event_1234567890abcdef",
            "protocol": "xray",
            "node_id": "untrusted-node",
            "node_name": "untrusted-name",
        }
        downgraded = _validate_event(
            raw, "node_trusted123456789012345678", "vmiss hk"
        )
        self.assertEqual(downgraded["event_type"], "proxy_activity")
        self.assertNotIn("destination_host", downgraded)
        event = _validate_event(
            raw, "node_trusted123456789012345678", "vmiss hk", behavior_audit_enabled=True
        )
        self.assertEqual(event["node_name"], "vmiss hk")
        self.assertEqual(event["destination_host"], "accounts.google.com")
        self.assertEqual(event["destination_category"], "account_service")
        self.assertEqual(event["source_port"], 54321)

    def test_http_enrollment_reporting_replay_and_uninstall_lifecycle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry = NodeRegistry(root / "nodes.json", replay_window_seconds=300)
            asset = root / "vpspc-node.py"
            asset.write_text("# node agent\n", encoding="utf-8")
            inbox = root / "node-inbox.jsonl"
            server = NodeHTTPServer(
                ("127.0.0.1", 0),
                NodeRequestHandler,
                {
                    "registry": registry,
                    "public_base_url": "http://127.0.0.1",
                    "agent_asset_path": str(asset),
                    "inbox_path": inbox,
                    "max_batch_events": 500,
                    "max_request_bytes": 1_048_576,
                },
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)

            def request(path, body, headers=None):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                connection.request("POST", path, body=body, headers=headers or {})
                response = connection.getresponse()
                value = json.loads(response.read())
                connection.close()
                return response.status, value

            invalid_status, invalid = request(
                "/v1/node/enroll",
                b"\xff",
                {"Content-Type": "application/json", "Content-Length": "1"},
            )
            self.assertEqual(invalid_status, 400)
            self.assertFalse(invalid["ok"])

            link = registry.create_enrollment("edge-http")
            enrollment_body = json.dumps(
                {
                    "installation_id": "install_http12345",
                    "node_name": "host",
                    "agent_version": "test",
                    "replace_existing": False,
                },
                separators=(",", ":"),
            ).encode("utf-8")
            status, enrolled = request(
                "/v1/node/enroll",
                enrollment_body,
                {
                    "Content-Type": "application/json",
                    "X-VPSPC-Enroll": link["token"],
                    "Content-Length": str(len(enrollment_body)),
                },
            )
            self.assertEqual(status, 200)

            event_body = json.dumps(
                {
                    "events": [
                        {
                            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            "event_type": "proxy_activity",
                            "user": "panel-user-http",
                            "source_ip": "198.51.100.20",
                            "event_id": "event_http12345678",
                            "protocol": "xray",
                            "destination": "must-not-persist.example",
                        }
                    ]
                },
                separators=(",", ":"),
            ).encode("utf-8")
            timestamp = str(int(datetime.now(timezone.utc).timestamp()))
            nonce = "nonce_http_1234567890"
            auth_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(event_body)),
                "X-VPSPC-Node": enrolled["node_id"],
                "X-VPSPC-Timestamp": timestamp,
                "X-VPSPC-Nonce": nonce,
                "X-VPSPC-Signature": sign_request(
                    enrolled["credential"], timestamp, nonce, event_body
                ),
            }
            status, accepted = request("/v1/node/events", event_body, auth_headers)
            self.assertEqual((status, accepted["accepted"]), (200, 1))
            stored = json.loads(inbox.read_text(encoding="utf-8"))
            self.assertNotIn("destination", stored)
            self.assertEqual(stored["node_name"], "edge-http")

            replay_status, replay = request("/v1/node/events", event_body, auth_headers)
            self.assertEqual(replay_status, 401)
            self.assertIn("already been used", replay["error"])

            command = registry.request_uninstall(enrolled["node_id"])
            empty_body = b'{"events":[]}'
            timestamp = str(int(datetime.now(timezone.utc).timestamp()))
            command_nonce = "nonce_command_12345678"
            command_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(empty_body)),
                "X-VPSPC-Node": enrolled["node_id"],
                "X-VPSPC-Timestamp": timestamp,
                "X-VPSPC-Nonce": command_nonce,
                "X-VPSPC-Signature": sign_request(
                    enrolled["credential"], timestamp, command_nonce, empty_body
                ),
            }
            status, command_response = request("/v1/node/events", empty_body, command_headers)
            self.assertEqual(status, 200)
            self.assertEqual(command_response["command"]["id"], command["id"])

            ack_body = json.dumps(
                {"command_id": command["id"]}, separators=(",", ":")
            ).encode("utf-8")
            timestamp = str(int(datetime.now(timezone.utc).timestamp()))
            ack_nonce = "nonce_acknowledge_123456"
            ack_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(ack_body)),
                "X-VPSPC-Node": enrolled["node_id"],
                "X-VPSPC-Timestamp": timestamp,
                "X-VPSPC-Nonce": ack_nonce,
                "X-VPSPC-Signature": sign_request(
                    enrolled["credential"], timestamp, ack_nonce, ack_body
                ),
            }
            status, acknowledged = request(
                "/v1/node/command-ack", ack_body, ack_headers
            )
            self.assertEqual((status, acknowledged["ok"]), (200, True))
            registered = {item["node_id"]: item for item in registry.list_nodes()}
            self.assertTrue(registered[enrolled["node_id"]]["revoked"])
            self.assertEqual(
                registered[enrolled["node_id"]]["uninstalled_at"][:10],
                datetime.now(timezone.utc).date().isoformat(),
            )

    def test_authenticated_maintenance_endpoints_and_fixed_update_asset(self):
        """Nodes can only claim and advance their own short-lived commands."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry = NodeRegistry(root / "nodes.json", replay_window_seconds=300)
            store = MaintenanceStore(root / "maintenance.json")
            cache = root / "release-cache"
            release_source = GitHubReleaseSource(cache)
            artifact_payload = b"verified node update artifact\n"
            artifact_id = "sha256-" + hashlib.sha256(artifact_payload).hexdigest()
            cache.mkdir(mode=0o700)
            artifact_path = cache / (artifact_id + ".bundle")
            artifact_path.write_bytes(artifact_payload)
            artifact_path.chmod(0o600)
            (cache / "artifacts.json").write_text(
                json.dumps({"schema_version": 1, "artifacts": {artifact_id: artifact_path.name}}),
                encoding="utf-8",
            )

            first_link = registry.create_enrollment("vmiss hk")
            first = registry.enroll(
                first_link["token"],
                {"installation_id": "install_task_http_001", "node_name": "host-a", "agent_version": "test"},
            )
            second_link = registry.create_enrollment("vmiss sg")
            second = registry.enroll(
                second_link["token"],
                {"installation_id": "install_task_http_002", "node_name": "host-b", "agent_version": "test"},
            )
            initial_task = store.create_node_tasks(
                "job_maintenance_http_001",
                [{"node_id": first["node_id"], "name": "vmiss hk"}],
                {"kind": "node_update", "artifact_id": artifact_id},
            )[0]

            agent_asset = root / "vpspc-node.py"
            agent_asset.write_text("# node agent\n", encoding="utf-8")
            server = NodeHTTPServer(
                ("127.0.0.1", 0),
                NodeRequestHandler,
                {
                    "registry": registry,
                    "maintenance_store": store,
                    "release_source": release_source,
                    "public_base_url": "http://127.0.0.1",
                    "agent_asset_path": str(agent_asset),
                    "inbox_path": root / "node-inbox.jsonl",
                    "max_batch_events": 500,
                    "max_request_bytes": 1024,
                },
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)

            nonce_counter = 0

            def request(method, path, body=b"", headers=None):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                connection.request(method, path, body=body, headers=headers or {})
                response = connection.getresponse()
                payload = response.read()
                result = (response.status, dict(response.getheaders()), payload)
                connection.close()
                return result

            def signed_request(path, value, node=first, *, nonce=None):
                nonlocal nonce_counter
                body = json.dumps(value, separators=(",", ":")).encode("utf-8")
                if nonce is None:
                    nonce_counter += 1
                    nonce = f"nonce_maintenance_{nonce_counter:08d}"
                timestamp = str(int(datetime.now(timezone.utc).timestamp()))
                return request(
                    "POST",
                    path,
                    body,
                    {
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                        "X-VPSPC-Node": node["node_id"],
                        "X-VPSPC-Timestamp": timestamp,
                        "X-VPSPC-Nonce": nonce,
                        "X-VPSPC-Signature": sign_request(node["credential"], timestamp, nonce, body),
                    },
                )

            status, _headers, payload = signed_request(
                "/v1/node/heartbeat",
                {"agent_version": "0.2.0", "agent_protocol": 2, "claim": True},
            )
            heartbeat = json.loads(payload)
            self.assertEqual(status, 200)
            self.assertEqual(heartbeat["task"]["task_id"], initial_task["task_id"])
            self.assertEqual(heartbeat["task"]["node_id"], first["node_id"])
            self.assertNotIn("credential", json.dumps(heartbeat))
            registered = {item["node_id"]: item for item in registry.list_nodes()}
            self.assertEqual(registered[first["node_id"]]["agent_version"], "0.2.0")

            replay_body = json.dumps(
                {"agent_version": "0.2.0", "agent_protocol": 2, "claim": False},
                separators=(",", ":"),
            ).encode("utf-8")
            replay_timestamp = str(int(datetime.now(timezone.utc).timestamp()))
            replay_nonce = "nonce_maintenance_replay_01"
            replay_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(replay_body)),
                "X-VPSPC-Node": first["node_id"],
                "X-VPSPC-Timestamp": replay_timestamp,
                "X-VPSPC-Nonce": replay_nonce,
                "X-VPSPC-Signature": sign_request(
                    first["credential"], replay_timestamp, replay_nonce, replay_body
                ),
            }
            first_status, _headers, _payload = request(
                "POST", "/v1/node/heartbeat", replay_body, replay_headers
            )
            replay_status, _headers, replay_payload = request(
                "POST", "/v1/node/heartbeat", replay_body, replay_headers
            )
            self.assertEqual(first_status, 200)
            self.assertEqual(replay_status, 401)
            self.assertIn("already been used", json.loads(replay_payload)["error"])

            status, _headers, payload = signed_request(
                "/v1/node/task-status",
                {"task_id": initial_task["task_id"], "status": "downloading", "result": {"stage": "fetch"}},
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(payload)["task"]["status"], "downloading")
            status, _headers, payload = signed_request(
                "/v1/node/task-status",
                {"task_id": initial_task["task_id"], "status": "installing"},
                node=second,
            )
            self.assertEqual(status, 401)
            self.assertIn("does not belong", json.loads(payload)["error"])

            removal_task = store.create_node_tasks(
                "job_maintenance_http_002",
                [{"node_id": first["node_id"], "name": "vmiss hk"}],
                {"kind": "node_destroy"},
            )[0]
            status, _headers, payload = signed_request(
                "/v1/node/heartbeat",
                {"agent_version": "0.2.0", "agent_protocol": 2, "claim": True},
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(payload)["task"]["task_id"], removal_task["task_id"])
            receipt = store.issue_uninstall_receipt(first["node_id"], removal_task["task_id"])
            receipt_body = json.dumps(
                {
                    "node_id": first["node_id"],
                    "task_id": removal_task["task_id"],
                    "status": "success",
                    "removed_paths_count": 6,
                },
                separators=(",", ":"),
            ).encode("utf-8")
            status, _headers, _payload = signed_request(
                "/v1/node/uninstall-receipt", json.loads(receipt_body)
            )
            self.assertEqual(status, 401)
            status, _headers, payload = request(
                "POST",
                "/v1/node/uninstall-receipt",
                receipt_body,
                {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(receipt_body)),
                    "Authorization": "Bearer " + receipt["token"],
                },
            )
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(payload)["ok"])
            self.assertEqual(
                store.node_results("job_maintenance_http_002")[first["node_id"]]["status"], "success"
            )
            expired = store.issue_uninstall_receipt(first["node_id"], removal_task["task_id"])
            store.expire(datetime.now(timezone.utc) + timedelta(seconds=121))
            status, _headers, _payload = request(
                "POST",
                "/v1/node/uninstall-receipt",
                receipt_body,
                {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(receipt_body)),
                    "Authorization": "Bearer " + expired["token"],
                },
            )
            self.assertEqual(status, 401)

            status, headers, payload = request("GET", "/assets/updates/" + artifact_id)
            self.assertEqual(status, 200)
            self.assertEqual(payload, artifact_payload)
            self.assertEqual(headers["Content-Length"], str(len(artifact_payload)))
            self.assertEqual(headers["Cache-Control"], "public, immutable")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            for path in ("/assets/updates/unknown", "/assets/updates/" + artifact_id + "?x=1"):
                with self.subTest(path=path):
                    self.assertEqual(request("GET", path)[0], 404)

            oversized = b"x" * 1025
            status, _headers, _payload = request(
                "POST",
                "/v1/node/heartbeat",
                oversized,
                {"Content-Type": "application/json", "Content-Length": str(len(oversized))},
            )
            self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
