from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tarfile
import tempfile
import threading
import time
import unittest

from vps_audit.maintenance.helper_client import HostUpdaterClient
from vps_audit.maintenance.ownership import OwnedResource, OwnershipManifest, file_fingerprint


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "deploy" / "update" / "vpspc-host-updater.py"


def load_helper_module():
    spec = importlib.util.spec_from_file_location("vpspc_host_updater", HELPER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load host updater")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_bundle(path: Path, files: dict[str, bytes]) -> str:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot_tree(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class RecordingRunner:
    def __init__(self):
        self.commands: list[tuple[str, ...]] = []

    def run(self, command, check: bool = True) -> int:
        self.commands.append(tuple(command))
        return 0


class HostUpdaterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.install_root = self.root / "install"
        self.install_root.mkdir()
        (self.install_root / "vps_audit").mkdir()
        (self.install_root / "vps_audit" / "old.py").write_text("OLD = True\n", encoding="utf-8")
        (self.install_root / "venv-keep.txt").write_text("preserved\n", encoding="utf-8")

        self.config_path = self.root / "config.json"
        self.config_path.write_text("{}\n", encoding="utf-8")
        self.cache_root = self.root / "cache"
        self.cache_root.mkdir()
        self.work_root = self.root / "work"
        self.key_path = self.root / "updater.key"
        self.key_path.write_text("test-secret-value\n", encoding="utf-8")
        self.key_path.chmod(0o600)
        self.runner = RecordingRunner()
        self.helper_module = load_helper_module()
        self.paths = self.helper_module.NativePaths(
            install_root=self.install_root,
            config_path=self.config_path,
            cache_root=self.cache_root,
            work_root=self.work_root,
            ownership_manifest=self.root / "ownership.json",
            allowed_roots=(self.root,),
            enabled_units=("vps-audit.service",),
        )
        self.helper = self.helper_module.HostUpdater(
            paths=self.paths,
            key_path=self.key_path,
            runner=self.runner,
            require_root_owned_files=False,
        )

    def request(self, artifact_id: str = "controller-v1.2.3") -> dict[str, str]:
        artifact = self.cache_root / (artifact_id + ".tar.gz")
        digest = write_bundle(
            artifact,
            {
                "vps_audit/new.py": b"NEW = True\n",
                "pyproject.toml": b"[project]\nname='vpspc'\n",
            },
        )
        return {
            "action": "native-update",
            "job_id": "job_12345678",
            "artifact_id": artifact_id,
            "version": "v1.2.3",
            "sha256": digest,
        }

    def signed(self, method: str, path: str, body: dict[str, str], **changes):
        timestamp = changes.pop("timestamp", int(time.time()))
        nonce = changes.pop("nonce", "a" * 32)
        envelope = {
            "method": method,
            "path": path,
            "timestamp": timestamp,
            "nonce": nonce,
            "body": body,
        }
        envelope["signature"] = self.helper_module.sign_envelope(
            "test-secret-value", method, path, timestamp, nonce, body
        )
        envelope.update(changes)
        return envelope

    def test_helper_rejects_shell_url_and_caller_paths(self):
        for payload in (
            {"action": "exec", "command": "id"},
            {"action": "native-update", "url": "https://evil.example/a"},
            {"action": "controller-destroy", "path": "/"},
        ):
            with self.subTest(payload=payload):
                result = self.helper.handle(payload)
                self.assertEqual(result["error"], "unsupported request fields")

    def test_signed_protocol_rejects_replay_and_old_requests(self):
        body = self.request()
        envelope = self.signed("POST", "/v1/native-update", body)
        first = self.helper.handle_envelope(envelope, healthcheck=lambda _root: True)
        self.assertEqual(first["status"], "success")

        replay = self.helper.handle_envelope(envelope, healthcheck=lambda _root: True)
        self.assertEqual(replay["status"], "error")
        self.assertEqual(replay["error"], "request nonce has already been used")

        old = self.signed(
            "GET", "/v1/jobs/job_12345678", {}, timestamp=int(time.time()) - 61, nonce="b" * 32
        )
        expired = self.helper.handle_envelope(old)
        self.assertEqual(expired["status"], "error")
        self.assertEqual(expired["error"], "request timestamp is outside the replay window")

    def test_client_uses_signed_unix_socket_protocol(self):
        listener_path = self.root / "updater.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(listener_path))
        listener.listen(1)
        received: list[dict] = []

        def serve_one() -> None:
            with listener:
                connection, _ = listener.accept()
                with connection:
                    raw = b""
                    while True:
                        block = connection.recv(8192)
                        if not block:
                            break
                        raw += block
                    envelope = json.loads(raw.decode("utf-8"))
                    received.append(envelope)
                    response = self.helper.handle_envelope(envelope, healthcheck=lambda _root: True)
                    connection.sendall(json.dumps(response).encode("utf-8"))

        worker = threading.Thread(target=serve_one)
        worker.start()
        client = HostUpdaterClient(listener_path, self.key_path, timeout_seconds=5)
        result = client.native_update(
            job_id="job_12345678",
            artifact_id="controller-v1.2.3",
            version="v1.2.3",
            sha256=self.request()["sha256"],
        )
        worker.join(timeout=5)

        self.assertFalse(worker.is_alive())
        self.assertEqual(result["status"], "success")
        self.assertEqual(received[0]["path"], "/v1/native-update")
        self.assertNotIn("command", received[0]["body"])

    def test_native_health_failure_restores_install_tree(self):
        before = snapshot_tree(self.install_root)
        result = self.helper.native_update(self.request(), healthcheck=lambda _root: False)
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(snapshot_tree(self.install_root), before)
        self.assertFalse(any(self.work_root.iterdir()))
        self.assertIn(("systemctl", "stop", "vps-audit.service"), self.runner.commands)
        self.assertIn(("systemctl", "start", "vps-audit.service"), self.runner.commands)

    def test_native_update_only_reads_fixed_cache_artifact_and_cleans_workspace(self):
        request = self.request()
        result = self.helper.native_update(request, healthcheck=lambda _root: True)
        self.assertEqual(result["status"], "success")
        self.assertEqual((self.install_root / "vps_audit" / "new.py").read_text(encoding="utf-8"), "NEW = True\n")
        self.assertEqual((self.install_root / "venv-keep.txt").read_text(encoding="utf-8"), "preserved\n")
        self.assertFalse(any(self.work_root.iterdir()))

    def test_native_update_preserves_venv_links_without_following_them(self):
        venv_bin = self.install_root / "venv" / "bin"
        venv_bin.mkdir(parents=True)
        venv_python = venv_bin / "python"
        venv_python.symlink_to("/usr/bin/python3")

        result = self.helper.native_update(self.request(), healthcheck=lambda _root: True)

        self.assertEqual(result["status"], "success")
        self.assertTrue((self.install_root / "venv" / "bin" / "python").is_symlink())
        self.assertEqual(os.readlink(self.install_root / "venv" / "bin" / "python"), "/usr/bin/python3")

    def test_native_update_rejects_archive_path_escape_before_stopping_services(self):
        artifact_id = "controller-v1.2.3"
        artifact = self.cache_root / (artifact_id + ".tar.gz")
        with tarfile.open(artifact, "w:gz") as archive:
            entry = tarfile.TarInfo("../outside.py")
            entry.size = 4
            archive.addfile(entry, io.BytesIO(b"nope"))
        request = {
            "action": "native-update",
            "job_id": "job_12345678",
            "artifact_id": artifact_id,
            "version": "v1.2.3",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }

        result = self.helper.native_update(request, healthcheck=lambda _root: True)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["stage"], "staging")
        self.assertFalse((self.root / "outside.py").exists())
        self.assertNotIn(("systemctl", "stop", "vps-audit.service"), self.runner.commands)

    def test_controller_destroy_returns_verified_plan_without_deleting(self):
        data = self.root / "data"
        data.mkdir()
        marker = data / ".vps-audit-managed"
        marker.write_text("managed-by=vpspc\n", encoding="utf-8")
        event = data / "events.jsonl"
        event.write_text("keep until final coordinator confirmation\n", encoding="utf-8")
        manifest = OwnershipManifest(
            schema_version=1,
            install_mode="native",
            resources=(
                OwnedResource(
                    kind="managed_data",
                    path=str(data),
                    marker=".vps-audit-managed",
                    fingerprint=file_fingerprint(marker),
                ),
            ),
        )
        self.paths.ownership_manifest.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
        self.paths.ownership_manifest.chmod(0o600)

        result = self.helper.controller_destroy(
            {
                "action": "controller-destroy",
                "job_id": "job_12345678",
                "confirmation_id": "confirm_" + "a" * 32,
            }
        )
        self.assertEqual(result["status"], "planned")
        self.assertIn(str(event.resolve()), result["removal_plan"]["files"])
        self.assertTrue(event.exists())
        self.assertTrue(marker.exists())

    def test_units_are_socket_activated_and_constrained(self):
        systemd = ROOT / "deploy" / "systemd"
        service = (systemd / "vps-audit-update-helper.service").read_text(encoding="utf-8")
        socket_unit = (systemd / "vps-audit-update-helper.socket").read_text(encoding="utf-8")
        self.assertIn("ListenStream=/run/vpspc/updater.sock", socket_unit)
        self.assertIn("SocketMode=0600", socket_unit)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("/run/vpspc", service)
        self.assertNotIn("docker.sock", service)


if __name__ == "__main__":
    unittest.main()
