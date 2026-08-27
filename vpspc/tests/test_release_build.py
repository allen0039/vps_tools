import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from vps_audit.maintenance.models import ReleaseManifest
from vps_audit.maintenance.releases import GitHubReleaseSource


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ReleaseBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scripts.build_vpspc_release import build_release

        cls.build_release = staticmethod(build_release)

    def test_release_builder_is_deterministic_and_excludes_runtime_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self.build_release(
                ROOT,
                root / "one",
                version="v0.7.0",
                revision="a" * 40,
                channel="stable",
                docker_digest="sha256:" + "b" * 64,
            )
            second = self.build_release(
                ROOT,
                root / "two",
                version="v0.7.0",
                revision="a" * 40,
                channel="stable",
                docker_digest="sha256:" + "b" * 64,
            )

            self.assertEqual(sha256(first.controller), sha256(second.controller))
            self.assertEqual(sha256(first.node), sha256(second.node))

            with tarfile.open(first.controller, "r:gz") as archive:
                members = archive.getmembers()
            names = [member.name for member in members]
            self.assertEqual(names, sorted(names))
            self.assertIn("vpspc/vps_audit/__init__.py", names)
            self.assertIn("vpspc/deploy/node/vpspc-node.py", names)
            self.assertNotIn("vpspc/docker/secrets/web_token", names)
            self.assertNotIn("vpspc/docker/config.json", names)
            self.assertFalse(any(name.startswith("vpspc/tests/") for name in names))
            for member in members:
                self.assertTrue(member.isfile())
                self.assertEqual(member.mtime, 0)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)

    def test_manifest_uses_actual_artifacts_and_validates_against_existing_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = self.build_release(
                ROOT,
                Path(temporary),
                version="v0.7.0",
                revision="c" * 40,
                channel="stable",
                docker_digest="sha256:" + "d" * 64,
            )
            raw_manifest = json.loads(result.manifest.read_text(encoding="utf-8"))
            manifest = ReleaseManifest.from_dict(raw_manifest)
            GitHubReleaseSource(Path(temporary) / "cache").parse_manifest(raw_manifest)
            self.assertEqual(manifest.version, "v0.7.0")
            self.assertEqual(manifest.channel, "stable")
            self.assertEqual(manifest.controller.sha256, sha256(result.controller))
            self.assertEqual(manifest.controller.size, result.controller.stat().st_size)
            self.assertEqual(manifest.node.sha256, sha256(result.node))
            self.assertIn("/releases/download/v0.7.0/", manifest.controller.url)

            checksums = result.checksums.read_text(encoding="utf-8")
            self.assertIn(sha256(result.controller), checksums)
            self.assertIn(sha256(result.node), checksums)
            self.assertIn(sha256(result.manifest), checksums)

    def test_edge_build_uses_only_the_immutable_edge_release_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = self.build_release(
                ROOT,
                Path(temporary),
                version="edge",
                revision="e" * 40,
                channel="edge",
                docker_digest="sha256:" + "f" * 64,
            )
            manifest = ReleaseManifest.from_dict(
                json.loads(result.manifest.read_text(encoding="utf-8"))
            )
            self.assertEqual(result.controller.name, "vpspc-controller-edge.tar.gz")
            self.assertEqual(result.node.name, "vpspc-node-edge.py")
            self.assertEqual(manifest.version, "edge")
            self.assertIn("/releases/download/edge/", manifest.node.url)

    def test_builder_rejects_a_tracked_secret_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            (source / "deploy/node").mkdir(parents=True)
            (source / "vps_audit").mkdir()
            (source / "docker/secrets").mkdir(parents=True)
            (source / "deploy/node/vpspc-node.py").write_text("print('node')\n", encoding="utf-8")
            (source / "vps_audit/__init__.py").write_text("__version__ = '0.7.0'\n", encoding="utf-8")
            (source / "docker/secrets/web_token").write_text("must-not-package\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "add", "."], check=True)

            with self.assertRaisesRegex(ValueError, "secret|unsafe"):
                self.build_release(
                    source,
                    Path(temporary) / "out",
                    version="v0.7.0",
                    revision="a" * 40,
                    channel="stable",
                    docker_digest="sha256:" + "b" * 64,
                )

    def test_cli_requires_an_immutable_docker_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/build_vpspc_release.py"),
                    "--channel",
                    "stable",
                    "--version",
                    "v0.7.0",
                    "--revision",
                    "a" * 40,
                    "--output",
                    str(Path(temporary) / "out"),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("--docker-digest", completed.stderr)


if __name__ == "__main__":
    unittest.main()
