import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from vps_audit.maintenance.releases import (
    API_ROOT,
    GitHubReleaseSource,
    artifact_id_for,
    safe_extract_tar,
    verify_file,
)


def sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def artifact(name, payload, release_tag="v1.2.3"):
    return {
        "name": name,
        "url": (
            "https://github.com/allen0039/vps_tools/releases/download/"
            f"{release_tag}/{name}"
        ),
        "sha256": sha256(payload),
        "size": len(payload),
    }


def manifest(channel, revision, controller_payload=b"controller", node_payload=b"node"):
    version = "edge" if channel == "edge" else "v1.2.3"
    return {
        "schema_version": 1,
        "version": version,
        "channel": channel,
        "source_revision": revision,
        "controller_protocol": 1,
        "node_protocol": 1,
        "config_schema_min": 1,
        "config_schema_max": 1,
        "controller_upgrade_from": "v0.1.0",
        "controller_downgrade_from": "v2.0.0",
        "node_upgrade_from": "v0.1.0",
        "node_downgrade_from": "v2.0.0",
        "artifacts": {
            "controller": artifact(
                "vpspc-controller-v1.2.3.tar.gz", controller_payload, version
            ),
            "node": artifact("vpspc-node-v1.2.3.py", node_payload, version),
        },
        "docker_digest": "sha256:" + "b" * 64,
    }


class FixtureResponse(io.BytesIO):
    def __init__(self, payload, url):
        super().__init__(payload)
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def geturl(self):
        return self._url


class FixtureOpener:
    def __init__(self, payloads, redirects=None):
        self.payloads = payloads
        self.redirects = redirects or {}
        self.calls = []

    def __call__(self, request, timeout):
        url = request.full_url
        self.calls.append((url, timeout))
        return FixtureResponse(self.payloads[url], self.redirects.get(url, url))


def tar_archive(member_name, payload=b"content", member_type=tarfile.REGTYPE):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        info = tarfile.TarInfo(member_name)
        info.type = member_type
        if member_type == tarfile.REGTYPE:
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        else:
            info.linkname = "target"
            archive.addfile(info)
    return output.getvalue()


class GitHubReleaseSourceTests(unittest.TestCase):
    def test_catalog_rejects_asset_outside_fixed_repository(self):
        raw = manifest("stable", "a" * 40)
        raw["artifacts"] = dict(raw["artifacts"])
        raw["artifacts"]["controller"] = dict(
            raw["artifacts"]["controller"], url="https://evil.example/a.tgz"
        )
        with tempfile.TemporaryDirectory() as temporary:
            source = GitHubReleaseSource(Path(temporary), opener=FixtureOpener({}))
            with self.assertRaisesRegex(ValueError, "allowed GitHub repository"):
                source.parse_manifest(raw)

    def test_fetches_fixed_release_and_edge_catalog_from_local_fixtures(self):
        stable_controller = b"stable-controller"
        stable_node = b"stable-node"
        edge_controller = b"edge-controller"
        edge_node = b"edge-node"
        stable_manifest_url = (
            "https://github.com/allen0039/vps_tools/releases/download/"
            "v1.2.3/manifest.json"
        )
        edge_manifest_url = (
            "https://github.com/allen0039/vps_tools/releases/download/edge/manifest.json"
        )
        release_payload = [
            {
                "tag_name": "v1.2.3",
                "draft": False,
                "prerelease": False,
                "assets": [{"name": "manifest.json", "browser_download_url": stable_manifest_url}],
            },
        ]
        payloads = {
            API_ROOT + "/releases?per_page=100": json.dumps(release_payload).encode("utf-8"),
            API_ROOT + "/releases/tags/edge": json.dumps({
                "tag_name": "edge",
                "draft": False,
                "prerelease": True,
                "assets": [{"name": "manifest.json", "browser_download_url": edge_manifest_url}],
            }).encode("utf-8"),
            stable_manifest_url: json.dumps(
                manifest("stable", "a" * 40, stable_controller, stable_node)
            ).encode("utf-8"),
            edge_manifest_url: json.dumps(
                manifest("edge", "c" * 40, edge_controller, edge_node)
            ).encode("utf-8"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            source = GitHubReleaseSource(Path(temporary), opener=FixtureOpener(payloads))
            catalog = source.fetch_catalog()
            self.assertEqual(catalog.stable.version, "v1.2.3")
            self.assertEqual(catalog.edge.version, "edge")
            self.assertEqual([item.version for item in catalog.releases], ["v1.2.3"])
            self.assertEqual(source.resolve("stable", None).version, "v1.2.3")
            self.assertEqual(source.resolve("stable", "v1.2.3").version, "v1.2.3")
            self.assertEqual(source.resolve("edge", None).source_revision, "c" * 40)

    def test_download_verifies_manifest_and_persists_safe_artifact_id_mapping(self):
        controller = b"verified-controller-bundle"
        raw = manifest("stable", "a" * 40, controller)
        controller_url = raw["artifacts"]["controller"]["url"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = GitHubReleaseSource(root, opener=FixtureOpener({controller_url: controller}))
            release = source.parse_manifest(raw)
            downloaded = source.download(release.controller)
            artifact_id = artifact_id_for(release.controller)
            self.assertEqual(downloaded.read_bytes(), controller)
            self.assertEqual(source.artifact_path(artifact_id), downloaded)
            self.assertEqual(source.cached_artifacts()[artifact_id], downloaded.name)
            self.assertEqual(downloaded.parent, root.resolve())
            self.assertTrue(downloaded.name.startswith(artifact_id))

    def test_download_rejects_redirect_outside_github_and_bad_payload(self):
        controller = b"verified-controller-bundle"
        raw = manifest("stable", "a" * 40, controller)
        controller_url = raw["artifacts"]["controller"]["url"]
        with tempfile.TemporaryDirectory() as temporary:
            source = GitHubReleaseSource(
                Path(temporary),
                opener=FixtureOpener({controller_url: controller}, {controller_url: "https://evil.example/a"}),
            )
            with self.assertRaisesRegex(ValueError, "allowed GitHub repository"):
                source.download(source.parse_manifest(raw).controller)

        with tempfile.TemporaryDirectory() as temporary:
            source = GitHubReleaseSource(Path(temporary), opener=FixtureOpener({controller_url: b"wrong"}))
            with self.assertRaisesRegex(ValueError, "size does not match|SHA-256"):
                source.download(source.parse_manifest(raw).controller)

    def test_verify_file_requires_exact_size_and_sha256(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact"
            path.write_bytes(b"artifact")
            verify_file(path, sha256(b"artifact"), len(b"artifact"))
            with self.assertRaisesRegex(ValueError, "size does not match"):
                verify_file(path, sha256(b"artifact"), 1)
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                verify_file(path, "a" * 64, len(b"artifact"))

    def test_safe_extract_rejects_parent_and_symlink_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, payload in (
                ("parent.tar.gz", tar_archive("../outside")),
                ("symlink.tar.gz", tar_archive("bad-link", member_type=tarfile.SYMTYPE)),
            ):
                archive = root / name
                archive.write_bytes(payload)
                with self.subTest(archive=name), self.assertRaisesRegex(ValueError, "unsafe archive"):
                    safe_extract_tar(archive, root / (name + ".out"), max_bytes=10_000_000)

    def test_safe_extract_enforces_total_limit_and_writes_only_regular_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bundle.tar.gz"
            archive.write_bytes(tar_archive("bundle/file.txt", b"trusted"))
            destination = root / "extract"
            extracted = safe_extract_tar(archive, destination, max_bytes=10_000_000)
            self.assertEqual(extracted, destination)
            self.assertEqual((destination / "bundle/file.txt").read_bytes(), b"trusted")
            with self.assertRaisesRegex(ValueError, "maximum"):
                safe_extract_tar(archive, root / "too-small", max_bytes=1)


if __name__ == "__main__":
    unittest.main()
