import re
import unittest
from pathlib import Path

from vps_audit import __version__, current_controller_version
from vps_audit.maintenance.models import (
    ArtifactSpec,
    CompatibilityError,
    ReleaseManifest,
    parse_release_version,
    validate_compatibility,
)


RELEASE_FIXTURE = {
    "schema_version": 1,
    "version": "v1.2.3",
    "channel": "stable",
    "source_revision": "c" * 40,
    "controller_protocol": 2,
    "node_protocol": 2,
    "config_schema_min": 1,
    "config_schema_max": 3,
    "controller_upgrade_from": "v0.1.0",
    "controller_downgrade_from": "v0.1.0",
    "node_upgrade_from": "v0.1.0",
    "node_downgrade_from": "v0.1.0",
    "artifacts": {
        "controller": {
            "name": "vpspc-controller-v1.2.3.tar.gz",
            "url": "https://github.com/allen0039/vps_tools/releases/download/v1.2.3/vpspc-controller-v1.2.3.tar.gz",
            "sha256": "a" * 64,
            "size": 12345,
        },
        "node": {
            "name": "vpspc-node-v1.2.3.py",
            "url": "https://github.com/allen0039/vps_tools/releases/download/v1.2.3/vpspc-node-v1.2.3.py",
            "sha256": "b" * 64,
            "size": 23456,
        },
    },
    "docker_digest": "sha256:" + "d" * 64,
}


class MaintenanceModelTests(unittest.TestCase):
    def test_release_version_accepts_release_and_rejects_arbitrary_ref(self):
        self.assertEqual(parse_release_version("v1.2.3"), (1, 2, 3))
        for value in (
            "1.2.3",
            "v01.2.3",
            "v1.02.3",
            "v1.2.03",
            "v1.2",
            "main",
            "feature/x",
            "deadbeef",
            "https://example.com/a",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_release_version(value)

    def test_manifest_requires_immutable_artifact_metadata(self):
        manifest = ReleaseManifest.from_dict(RELEASE_FIXTURE)
        self.assertEqual(manifest.controller, ArtifactSpec(
            name="vpspc-controller-v1.2.3.tar.gz",
            url=RELEASE_FIXTURE["artifacts"]["controller"]["url"],
            sha256="a" * 64,
            size=12345,
        ))
        self.assertEqual(manifest.node.sha256, "b" * 64)
        self.assertEqual(manifest.docker_digest, "sha256:" + "d" * 64)

    def test_manifest_rejects_missing_extra_or_mutable_metadata(self):
        cases = {
            "missing node": lambda value: value["artifacts"].pop("node"),
            "extra top-level": lambda value: value.update({"unexpected": True}),
            "uppercase checksum": lambda value: value["artifacts"]["controller"].update({"sha256": "A" * 64}),
            "mutable image tag": lambda value: value.update({"docker_digest": "ghcr.io/allen0039/vpspc:latest"}),
            "non-release stable version": lambda value: value.update({"version": "main"}),
            "malformed source revision": lambda value: value.update({"source_revision": "deadbeef"}),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                value = {
                    **RELEASE_FIXTURE,
                    "artifacts": {
                        key: dict(spec)
                        for key, spec in RELEASE_FIXTURE["artifacts"].items()
                    },
                }
                mutate(value)
                with self.assertRaises(ValueError):
                    ReleaseManifest.from_dict(value)

    def test_edge_manifest_requires_edge_version_and_immutable_revision(self):
        edge = dict(RELEASE_FIXTURE, channel="edge", version="edge")
        self.assertEqual(ReleaseManifest.from_dict(edge).channel, "edge")
        for value in ("v1.2.3", "main", "edge-20260827"):
            with self.subTest(value=value):
                invalid = dict(edge, version=value)
                with self.assertRaises(ValueError):
                    ReleaseManifest.from_dict(invalid)

    def test_compatibility_rejects_unsupported_protocol_config_and_downgrade(self):
        manifest = ReleaseManifest.from_dict(RELEASE_FIXTURE)
        cases = (
            {"current_protocol": 0, "config_schema": 2, "direction": "upgrade"},
            {"current_protocol": 2, "config_schema": 99, "direction": "upgrade"},
            {"current_protocol": 2, "config_schema": 2, "direction": "downgrade"},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(CompatibilityError, "incompatible") as raised:
                    validate_compatibility(
                        manifest=manifest,
                        component="controller",
                        current_version="v0.3.0",
                        **kwargs,
                    )
                self.assertEqual(raised.exception.stage, "compatibility_preflight")

    def test_compatibility_checks_source_floor_and_accepts_package_version(self):
        manifest = ReleaseManifest.from_dict(RELEASE_FIXTURE)
        with self.assertRaisesRegex(CompatibilityError, "incompatible"):
            validate_compatibility(
                manifest=manifest,
                component="node",
                current_version="v0.0.9",
                current_protocol=2,
                config_schema=2,
                direction="upgrade",
            )
        validate_compatibility(
            manifest=manifest,
            component="controller",
            current_version="1.2.2",
            current_protocol=2,
            config_schema=2,
            direction="upgrade",
        )

    def test_package_metadata_reads_the_single_source_version(self):
        root = Path(__file__).resolve().parents[1]
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        setup = (root / "setup.py").read_text(encoding="utf-8")

        self.assertRegex(__version__, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertEqual(current_controller_version(), __version__)
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn('version = {attr = "vps_audit.__version__"}', pyproject)
        self.assertNotIn('version = "0.6.0"', pyproject)
        self.assertIn("__version__", setup)
        self.assertNotIn('version="0.6.0"', setup)


if __name__ == "__main__":
    unittest.main()
