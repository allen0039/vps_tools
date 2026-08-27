import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from vps_audit.maintenance.ownership import (
    FalcoOwnership,
    OwnedResource,
    OwnershipManifest,
    build_removal_plan,
    classify_falco_ownership,
    file_fingerprint,
)


def fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def manifest(self, *resources: OwnedResource) -> OwnershipManifest:
        return OwnershipManifest(schema_version=1, install_mode="native", resources=resources)

    def mark_directory(self, path: Path, marker: str = ".vps-audit-managed") -> Path:
        path.mkdir(parents=True)
        marker_path = path / marker
        marker_path.write_text("managed-by=vpspc\n", encoding="utf-8")
        return marker_path

    def test_manifest_parser_rejects_unknown_fields_and_unsafe_resources(self):
        safe = self.root / "data"
        raw = {
            "schema_version": 1,
            "install_mode": "native",
            "resources": [
                {
                    "kind": "managed_data",
                    "path": str(safe),
                    "marker": ".vps-audit-managed",
                    "fingerprint": "a" * 64,
                }
            ],
        }
        parsed = OwnershipManifest.from_dict(raw)
        self.assertEqual(parsed.resources[0].path, str(safe))

        with_extra = dict(raw)
        with_extra["operator_path"] = "/tmp/should-not-be-accepted"
        with self.assertRaisesRegex(ValueError, "fields are invalid"):
            OwnershipManifest.from_dict(with_extra)

        unsafe = dict(raw)
        unsafe["resources"] = [dict(raw["resources"][0], path="/")]
        with self.assertRaisesRegex(ValueError, "unsafe or unowned"):
            OwnershipManifest.from_dict(unsafe)

        third_party = dict(raw)
        third_party["resources"] = [dict(raw["resources"][0], path="/etc/xray/config.json")]
        with self.assertRaisesRegex(ValueError, "unsafe or unowned"):
            OwnershipManifest.from_dict(third_party)

    def test_manifest_load_requires_private_mode_and_can_be_tested_without_root_owner(self):
        path = self.root / "ownership.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "install_mode": "native",
                    "resources": [],
                }
            ),
            encoding="utf-8",
        )
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(ValueError, "0600"):
            OwnershipManifest.load(path, require_root_owner=False)

        os.chmod(path, 0o600)
        loaded = OwnershipManifest.load(path, require_root_owner=False)
        self.assertEqual(loaded.resources, ())

    def test_removal_plan_rejects_root_home_and_unmarked_directory(self):
        foreign_directory = self.root / "foreign"
        foreign_directory.mkdir()
        for path in (Path("/"), Path("/root"), foreign_directory):
            resource = OwnedResource(
                kind="managed_directory",
                path=str(path),
                marker=".vps-audit-managed",
                fingerprint="0" * 64,
            )
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe or unowned"):
                build_removal_plan(self.manifest(resource), allowed_roots=(self.root,))

    def test_removal_plan_requires_marker_and_fingerprint_before_collecting_files(self):
        data = self.root / "state"
        marker = self.mark_directory(data)
        event = data / "events.jsonl"
        event.write_text("event\n", encoding="utf-8")
        resource = OwnedResource(
            kind="managed_data",
            path=str(data),
            marker=".vps-audit-managed",
            fingerprint=file_fingerprint(marker),
        )
        plan = build_removal_plan(self.manifest(resource), allowed_roots=(self.root,))
        self.assertIn(event.resolve(), plan.files)
        self.assertIn(data.resolve(), plan.directories)

        marker.write_text("modified by a different tool\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsafe or unowned"):
            build_removal_plan(self.manifest(resource), allowed_roots=(self.root,))

    def test_geolite_databases_are_removed_only_from_marked_vpspc_data_directory(self):
        vpspc_data = self.root / "vpspc-data"
        marker = self.mark_directory(vpspc_data)
        city = vpspc_data / "GeoLite2-City.mmdb"
        asn = vpspc_data / "GeoLite2-ASN.mmdb"
        city.write_bytes(b"vpspc-city")
        asn.write_bytes(b"vpspc-asn")

        shared_geoip = self.root / "shared-geoip"
        shared_geoip.mkdir()
        shared_city = shared_geoip / "GeoLite2-City.mmdb"
        shared_city.write_bytes(b"must-survive")

        resource = OwnedResource(
            kind="managed_data",
            path=str(vpspc_data),
            marker=".vps-audit-managed",
            fingerprint=file_fingerprint(marker),
        )
        plan = build_removal_plan(self.manifest(resource), allowed_roots=(self.root,))

        self.assertIn(city.resolve(), plan.files)
        self.assertIn(asn.resolve(), plan.files)
        self.assertNotIn(shared_city.resolve(), plan.files)
        self.assertTrue(shared_city.is_file())

    def test_falco_external_change_preserves_package_and_foreign_rules(self):
        managed = self.root / "config" / "managed"
        managed.mkdir(parents=True)
        (managed / "package").write_text("managed-by=vps-audit\n", encoding="utf-8")

        falco_root = self.root / "falco"
        foreign_rule = falco_root / "rules.d" / "foreign.yaml"
        foreign_rule.parent.mkdir(parents=True)
        foreign_rule.write_text("foreign-rule: before\n", encoding="utf-8")
        baseline = managed / "baseline.sha256"
        baseline.write_text(
            f"{file_fingerprint(foreign_rule)}  {foreign_rule}\n", encoding="utf-8"
        )

        vpspc_rule = falco_root / "rules.d" / "vps-audit-rules.yaml"
        vpspc_rule.write_text("# managed-by=vps-audit\nrule: audit\n", encoding="utf-8")
        # This file was created after the baseline.  It is known VPSPC content,
        # while the added foreign rule makes the package shared/conservative.
        (falco_root / "rules.d" / "another-tool.yaml").write_text("foreign\n", encoding="utf-8")

        package = OwnedResource(
            kind="falco_package",
            path=str(managed),
            marker="package",
            fingerprint=file_fingerprint(baseline),
        )
        rule = OwnedResource(
            kind="falco_rule",
            path=str(vpspc_rule),
            marker="managed-by=vps-audit",
            fingerprint=file_fingerprint(vpspc_rule),
        )
        manifest = self.manifest(package, rule)
        plan = build_removal_plan(
            manifest,
            allowed_roots=(self.root,),
            falco_snapshot_roots=(falco_root,),
        )

        self.assertNotIn("falco-package", plan.components)
        self.assertIn(vpspc_rule.resolve(), plan.files)
        self.assertNotIn(foreign_rule.resolve(), plan.files)
        self.assertIn("falco shared or externally changed", plan.safely_retained)

    def test_falco_package_is_exclusive_only_when_baseline_is_unchanged(self):
        managed = self.root / "config" / "managed"
        managed.mkdir(parents=True)
        (managed / "package").write_text("managed-by=vps-audit\n", encoding="utf-8")
        falco_root = self.root / "falco"
        foreign_rule = falco_root / "rules.d" / "foreign.yaml"
        foreign_rule.parent.mkdir(parents=True)
        foreign_rule.write_text("foreign-rule: before\n", encoding="utf-8")
        baseline = managed / "baseline.sha256"
        baseline.write_text(
            f"{file_fingerprint(foreign_rule)}  {foreign_rule}\n", encoding="utf-8"
        )
        package = OwnedResource(
            kind="falco_package",
            path=str(managed),
            marker="package",
            fingerprint=file_fingerprint(baseline),
        )

        classification = classify_falco_ownership(
            package,
            allowed_roots=(self.root,),
            snapshot_roots=(falco_root,),
        )
        self.assertEqual(classification, FalcoOwnership.EXCLUSIVE)
        plan = build_removal_plan(
            self.manifest(package),
            allowed_roots=(self.root,),
            falco_snapshot_roots=(falco_root,),
        )
        self.assertIn("falco-package", plan.components)

    def test_tree_with_symlink_is_safely_retained_instead_of_followed(self):
        data = self.root / "data"
        marker = self.mark_directory(data)
        foreign = self.root / "foreign.txt"
        foreign.write_text("keep", encoding="utf-8")
        (data / "link").symlink_to(foreign)
        resource = OwnedResource(
            kind="managed_data",
            path=str(data),
            marker=".vps-audit-managed",
            fingerprint=file_fingerprint(marker),
        )
        with self.assertRaisesRegex(ValueError, "unsafe or unowned"):
            build_removal_plan(self.manifest(resource), allowed_roots=(self.root,))
        self.assertEqual(foreign.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
