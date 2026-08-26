import os
import json
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "install.sh"
REMOTE_INSTALLER = PROJECT_ROOT / "remote-install.sh"


def run_bash(script: str, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", f'source "{INSTALLER}"\n{script}'],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


class InstallerTests(unittest.TestCase):
    def test_remote_installer_has_valid_shell_syntax(self):
        completed = subprocess.run(
            ["bash", "-n", str(REMOTE_INSTALLER)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_remote_installer_downloads_and_runs_packaged_installer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "vps_tools-test" / "vpspc"
            (package / "vps_audit").mkdir(parents=True)
            (package / "deploy" / "systemd").mkdir(parents=True)
            installer = package / "install.sh"
            installer.write_text(
                "#!/usr/bin/env bash\nset -eu\n"
                "[[ ${1:-} == install ]]\n"
                'touch "${REMOTE_INSTALL_MARKER:?}"\n',
                encoding="utf-8",
            )
            installer.chmod(0o755)
            (package / "remote-install.sh").write_text("fixture", encoding="utf-8")
            (package / "vps_audit" / "runtime.py").write_text("# fixture\n", encoding="utf-8")
            (package / "deploy" / "systemd" / "vps-audit.service").write_text(
                "# fixture\n", encoding="utf-8"
            )
            archive = root / "fixture.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                handle.add(package.parent, arcname=package.parent.name)

            mock_bin = root / "bin"
            mock_bin.mkdir()
            (mock_bin / "id").write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
            (mock_bin / "uname").write_text("#!/bin/sh\necho Linux\n", encoding="utf-8")
            (mock_bin / "curl").write_text(
                "#!/usr/bin/env python3\n"
                "import os, shutil, sys\n"
                'output = sys.argv[sys.argv.index("--output") + 1]\n'
                'shutil.copyfile(os.environ["FIXTURE_ARCHIVE"], output)\n',
                encoding="utf-8",
            )
            for executable in mock_bin.iterdir():
                executable.chmod(0o755)

            destination = root / "installed-source"
            marker = root / "install-ran"
            env = dict(os.environ)
            env.update(
                {
                    "PATH": f"{mock_bin}:{env['PATH']}",
                    "FIXTURE_ARCHIVE": str(archive),
                    "VPSPC_SOURCE_ROOT": str(destination),
                    "VPSPC_REF": "test",
                    "REMOTE_INSTALL_MARKER": str(marker),
                }
            )
            completed = subprocess.run(
                ["bash", str(REMOTE_INSTALLER)],
                env=env,
                text=True,
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(marker.is_file(), completed.stdout + completed.stderr)

    def test_storage_path_validation_accepts_scoped_absolute_path(self):
        completed = run_bash('validate_storage_path "/data/vps-audit" "测试目录"')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "/data/vps-audit")

    def test_storage_path_validation_rejects_dangerous_paths(self):
        for path in ("/", "/var", "/opt", "/home/alice/audit", "relative/path", "/data/../etc"):
            with self.subTest(path=path):
                completed = run_bash(f'validate_storage_path "{path}" "测试目录"')
                self.assertNotEqual(completed.returncode, 0)

    def test_managed_directory_is_private_and_nonempty_unmanaged_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            managed = root / "vps-audit"
            completed = run_bash(f'prepare_managed_directory "{managed}" "测试目录"')
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((managed / ".vps-audit-managed").is_file())
            self.assertEqual(stat.S_IMODE(managed.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((managed / ".vps-audit-managed").stat().st_mode),
                0o600,
            )

            unmanaged = root / "existing"
            unmanaged.mkdir()
            (unmanaged / "user-data.txt").write_text("preserve", encoding="utf-8")
            completed = run_bash(f'prepare_managed_directory "{unmanaged}" "测试目录"')
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual((unmanaged / "user-data.txt").read_text(encoding="utf-8"), "preserve")

    def test_existing_configured_directory_is_adopted_on_upgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = root / "legacy-audit"
            legacy.mkdir()
            (legacy / "events.jsonl").write_text("", encoding="utf-8")
            config = root / "config.json"
            config.write_text(
                '{"state_dir": "' + str(legacy) + '", "report_dir": "' + str(legacy / "reports") + '"}',
                encoding="utf-8",
            )
            completed = run_bash(
                f'CONFIG_FILE="{config}"\nprepare_managed_directory "{legacy}" "测试目录"'
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((legacy / ".vps-audit-managed").is_file())
            self.assertTrue((legacy / "events.jsonl").is_file())

    def test_systemd_unit_uses_custom_state_and_report_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            systemd_dir = root / "systemd"
            mock_bin = root / "bin"
            systemd_dir.mkdir()
            mock_bin.mkdir()
            systemctl = mock_bin / "systemctl"
            systemctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            systemctl.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            completed = run_bash(
                f'SYSTEMD_DIR="{systemd_dir}"\n'
                'install_systemd_units 7 "/data/vps-audit" "/data/vps-audit/reports"',
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            service = (systemd_dir / "vps-audit.service").read_text(encoding="utf-8")
            timer = (systemd_dir / "vps-audit.timer").read_text(encoding="utf-8")
            self.assertIn(
                "ReadWritePaths=/data/vps-audit /data/vps-audit/reports",
                service,
            )
            self.assertNotIn("@STATE_DIR@", service)
            self.assertNotIn("@REPORT_DIR@", service)
            self.assertNotIn("@INTERVAL@", timer)

    def test_noninteractive_configuration_keeps_custom_storage_defaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_dir = root / "config"
            config_dir.mkdir()
            config = config_dir / "config.json"
            state_dir = root / "custom-state"
            report_dir = root / "custom-reports"
            config.write_text(
                json.dumps(
                    {
                        "state_dir": str(state_dir),
                        "report_dir": str(report_dir),
                        "retention_days": 21,
                        "geoip": {"city_db": "/nonexistent", "asn_db": "/nonexistent"},
                    }
                ),
                encoding="utf-8",
            )
            completed = run_bash(
                f'CONFIG_DIR="{config_dir}"\n'
                f'CONFIG_FILE="{config}"\n'
                "write_runtime_config",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            written = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(written["state_dir"], str(state_dir))
            self.assertEqual(written["report_dir"], str(report_dir))
            self.assertEqual(written["retention_days"], 21)
            self.assertTrue((state_dir / ".vps-audit-managed").is_file())
            self.assertTrue((report_dir / ".vps-audit-managed").is_file())

    def test_purge_deletes_only_marked_configured_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_dir = root / "config"
            install_root = root / "application"
            systemd_dir = root / "systemd"
            state_dir = root / "custom-state"
            report_dir = state_dir / "reports"
            original_log = root / "mmwx.log"
            unrelated = root / "keep-me.txt"
            for directory in (config_dir, install_root, systemd_dir, state_dir, report_dir):
                directory.mkdir(exist_ok=True)
            (state_dir / ".vps-audit-managed").write_text("", encoding="utf-8")
            (report_dir / ".vps-audit-managed").write_text("", encoding="utf-8")
            original_log.write_text("original application log", encoding="utf-8")
            unrelated.write_text("unrelated", encoding="utf-8")
            config = config_dir / "config.json"
            config.write_text(
                json.dumps({"state_dir": str(state_dir), "report_dir": str(report_dir)}),
                encoding="utf-8",
            )
            mock_bin = root / "bin"
            mock_bin.mkdir()
            systemctl = mock_bin / "systemctl"
            systemctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            systemctl.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            completed = run_bash(
                "need_root() { :; }\n"
                f'INSTALL_ROOT="{install_root}"\n'
                f'CONFIG_DIR="{config_dir}"\n'
                f'CONFIG_FILE="{config}"\n'
                f'SYSTEMD_DIR="{systemd_dir}"\n'
                "uninstall_app --purge",
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(state_dir.exists())
            self.assertFalse(config_dir.exists())
            self.assertFalse(install_root.exists())
            self.assertEqual(original_log.read_text(encoding="utf-8"), "original application log")
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "unrelated")


if __name__ == "__main__":
    unittest.main()
