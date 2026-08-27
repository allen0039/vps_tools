import os
import grp
import json
import pwd
import stat
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
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
    def test_node_reporting_mode_uses_numeric_menu(self):
        controller = run_bash(
            'ask() { printf 1; }\nselect_node_reporting_mode node_reporting'
        )
        self.assertEqual(controller.returncode, 0, controller.stderr)
        self.assertEqual(controller.stdout, "controller_only")
        self.assertIn("1. 仅主控监控", controller.stderr)
        self.assertIn("2. 允许节点轻量上报", controller.stderr)

        reporting = run_bash(
            'ask() { printf 2; }\nselect_node_reporting_mode controller_only'
        )
        self.assertEqual(reporting.returncode, 0, reporting.stderr)
        self.assertEqual(reporting.stdout, "node_reporting")

        invalid = run_bash('ask() { printf 3; }\nselect_node_reporting_mode controller_only')
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("请选择 1 或 2", invalid.stderr)

    def test_geoip_database_is_auto_detected_in_state_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            geoip = state / "geoip"
            geoip.mkdir(parents=True)
            city = geoip / "GeoLite2-City.mmdb"
            city.write_bytes(b"fixture")
            completed = run_bash(
                f'detect_geoip_database GeoLite2-City.mmdb "" "{state}"'
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, str(city))

    def test_missing_geoip_decline_skips_without_path_prompt(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            completed = run_bash(
                'detect_geoip_database() { :; }\n'
                'ask_yes_no() { return 1; }\n'
                f'configure_geoip_databases "{state}"'
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "\t")
            self.assertIn("已跳过 GeoIP 安装", completed.stderr)
            self.assertNotIn("MMDB 路径", completed.stderr)

    def test_missing_geoip_accept_installs_both_databases(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            destination = state / "geoip"
            completed = run_bash(
                'detect_geoip_database() { :; }\n'
                'ask_yes_no() { return 0; }\n'
                'install_maxmind_geoip_databases() {\n'
                '  mkdir -p "$1"\n'
                '  : > "$1/GeoLite2-City.mmdb"\n'
                '  : > "$1/GeoLite2-ASN.mmdb"\n'
                '}\n'
                f'configure_geoip_databases "{state}"'
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                completed.stdout,
                f"{destination / 'GeoLite2-City.mmdb'}\t{destination / 'GeoLite2-ASN.mmdb'}",
            )
            self.assertIn("已安装", completed.stderr)

    def test_mmwx_timezone_is_inferred_independently_from_host_timezone(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "mmwx.log"
            log.write_text(
                'time="2026-08-26 20:00:00" level="INFO " msg="用户获取订阅" username=test ip=192.0.2.1\n',
                encoding="utf-8",
            )
            modified = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc).timestamp()
            os.utime(log, (modified, modified))
            completed = run_bash(f'detect_miaomiaowux_timezone "{log}" ""')
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "+08:00")

    def test_configured_native_mmwx_log_is_auto_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "mmwx.log"
            log.write_text("fixture\n", encoding="utf-8")
            completed = run_bash(f'detect_miaomiaowux_log "{log}"')
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, str(log))

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
            self.assertTrue((destination / ".vpspc-source-managed").is_file())

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
            systemctl_log = root / "systemctl.log"
            systemctl.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$MOCK_SYSTEMCTL_LOG"\nexit 0\n',
                encoding="utf-8",
            )
            systemctl.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            env["MOCK_SYSTEMCTL_LOG"] = str(systemctl_log)
            completed = run_bash(
                f'SYSTEMD_DIR="{systemd_dir}"\n'
                'install_systemd_units 7 "/data/vps-audit" "/data/vps-audit/reports" "/archive/vpspc-connections"',
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            service = (systemd_dir / "vps-audit.service").read_text(encoding="utf-8")
            timer = (systemd_dir / "vps-audit.timer").read_text(encoding="utf-8")
            bot_service = (systemd_dir / "vps-audit-bot.service").read_text(encoding="utf-8")
            receiver_service = (systemd_dir / "vps-audit-node-receiver.service").read_text(
                encoding="utf-8"
            )
            self.assertIn(
                "ReadWritePaths=/data/vps-audit /data/vps-audit/reports /archive/vpspc-connections",
                service,
            )
            self.assertNotIn("@STATE_DIR@", service)
            self.assertNotIn("@REPORT_DIR@", service)
            self.assertNotIn("@BEHAVIOR_ARCHIVE_DIR@", service)
            self.assertNotIn("@SUPPLEMENTARY_GROUPS@", service)
            self.assertNotIn("@CAPABILITY_BOUNDING_SET@", service)
            self.assertNotIn("@INTERVAL@", timer)
            self.assertIn("ReadWritePaths=/etc/vps-audit /data/vps-audit /archive/vpspc-connections", bot_service)
            self.assertNotIn("@STATE_DIR@", bot_service)
            self.assertIn("ReadWritePaths=/data/vps-audit /archive/vpspc-connections", receiver_service)
            self.assertIn("/opt/vps-audit/manager/deploy/node", receiver_service)
            self.assertNotIn("@STATE_DIR@", receiver_service)
            self.assertNotIn("enable", systemctl_log.read_text(encoding="utf-8"))

    def test_node_receiver_service_follows_configured_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            systemd_dir = root / "systemd"
            systemd_dir.mkdir()
            (systemd_dir / "vps-audit-node-receiver.service").write_text(
                "fixture\n", encoding="utf-8"
            )
            mock_bin = root / "bin"
            mock_bin.mkdir()
            systemctl_log = root / "systemctl.log"
            (mock_bin / "systemctl").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$MOCK_SYSTEMCTL_LOG"\nexit 0\n',
                encoding="utf-8",
            )
            (mock_bin / "systemctl").chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            env["MOCK_SYSTEMCTL_LOG"] = str(systemctl_log)
            variables = f'CONFIG_FILE="{config}"\nSYSTEMD_DIR="{systemd_dir}"\n'

            config.write_text(
                json.dumps({"node_reporting": {"mode": "node_reporting"}}),
                encoding="utf-8",
            )
            completed = run_bash(variables + "configure_node_receiver_service", env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                systemctl_log.read_text(encoding="utf-8").splitlines(),
                [
                    "enable vps-audit-node-receiver.service",
                    "restart vps-audit-node-receiver.service",
                ],
            )

            systemctl_log.write_text("", encoding="utf-8")
            config.write_text(
                json.dumps({"node_reporting": {"mode": "controller_only"}}),
                encoding="utf-8",
            )
            completed = run_bash(variables + "configure_node_receiver_service", env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                systemctl_log.read_text(encoding="utf-8").splitlines(),
                ["disable --now vps-audit-node-receiver.service"],
            )

    def test_cli_shortcut_is_removed_only_when_managed(self):
        with tempfile.TemporaryDirectory() as temporary:
            shortcut = Path(temporary) / "bin" / "vpspc"
            completed = run_bash(
                f'CLI_SHORTCUT="{shortcut}"\ninstall_cli_shortcut\nremove_cli_shortcut'
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(shortcut.exists())

            shortcut.parent.mkdir(parents=True, exist_ok=True)
            shortcut.write_text("#!/bin/sh\necho unrelated\n", encoding="utf-8")
            completed = run_bash(f'CLI_SHORTCUT="{shortcut}"\nremove_cli_shortcut')
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(shortcut.is_file())
            self.assertIn("unrelated", shortcut.read_text(encoding="utf-8"))

    def test_systemd_unit_adds_only_required_log_read_group(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            systemd_dir = root / "systemd"
            mock_bin = root / "bin"
            systemd_dir.mkdir()
            mock_bin.mkdir()
            (mock_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (mock_bin / "systemctl").chmod(0o755)
            auth_log = root / "auth.log"
            auth_log.write_text("fixture\n", encoding="utf-8")
            auth_log.chmod(0o640)
            if os.geteuid() == 0:
                account = next(item for item in pwd.getpwall() if 0 < item.pw_uid < 2**31)
                group = next(item for item in grp.getgrall() if 0 < item.gr_gid < 2**31)
                os.chown(auth_log, account.pw_uid, group.gr_gid)
            else:
                available_gid = next(
                    (gid for gid in os.getgroups() if 0 < gid < 2**31),
                    None,
                )
                if available_gid is None:
                    self.skipTest("no non-root supplementary group available")
                os.chown(auth_log, -1, available_gid)
            expected_group = grp.getgrgid(auth_log.stat().st_gid).gr_name
            config = root / "config.json"
            config.write_text(json.dumps({"auth_logs": [str(auth_log)]}), encoding="utf-8")
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            completed = run_bash(
                f'SYSTEMD_DIR="{systemd_dir}"\n'
                f'CONFIG_FILE="{config}"\n'
                'install_systemd_units 5 "/data/vps-audit" "/data/vps-audit/reports" "/data/vps-audit/behavior-audit"',
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            service = (systemd_dir / "vps-audit.service").read_text(encoding="utf-8")
            self.assertIn(f"SupplementaryGroups={expected_group}", service)
            self.assertIn("CapabilityBoundingSet=\n", service)

    def test_systemd_unit_uses_read_only_capability_for_owner_only_app_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            systemd_dir = root / "systemd"
            mock_bin = root / "bin"
            systemd_dir.mkdir()
            mock_bin.mkdir()
            (mock_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (mock_bin / "systemctl").chmod(0o755)
            app_log = root / "mmwx.log"
            app_log.write_text("fixture\n", encoding="utf-8")
            app_log.chmod(0o600)
            if os.geteuid() == 0:
                account = next(item for item in pwd.getpwall() if 0 < item.pw_uid < 2**31)
                group = next(item for item in grp.getgrall() if 0 < item.gr_gid < 2**31)
                os.chown(app_log, account.pw_uid, group.gr_gid)
            config = root / "config.json"
            config.write_text(
                json.dumps({"miaomiaowux_logs": [str(app_log)]}),
                encoding="utf-8",
            )
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            completed = run_bash(
                f'SYSTEMD_DIR="{systemd_dir}"\n'
                f'CONFIG_FILE="{config}"\n'
                'install_systemd_units 5 "/data/vps-audit" "/data/vps-audit/reports" "/data/vps-audit/behavior-audit"',
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            service = (systemd_dir / "vps-audit.service").read_text(encoding="utf-8")
            self.assertIn("CapabilityBoundingSet=CAP_DAC_READ_SEARCH", service)

    def test_timer_is_enabled_only_after_initial_audit_succeeds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mock_bin = root / "bin"
            mock_bin.mkdir()
            systemctl_log = root / "systemctl.log"
            (mock_bin / "systemctl").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$MOCK_SYSTEMCTL_LOG"\n'
                'if [ "${FAIL_AUDIT:-0}" = "1" ] && [ "${1:-}" = "start" ]; then exit 1; fi\n'
                'exit 0\n',
                encoding="utf-8",
            )
            (mock_bin / "journalctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            for executable in mock_bin.iterdir():
                executable.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            env["MOCK_SYSTEMCTL_LOG"] = str(systemctl_log)

            completed = run_bash("run_initial_audit_and_enable_timer", env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            calls = systemctl_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(calls, ["start vps-audit.service", "enable --now vps-audit.timer"])

            systemctl_log.write_text("", encoding="utf-8")
            env["FAIL_AUDIT"] = "1"
            completed = run_bash("run_initial_audit_and_enable_timer", env=env)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(
                systemctl_log.read_text(encoding="utf-8").splitlines(),
                ["start vps-audit.service"],
            )

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
                        "subscription_monitoring": {
                            "enabled": True,
                            "mode": "allowlist",
                            "users": ["alice", "bob"],
                        },
                        "geoip": {"city_db": "/nonexistent", "asn_db": "/nonexistent"},
                        "openai_review": {
                            "enabled": True,
                            "active_provider": "vendor",
                            "providers": {
                                "vendor": {
                                    "display_name": "Vendor",
                                    "base_url": "https://vendor.example/v1",
                                    "api_mode": "chat_completions",
                                    "api_key_file": str(config_dir / "ai-providers" / "vendor.key"),
                                    "model": "vendor-model",
                                    "timeout_seconds": 25,
                                }
                            },
                        },
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
            self.assertEqual(written["subscription_monitoring"]["mode"], "allowlist")
            self.assertEqual(written["subscription_monitoring"]["users"], ["alice", "bob"])
            self.assertEqual(written["openai_review"]["active_provider"], "vendor")
            self.assertEqual(written["node_reporting"]["mode"], "controller_only")
            self.assertEqual(
                written["openai_review"]["providers"]["vendor"]["model"], "vendor-model"
            )
            self.assertTrue((state_dir / ".vps-audit-managed").is_file())
            self.assertTrue((report_dir / ".vps-audit-managed").is_file())

    def test_managed_falco_install_and_uninstall_are_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mock_bin = root / "bin"
            mock_bin.mkdir()
            apt_log = root / "apt.log"
            (mock_bin / "apt-get").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$MOCK_APT_LOG"\nexit 0\n',
                encoding="utf-8",
            )
            (mock_bin / "systemctl").write_text(
                '#!/bin/sh\n'
                'if [ "${1:-}" = "is-enabled" ]; then echo disabled; exit 1; fi\n'
                'if [ "${1:-}" = "is-active" ]; then exit 0; fi\n'
                'exit 0\n',
                encoding="utf-8",
            )
            (mock_bin / "falco").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            for executable in mock_bin.iterdir():
                executable.chmod(0o755)

            config_dir = root / "config"
            managed_dir = config_dir / "managed"
            rule = root / "etc-falco" / "rules.d" / "vps-audit-rules.yaml"
            override_dir = root / "systemd" / "falco-modern-bpf.service.d"
            override = override_dir / "vps-audit.conf"
            log_dir = root / "logs"
            log_file = log_dir / "falco-events.json"
            logrotate = root / "logrotate" / "vps-audit-falco"
            repo_list = root / "repo" / "falcosecurity.list"
            repo_key = root / "repo" / "falco.gpg"
            repo_list.parent.mkdir()
            repo_list.write_text("pre-existing repository\n", encoding="utf-8")
            repo_key.write_text("pre-existing key\n", encoding="utf-8")
            unrelated = root / "unrelated-service.conf"
            unrelated.write_text("preserve", encoding="utf-8")

            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            env["MOCK_APT_LOG"] = str(apt_log)
            variables = (
                f'CONFIG_DIR="{config_dir}"\n'
                f'FALCO_MANAGED_DIR="{managed_dir}"\n'
                f'FALCO_RULE_FILE="{rule}"\n'
                f'FALCO_OVERRIDE_DIR="{override_dir}"\n'
                f'FALCO_OVERRIDE_FILE="{override}"\n'
                f'FALCO_LOG_DIR="{log_dir}"\n'
                f'FALCO_LOG_FILE="{log_file}"\n'
                f'FALCO_LOGROTATE_FILE="{logrotate}"\n'
                f'FALCO_REPO_LIST="{repo_list}"\n'
                f'FALCO_REPO_KEY="{repo_key}"\n'
            )
            completed = run_bash(variables + "install_managed_falco 9", env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(rule.is_file())
            override_text = override.read_text(encoding="utf-8")
            self.assertIn("engine.kind=modern_ebpf", override_text)
            self.assertIn("rules[0].disable.rule=*", override_text)
            self.assertIn("rules[1].enable.tag=vps_audit", override_text)
            self.assertIn("rotate 9", logrotate.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(log_file.stat().st_mode), 0o600)
            self.assertTrue((managed_dir / "package").is_file())

            completed = run_bash(variables + "uninstall_managed_falco", env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(rule.exists())
            self.assertFalse(override.exists())
            self.assertFalse(logrotate.exists())
            self.assertFalse(log_dir.exists())
            self.assertFalse(managed_dir.exists())
            self.assertEqual(repo_list.read_text(encoding="utf-8"), "pre-existing repository\n")
            self.assertEqual(repo_key.read_text(encoding="utf-8"), "pre-existing key\n")
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve")
            self.assertIn("purge -y falco", apt_log.read_text(encoding="utf-8"))

    def test_falco_failure_rolls_back_managed_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mock_bin = root / "bin"
            mock_bin.mkdir()
            apt_log = root / "apt.log"
            (mock_bin / "apt-get").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$MOCK_APT_LOG"\nexit 0\n',
                encoding="utf-8",
            )
            (mock_bin / "systemctl").write_text(
                '#!/bin/sh\n'
                'if [ "${1:-}" = "is-enabled" ]; then echo disabled; exit 1; fi\n'
                'if [ "${1:-}" = "is-active" ]; then exit 1; fi\n'
                'exit 0\n',
                encoding="utf-8",
            )
            (mock_bin / "falco").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (mock_bin / "sleep").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            for executable in mock_bin.iterdir():
                executable.chmod(0o755)

            config_dir = root / "config"
            managed_dir = config_dir / "managed"
            rule = root / "etc-falco" / "rules.d" / "vps-audit-rules.yaml"
            override_dir = root / "systemd" / "falco-modern-bpf.service.d"
            log_dir = root / "logs"
            repo_dir = root / "repo"
            repo_dir.mkdir()
            repo_list = repo_dir / "falcosecurity.list"
            repo_key = repo_dir / "falco.gpg"
            repo_list.write_text("preserve repo\n", encoding="utf-8")
            repo_key.write_text("preserve key\n", encoding="utf-8")
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            env["MOCK_APT_LOG"] = str(apt_log)
            variables = (
                f'CONFIG_DIR="{config_dir}"\n'
                f'FALCO_MANAGED_DIR="{managed_dir}"\n'
                f'FALCO_RULE_FILE="{rule}"\n'
                f'FALCO_OVERRIDE_DIR="{override_dir}"\n'
                f'FALCO_OVERRIDE_FILE="{override_dir / "vps-audit.conf"}"\n'
                f'FALCO_LOG_DIR="{log_dir}"\n'
                f'FALCO_LOG_FILE="{log_dir / "falco-events.json"}"\n'
                f'FALCO_LOGROTATE_FILE="{root / "vps-audit-falco.logrotate"}"\n'
                f'FALCO_REPO_LIST="{repo_list}"\n'
                f'FALCO_REPO_KEY="{repo_key}"\n'
            )
            completed = run_bash(
                variables
                + "if install_managed_falco 7; then exit 9; else rollback_falco_install; fi",
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(rule.exists())
            self.assertFalse(override_dir.exists())
            self.assertFalse(log_dir.exists())
            self.assertFalse(managed_dir.exists())
            self.assertEqual(repo_list.read_text(encoding="utf-8"), "preserve repo\n")
            self.assertEqual(repo_key.read_text(encoding="utf-8"), "preserve key\n")
            self.assertIn("purge -y falco", apt_log.read_text(encoding="utf-8"))

    def test_falco_uninstall_preserves_package_when_external_config_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mock_bin = root / "bin"
            mock_bin.mkdir()
            apt_log = root / "apt.log"
            (mock_bin / "apt-get").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$MOCK_APT_LOG"\nexit 0\n',
                encoding="utf-8",
            )
            (mock_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            for executable in mock_bin.iterdir():
                executable.chmod(0o755)

            config_dir = root / "config"
            managed_dir = config_dir / "managed"
            managed_dir.mkdir(parents=True)
            for component in (
                "package",
                "repository",
                "repository-key",
                "falcoctl-mask",
                "rule",
                "service-override",
                "logrotate",
                "log-directory",
            ):
                (managed_dir / component).write_text("managed\n", encoding="utf-8")
            (managed_dir / "baseline.sha256").write_text("", encoding="utf-8")

            falco_etc = root / "etc-falco"
            rule = falco_etc / "rules.d" / "vps-audit-rules.yaml"
            rule.parent.mkdir(parents=True)
            rule.write_text("managed rule\n", encoding="utf-8")
            external_rule = rule.parent / "external-service.yaml"
            external_rule.write_text("external rule\n", encoding="utf-8")
            override_dir = root / "systemd" / "falco-modern-bpf.service.d"
            override_dir.mkdir(parents=True)
            override = override_dir / "vps-audit.conf"
            override.write_text("managed override\n", encoding="utf-8")
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / ".vps-audit-falco-managed").write_text("", encoding="utf-8")
            log_file = log_dir / "falco-events.json"
            log_file.write_text("", encoding="utf-8")
            logrotate = root / "vps-audit-falco.logrotate"
            logrotate.write_text("managed\n", encoding="utf-8")
            repo_list = root / "falcosecurity.list"
            repo_key = root / "falco.gpg"
            repo_list.write_text("repository\n", encoding="utf-8")
            repo_key.write_text("key\n", encoding="utf-8")

            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            env["MOCK_APT_LOG"] = str(apt_log)
            completed = run_bash(
                f'CONFIG_DIR="{config_dir}"\n'
                f'FALCO_MANAGED_DIR="{managed_dir}"\n'
                f'FALCO_ETC_DIR="{falco_etc}"\n'
                f'FALCOCTL_ETC_DIR="{root / "etc-falcoctl"}"\n'
                f'FALCO_RULE_FILE="{rule}"\n'
                f'FALCO_OVERRIDE_DIR="{override_dir}"\n'
                f'FALCO_OVERRIDE_FILE="{override}"\n'
                f'FALCO_LOG_DIR="{log_dir}"\n'
                f'FALCO_LOG_FILE="{log_file}"\n'
                f'FALCO_LOGROTATE_FILE="{logrotate}"\n'
                f'FALCO_REPO_LIST="{repo_list}"\n'
                f'FALCO_REPO_KEY="{repo_key}"\n'
                "uninstall_managed_falco",
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(external_rule.is_file())
            self.assertFalse(rule.exists())
            self.assertFalse(override.exists())
            self.assertTrue(repo_list.is_file())
            self.assertTrue(repo_key.is_file())
            self.assertFalse(managed_dir.exists())
            self.assertFalse(apt_log.exists(), "shared Falco package must not be purged")

    def test_destroy_removes_managed_source_but_preserves_unrelated_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "vps-audit-src"
            config_dir = root / "config"
            install_root = root / "application"
            systemd_dir = root / "systemd"
            state_dir = root / "state"
            report_dir = state_dir / "reports"
            for directory in (source, config_dir, install_root, systemd_dir, state_dir, report_dir):
                directory.mkdir(exist_ok=True)
            (source / ".vpspc-source-managed").write_text("managed\n", encoding="utf-8")
            (state_dir / ".vps-audit-managed").write_text("", encoding="utf-8")
            (report_dir / ".vps-audit-managed").write_text("", encoding="utf-8")
            config = config_dir / "config.json"
            config.write_text(
                json.dumps({"state_dir": str(state_dir), "report_dir": str(report_dir)}),
                encoding="utf-8",
            )
            unrelated = root / "other-service.data"
            unrelated.write_text("preserve", encoding="utf-8")
            mock_bin = root / "bin"
            mock_bin.mkdir()
            (mock_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (mock_bin / "systemctl").chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            completed = run_bash(
                "need_root() { :; }\n"
                f'SCRIPT_DIR="{source}"\n'
                f'INSTALL_ROOT="{install_root}"\n'
                f'CONFIG_DIR="{config_dir}"\n'
                f'CONFIG_FILE="{config}"\n'
                f'SYSTEMD_DIR="{systemd_dir}"\n'
                f'FALCO_MANAGED_DIR="{config_dir / "managed"}"\n'
                "destroy_app",
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(source.exists())
            self.assertFalse(config_dir.exists())
            self.assertFalse(install_root.exists())
            self.assertFalse(state_dir.exists())
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve")

    def test_settings_snapshot_restores_config_secrets_and_systemd_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_dir = root / "config"
            systemd_dir = root / "systemd"
            config_dir.mkdir()
            systemd_dir.mkdir()
            config = config_dir / "config.json"
            token = config_dir / "telegram.token"
            ai_keys = config_dir / "ai-providers"
            ai_keys.mkdir()
            first_ai_key = ai_keys / "first.key"
            service = systemd_dir / "vps-audit.service"
            timer = systemd_dir / "vps-audit.timer"
            bot_service = systemd_dir / "vps-audit-bot.service"
            receiver_service = systemd_dir / "vps-audit-node-receiver.service"
            config.write_text('{"retention_days": 7}\n', encoding="utf-8")
            token.write_text("old-token\n", encoding="utf-8")
            first_ai_key.write_text("old-ai-key\n", encoding="utf-8")
            service.write_text("old-service\n", encoding="utf-8")
            timer.write_text("old-timer\n", encoding="utf-8")
            bot_service.write_text("old-bot-service\n", encoding="utf-8")
            receiver_service.write_text("old-receiver-service\n", encoding="utf-8")

            mock_bin = root / "bin"
            mock_bin.mkdir()
            (mock_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (mock_bin / "systemctl").chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{mock_bin}:{env['PATH']}"
            variables = (
                "need_root() { :; }\n"
                f'CONFIG_DIR="{config_dir}"\n'
                f'CONFIG_FILE="{config}"\n'
                f'SYSTEMD_DIR="{systemd_dir}"\n'
                f'FALCO_MANAGED_DIR="{config_dir / "managed"}"\n'
            )
            completed = run_bash(variables + "create_settings_snapshot", env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)

            config.write_text('{"retention_days": 30}\n', encoding="utf-8")
            token.write_text("new-token\n", encoding="utf-8")
            (config_dir / "openai.key").write_text("new-key\n", encoding="utf-8")
            first_ai_key.write_text("changed-ai-key\n", encoding="utf-8")
            (ai_keys / "second.key").write_text("new-provider-key\n", encoding="utf-8")
            service.write_text("new-service\n", encoding="utf-8")
            timer.write_text("new-timer\n", encoding="utf-8")
            bot_service.write_text("new-bot-service\n", encoding="utf-8")
            receiver_service.write_text("new-receiver-service\n", encoding="utf-8")
            completed = run_bash(variables + "rollback_settings_app", env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(config.read_text(encoding="utf-8"), '{"retention_days": 7}\n')
            self.assertEqual(token.read_text(encoding="utf-8"), "old-token\n")
            self.assertFalse((config_dir / "openai.key").exists())
            self.assertEqual(first_ai_key.read_text(encoding="utf-8"), "old-ai-key\n")
            self.assertFalse((ai_keys / "second.key").exists())
            self.assertEqual(service.read_text(encoding="utf-8"), "old-service\n")
            self.assertEqual(timer.read_text(encoding="utf-8"), "old-timer\n")
            self.assertEqual(bot_service.read_text(encoding="utf-8"), "old-bot-service\n")
            self.assertEqual(
                receiver_service.read_text(encoding="utf-8"), "old-receiver-service\n"
            )

    def test_purge_deletes_only_marked_configured_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_dir = root / "config"
            install_root = root / "application"
            systemd_dir = root / "systemd"
            state_dir = root / "custom-state"
            report_dir = state_dir / "reports"
            behavior_dir = root / "connection-archive"
            original_log = root / "mmwx.log"
            unrelated = root / "keep-me.txt"
            for directory in (config_dir, install_root, systemd_dir, state_dir, report_dir, behavior_dir):
                directory.mkdir(exist_ok=True)
            (state_dir / ".vps-audit-managed").write_text("", encoding="utf-8")
            (report_dir / ".vps-audit-managed").write_text("", encoding="utf-8")
            (behavior_dir / ".vps-audit-managed").write_text("", encoding="utf-8")
            original_log.write_text("original application log", encoding="utf-8")
            unrelated.write_text("unrelated", encoding="utf-8")
            config = config_dir / "config.json"
            config.write_text(
                json.dumps({
                    "state_dir": str(state_dir),
                    "report_dir": str(report_dir),
                    "behavior_audit": {"enabled": True, "archive_dir": str(behavior_dir)},
                }),
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
                f'FALCO_MANAGED_DIR="{config_dir / "managed"}"\n'
                "uninstall_app --purge",
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(state_dir.exists())
            self.assertFalse(behavior_dir.exists())
            self.assertFalse(config_dir.exists())
            self.assertFalse(install_root.exists())
            self.assertEqual(original_log.read_text(encoding="utf-8"), "original application log")
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "unrelated")


if __name__ == "__main__":
    unittest.main()
