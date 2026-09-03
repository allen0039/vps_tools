import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "dns_tool.sh"


class DnsToolTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.log = self.root / "commands.log"
        self.resolv = self.root / "etc/resolv.conf"
        self.resolv.parent.mkdir(parents=True)
        self.resolv.write_text("search internal.example\nnameserver 10.0.0.2\n")
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": f"{self.bin_dir}:{self.env['PATH']}",
                "DNS_TOOL_ALLOW_NON_ROOT": "1",
                "DNS_TOOL_RESOLV_CONF": str(self.resolv),
                "DNS_TOOL_RESOLVED_DROPIN": str(
                    self.root / "etc/systemd/resolved.conf.d/dns.conf"
                ),
                "DNS_TOOL_NM_DROPIN": str(
                    self.root / "etc/NetworkManager/conf.d/dns.conf"
                ),
                "DNS_TOOL_RESOLVCONF_HEAD": str(
                    self.root / "etc/resolvconf/resolv.conf.d/head"
                ),
                "DNS_TOOL_STATE_DIR": str(self.root / "state"),
                "DNS_TOOL_INSTALL_PATH": str(self.root / "bin/dnstool"),
                "COMMAND_LOG": str(self.log),
            }
        )
        self.write_command(
            "systemctl",
            """#!/bin/sh
if [ \"$1\" = is-active ]; then exit 1; fi
printf '%s\\n' \"$*\" >>\"$COMMAND_LOG\"
""",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def write_command(self, name, content):
        path = self.bin_dir / name
        path.write_text(content)
        path.chmod(0o755)

    def run_script(self, *args, check=True, input_text=None):
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env=self.env,
            text=True,
            input=input_text,
            capture_output=True,
            check=check,
        )

    def test_static_provider_switch_and_restore(self):
        result = self.run_script("set", "cloudflare")
        self.assertIn("DNS 已切换为 cloudflare（static）", result.stdout)
        content = self.resolv.read_text()
        self.assertIn("nameserver 1.1.1.1", content)
        self.assertIn("nameserver 2606:4700:4700::1111", content)
        self.assertIn("search internal.example", content)

        status = self.run_script("status").stdout
        self.assertIn("提供商: cloudflare", status)
        self.assertIn("原始配置备份: 可恢复", status)

        self.run_script("restore")
        self.assertEqual(
            self.resolv.read_text(),
            "search internal.example\nnameserver 10.0.0.2\n",
        )
        restored_status = self.run_script("status").stdout
        self.assertIn("dnstool 当前配置: 未应用", restored_status)
        self.assertIn("原始配置备份: 可恢复", restored_status)

    def test_repeated_switch_restores_configuration_before_first_switch(self):
        self.run_script("set", "google")
        self.run_script("set", "alidns")
        self.run_script("restore")
        self.assertEqual(
            self.resolv.read_text(),
            "search internal.example\nnameserver 10.0.0.2\n",
        )

        self.resolv.write_text("nameserver 192.0.2.53\n")
        self.run_script("set", "custom", "151.243.229.229")
        self.run_script("restore")
        self.assertEqual(
            self.resolv.read_text(),
            "search internal.example\nnameserver 10.0.0.2\n",
        )

    def test_repeated_switch_in_one_menu_process_keeps_original_backup(self):
        result = self.run_script(
            "menu",
            input_text="1\ny\n2\ny\n8\ny\n0\n",
        )
        self.assertIn("DNS 已切换为 cloudflare", result.stdout)
        self.assertIn("DNS 已切换为 google", result.stdout)
        self.assertIn("已一键恢复首次修改前的初始 DNS 配置", result.stdout)
        self.assertEqual(
            self.resolv.read_text(),
            "search internal.example\nnameserver 10.0.0.2\n",
        )

    def test_custom_addresses_are_validated_before_changes(self):
        result = self.run_script("set", "custom", "999.1.1.1", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("无效的 IPv4/IPv6", result.stderr)
        self.assertFalse((self.root / "state").exists())
        self.assertEqual(self.resolv.read_text(), "search internal.example\nnameserver 10.0.0.2\n")

    def test_systemd_resolved_preserves_resolv_conf_symlink(self):
        resolved_resolv = self.root / "run/systemd/resolve/stub-resolv.conf"
        resolved_resolv.parent.mkdir(parents=True)
        resolved_resolv.write_text("nameserver 127.0.0.53\n")
        self.resolv.unlink()
        self.resolv.symlink_to(resolved_resolv)
        self.write_command(
            "systemctl",
            """#!/bin/sh
if [ \"$1 $2 $3\" = \"is-active --quiet systemd-resolved\" ]; then exit 0; fi
if [ \"$1\" = is-active ]; then exit 1; fi
printf '%s\\n' \"$*\" >>\"$COMMAND_LOG\"
""",
        )
        self.write_command("resolvectl", "#!/bin/sh\nexit 0\n")

        self.run_script("set", "quad9")
        self.assertTrue(self.resolv.is_symlink())
        dropin = Path(self.env["DNS_TOOL_RESOLVED_DROPIN"])
        self.assertIn("DNS=9.9.9.9 149.112.112.112", dropin.read_text())
        self.assertIn("restart systemd-resolved", self.log.read_text())

        self.run_script("restore")
        self.assertTrue(self.resolv.is_symlink())
        self.assertFalse(dropin.exists())

    def test_network_manager_is_configured_without_restarting_interface(self):
        self.write_command(
            "systemctl",
            """#!/bin/sh
if [ \"$1 $2 $3\" = \"is-active --quiet NetworkManager\" ]; then exit 0; fi
if [ \"$1\" = is-active ]; then exit 1; fi
printf '%s\\n' \"$*\" >>\"$COMMAND_LOG\"
""",
        )
        self.write_command("nmcli", "#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$COMMAND_LOG\"\n")

        self.run_script("set", "adguard")
        nm_dropin = Path(self.env["DNS_TOOL_NM_DROPIN"])
        self.assertIn("dns=none", nm_dropin.read_text())
        self.assertIn("general reload", self.log.read_text())
        self.assertNotIn("connection down", self.log.read_text())

    def test_resolvconf_updates_head_and_restores_it(self):
        head = Path(self.env["DNS_TOOL_RESOLVCONF_HEAD"])
        head.parent.mkdir(parents=True)
        head.write_text("search private.example\nnameserver 10.0.0.3\n")
        generated = self.root / "run/resolvconf/resolv.conf"
        generated.parent.mkdir(parents=True)
        generated.write_text("nameserver 10.0.0.3\n")
        self.resolv.unlink()
        self.resolv.symlink_to(generated)
        self.write_command(
            "resolvconf",
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$COMMAND_LOG\"\n",
        )

        self.run_script("set", "custom", "4.2.2.1", "2001:4860:4860::8888")
        self.assertIn("nameserver 4.2.2.1", head.read_text())
        self.assertIn("search private.example", head.read_text())
        self.assertIn("-u", self.log.read_text())

        self.run_script("restore")
        self.assertEqual(
            head.read_text(),
            "search private.example\nnameserver 10.0.0.3\n",
        )
        self.assertTrue(self.resolv.is_symlink())

    def test_resolvconf_refreshes_restore_when_original_head_was_missing(self):
        head = Path(self.env["DNS_TOOL_RESOLVCONF_HEAD"])
        generated = self.root / "run/resolvconf/resolv.conf"
        generated.parent.mkdir(parents=True)
        generated.write_text("nameserver 10.0.0.3\n")
        self.resolv.unlink()
        self.resolv.symlink_to(generated)
        self.write_command(
            "resolvconf",
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$COMMAND_LOG\"\n",
        )

        self.run_script("set", "custom", "4.2.2.1")
        self.assertTrue(head.exists())
        self.log.write_text("")

        self.run_script("restore")
        self.assertFalse(head.exists())
        self.assertIn("-u", self.log.read_text())
        self.assertTrue(self.resolv.is_symlink())

    def test_failed_service_restart_rolls_back_files(self):
        resolved_resolv = self.root / "run/systemd/resolve/stub-resolv.conf"
        resolved_resolv.parent.mkdir(parents=True)
        resolved_resolv.write_text("nameserver 127.0.0.53\n")
        self.resolv.unlink()
        self.resolv.symlink_to(resolved_resolv)
        original_target = os.readlink(self.resolv)
        self.write_command(
            "systemctl",
            """#!/bin/sh
if [ \"$1 $2 $3\" = \"is-active --quiet systemd-resolved\" ]; then exit 0; fi
if [ \"$1\" = restart ]; then exit 1; fi
if [ \"$1\" = is-active ]; then exit 1; fi
exit 0
""",
        )

        result = self.run_script("set", "google", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("正在自动恢复原配置", result.stderr)
        self.assertTrue(self.resolv.is_symlink())
        self.assertEqual(os.readlink(self.resolv), original_target)
        self.assertFalse(Path(self.env["DNS_TOOL_RESOLVED_DROPIN"]).exists())

    def test_single_custom_dns_restores_initial_mode(self):
        self.resolv.chmod(0o640)

        self.run_script("set", "custom", "151.243.229.229")
        content = self.resolv.read_text()
        self.assertIn("nameserver 151.243.229.229", content)
        self.assertEqual(content.count("nameserver "), 1)

        self.run_script("restore")
        self.assertEqual(
            self.resolv.read_text(),
            "search internal.example\nnameserver 10.0.0.2\n",
        )
        self.assertEqual(self.resolv.stat().st_mode & 0o777, 0o640)

    def test_install_saves_initial_backup_and_menu_displays_it_in_chinese(self):
        self.resolv.chmod(0o640)
        install_result = self.run_script("install")
        self.assertIn("已自动保存首次部署时的初始 DNS 配置", install_result.stdout)
        installed_command = Path(self.env["DNS_TOOL_INSTALL_PATH"])
        self.assertEqual(installed_command.name, "dnstool")
        self.assertTrue(os.access(installed_command, os.X_OK))

        self.resolv.write_text("nameserver 192.0.2.53\n")
        menu_result = self.run_script("menu", input_text="8\ny\n0\n")
        self.assertIn(
            "初始 DNS 备份: 已保存（DNS: 10.0.0.2）",
            menu_result.stdout,
        )
        self.assertIn("一键恢复首次修改前的初始配置", menu_result.stdout)
        self.assertEqual(
            self.resolv.read_text(),
            "search internal.example\nnameserver 10.0.0.2\n",
        )
        self.assertEqual(self.resolv.stat().st_mode & 0o777, 0o640)

    def test_reinstall_does_not_replace_initial_backup(self):
        self.run_script("install")
        self.resolv.write_text("nameserver 192.0.2.53\n")
        self.run_script("install")
        self.run_script("restore")
        self.assertEqual(
            self.resolv.read_text(),
            "search internal.example\nnameserver 10.0.0.2\n",
        )


if __name__ == "__main__":
    unittest.main()
