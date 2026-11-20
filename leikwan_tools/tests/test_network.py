"""System network tests using isolated files and mocked service control."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from leikwan_tools import network
from leikwan_tools.cli import main


class NetworkSettingsTest(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        root = Path(workspace.name).resolve()
        self.etc = root / "etc"
        self.etc.mkdir()
        self.state = root / "var" / "system-network"
        self.proc = root / "proc"
        paths = patch.multiple(network, ETC=self.etc, STATE=self.state, PROC_SYS=self.proc)
        paths.start()
        self.addCleanup(paths.stop)
        ssh = patch.dict(os.environ, {"SSH_CONNECTION": ""})
        ssh.start()
        self.addCleanup(ssh.stop)

    def change(self, feature, value="", *, restore=False):
        return network._change(feature, restore=restore, value=value)

    def sysctl(self, name, value):
        path = self.proc / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n", encoding="ascii")
        return path

    def test_ipv4_preference_keeps_defaults_and_original_file(self):
        gai = self.etc / "gai.conf"
        original = b"# example\r\n#precedence ::ffff:0:0/96 100\r\n"
        gai.write_bytes(original)
        gai.chmod(0o640)
        self.change("ipv4-prefer")
        applied = gai.read_text()
        self.assertIn("precedence ::/0 40", applied)
        self.assertIn("\nprecedence ::ffff:0:0/96 100", applied)
        self.change("ipv4-prefer")
        self.assertEqual(gai.read_text(), applied)
        self.assertEqual(network.pending_network_settings(), ["ipv4-prefer"])
        self.change("ipv4-prefer", restore=True)
        self.assertEqual(gai.read_bytes(), original)
        self.assertEqual(gai.stat().st_mode & 0o777, 0o640)
        self.assertEqual(network.pending_network_settings(), [])

    def test_no_backup_does_not_modify_unmanaged_configuration(self):
        gai = self.etc / "gai.conf"
        gai.write_text("precedence ::1/128 50\n")
        self.change("ipv4-prefer", restore=True)
        self.assertEqual(gai.read_text(), "precedence ::1/128 50\n")
        self.assertFalse(self.state.exists())

    def test_dns_updates_keep_first_backup_and_search_settings(self):
        resolv = self.etc / "resolv.conf"
        original = "search example.test\nnameserver 192.0.2.53\noptions timeout:1\n"
        resolv.write_text(original)
        self.change("dns", "8.8.8.8,1.1.1.1")
        self.change("dns", "2001:4860:4860::8888,9.9.9.9")
        applied = resolv.read_text()
        self.assertIn("nameserver 2001:4860:4860::8888\n", applied)
        self.assertNotIn("nameserver 8.8.8.8", applied)
        self.assertIn("search example.test\noptions timeout:1\n", applied)
        self.assertEqual(applied.count(network.MANAGED_MARKER), 1)
        self.change("dns", restore=True)
        self.assertEqual(resolv.read_text(), original)

    def test_dns_rejects_external_edits_and_foreign_symlink(self):
        resolv = self.etc / "resolv.conf"
        resolv.write_text("nameserver 192.0.2.53\n")
        self.change("dns", "1.1.1.1")
        resolv.write_text("nameserver 192.0.2.54\n")
        with self.assertRaisesRegex(network.NetworkError, "外部修改"):
            self.change("dns", restore=True)
        self.assertEqual(resolv.read_text(), "nameserver 192.0.2.54\n")
        resolv.unlink()
        resolv.symlink_to(self.etc / "managed-by-other-service")
        with self.assertRaisesRegex(network.NetworkError, "符号链接"):
            self.change("dns", "1.1.1.1")

    def test_failed_dns_restart_rolls_back_and_restarts_again(self):
        with patch.object(network, "_dns_contents", return_value={network.RESOLVED_CONF: "[Resolve]\nDNS=1.1.1.1\n"}), \
                patch.object(network, "_resolved_active", return_value=True), \
                patch.object(network, "_cmd", side_effect=[network.NetworkError("restart failed"), ""]) as command:
            with self.assertRaisesRegex(network.NetworkError, "已回滚"):
                self.change("dns", "1.1.1.1")
        self.assertEqual(command.call_count, 2)
        self.assertFalse((self.etc / network.RESOLVED_CONF).exists())
        self.assertEqual(network.pending_network_settings(), [])

    def test_ipv6_restores_per_interface_state_and_refuses_ipv6_ssh(self):
        all_path = self.sysctl("net/ipv6/conf/all/disable_ipv6", "0")
        default_path = self.sysctl("net/ipv6/conf/default/disable_ipv6", "0")
        eth_path = self.sysctl("net/ipv6/conf/eth0.100/disable_ipv6", "1")
        with patch.dict(os.environ, {"SSH_CONNECTION": "2001:db8::2 40000 2001:db8::1 2222"}):
            with self.assertRaisesRegex(network.NetworkError, "IPv6 SSH"):
                self.change("ipv6")
        self.change("ipv6")
        new_path = self.sysctl("net/ipv6/conf/eth1/disable_ipv6", "1")
        self.assertEqual([path.read_text().strip() for path in (all_path, default_path, eth_path)], ["1", "1", "1"])
        self.change("ipv6", restore=True)
        self.assertEqual([path.read_text().strip() for path in (all_path, default_path, eth_path, new_path)], ["0", "0", "1", "0"])

    def test_bbr_restores_previous_runtime_values(self):
        qdisc = self.sysctl("net/core/default_qdisc", "fq_codel")
        congestion = self.sysctl("net/ipv4/tcp_congestion_control", "cubic")
        self.sysctl("net/ipv4/tcp_available_congestion_control", "reno cubic bbr")
        self.change("bbr")
        self.change("bbr")
        self.assertEqual((qdisc.read_text().strip(), congestion.read_text().strip()), ("fq", "bbr"))
        self.change("bbr", restore=True)
        self.assertEqual((qdisc.read_text().strip(), congestion.read_text().strip()), ("fq_codel", "cubic"))

    def test_bbr_rejects_unsupported_kernel_without_writing_configuration(self):
        self.sysctl("net/ipv4/tcp_available_congestion_control", "reno cubic")
        with patch.object(network, "_cmd", return_value="") as command:
            with self.assertRaisesRegex(network.NetworkError, "不支持 BBR"):
                self.change("bbr")
        command.assert_called_once_with("modprobe", "tcp_bbr")
        self.assertEqual(network.pending_network_settings(), [])
        self.assertFalse((self.etc / "sysctl.d").exists())

    def test_nft_requires_ipv6_ssh_port_and_scopes_rules_to_ipv6(self):
        with patch.dict(os.environ, {"SSH_CONNECTION": "2001:db8::2 40000 2001:db8::1 2222"}), \
                patch.object(network.shutil, "which", return_value="/usr/sbin/nft"):
            with self.assertRaisesRegex(network.NetworkError, "2222"):
                network._nft_contents("22,8443")
            with self.assertRaisesRegex(network.NetworkError, "无效"):
                network._nft_contents("2222,65536")
            rules = network._nft_contents("8443,2222,2222")[network.NFT_CONF]
        self.assertIn(f"table ip6 {network.NFT_TABLE}", rules)
        self.assertIn("tcp dport { 2222, 8443 } accept", rules)
        self.assertIn("meta l4proto ipv6-icmp accept", rules)
        self.assertIn("ct state established,related accept", rules)
        self.assertIn("counter drop", rules)

    def test_cli_menu_status_does_not_apply_any_write(self):
        output = io.StringIO()
        with patch("builtins.input", side_effect=["5", "3", "1", "0", "0", "0"]), \
                patch("leikwan_tools.cli.network_command", return_value={"状态": "只读"}) as command, \
                redirect_stdout(output):
            self.assertEqual(main(["menu"]), 0)
        command.assert_called_once_with("status", "status", "")
        self.assertIn("IPv6 入站收口 nftables", output.getvalue())
        self.assertIn("状态: 只读", output.getvalue())

    def test_cli_requires_confirmation_before_any_write(self):
        with redirect_stderr(io.StringIO()), patch("leikwan_tools.cli.network_command") as command:
            with self.assertRaises(SystemExit) as error:
                main(["system", "ipv6", "disable"])
        self.assertEqual(error.exception.code, 2)
        command.assert_not_called()

    def test_cli_menu_passes_custom_dns_as_data(self):
        inputs = ["5", "3", "3", "1", "--help", "y", "0", "0", "0"]
        with patch("builtins.input", side_effect=inputs), \
                patch("leikwan_tools.cli.network_command", return_value={"结果": "模拟"}) as command, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(main(["menu"]), 0)
        command.assert_called_once_with("dns", "set", "--help")
