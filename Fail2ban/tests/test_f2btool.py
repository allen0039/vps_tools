import ast
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "f2btool.py"
spec = importlib.util.spec_from_file_location("f2btool", SCRIPT)
f2b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f2b)


def result(args, code=0, output=""):
    return subprocess.CompletedProcess(args, code, output, "")


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.app = f2b.App(root / "etc", root / "state")
        self.settings = copy.deepcopy(f2b.DEFAULTS)
        self.settings["ports"] = [22022]
        self.calls = []
        wait = patch.object(self.app, "wait_firewall")
        wait.start()
        self.addCleanup(wait.stop)

    def save(self):
        f2b.atomic_write(self.app.config, f2b.render(self.settings))

    def runner(self, args, **kwargs):
        self.calls.append([str(value) for value in args])
        if args[:3] == ["systemctl", "is-active", "--quiet"]:
            return result(args, 1)
        if args[:3] == ["systemctl", "is-enabled", "--quiet"]:
            return result(args, 1)
        if args[-1] == "-d":
            current = self.app.load()
            commands = [] if current is None or not current["enabled"] else [
                ["add", "sshd", "systemd"], ["set", "sshd", "addaction", "vpstools-sshd"], ["start", "sshd"]]
            return result(args, output="\n".join(map(repr, commands)))
        return result(args)

    def test_ip_inputs_and_config_injection_rejected(self):
        for value in ("$(touch /tmp/nope)", "203.0.113.1\n[DEFAULT]", "0.0.0.0/0", "::/0"):
            with self.subTest(value=value), self.assertRaises(f2b.ToolError):
                f2b.normalize_ip(value)
        self.assertEqual(f2b.normalize_ip("203.0.113.55/24"), "203.0.113.0/24")
        self.assertEqual(f2b.normalize_ip("2001:db8::1"), "2001:db8::1")
        for key, value in (("bantime", -1), ("findtime", 0), ("maxretry", True), ("ports", [70000]),
                           ("ignoreip", ["127.0.0.1\n[DEFAULT]"])):
            settings = dict(self.settings, **{key: value})
            with self.subTest(key=key), self.assertRaises(f2b.ToolError):
                f2b.render(settings)

    def test_manual_edits_and_symlinks_are_not_overwritten(self):
        self.save()
        self.app.config.write_text(self.app.config.read_text().replace("maxretry = 5", "maxretry = 1"))
        with self.assertRaises(f2b.ToolError):
            self.app.load()
        self.app.config.unlink()
        target = Path(self.temp.name) / "target"
        target.write_text("keep")
        self.app.config.symlink_to(target)
        with self.assertRaises(f2b.ToolError):
            self.app.load()
        self.assertEqual(target.read_text(), "keep")

    def test_failed_config_validation_restores_file_without_reloading_service(self):
        self.save()
        old = self.app.config.read_text()
        def runner(args, **kwargs):
            if args[-1] == "-t":
                raise f2b.ToolError("bad config")
            return self.runner(args, **kwargs)
        with patch.object(f2b, "run", side_effect=runner):
            with self.assertRaisesRegex(f2b.ToolError, "已恢复配置"):
                self.app.apply(dict(self.settings, maxretry=3))
        self.assertEqual(self.app.config.read_text(), old)
        self.assertFalse(any("reload" in args or "start" in args for args in self.calls))
        self.assertEqual(len(self.app.backups()), 1)

    def test_failed_reload_restores_live_jail_and_old_config(self):
        self.save()
        old = self.app.config.read_text()
        reloads = []
        def runner(args, **kwargs):
            self.calls.append([str(value) for value in args])
            if "--quiet" in args:
                return result(args)
            if "reload" in args:
                reloads.append(self.app.config.read_text())
                if len(reloads) == 1:
                    raise f2b.ToolError("reload failed")
            return self.runner(args, **kwargs)
        with patch.object(f2b, "run", side_effect=runner):
            with self.assertRaisesRegex(f2b.ToolError, "reload failed"):
                self.app.apply(dict(self.settings, maxretry=3))
        self.assertEqual(self.app.config.read_text(), old)
        self.assertEqual(len(reloads), 2)
        self.assertEqual(reloads[-1], old)
        self.assertFalse(any("stop" in args for args in self.calls))

    def test_runtime_override_failure_rolls_back(self):
        self.save()
        def runner(args, **kwargs):
            if "--quiet" in args:
                return result(args)
            return self.runner(args, **kwargs)
        with patch.object(f2b, "run", side_effect=runner), patch.object(self.app, "verify_runtime", side_effect=f2b.ToolError("overridden")):
            with self.assertRaisesRegex(f2b.ToolError, "overridden"):
                self.app.apply(dict(self.settings, scope="all"))
        self.assertEqual(self.app.load(), self.settings)

    def test_disabled_state_shadowed_by_later_config_is_rejected_before_reload(self):
        self.save()
        def runner(args, **kwargs):
            if args[-1] == "-d":
                return result(args, output="['start', 'sshd']\n")
            return self.runner(args, **kwargs)
        with patch.object(f2b, "run", side_effect=runner), self.assertRaisesRegex(f2b.ToolError, "覆盖"):
            self.app.apply(dict(self.settings, enabled=False))
        self.assertTrue(self.app.load()["enabled"])
        self.assertFalse(any("reload" in args for args in self.calls))

    def test_add_cidr_white_list_unbans_contained_ipv4_and_ipv6_only(self):
        settings = dict(self.settings, ignoreip=["203.0.113.0/24", "2001:db8::/32"])
        def runner(args, **kwargs):
            if args[-3:] == ["get", "sshd", "banip"]:
                return result(args, output="203.0.113.8 198.51.100.7 2001:db8::1")
            return self.runner(args, **kwargs)
        with patch.object(f2b, "run", side_effect=runner):
            self.app.release_ignored(settings)
        self.assertEqual([args[-1] for args in self.calls if "unbanip" in args], ["203.0.113.8", "2001:db8::1"])

    def test_sync_stopped_service_preserves_stopped_state(self):
        self.save()
        with patch.object(self.app, "preflight"), patch.object(self.app, "ports", return_value=[2222]), patch.object(f2b, "run", side_effect=self.runner):
            self.app.sync_ports()
        self.assertEqual(self.app.load()["ports"], [2222])
        self.assertFalse(any("start" in args or "enable" in args or "reload" in args for args in self.calls))

    def test_enable_absent_jail_uses_reload_without_jail_restart(self):
        def runner(args, **kwargs):
            if args[-2:] == ["status", "sshd"]:
                return result(args, 1)
            return self.runner(args, **kwargs)
        with patch.object(f2b, "run", side_effect=runner):
            self.app.reload_sshd(enabled=True)
        self.assertEqual(self.calls[-1][-1], "reload")
        self.assertNotIn("--restart", self.calls[-1])

    def test_fresh_start_failure_removes_new_file_and_stops_partial_service(self):
        def runner(args, **kwargs):
            if args[:2] == ["systemctl", "start"]:
                self.calls.append(args)
                raise f2b.ToolError("start failed")
            return self.runner(args, **kwargs)
        with patch.object(f2b, "run", side_effect=runner):
            with self.assertRaisesRegex(f2b.ToolError, "start failed"):
                self.app.apply(self.settings, activate=True)
        self.assertFalse(self.app.config.exists())
        self.assertIn(["systemctl", "stop", "fail2ban"], self.calls)
        self.assertIn(["systemctl", "disable", "fail2ban"], self.calls)

    def test_persistence_failure_after_start_restores_configuration_and_service_state(self):
        self.save()
        old = self.app.config.read_text()
        with patch.object(f2b, "run", side_effect=self.runner), patch.object(self.app, "verify_runtime"), patch.object(self.app, "release_ignored"), patch.object(self.app, "refresh_persistence", side_effect=f2b.ToolError("static snapshot failed")):
            with self.assertRaisesRegex(f2b.ToolError, "static snapshot failed"):
                self.app.apply(dict(self.settings, maxretry=3), activate=True)
        self.assertEqual(self.app.config.read_text(), old)
        self.assertIn(["systemctl", "enable", "fail2ban"], self.calls)
        self.assertIn(["systemctl", "stop", "fail2ban"], self.calls)
        self.assertIn(["systemctl", "disable", "fail2ban"], self.calls)

    def test_inherited_whitelist_is_parsed_by_fail2ban_in_a_copy(self):
        (self.app.config_dir / "jail.d").mkdir(parents=True)
        (self.app.config_dir / "jail.local").write_text("[DEFAULT]\nignoreip = trusted.example.com\n")
        def runner(args, **kwargs):
            staged = Path(args[2])
            self.assertNotEqual(staged, self.app.config_dir)
            self.assertNotIn("ignoreip =", (staged / "jail.d" / f2b.CONFIG_NAME).read_text())
            return result(args, output="['set', 'sshd', 'addignoreip', 'trusted.example.com', '203.0.113.0/24']\n")
        with patch.object(f2b, "run", side_effect=runner):
            whitelist = self.app.inherited_ignoreip(self.settings)
        self.assertEqual(whitelist, ["trusted.example.com", "203.0.113.0/24", "127.0.0.1/8", "::1"])
        self.assertFalse(self.app.config.exists())

    def test_restore_uses_current_ssh_ports(self):
        self.save()
        backup = self.app.snapshot(self.app.config.read_text())
        with patch.object(f2b, "run", side_effect=self.runner), patch.object(self.app, "preflight"), patch.object(self.app, "ports", return_value=[2222]):
            self.app.restore(backup.name)
        self.assertEqual(self.app.load()["ports"], [2222])
        for value in ("../other", "/etc/passwd", "20261003T000000Z-zzzzzzzz"):
            with self.subTest(value=value), self.assertRaises(f2b.ToolError):
                self.app.restore(value)

    def test_lock_prevents_overlapping_mutations(self):
        with self.app.lock():
            with self.assertRaisesRegex(f2b.ToolError, "另一个"):
                with self.app.lock():
                    self.fail("lock acquired twice")

    def test_refreshes_existing_static_persistence_without_installing_service(self):
        with patch.object(f2b.shutil, "which", side_effect=lambda name: "/usr/local/sbin/safe-ssh-port" if name == "safe-ssh-port" else "/usr/sbin/netfilter-persistent"), patch.object(f2b, "run", side_effect=self.runner):
            self.app.refresh_persistence()
        self.assertEqual(self.calls[-1], ["/usr/local/sbin/safe-ssh-port", "firewall-save"])
        self.calls.clear()
        with patch.object(f2b.shutil, "which", return_value=None), patch.object(f2b, "run", side_effect=self.runner):
            self.app.refresh_persistence()
        self.assertEqual(self.calls, [])

    def test_unban_targets_only_sshd_and_passes_ip_as_one_argument(self):
        self.save()
        with patch.object(f2b, "run", side_effect=self.runner):
            self.app.unban("2001:db8::1")
        self.assertEqual(self.calls[-1][-4:], ["set", "sshd", "unbanip", "2001:db8::1"])

    def test_kernel_rules_must_cover_ports_and_precede_allentool_for_both_families(self):
        records = {
            "iptables": "-A INPUT -p tcp -m multiport --dports 22022 -j f2b-vpstools-sshd\n-A INPUT -j ALLENTOOL_INPUT\n",
            "ip6tables": "-A INPUT -p tcp -m multiport --dports 22022 -j f2b-vpstools-sshd\n"}
        def runner(args, **kwargs):
            return result(args, output=records[args[0]] if args[-1] == "INPUT" else "-A f2b-vpstools-sshd -j RETURN\n")
        with patch.object(f2b, "run", side_effect=runner):
            self.app.verify_firewall(self.settings)
            records["ip6tables"] = "-A INPUT -j ALLENTOOL_ACCESS\n" + records["ip6tables"]
            with self.assertRaisesRegex(f2b.ToolError, "之前"):
                self.app.verify_firewall(self.settings)
            records["ip6tables"] = "-A INPUT -p tcp -m multiport --dports 22 -j f2b-vpstools-sshd\n"
            with self.assertRaisesRegex(f2b.ToolError, "不一致"):
                self.app.verify_firewall(self.settings)

    def test_effective_settings_include_ipv6_whitelist_and_named_action(self):
        values = {"bantime": "604800", "findtime": "600", "maxretry": "5", "ignoreip": "|- 127.0.0.0/8\n`- ::1\n",
                  "name": "vpstools-sshd", "chain": "INPUT", "port": "22022", "protocol": "tcp"}
        def runner(args, **kwargs):
            if "get" in args:
                return result(args, output=values[args[-1]])
            return result(args)
        with patch.object(f2b, "run", side_effect=runner):
            self.app.verify_runtime(self.settings)
            values["port"] = "22"
            with self.assertRaisesRegex(f2b.ToolError, "port"):
                self.app.verify_runtime(self.settings)


@unittest.skipUnless(shutil.which("fail2ban-client") and Path("/etc/fail2ban/jail.conf").exists(),
                     "requires installed Fail2ban configuration")
class InstalledConfigTest(unittest.TestCase):
    def test_generated_jail_is_understood_by_actual_fail2ban(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "config"
            shutil.copytree("/etc/fail2ban", root)
            for scope in ("ssh", "all"):
                settings = dict(copy.deepcopy(f2b.DEFAULTS), ports=[22022, 2222], scope=scope)
                f2b.atomic_write(root / "jail.d" / f2b.CONFIG_NAME, f2b.render(settings))
                checked = f2b.run(["fail2ban-client", "-c", root, "-t"])
                self.assertIn("successful", checked.stdout + checked.stderr)
                dumped = f2b.run(["fail2ban-client", "-c", root, "-d"])
                commands = []
                for line in dumped.stdout.splitlines():
                    try:
                        commands.append(ast.literal_eval(line))
                    except (SyntaxError, ValueError):
                        pass
                self.assertIn(["add", "sshd", "systemd"], commands)
                self.assertIn(["set", "sshd", "addaction", "vpstools-sshd"], commands)


if __name__ == "__main__":
    with contextlib.redirect_stdout(io.StringIO()):
        unittest.main()
