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

    def test_configure_does_not_automatically_whitelist_current_ssh_ip(self):
        source = "203.0.113.8"
        for command in (None, ["configure", "--yes"], ["configure", "--no-current-ip", "--yes"]):
            with self.subTest(command=command), \
                    patch.object(self.app, "preflight"), \
                    patch.object(self.app, "ports", return_value=[22022]), \
                    patch.object(self.app, "inherited_ignoreip", return_value=self.settings["ignoreip"]), \
                    patch.object(self.app, "apply") as apply, \
                    patch.object(f2b, "current_ip", return_value=source), \
                    patch.object(f2b, "confirm", side_effect=[False, True] if command is None else [True]), \
                    patch("builtins.input", side_effect=[""] * 5), \
                    patch.object(f2b.sys, "platform", "linux"), \
                    patch.object(f2b.os, "geteuid", return_value=0), \
                    patch.object(f2b, "App", return_value=self.app), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                if command is None:
                    self.app.configure()
                else:
                    f2b.main(command)
                self.assertNotIn(source, apply.call_args.args[0]["ignoreip"])
                self.assertIn(source + "（默认不加入白名单）", output.getvalue())

    def test_menu_current_ip_whitelist_choice_defaults_to_no(self):
        cases = [
            ("203.0.113.8", [], "", False),
            ("203.0.113.8", [], "n", False),
            ("203.0.113.8", [], "y", True),
            ("203.0.113.8", ["203.0.113.8", "203.0.113.8/32"], "", False),
            ("203.0.113.8", ["203.0.113.8"], "y", True),
            ("2001:db8::8", ["2001:db8:0:0::8/128"], "", False),
            ("2001:db8::8", [], "y", True),
        ]
        for source, single_entries, answer, included in cases:
            with self.subTest(source=source, single_entries=single_entries, answer=answer):
                settings = copy.deepcopy(self.settings)
                preserved = ["198.51.100.7", "203.0.113.0/24", "2001:db8::/32", "trusted.example.com"]
                settings["ignoreip"].extend([*preserved, *single_entries])
                with patch.object(self.app, "preflight"), \
                        patch.object(self.app, "load", return_value=settings), \
                        patch.object(self.app, "ports", return_value=[22022]), \
                        patch.object(self.app, "apply") as apply, \
                        patch.object(f2b, "current_ip", return_value=source), \
                        patch.object(f2b.sys.stdin, "isatty", return_value=True), \
                        patch("builtins.input", side_effect=[""] * 4 + [answer, "", "y"]) as input_mock, \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.app.configure()
                whitelist = apply.call_args.args[0]["ignoreip"]
                self.assertEqual(source in whitelist, included)
                for entry in preserved:
                    self.assertIn(entry, whitelist)
                if not included:
                    for entry in single_entries:
                        self.assertNotIn(entry, whitelist)
                self.assertIn(f"是否将当前 SSH 来源 IP {source} 加入白名单？ [y/N] ",
                              [call.args[0] for call in input_mock.call_args_list])
                self.assertIn("仍被已有网段白名单覆盖", output.getvalue())
                if single_entries:
                    self.assertIn("选择否将移除这些条目", output.getvalue())

    def test_menu_without_detected_source_does_not_ask_to_whitelist_it(self):
        with patch.object(self.app, "preflight"), \
                patch.object(self.app, "ports", return_value=[22022]), \
                patch.object(self.app, "inherited_ignoreip", return_value=self.settings["ignoreip"]), \
                patch.object(self.app, "apply") as apply, \
                patch.object(f2b, "current_ip", return_value=None), \
                patch.object(f2b.sys.stdin, "isatty", return_value=True), \
                patch("builtins.input", side_effect=[""] * 5 + ["y"]) as input_mock, \
                contextlib.redirect_stdout(io.StringIO()):
            self.app.configure()
        self.assertEqual(apply.call_args.args[0]["ignoreip"], self.settings["ignoreip"])
        self.assertFalse(any("是否将当前 SSH 来源 IP" in call.args[0]
                             for call in input_mock.call_args_list))

    def test_configure_preserves_existing_whitelist_and_accepts_explicit_ip(self):
        source = "203.0.113.8"
        self.settings["ignoreip"].append("198.51.100.7")
        self.save()
        with patch.object(self.app, "preflight"), \
                patch.object(self.app, "ports", return_value=[22022]), \
                patch.object(self.app, "apply") as apply, \
                patch.object(f2b, "current_ip", return_value=source), \
                patch.object(f2b.sys, "platform", "linux"), \
                patch.object(f2b.os, "geteuid", return_value=0), \
                patch.object(f2b, "App", return_value=self.app), \
                contextlib.redirect_stdout(io.StringIO()):
            f2b.main(["configure", "--ignore-ip", source, "--yes"])
        self.assertIn("198.51.100.7", apply.call_args.args[0]["ignoreip"])
        self.assertIn(source, apply.call_args.args[0]["ignoreip"])

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

    def test_status_summarizes_fail2ban_and_banned_addresses(self):
        jail = ("Status for the jail: sshd\n"
                "|- Filter\n|  |- Currently failed: 1\n|  `- Total failed: 12\n"
                "`- Actions\n   |- Currently banned: 2\n   |- Total banned: 4\n"
                "   `- Banned IP list: 203.0.113.8 2001:db8::8\n")
        rules = f"-A INPUT -p tcp --dports 22022 -j {f2b.CHAIN}\n-A INPUT -j ACCEPT\n"
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(self.app, "load", return_value=self.settings))
            stack.enter_context(patch.object(self.app, "ports", return_value=[22022]))
            stack.enter_context(patch.object(self.app, "client", return_value=result([], output=jail)))
            stack.enter_context(patch.object(f2b.shutil, "which", return_value="/usr/bin/tool"))
            stack.enter_context(patch.object(f2b, "run", return_value=result([], output=rules)))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.app.status()
        text = output.getvalue()
        self.assertIn("封禁规则：10 分钟内失败 5 次 → 封禁 7 天", text)
        self.assertIn("登录失败：当前 1 次 / 累计 12 次", text)
        self.assertIn("IP 封禁：当前 2 个 / 累计 4 个", text)
        self.assertIn("1. 203.0.113.8\n  2. 2001:db8::8", text)
        self.assertIn("IPv4：规则顺序正常", text)
        self.assertNotIn("Journal matches", text)

    def test_status_distinguishes_empty_list_from_client_failure(self):
        jail = ("Status for the jail: sshd\n|- Filter\n"
                "|  |- Currently failed: 0\n|  `- Total failed: 0\n"
                "`- Actions\n   |- Currently banned: 0\n   |- Total banned: 0\n"
                "   `- Banned IP list:\n")
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(self.app, "load", return_value=self.settings))
            stack.enter_context(patch.object(self.app, "ports", return_value=[22022]))
            stack.enter_context(patch.object(self.app, "client", return_value=result([], output=jail)))
            stack.enter_context(patch.object(f2b.shutil, "which", side_effect=lambda command: "/usr/bin/tool" if command == "fail2ban-client" else None))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.app.status()
            self.assertIn("暂无封禁 IP", output.getvalue())

        failure = subprocess.CompletedProcess([], 1, "", "Connection refused")
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(self.app, "load", return_value=self.settings))
            stack.enter_context(patch.object(self.app, "ports", return_value=[22022]))
            stack.enter_context(patch.object(self.app, "client", return_value=failure))
            stack.enter_context(patch.object(f2b.shutil, "which", side_effect=lambda command: "/usr/bin/tool" if command == "fail2ban-client" else None))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.app.status()
            self.assertIn("封禁列表：无法读取", output.getvalue())
            self.assertIn("Connection refused", output.getvalue())
            self.assertNotIn("暂无封禁 IP", output.getvalue())


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
