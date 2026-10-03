import importlib.util
import io
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "ipv6_tool.py"
spec = importlib.util.spec_from_file_location("ipv6_tool", SCRIPT)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class FakeLinux:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.indices = {"lo": 1, "eth0": 2, "eth1": 3}
        self.fail_update = 0
        self.fail_restore = False
        self.wrong_generated = False
        self.on_update = None
        self.original_grub = b"menuentry 'Linux' {\n linux /boot/vmlinuz-test root=/dev/vda1 quiet\n}\n"

    def __call__(self, args, data=None, binary=False):
        self.calls.append((args, data, binary))
        if args == ["ip", "-j", "link", "show"]:
            return json.dumps([{"ifname": name, "ifindex": index} for name, index in self.indices.items()])
        if args == ["ip", "-6", "address", "save"]:
            return b"address-netlink-dump\x00\xff"
        if args == ["ip", "-6", "route", "save", "table", "all"]:
            return b"route-netlink-dump\x00\xfe"
        if args[:3] == ["ip", "-6", "address"] and args[3] == "restore":
            if self.fail_restore:
                raise tool.ToolError("fake address restore failed")
            assert data == b"address-netlink-dump\x00\xff"
            return b""
        if args[:3] == ["ip", "-6", "route"] and args[3] == "restore":
            assert data == b"route-netlink-dump\x00\xfe"
            return b""
        if args == ["update-grub"]:
            if self.on_update:
                self.on_update()
            if self.fail_update:
                self.fail_update -= 1
                raise tool.ToolError("fake update-grub failed")
            disabled = (self.root / "etc/default/grub.d/99-ipv6tool.cfg").exists()
            flag = b" ipv6.disable=1" if disabled and not self.wrong_generated else b""
            config = self.original_grub.replace(b" quiet", b" quiet" + flag)
            (self.root / "boot/grub/grub.cfg").write_bytes(config)
            return "generated"
        if args == ["bootctl", "status", "--no-pager"]:
            return "Current Boot Loader:\n Product: GRUB\n"
        if args[0] == "ip":
            return ""
        raise AssertionError("unexpected command: " + repr(args))


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fake = FakeLinux(self.root)
        self.manager = tool.Manager(self.root, self.fake)
        for name, data in {
            "etc/os-release": b'ID=ubuntu\n',
            "etc/default/grub": b'GRUB_CMDLINE_LINUX="console=ttyS0"\n',
            "etc/default/grub.d/10-cloud.cfg": b'GRUB_TIMEOUT=1\n',
            "boot/grub/grub.cfg": self.fake.original_grub,
            "proc/sys/kernel/random/boot_id": b"boot-1\n",
            "proc/cmdline": b"root=/dev/vda1 quiet\n",
            "usr/sbin/grub-mkconfig": b'for x in /etc/default/grub.d/*.cfg; do . "$x"; done\n',
        }.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name, value in {"all": "0", "default": "0", "lo": "0", "eth0": "0", "eth1": "1"}.items():
            self.add_interface(name, value)
        self.patcher = mock.patch.object(tool.shutil, "which", side_effect=self.which)
        self.patcher.start()
        # CLI 在任何修改前都会获取锁并创建私有状态目录。
        with self.manager.locked():
            pass

    def tearDown(self):
        self.patcher.stop()
        self.temporary.cleanup()

    def which(self, name):
        if name == "grub-mkconfig":
            return str(self.root / "usr/sbin/grub-mkconfig")
        if name in ("update-grub", "ip"):
            return "/usr/sbin/" + name
        return None

    def add_interface(self, name, value):
        path = self.root / "proc/sys/net/ipv6/conf" / name / "disable_ipv6"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n")

    def boot_command_count(self):
        return sum(args == ["update-grub"] for args, _, _ in self.fake.calls)

    def test_priority_switch_preserves_custom_rules_and_restores_original(self):
        original = b"# custom\nlabel fc00::/7 6\nprecedence fc00::/7 25\nprecedence ::ffff:0:0/96 5\n"
        self.manager.gai.write_bytes(original)
        self.manager.gai.chmod(0o640)
        self.manager.priority("ipv4", backup=True)
        baseline = self.manager.state()["priority"]["backup"]
        applied = self.manager.gai.read_text()
        self.assertIn("label fc00::/7 6", applied)
        self.assertIn("precedence fc00::/7 25", applied)
        self.assertIn("precedence ::ffff:0:0/96 100", applied)
        self.assertIn("precedence ::1/128 50", applied)
        self.manager.priority("ipv6")
        self.assertEqual(self.manager.state()["priority"]["backup"], baseline)
        self.assertIn("precedence ::ffff:0:0/96 10", self.manager.gai.read_text())
        self.manager.priority("restore")
        self.assertEqual(self.manager.gai.read_bytes(), original)
        self.assertEqual(self.manager.gai.stat().st_mode & 0o777, 0o640)
        self.assertNotIn("priority", self.manager.state())

    def test_priority_restore_originally_absent_file(self):
        self.manager.priority("ipv4")
        self.manager.priority("restore")
        self.assertFalse(self.manager.gai.exists())

    def test_priority_external_change_is_not_overwritten(self):
        self.manager.priority("ipv4")
        self.manager.gai.write_text("# external modification\n")
        for mode in ("ipv6", "restore"):
            with self.assertRaisesRegex(tool.ToolError, "其他程序修改"):
                self.manager.priority(mode)
        self.assertEqual(self.manager.gai.read_text(), "# external modification\n")

    def test_invalid_precedence_is_rejected_before_writing(self):
        original = b"precedence not-an-ip 100\n"
        self.manager.gai.write_bytes(original)
        with self.assertRaises(tool.ToolError):
            self.manager.priority("ipv4")
        self.assertEqual(self.manager.gai.read_bytes(), original)
        self.assertFalse(self.manager.state_file.exists())

    def test_priority_backup_failure_does_not_write(self):
        with mock.patch.object(self.manager, "backup", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.manager.priority("ipv4", backup=True)
        self.assertFalse(self.manager.gai.exists())

    def test_priority_journal_recovers_interrupted_first_write(self):
        original = tool.file_snapshot(self.manager.gai)
        desired = tool.priority_config(b"", "ipv4")
        name = self.manager.backup("priority", {"gai": original})
        self.manager.save_state({"priority": {"backup": name, "applied": tool.digest(desired),
                                             "mode": "ipv4", "phase": "preparing", "previous": original}})
        self.manager.priority("restore")
        self.assertFalse(self.manager.gai.exists())
        self.assertNotIn("priority", self.manager.state())

    def test_priority_journal_recovers_interrupted_switch(self):
        self.manager.priority("ipv4")
        state = self.manager.state()
        previous = tool.file_snapshot(self.manager.gai)
        state["priority"].update(phase="preparing", applied=tool.digest(tool.priority_config(b"", "ipv6")),
                                 previous=previous, mode="ipv6")
        self.manager.save_state(state)
        self.manager.priority("restore")
        self.assertFalse(self.manager.gai.exists())

    def test_temporary_restores_flags_and_binary_dumps(self):
        original = self.manager.flags()
        self.manager.temporary()
        self.assertTrue(all(value == "1" for value in self.manager.flags().values()))
        self.assertFalse(self.manager.boot_file.exists())
        self.assertFalse(self.manager.gai.exists())
        self.assertEqual(self.boot_command_count(), 0)
        self.manager.enable()
        self.assertEqual(self.manager.flags(), original)
        self.assertNotIn("temporary", self.manager.state())
        self.assertTrue(any(args == ["ip", "-6", "route", "restore"] for args, _, _ in self.fake.calls))

    def test_repeated_temporary_keeps_first_backup(self):
        self.manager.temporary(backup=True)
        name = self.manager.state()["temporary"]["backup"]
        self.manager.temporary()
        self.assertEqual(self.manager.state()["temporary"]["backup"], name)
        self.manager.enable()
        self.assertEqual(self.manager.flags()["eth0"], "0")

    def test_external_reenable_is_reported(self):
        self.manager.temporary()
        self.add_interface("eth0", "0")
        with self.assertRaisesRegex(tool.ToolError, "重新启用"):
            self.manager.temporary()

    def test_temporary_disable_failure_rolls_back(self):
        original = self.manager.flags()
        real = self.manager.write_flag
        failures = [True]
        def write(name, value):
            if name == "eth0" and value == "1" and failures:
                failures.pop()
                raise tool.ToolError("fake sysctl failure")
            real(name, value)
        with mock.patch.object(self.manager, "write_flag", side_effect=write):
            with self.assertRaisesRegex(tool.ToolError, "fake sysctl failure"):
                self.manager.temporary()
        self.assertEqual(self.manager.flags(), original)
        self.assertNotIn("temporary", self.manager.state())

    def test_new_interface_restores_previous_default(self):
        self.manager.temporary()
        self.add_interface("eth2", "1")
        self.fake.indices["eth2"] = 4
        self.manager.enable()
        self.assertEqual(self.manager.flags()["eth2"], "0")
        self.assertEqual(self.manager.flags()["eth1"], "1")

    def test_changed_interface_index_is_rejected_without_restore(self):
        self.manager.temporary()
        self.fake.indices["eth0"] = 99
        with self.assertRaisesRegex(tool.ToolError, "索引"):
            self.manager.enable()
        self.assertEqual(self.manager.flags()["eth0"], "1")
        self.assertIn("temporary", self.manager.state())

    def test_no_runtime_restore_after_reboot(self):
        self.manager.temporary()
        (self.root / "proc/sys/kernel/random/boot_id").write_text("boot-2")
        self.fake.calls.clear()
        self.manager.enable()
        self.assertFalse(any("restore" in args for args, _, _ in self.fake.calls))
        self.assertNotIn("temporary", self.manager.state())

    def test_temporary_restore_failure_retains_backup_for_retry(self):
        self.manager.temporary()
        self.fake.fail_restore = True
        with self.assertRaises(tool.ToolError):
            self.manager.enable()
        self.assertIn("temporary", self.manager.state())
        self.fake.fail_restore = False
        self.manager.enable()
        self.assertNotIn("temporary", self.manager.state())

    def test_complete_verifies_backup_before_first_write(self):
        observed = []
        def check():
            state = self.manager.state()
            saved = self.manager.read_backup(state["complete"]["backup"], "complete")
            self.assertEqual(saved["sources"]["boot/grub/grub.cfg"]["sha256"], tool.digest(self.fake.original_grub))
            observed.append(True)
        self.fake.on_update = check
        result = self.manager.complete()
        self.assertEqual(observed, [True])
        self.assertIn("重启后生效", result)
        self.assertEqual(self.manager.boot_file.read_bytes(), tool.BOOT_CONTENT)
        self.assertFalse(self.manager.kernel_disabled())
        self.assertEqual(self.manager.flags()["eth0"], "0")

    def test_complete_backup_failure_stops_before_mutations(self):
        with mock.patch.object(self.manager, "backup", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.manager.complete()
        self.assertFalse(self.manager.boot_file.exists())
        self.assertEqual(self.boot_command_count(), 0)
        self.assertEqual(self.manager.grub_cfg.read_bytes(), self.fake.original_grub)

    def test_repeated_complete_preserves_baseline(self):
        self.manager.complete()
        name = self.manager.state()["complete"]["backup"]
        self.manager.complete()
        self.assertEqual(self.manager.state()["complete"]["backup"], name)
        self.assertEqual(self.boot_command_count(), 1)

    def test_complete_update_failure_rolls_back(self):
        self.fake.fail_update = 1
        with self.assertRaisesRegex(tool.ToolError, "fake update-grub"):
            self.manager.complete()
        self.assertFalse(self.manager.boot_file.exists())
        self.assertNotIn("complete", self.manager.state())
        self.assertEqual(self.manager.grub_cfg.read_bytes(), self.fake.original_grub)
        self.assertEqual(self.boot_command_count(), 2)

    def test_complete_generated_output_mismatch_rolls_back(self):
        self.fake.wrong_generated = True
        with self.assertRaisesRegex(tool.ToolError, "目标不一致"):
            self.manager.complete()
        self.assertFalse(self.manager.boot_file.exists())
        self.assertNotIn("complete", self.manager.state())

    def test_complete_rollback_failure_can_be_recovered(self):
        self.fake.fail_update = 2
        with self.assertRaisesRegex(tool.ToolError, "自动恢复失败"):
            self.manager.complete()
        self.assertIn("complete", self.manager.state())
        self.manager.enable()
        self.assertNotIn("complete", self.manager.state())

    def test_complete_restore_preserves_unrelated_boot_edits_and_priority(self):
        self.manager.priority("ipv4")
        self.manager.complete()
        source = self.root / "etc/default/grub"
        source.write_bytes(source.read_bytes() + b'GRUB_TIMEOUT=9\n')
        (self.root / "proc/cmdline").write_text("quiet ipv6.disable=1")
        result = self.manager.enable()
        self.assertIn("重启后重新启用", result)
        self.assertIn(b"GRUB_TIMEOUT=9", source.read_bytes())
        self.assertIn("priority", self.manager.state())
        self.assertNotIn("complete", self.manager.state())
        self.assertFalse(self.manager.boot_file.exists())

    def test_restore_update_failure_is_retryable(self):
        self.manager.complete()
        self.fake.fail_update = 1
        with self.assertRaises(tool.ToolError):
            self.manager.enable()
        self.assertEqual(self.manager.state()["complete"]["phase"], "restoring")
        self.manager.enable()
        self.assertNotIn("complete", self.manager.state())

    def test_corrupt_backup_blocks_restore_before_mutation(self):
        self.manager.complete()
        name = self.manager.state()["complete"]["backup"]
        path = self.manager.state_dir / "backups" / name
        value = json.loads(path.read_text())
        value["record"]["payload"]["boot_id"] = "corrupted"
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(tool.ToolError, "完整性"):
            self.manager.enable()
        self.assertEqual(self.manager.boot_file.read_bytes(), tool.BOOT_CONTENT)

    def test_external_boot_fragment_edit_blocks_restore(self):
        self.manager.complete()
        self.manager.boot_file.write_bytes(tool.BOOT_CONTENT + b"# edited\n")
        with self.assertRaisesRegex(tool.ToolError, "外部修改"):
            self.manager.enable()
        self.assertIn(b"# edited", self.manager.boot_file.read_bytes())

    def test_unknown_boot_environment_is_rejected(self):
        (self.root / "etc/os-release").write_text("ID=fedora\n")
        with self.assertRaisesRegex(tool.ToolError, "Debian/Ubuntu"):
            self.manager.complete()
        self.assertFalse(self.manager.boot_file.exists())

    def test_systemd_boot_entries_are_rejected(self):
        (self.root / "boot/loader/entries").mkdir(parents=True)
        with self.assertRaisesRegex(tool.ToolError, "其他启动项"):
            self.manager.complete()

    def test_existing_foreign_disable_is_not_adopted(self):
        (self.root / "etc/default/grub").write_text('GRUB_CMDLINE_LINUX="ipv6.disable=0"\n')
        with self.assertRaisesRegex(tool.ToolError, "已有 ipv6.disable"):
            self.manager.complete()
        self.assertFalse(self.manager.boot_file.exists())

    def test_complete_requires_restoring_temporary_first(self):
        self.manager.temporary()
        with self.assertRaisesRegex(tool.ToolError, "先恢复临时"):
            self.manager.complete()

    def test_temporary_refuses_kernel_disabled(self):
        (self.root / "proc/cmdline").write_text("ipv6.disable=1")
        with self.assertRaisesRegex(tool.ToolError, "内核关闭"):
            self.manager.temporary()

    def test_priority_restore_does_not_enable_ipv6(self):
        self.manager.priority("ipv4")
        self.manager.temporary()
        self.manager.priority("restore")
        self.assertEqual(self.manager.flags()["eth0"], "1")
        self.assertIn("temporary", self.manager.state())

    def test_backup_permissions_and_operation_lock(self):
        with self.manager.locked():
            self.manager.priority("ipv4", backup=True)
            with self.assertRaisesRegex(tool.ToolError, "正在运行"):
                with self.manager.locked():
                    pass
        self.assertEqual(self.manager.state_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.manager.state_file.stat().st_mode & 0o777, 0o600)
        for path in (self.manager.state_dir / "backups").iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_symlink_gai_is_not_followed(self):
        target = self.root / "other"
        target.write_text("unchanged")
        self.manager.gai.symlink_to(target)
        with self.assertRaisesRegex(tool.ToolError, "非普通文件"):
            self.manager.priority("ipv4")
        self.assertEqual(target.read_text(), "unchanged")

    def test_state_reports_per_interface_flags_not_all(self):
        self.add_interface("all", "1")
        result = self.manager.status()
        self.assertIn("eth0=启用", result)
        self.assertIn("eth1=禁用", result)

    def test_interactive_menu_full_lifecycle(self):
        output = io.StringIO()
        output.isatty = lambda: True
        answers = ["1", "2", "y", "", "3", "y", "", "4", "y", "", "5", "y", "",
                   "7", "y", "", "6", "y", "7", "y", "", "0"]
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(tool, "require_glibc"), \
                mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch.object(sys, "stdout", output), \
                mock.patch("builtins.input", side_effect=answers):
            tool.menu(self.manager)
        shown = re.sub(r"\x1b\[[0-9;]*m", "", output.getvalue())
        self.assertIn("Ipv4和ipv6管理", shown)
        self.assertIn("当前网络优先级设置：IPv6 优先（系统默认）", shown)
        self.assertIn("当前网络优先级设置：IPv4 优先", shown)
        self.assertIn("当前网络优先级设置：IPv6 优先\n", shown)
        self.assertIn("当前 IP 状态：IPv4 已启用  IPv6 已禁用", shown)
        self.assertIn("当前 IP 状态：IPv4 已启用  IPv6 已启用", shown)
        self.assertIn("已临时禁用", shown)
        self.assertIn("关闭前的启动配置已恢复", shown)
        self.assertFalse(self.manager.gai.exists())
        self.assertFalse(self.manager.boot_file.exists())
        self.assertEqual(self.manager.flags()["eth0"], "0")
        self.assertFalse(any(key in self.manager.state() for key in ("priority", "temporary", "complete")))
        self.assertEqual(len(self.manager.list_backups()), 1)  # 仅彻底关闭强制备份

    def test_optional_backups_default_to_no_and_restore_still_works(self):
        with mock.patch.object(tool, "require_glibc"), \
                mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", side_effect=["y", "", "y", "n", "y", ""]):
            tool.operate(self.manager, "priority", "ipv4")
            tool.operate(self.manager, "priority", "ipv6")
            tool.operate(self.manager, "priority", "restore")
        self.assertFalse(self.manager.gai.exists())
        self.assertEqual(self.manager.list_backups(), [])

        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", side_effect=["y", "", "y", ""]):
            tool.operate(self.manager, "disable", "temporary")
            tool.operate(self.manager, "enable")
        self.assertEqual(self.manager.flags()["eth0"], "0")
        self.assertEqual(self.manager.list_backups(), [])

    def test_priority_confirmation_defaults_to_yes_but_backup_defaults_to_no(self):
        prompts = []
        def answer(prompt):
            prompts.append(prompt)
            return ""
        with mock.patch.object(tool, "require_glibc"), \
                mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", side_effect=answer):
            tool.operate(self.manager, "priority", "ipv4")
            tool.operate(self.manager, "priority", "ipv6")
        self.assertEqual([prompt for prompt in prompts if "设置" in prompt],
                         ["设置 ipv4 优先？ [Y/n] ", "设置 ipv6 优先？ [Y/n] "])
        self.assertEqual(prompts.count("是否备份当前配置？ [y/N] "), 2)
        self.assertEqual(self.manager.state()["priority"]["mode"], "ipv6")
        self.assertEqual(self.manager.list_backups(), [])

    def test_priority_explicit_no_cancels_and_restore_still_defaults_to_no(self):
        with mock.patch.object(tool, "require_glibc"), \
                mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", return_value="n") as answer:
            with self.assertRaisesRegex(tool.ToolError, "已取消"):
                tool.operate(self.manager, "priority", "ipv4")
        self.assertEqual(answer.call_count, 1)
        self.assertEqual(self.manager.list_backups(), [])
        self.assertFalse(self.manager.gai.exists())

        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", return_value="") as answer:
            with self.assertRaisesRegex(tool.ToolError, "已取消"):
                tool.operate(self.manager, "priority", "restore")
        self.assertEqual(answer.call_args.args[0], "恢复原优先级配置？ [y/N] ")

    def test_optional_backup_yes_creates_file(self):
        with mock.patch.object(tool, "require_glibc"), \
                mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", side_effect=["y", "y"]):
            tool.operate(self.manager, "priority", "ipv4")
        self.assertEqual(len(self.manager.list_backups()), 1)

    def test_noninteractive_yes_defaults_to_no_backup(self):
        with mock.patch.object(tool, "require_glibc"), \
                mock.patch.object(sys.stdin, "isatty", return_value=False):
            tool.operate(self.manager, "priority", "ipv4", yes=True)
        self.assertEqual(self.manager.list_backups(), [])
        self.assertIn("recovery", self.manager.state()["priority"])

    def test_explicit_backup_with_yes_creates_file(self):
        with mock.patch.object(tool, "require_glibc"), \
                mock.patch.object(sys.stdin, "isatty", return_value=False):
            tool.operate(self.manager, "priority", "ipv4", yes=True, backup=True)
        self.assertEqual(len(self.manager.list_backups()), 1)

    def test_later_backup_opt_in_uses_original_recovery_data(self):
        original = b"# original\n"
        self.manager.gai.write_bytes(original)
        self.manager.priority("ipv4")
        self.assertEqual(self.manager.list_backups(), [])
        self.manager.priority("ipv6", backup=True)
        name = self.manager.state()["priority"]["backup"]
        self.assertEqual(tool.unpack(self.manager.read_backup(name, "priority")["gai"]["data"]), original)
        self.manager.priority("restore")
        self.assertEqual(self.manager.gai.read_bytes(), original)

    def test_later_temporary_backup_opt_in_uses_original_recovery_data(self):
        original = self.manager.flags()
        self.manager.temporary()
        self.assertEqual(self.manager.list_backups(), [])
        self.manager.temporary(backup=True)
        name = self.manager.state()["temporary"]["backup"]
        self.assertEqual(self.manager.read_backup(name, "temporary")["flags"], original)
        self.manager.enable()
        self.assertEqual(self.manager.flags(), original)

    def test_interactive_cancel_does_not_modify_configuration(self):
        output = io.StringIO()
        output.isatty = lambda: True
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch.object(sys, "stdout", output), \
                mock.patch.object(sys, "stderr", output), \
                mock.patch("builtins.input", side_effect=["6", "n", "0"]):
            tool.menu(self.manager)
        self.assertIn("已取消", output.getvalue())
        self.assertFalse(self.manager.boot_file.exists())
        self.assertEqual(self.boot_command_count(), 0)

    def test_menu_reads_existing_gai_priority_without_tool_state(self):
        self.manager.gai.write_text("# configured elsewhere\nprecedence ::ffff:0:0/96 100\n")
        self.assertEqual(self.manager.priority_description(),
                         "IPv4 优先（gai.conf 自定义策略）")
        output = io.StringIO()
        output.isatty = lambda: True
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch.object(sys, "stdout", output), \
                mock.patch("builtins.input", side_effect=["0"]):
            tool.menu(self.manager)
        shown = re.sub(r"\x1b\[[0-9;]*m", "", output.getvalue())
        self.assertIn("当前网络优先级设置：IPv4 优先", shown)

    def test_menu_reports_external_priority_change(self):
        self.manager.priority("ipv4")
        self.manager.gai.write_text("# changed by another program\n")
        self.assertIn("实际优先级待确认", self.manager.priority_description())

    def test_priority_color_only_in_interactive_terminal(self):
        output = io.StringIO()
        output.isatty = lambda: True
        with mock.patch.object(sys, "stdout", output), mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(tool.highlighted_priority("IPv4 优先"),
                             "\x1b[1;33mIPv4\x1b[0m 优先")
        with mock.patch.object(sys, "stdout", output), mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertEqual(tool.highlighted_priority("IPv4 优先"), "IPv4 优先")
        self.assertEqual(tool.highlighted_priority("IPv4 优先"), "IPv4 优先")

    def test_original_backup_is_labeled_and_protected(self):
        self.manager.priority("ipv4", backup=True)
        original = self.manager.state()["priority"]["backup"]
        self.manager.priority("ipv6")
        items = self.manager.list_backups()
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["origin"])
        self.assertTrue(items[0]["active"])
        self.assertIn("原始", items[0]["note"])
        details = self.manager.backup_details(original)
        self.assertIn("原始备份", details)
        self.assertIn("/etc/gai.conf", details)
        with self.assertRaisesRegex(tool.ToolError, "不能删除"):
            self.manager.delete_backup(original)
        self.manager.priority("restore")
        self.manager.delete_backup(original)
        self.assertEqual(self.manager.list_backups(), [])

    def test_manual_backup_has_note_and_source_files(self):
        self.manager.gai.write_text("# my priority baseline\n")
        name = self.manager.create_manual_backup("升级前")
        details = self.manager.backup_details(name)
        self.assertIn("备注：升级前", details)
        self.assertIn("手动备份", details)
        self.assertIn("原文件：/etc/gai.conf", details)
        self.assertIn("原文件：/etc/default/grub", details)
        self.assertIn("运行快照：接口开关、地址和路由", details)
        self.assertEqual(self.manager.read_backup_record(name)["role"], "manual")
        self.manager.delete_backup(name)
        self.assertFalse((self.manager.state_dir / "backups" / name).exists())

    def test_backup_submenu_add_view_and_delete(self):
        output = io.StringIO()
        output.isatty = lambda: True
        answers = ["4", "升级前手动备份", "1", "2", "1", "3", "1", "5", "1", "y", "0"]
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch.object(sys, "stdout", output), \
                mock.patch("builtins.input", side_effect=answers):
            tool.backup_menu(self.manager)
        self.assertIn("升级前手动备份", output.getvalue())
        self.assertIn("备份文件：", output.getvalue())
        self.assertIn("--- /etc/default/grub ---", output.getvalue())
        self.assertIn("已删除备份", output.getvalue())
        self.assertEqual(self.manager.list_backups(), [])

    def test_corrupt_unused_backup_can_be_removed(self):
        name = self.manager.create_manual_backup("待删")
        path = self.manager.state_dir / "backups" / name
        path.write_text("invalid json")
        self.assertIsNotNone(self.manager.list_backups()[0]["error"])
        self.manager.delete_backup(name)
        self.assertFalse(path.exists())

    def test_legacy_active_backup_gets_original_label(self):
        self.manager.priority("ipv4", backup=True)
        name = self.manager.state()["priority"]["backup"]
        path = self.manager.state_dir / "backups" / name
        envelope = json.loads(path.read_text())
        for key in ("note", "role", "created_at"):
            del envelope["record"][key]
        envelope["sha256"] = tool.digest(tool.canonical(envelope["record"]))
        path.write_bytes(tool.canonical(envelope))
        item = self.manager.list_backups()[0]
        self.assertTrue(item["origin"])
        self.assertIn("原始", item["note"])
        self.assertIn("原始备份", self.manager.backup_details(name))
        self.manager.priority("restore")

    def test_main_menu_opens_backup_submenu(self):
        output = io.StringIO()
        output.isatty = lambda: True
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch.object(sys, "stdout", output), \
                mock.patch("builtins.input", side_effect=["8", "0", "0"]):
            tool.menu(self.manager)
        self.assertIn("备份数据管理", output.getvalue())

    def test_ip_status_distinguishes_disabled_and_loopback(self):
        self.assertEqual(self.manager.ip_status_description(), "IPv4 已启用  IPv6 已启用")
        self.add_interface("eth0", "1")
        self.assertEqual(self.manager.ip_status_description(), "IPv4 已启用  IPv6 已启用（仅回环）")
        self.add_interface("lo", "1")
        self.assertEqual(self.manager.ip_status_description(), "IPv4 已启用  IPv6 已禁用")
        self.add_interface("lo", "0")
        (self.root / "proc/cmdline").write_text("ipv6.disable=1")
        self.assertEqual(self.manager.ip_status_description(), "IPv4 已启用  IPv6 已禁用")


class GuardTests(unittest.TestCase):
    def test_ipv6_ssh_is_blocked_even_with_yes(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = tool.Manager(Path(directory))
            with mock.patch.dict(os.environ, {"SSH_CONNECTION": "2001:db8::1 40000 2001:db8::2 22"}, clear=True):
                with self.assertRaisesRegex(tool.ToolError, "当前 SSH 使用 IPv6"):
                    tool.operate(manager, "disable", "complete", yes=True)
            self.assertFalse(manager.boot_file.exists())

    def test_ipv4_ssh_is_allowed(self):
        with mock.patch.dict(os.environ, {"SSH_CONNECTION": "198.51.100.1 40000 203.0.113.1 22"}, clear=True):
            tool.guard_ssh()

    def test_ipv6_ssh_client_fallback_is_blocked(self):
        with mock.patch.dict(os.environ, {"SSH_CLIENT": "2001:db8::1 40000 22"}, clear=True):
            with self.assertRaises(tool.ToolError):
                tool.guard_ssh()

    def test_missing_or_malformed_ssh_metadata_is_blocked(self):
        for environment in ({"SSH_TTY": "/dev/pts/0"}, {"SSH_CONNECTION": "bad metadata"}):
            with mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(tool.ToolError):
                    tool.guard_ssh()

    def test_musl_priority_is_rejected(self):
        with mock.patch.object(tool.os, "confstr", return_value=None):
            with self.assertRaisesRegex(tool.ToolError, "glibc"):
                tool.require_glibc()

    def test_help_and_version_work_without_system_mutation(self):
        for arguments in (["--help"], ["--version"], ["disable", "--help"]):
            result = subprocess.run([sys.executable, str(SCRIPT)] + arguments, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
