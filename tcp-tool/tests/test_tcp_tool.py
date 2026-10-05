import importlib.util
import json
import os
import pty
import select
import signal
from pathlib import Path
import subprocess
import tempfile
import termios
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "tcp_tool.py"
spec = importlib.util.spec_from_file_location("tcp_tool", SOURCE)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class FakeSystem:
    def __init__(self):
        self.values = {
            "net.ipv4.tcp_congestion_control": "cubic",
            "net.ipv4.tcp_available_congestion_control": "reno cubic bbr",
            "net.core.default_qdisc": "pfifo_fast",
            "net.ipv4.tcp_fin_timeout": "60",
            "net.ipv4.tcp_sack": "1",
            "kernel.panic": "0",
            "vm.swappiness": "60",
            "net.ipv4.tcp_adv_win_scale": "1",
            "net.ipv4.tcp_rmem": "4096 131072 6291456",
        }
        self.writes = []
        self.fail_key = None
        self.fail_restore = False
        self.boot = "test-boot"

    def read(self, key):
        if key not in self.values:
            raise FileNotFoundError(key)
        return self.values[key]

    def write(self, key, value):
        self.writes.append((key, value))
        # Model a write that mutates before reporting failure.
        self.values[key] = value
        if key == self.fail_key:
            self.fail_key = None
            raise RuntimeError("permission denied")
        if self.fail_restore and key == "net.core.default_qdisc" and value == "pfifo_fast":
            self.values[key] = "fq"
            raise RuntimeError("restore denied")

    def boot_id(self):
        return self.boot


class ParserTests(unittest.TestCase):
    def test_markdown_crlf_comments_and_escaped_paste(self):
        values = tool.parse_config("```ini\r\n# title\r\n\r\n"
                                   "kernel.core_pattern = core\\_%e\\\r\n"
                                   "net.ipv4.tcp_rmem = 32768 262144 70411879\\\r\n"
                                   "net.ipv4.tcp_fin_timeout = 010 # secs\r\n```\r\n")
        self.assertEqual(values["kernel.core_pattern"], "core_%e")
        self.assertEqual(values["net.ipv4.tcp_rmem"], "32768 262144 70411879")
        self.assertEqual(values["net.ipv4.tcp_fin_timeout"], "10")

    def test_commands_and_expressions_never_accepted(self):
        bad = ["sudo sh -c 'echo x > /etc/sysctl.conf'",
               "net.core.default_qdisc = $(touch /tmp/should-not-exist)",
               "net.core.default_qdisc = `id`", "kernel.core_pattern = |/bin/sh",
               "net.ipv4.tcp_fin_timeout = 10; reboot", "net.ipv4.tcp_fin_timeout = 10\x00",
               "net.ipv4.tcp_fin_timeout = 10\nnet.ipv4.tcp_fin_timeout = 20",
               "net.ipv4.ip_forward = 1", "net.ipv4.tcp_rmem = 1 2",
               "net.ipv4.tcp_fin_timeout = " + "9" * 200,
               "", "# comment only", "x" * (128 * 1024 + 1)]
        for text in bad:
            with self.subTest(text=text[:100]):
                with self.assertRaises(ValueError):
                    tool.parse_config(text)

    def test_numeric_relations(self):
        self.assertIsNotNone(tool.value_issue("net.ipv4.tcp_rmem", "3 2 1"))
        self.assertIsNotNone(tool.value_issue("net.ipv4.ip_local_port_range", "65535 1024"))
        self.assertIsNotNone(tool.value_issue("net.ipv4.ip_local_port_range", "1024 65536"))
        self.assertIsNotNone(tool.value_issue("vm.dirty_ratio", "101"))
        self.assertIsNone(tool.value_issue("net.ipv4.tcp_adv_win_scale", "-2"))


class PlanTests(unittest.TestCase):
    def test_unsupported_and_invalid_website_values(self):
        system = FakeSystem()
        values = tool.parse_config("net.ipv4.tcp_fack = 1\nnet.ipv4.route.gc_timeout = 100\n"
                                   "net.ipv4.tcp_adv_win_scale = 34\nnet.ipv4.tcp_fin_timeout = 10")
        rows = tool.make_plan(values, system)
        self.assertEqual([r["key"] for r in rows if not r["reason"]], ["net.ipv4.tcp_fin_timeout"])
        self.assertEqual(system.writes, [])

    def test_no_algorithm_substitution(self):
        system = FakeSystem()
        system.values["net.ipv4.tcp_available_congestion_control"] = "reno cubic"
        row = tool.make_plan({"net.ipv4.tcp_congestion_control": "bbr"}, system)[0]
        self.assertIn("算法未就绪", row["reason"])
        self.assertEqual(row["value"], "bbr")

    def test_system_values_require_opt_in(self):
        values = {"kernel.panic": "1", "vm.swappiness": "5", "net.core.default_qdisc": "fq"}
        self.assertEqual(sum(not r["reason"] for r in tool.make_plan(values, FakeSystem())), 1)
        self.assertEqual(sum(not r["reason"] for r in tool.make_plan(values, FakeSystem(), True)), 3)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.system = FakeSystem()
        self.config = self.root / "etc" / "sysctl.d" / "99-z-tcptool.conf"
        self.engine = tool.Engine(self.system, self.config, self.root / "state")
        self.values = {"net.core.default_qdisc": "fq", "net.ipv4.tcp_fin_timeout": "10"}

    def test_apply_and_restore_missing_original_file(self):
        original = dict(self.system.values)
        path, _ = self.engine.apply(self.values)
        self.assertEqual(self.config.read_text(), tool.serialize(self.values))
        self.assertEqual(self.engine.latest()[1]["status"], "applied")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.engine.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.engine.rollback(), path)
        self.assertFalse(self.config.exists())
        self.assertEqual(self.system.values, original)
        self.assertIsNone(self.engine.latest())

    def test_repeated_import_retains_keys_then_rolls_back_in_order(self):
        original = dict(self.system.values)
        first, _ = self.engine.apply(self.values)
        content = self.config.read_bytes()
        second, _ = self.engine.apply({"net.ipv4.tcp_congestion_control": "bbr"})
        self.assertIn("net.core.default_qdisc = fq", self.config.read_text())
        self.assertEqual(self.engine.rollback(), second)
        self.assertEqual(self.config.read_bytes(), content)
        self.assertEqual(self.system.read("net.ipv4.tcp_congestion_control"), "cubic")
        self.assertEqual(self.engine.rollback(), first)
        self.assertEqual(self.system.values, original)

    def test_existing_managed_file_permissions_restored(self):
        self.config.parent.mkdir(parents=True)
        original = tool.serialize({"net.ipv4.tcp_sack": "1"})
        self.config.write_text(original)
        self.config.chmod(0o640)
        self.engine.apply(self.values)
        self.engine.rollback()
        self.assertEqual(self.config.read_text(), original)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)

    def test_mid_apply_failure_restores_even_failed_key(self):
        original = dict(self.system.values)
        self.system.fail_key = "net.ipv4.tcp_fin_timeout"
        with self.assertRaisesRegex(RuntimeError, "已撤销本次修改"):
            self.engine.apply(self.values)
        self.assertEqual(self.system.values, original)
        self.assertFalse(self.config.exists())
        self.assertEqual(self.engine.records()[0][1]["status"], "cancelled")

    def test_persistence_failure_restores_runtime(self):
        original = dict(self.system.values)
        real_write = tool.atomic_write

        def fail_config(path, *args, **kwargs):
            if path == self.config:
                raise OSError("disk full")
            return real_write(path, *args, **kwargs)

        with mock.patch.object(tool, "atomic_write", side_effect=fail_config):
            with self.assertRaisesRegex(RuntimeError, "disk full"):
                self.engine.apply(self.values)
        self.assertEqual(self.system.values, original)
        self.assertFalse(self.config.exists())

    def test_backup_failure_prevents_mutation(self):
        with mock.patch.object(self.engine, "save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.engine.apply(self.values)
        self.assertEqual(self.system.writes, [])
        self.assertFalse(self.config.exists())

    def test_failed_automatic_restore_blocks_new_apply_and_is_retryable(self):
        self.system.fail_key = "net.ipv4.tcp_fin_timeout"
        self.system.fail_restore = True
        with self.assertRaisesRegex(RuntimeError, "恢复不完整"):
            self.engine.apply(self.values)
        self.assertEqual(self.engine.latest()[1]["status"], "rollback_failed")
        with self.assertRaisesRegex(RuntimeError, "未完成操作"):
            self.engine.apply(self.values)
        self.system.fail_restore = False
        self.engine.rollback()
        self.assertEqual(self.system.values["net.core.default_qdisc"], "pfifo_fast")

    def test_pending_journal_can_recover_interrupted_apply(self):
        path, _ = self.engine.apply(self.values)
        data = self.engine.records()[0][1]
        data["status"] = "pending"
        self.engine.save(path, data)
        self.config.unlink()  # Simulate interruption before configuration publication.
        with self.assertRaisesRegex(RuntimeError, "未完成操作"):
            self.engine.apply(self.values)
        self.engine.rollback()
        self.assertEqual(self.system.values["net.ipv4.tcp_fin_timeout"], "60")

    def test_external_file_modification_is_never_overwritten(self):
        self.engine.apply(self.values)
        self.config.write_text("# external edits\n")
        writes = list(self.system.writes)
        for operation in (self.engine.rollback, lambda: self.engine.apply(self.values)):
            with self.assertRaisesRegex(RuntimeError, "外部修改|拒绝覆盖"):
                operation()
        self.assertEqual(self.config.read_text(), "# external edits\n")
        self.assertEqual(self.system.writes, writes)

    def test_external_runtime_modification_prevents_entire_rollback(self):
        self.engine.apply(self.values)
        self.system.values["net.ipv4.tcp_fin_timeout"] = "20"
        writes = list(self.system.writes)
        with self.assertRaisesRegex(RuntimeError, "外部修改"):
            self.engine.rollback()
        self.assertEqual(self.system.writes, writes)
        self.assertEqual(self.system.values["net.core.default_qdisc"], "fq")

    def test_new_boot_can_restore_original_runtime(self):
        self.engine.apply(self.values)
        self.system.boot = "next-boot"
        self.system.values["net.ipv4.tcp_fin_timeout"] = "30"
        self.engine.rollback()
        self.assertEqual(self.system.values["net.ipv4.tcp_fin_timeout"], "60")

    def test_unknown_or_symlink_config_is_refused(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text("net.ipv4.tcp_fin_timeout = 15\n")
        with self.assertRaisesRegex(RuntimeError, "不属于"):
            self.engine.apply(self.values)
        self.config.unlink()
        original = self.root / "untouched"
        original.write_text("keep this")
        self.config.symlink_to(original)
        with self.assertRaisesRegex(RuntimeError, "符号链接"):
            self.engine.apply(self.values)
        self.assertEqual(original.read_text(), "keep this")
        self.assertEqual(self.system.writes, [])

    def test_modified_backup_detected_before_restore(self):
        path, _ = self.engine.apply(self.values)
        data = json.loads(path.read_text())
        data["before"]["net.ipv4.tcp_fin_timeout"] = "999"
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(RuntimeError, "校验失败"):
            self.engine.rollback()
        self.assertEqual(self.system.values["net.ipv4.tcp_fin_timeout"], "10")

    def test_concurrent_lock_prevents_mutations(self):
        with self.engine.lock():
            with self.assertRaisesRegex(RuntimeError, "正在进行"):
                self.engine.apply(self.values)
        self.assertEqual(self.system.writes, [])

    def test_all_skipped_creates_no_backup_or_config(self):
        with self.assertRaisesRegex(RuntimeError, "没有可应用"):
            self.engine.apply({"net.ipv4.tcp_fack": "1"})
        self.assertEqual(self.engine.records(), [])
        self.assertFalse(self.config.exists())

    def test_keyboard_interrupt_restores_transaction(self):
        original = dict(self.system.values)
        real_write = self.system.write

        def interrupt(key, value):
            if key == "net.ipv4.tcp_fin_timeout" and value == "10":
                raise KeyboardInterrupt()
            real_write(key, value)

        with mock.patch.object(self.system, "write", side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, "已撤销"):
                self.engine.apply(self.values)
        self.assertEqual(self.system.values, original)

    def test_identical_reapply_creates_no_writes_or_backup(self):
        first, _ = self.engine.apply(self.values)
        writes = list(self.system.writes)
        path, rows = self.engine.apply(self.values)
        self.assertIsNone(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(self.system.writes, writes)
        self.assertEqual(len(self.engine.records()), 1)
        self.assertEqual(self.engine.rollback(), first)

    def test_same_live_values_still_publish_missing_config(self):
        self.system.values.update(self.values)
        path, _ = self.engine.apply(self.values)
        self.assertIsNotNone(path)
        self.assertEqual(self.system.writes, [])
        self.assertEqual(self.config.read_text(), tool.serialize(self.values))
        self.engine.rollback()
        self.assertFalse(self.config.exists())
        for key, value in self.values.items():
            self.assertEqual(self.system.read(key), value)

    def test_reapply_repairs_runtime_drift(self):
        self.engine.apply(self.values)
        self.system.values["net.ipv4.tcp_fin_timeout"] = "20"
        path, _ = self.engine.apply(self.values)
        self.assertIsNotNone(path)
        self.assertEqual(self.system.read("net.ipv4.tcp_fin_timeout"), "10")
        self.engine.rollback()
        self.assertEqual(self.system.read("net.ipv4.tcp_fin_timeout"), "20")

    def test_cleaning_retired_records_preserves_entire_active_chain(self):
        original = dict(self.system.values)
        first, _ = self.engine.apply(self.values)
        retired, _ = self.engine.apply({"net.ipv4.tcp_congestion_control": "bbr"})
        self.engine.rollback()
        latest, _ = self.engine.apply({"net.ipv4.tcp_fin_timeout": "15"})
        inventory = self.engine.backup_inventory()
        self.assertEqual([p for p, _, protected in inventory if protected], [first, latest])
        self.assertEqual(self.engine.cleanup_candidates(), [retired])
        writes = list(self.system.writes)
        config = self.config.read_bytes()
        self.assertEqual(self.engine.delete_backups([retired.name]), 1)
        self.assertEqual(self.system.writes, writes)
        self.assertEqual(self.config.read_bytes(), config)
        self.engine.rollback()
        self.engine.rollback()
        self.assertEqual(self.system.values, original)
        self.assertFalse(self.config.exists())

    def test_bulk_delete_validates_entire_selection_before_deleting(self):
        first, _ = self.engine.apply(self.values)
        retired, _ = self.engine.apply({"net.ipv4.tcp_congestion_control": "bbr"})
        self.engine.rollback()
        with self.assertRaisesRegex(RuntimeError, "不能删除"):
            self.engine.delete_backups([retired.name, first.name])
        self.assertTrue(retired.exists())
        self.assertTrue(first.exists())
        with self.assertRaisesRegex(ValueError, "不存在"):
            self.engine.delete_backups([retired.name, "../outside.json"])
        self.assertTrue(retired.exists())

    def test_pending_and_failed_records_are_protected(self):
        path, _ = self.engine.apply(self.values)
        for status in ("pending", "rollback_failed"):
            data = self.engine.records()[0][1]
            data["status"] = status
            self.engine.save(path, data)
            self.assertEqual(self.engine.cleanup_candidates(), [])
            with self.assertRaisesRegex(RuntimeError, "不能删除"):
                self.engine.delete_backups([path.name])

    def test_cleanup_keep_and_cancelled_records(self):
        retired = []
        for _ in range(3):
            self.system.fail_key = "net.ipv4.tcp_fin_timeout"
            with self.assertRaises(RuntimeError):
                self.engine.apply(self.values)
            retired.append(self.engine.records()[-1][0])
        self.assertEqual(self.engine.cleanup_candidates(1), retired[:2])
        self.assertEqual(self.engine.cleanup_candidates(10), [])
        with self.assertRaises(ValueError):
            self.engine.cleanup_candidates(-1)
        self.engine.delete_backups([p.name for p in retired[:2]])
        self.assertEqual([p for p, _ in self.engine.records()], retired[2:])

    def test_profiles_are_independent_of_backups_and_config(self):
        values = dict(self.values, **{"kernel.panic": "1", "net.ipv4.tcp_fack": "1"})
        path = self.engine.save_profile("上海-千兆", values)
        self.assertEqual(self.engine.load_profile("上海-千兆"), values)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.engine.profile_names(), ["上海-千兆"])
        self.assertEqual(self.engine.records(), [])
        self.assertFalse(self.config.exists())
        self.assertEqual(self.system.writes, [])
        with self.assertRaisesRegex(RuntimeError, "已存在"):
            self.engine.save_profile("上海-千兆", self.values)
        self.engine.save_profile("上海-千兆", self.values, overwrite=True)
        self.assertEqual(self.engine.load_profile("上海-千兆"), self.values)
        self.engine.delete_profile("上海-千兆")
        self.assertEqual(self.engine.profile_names(), [])
        self.assertEqual(self.system.writes, [])

    def test_profile_integrity_and_path_validation(self):
        for name in ("../escape", "a/b", "..", "", "x" * 61):
            with self.assertRaises(ValueError):
                self.engine.save_profile(name, self.values)
        path = self.engine.save_profile("last-import", self.values)
        data = json.loads(path.read_text())
        data["values"]["net.ipv4.tcp_fin_timeout"] = "999"
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(RuntimeError, "校验失败"):
            self.engine.load_profile("last-import")
        path.unlink()
        outside = self.root / "outside"
        outside.write_text("untouched")
        path.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "符号链接"):
            self.engine.save_profile("last-import", self.values, overwrite=True)
        self.assertEqual(outside.read_text(), "untouched")

    def test_edited_profile_does_not_mutate_live_state_before_apply(self):
        updated = tool.edit_values(self.values, "net.ipv4.tcp_fin_timeout", "015")
        self.assertEqual(updated["net.ipv4.tcp_fin_timeout"], "15")
        self.assertEqual(self.values["net.ipv4.tcp_fin_timeout"], "10")
        self.engine.save_profile("last-import", updated)
        self.assertEqual(self.system.read("net.ipv4.tcp_fin_timeout"), "60")
        self.assertFalse(self.config.exists())
        self.engine.apply(self.engine.load_profile("last-import"))
        self.assertEqual(self.system.read("net.ipv4.tcp_fin_timeout"), "15")
        for key, value in (("missing", "1"), ("net.core.default_qdisc", "$(id)"),
                           ("net.ipv4.tcp_fin_timeout", "10\nnet.ipv4.tcp_sack = 0")):
            with self.assertRaises(ValueError):
                tool.edit_values(self.values, key, value)


class UITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.system = FakeSystem()
        self.engine = tool.Engine(self.system, root / "config.conf", root / "state")
        self.values = {"net.ipv4.tcp_fin_timeout": "10"}
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(tool, "require_root").start()
        mock.patch.object(tool, "conflicts", return_value=[]).start()
        mock.patch("builtins.print").start()

    def test_paste_ctrl_d_and_blank_lines(self):
        with mock.patch("builtins.input", side_effect=["", "net.ipv4.tcp_fin_timeout = 10", "", EOFError()]):
            self.assertEqual(tool.read_paste(), self.values)
        for ending in ("CANCEL", EOFError()):
            with mock.patch("builtins.input", side_effect=[ending]):
                self.assertIsNone(tool.read_paste())

    def test_import_save_and_reuse_menu_without_second_paste(self):
        inputs = ["1", "net.ipv4.tcp_fin_timeout = 10", "END", "5", "我的方案", "0",
                  "6", "2", "1", "y", "0", "0"]
        with mock.patch.object(tool.sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", side_effect=inputs):
            self.assertEqual(tool.menu(self.system, self.engine), 0)
        self.assertEqual(self.engine.profile_names(), ["last-import", "我的方案"])
        self.assertEqual(self.system.read("net.ipv4.tcp_fin_timeout"), "10")
        self.assertEqual(len(self.engine.records()), 1)

    def test_edit_by_number_and_apply(self):
        with mock.patch("builtins.input", side_effect=["4", "1", "20", "y"]):
            tool.parameter_actions(self.values, self.system, self.engine)
        self.assertEqual(self.system.read("net.ipv4.tcp_fin_timeout"), "20")
        self.assertEqual(self.engine.load_profile("last-import")["net.ipv4.tcp_fin_timeout"], "20")

    def test_direct_confirmation_is_one_step(self):
        with mock.patch("builtins.input", side_effect=["y"]) as read:
            tool.parameter_actions(self.values, self.system, self.engine)
        self.assertEqual(read.call_count, 1)
        self.assertEqual(self.system.read("net.ipv4.tcp_fin_timeout"), "10")

    def test_return_and_no_cancel_without_writes(self):
        for response in ("", "n", "0"):
            with mock.patch("builtins.input", side_effect=[response]):
                tool.parameter_actions(self.values, self.system, self.engine)
        self.assertEqual(self.system.writes, [])

    def test_paste_interrupt_returns_to_main_menu(self):
        with mock.patch.object(tool.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(tool, "read_paste", side_effect=KeyboardInterrupt()), \
                mock.patch("builtins.input", side_effect=["1", "0"]):
            self.assertEqual(tool.menu(self.system, self.engine), 0)
        self.assertEqual(self.system.writes, [])

    def test_backup_cleanup_requires_confirmation(self):
        path, _ = self.engine.apply(self.values)
        self.engine.rollback()
        with mock.patch("builtins.input", side_effect=["3", "", "n", "0"]):
            tool.backup_menu(self.system, self.engine)
        self.assertTrue(path.exists())
        with mock.patch("builtins.input", side_effect=["3", "", "y", "0"]):
            tool.backup_menu(self.system, self.engine)
        self.assertFalse(path.exists())

    def test_cli_cleanup_preview_and_profile_apply(self):
        self.engine.save_profile("我的方案", self.values)
        with mock.patch.object(tool, "System", return_value=self.system), \
                mock.patch.object(tool, "Engine", return_value=self.engine):
            self.assertEqual(tool.main(["apply", "--profile", "我的方案", "--yes"]), 0)
            self.engine.rollback()
            self.assertEqual(tool.main(["backup-cleanup"]), 0)
            self.assertEqual(len(self.engine.records()), 1)
            self.assertEqual(tool.main(["backup-cleanup", "--yes"]), 0)
            self.assertEqual(self.engine.records(), [])
            self.assertEqual(self.engine.profile_names(), ["我的方案"])
            with mock.patch.object(tool.sys, "stderr"), self.assertRaises(SystemExit) as error:
                tool.main(["apply", "example.conf", "--profile", "我的方案"])
            self.assertEqual(error.exception.code, 2)


class TerminalPasteTests(unittest.TestCase):
    def run_terminal(self, payload=None, interrupt=False, check_trailing=False):
        master, slave = pty.openpty()
        original = termios.tcgetattr(slave)
        code = ("import runpy,json,sys; ns=runpy.run_path(sys.argv[1]); "
                "exec(\"try:\\n result=ns['read_paste']()\\n print('RESULT='+json.dumps(result))"
                "\\nexcept BaseException as error:\\n print('ERROR='+type(error).__name__)\")")
        if check_trailing:
            code += "; print('NEXT_PROMPT',flush=True); print('NEXT='+input())"
        child = subprocess.Popen([os.sys.executable, "-c", code, str(SOURCE)],
                                 stdin=slave, stdout=slave, stderr=slave,
                                 env=dict(os.environ, TERM="xterm", PYTHONDONTWRITEBYTECODE="1"))
        output = bytearray()

        def until(marker):
            deadline = time.monotonic() + 5
            while marker not in output:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, output.decode(errors="replace"))
                ready, _, _ = select.select([master], [], [], remaining)
                self.assertTrue(ready, output.decode(errors="replace"))
                output.extend(os.read(master, 8192))

        try:
            until(b"\x1b[?2004h")
            if interrupt:
                child.send_signal(signal.SIGINT)
            else:
                os.write(master, payload)
            until(b"\x1b[?2004l")
            if check_trailing:
                until(b"NEXT_PROMPT")
                os.write(master, b"n\n")
                until(b"NEXT=n")
            child.wait(timeout=5)
            while select.select([master], [], [], 0)[0]:
                output.extend(os.read(master, 8192))
            self.assertEqual(child.returncode, 0, output.decode(errors="replace"))
            restored = termios.tcgetattr(slave)
            # macOS can set its kernel-maintained PENDIN flag on canonical restore.
            pending = getattr(termios, "PENDIN", 0)
            restored[3] &= ~pending
            original[3] &= ~pending
            self.assertEqual(restored, original)
            return output.decode("utf-8")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            os.close(master)
            os.close(slave)

    def test_bracketed_paste_ends_automatically_and_drops_queued_answers(self):
        payload = ("\x1b[200~# 中文注释\r\n\r\nnet.ipv4.tcp_fin_timeout = 10\r\n"
                   "\r\nnet.core.default_qdisc = fq\x1b[201~y\n").encode()
        output = self.run_terminal(payload, check_trailing=True)
        self.assertIn('"net.ipv4.tcp_fin_timeout": "10"', output)
        self.assertIn('"net.core.default_qdisc": "fq"', output)
        self.assertIn("NEXT=n", output)

    def test_manual_end_still_works(self):
        output = self.run_terminal(b"net.ipv4.tcp_fin_timeout = 10\nEND\n")
        self.assertIn('"net.ipv4.tcp_fin_timeout": "10"', output)

    def test_ctrl_d_and_cancel(self):
        output = self.run_terminal(b"net.ipv4.tcp_fin_timeout = 10\x04")
        self.assertIn('"net.ipv4.tcp_fin_timeout": "10"', output)
        output = self.run_terminal(b"CANCEL\n")
        self.assertIn("RESULT=null", output)

    def test_terminal_restored_on_interrupt_and_invalid_data(self):
        self.assertIn("ERROR=KeyboardInterrupt", self.run_terminal(interrupt=True))
        self.assertIn("ERROR=ValueError", self.run_terminal(b"\x1b[200~sudo reboot\x1b[201~"))
        self.assertIn("ERROR=ValueError", self.run_terminal(b"\x1b[200~value\x1b[31m\x1b[201~"))


class SystemTests(unittest.TestCase):
    def test_write_uses_argument_array_and_verifies_readback(self):
        with mock.patch.object(tool.platform, "system", return_value="Linux"), \
                mock.patch.object(tool.shutil, "which", return_value="/sbin/sysctl"):
            system = tool.System()
        result = subprocess.CompletedProcess([], 0, "ok", "")
        with mock.patch.object(tool.subprocess, "run", return_value=result) as run, \
                mock.patch.object(system, "read", return_value="20"):
            with self.assertRaisesRegex(RuntimeError, "读回不一致"):
                system.write("net.ipv4.tcp_fin_timeout", "10")
            self.assertEqual(run.call_args[0][0], ["/sbin/sysctl", "-w", "net.ipv4.tcp_fin_timeout=10"])
            self.assertNotIn("shell", run.call_args[1])

    def test_help_and_version_work_without_linux(self):
        for argument in ("--help", "--version"):
            result = subprocess.run([os.sys.executable, str(SOURCE), argument], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
