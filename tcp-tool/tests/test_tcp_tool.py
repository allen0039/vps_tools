import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
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
