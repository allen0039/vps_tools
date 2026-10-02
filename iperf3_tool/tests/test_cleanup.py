import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("iperf_cleanup", ROOT / "iperf3_tool.py")
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.output = io.StringIO()
        patch = contextlib.redirect_stdout(self.output)
        patch.__enter__()
        self.addCleanup(patch.__exit__, None, None, None)

    def session(self, status="complete", interactive=False):
        session = tool.Session(tool.Config("127.0.0.1", streams=(1,), output_dir=str(self.base)),
                               interactive=interactive)
        session.save(status)
        (session.directory / "test-01.json").write_text('{"sample": true}')
        return session

    def test_current_defaults_to_delete_only_current(self):
        session, other = self.session(), self.session()
        with mock.patch("builtins.input", return_value="") as prompt:
            tool.cleanup_current(session.directory)
        self.assertIn("[y]", prompt.call_args.args[0])
        self.assertFalse(session.directory.exists())
        self.assertTrue(other.directory.exists())
        self.assertTrue(self.base.exists())

    def test_current_no_preserves_data_and_yes_deletes(self):
        session = self.session()
        with mock.patch("builtins.input", return_value="n"):
            tool.cleanup_current(session.directory)
        self.assertTrue((session.directory / "test-01.json").exists())
        with mock.patch("builtins.input", return_value="y"):
            tool.cleanup_current(session.directory)
        self.assertFalse(session.directory.exists())

    def test_current_eof_or_interrupt_preserves_data(self):
        session = self.session()
        for error in (EOFError, KeyboardInterrupt, tool.Cancelled):
            with self.subTest(error=error), mock.patch("builtins.input", side_effect=error):
                tool.cleanup_current(session.directory)
            self.assertTrue(session.directory.exists())

    def test_selective_history_cleanup_rejects_bad_indices(self):
        sessions = [self.session() for _ in range(3)]
        ordered = sorted((session.directory for session in sessions), reverse=True)
        with mock.patch("builtins.input", side_effect=["4", "0,1", "x", "1,3,1", "y"]):
            tool.cleanup_history(str(self.base))
        self.assertFalse(ordered[0].exists())
        self.assertTrue(ordered[1].exists())
        self.assertFalse(ordered[2].exists())
        self.assertIn("文件大小合计", self.output.getvalue())
        self.assertIn("已清理 2 个", self.output.getvalue())

    def test_all_requires_confirmation_and_defaults_to_no(self):
        sessions = [self.session(), self.session("failed")]
        with mock.patch("builtins.input", side_effect=["all", ""]):
            tool.cleanup_history(str(self.base))
        self.assertTrue(all(session.directory.exists() for session in sessions))
        with mock.patch("builtins.input", side_effect=["all", "y"]):
            tool.cleanup_history(str(self.base))
        self.assertTrue(all(not session.directory.exists() for session in sessions))

    def test_empty_or_missing_history_does_not_prompt_or_create_directory(self):
        with mock.patch("builtins.input") as prompt:
            tool.cleanup_history(str(self.base))
            tool.cleanup_history(str(self.base / "missing"))
        prompt.assert_not_called()
        self.assertFalse((self.base / "missing").exists())

    def test_running_unknown_invalid_and_symlink_directories_are_preserved(self):
        completed, running, no_report = self.session(), self.session("running"), self.session()
        (no_report.directory / "report.json").unlink()
        invalid = self.session()
        (invalid.directory / "session.json").write_text("[]")
        unknown = self.base / "other-project"
        unknown.mkdir()
        external = self.base / "external"
        external.mkdir()
        sentinel = external / "keep.txt"
        sentinel.write_text("keep")
        (completed.directory / "linked-data").symlink_to(external, target_is_directory=True)
        (completed.directory / "linked-file").symlink_to(sentinel)
        linked = self.base / "20260101T000000Z-symlink"
        linked.symlink_to(completed.directory, target_is_directory=True)
        with mock.patch("builtins.input", side_effect=["all", "y"]):
            tool.cleanup_history(str(self.base))
        self.assertFalse(completed.directory.exists())
        for directory in (running.directory, no_report.directory, invalid.directory, unknown, external):
            self.assertTrue(directory.exists())
        self.assertTrue(linked.is_symlink())
        self.assertEqual(sentinel.read_text(), "keep")

    def test_changed_report_is_rechecked_before_delete(self):
        session = self.session()
        def answer(_prompt):
            session.save("running")
            return "y"
        with mock.patch("builtins.input", side_effect=answer):
            tool.cleanup_current(session.directory)
        self.assertTrue(session.directory.exists())

    def test_deletion_failure_is_reported_and_remaining_selection_continues(self):
        first, second = self.session(), self.session()
        real_delete = tool.shutil.rmtree
        def remove(directory):
            if directory == first.directory:
                raise PermissionError("denied")
            real_delete(directory)
        with mock.patch.object(tool.shutil, "rmtree", side_effect=remove):
            tool.delete_results([first.directory, second.directory], self.base)
        self.assertTrue(first.directory.exists())
        self.assertFalse(second.directory.exists())
        self.assertIn("清理失败", self.output.getvalue())

    def test_session_failure_prompts_after_stop_and_summary_and_keeps_exit_code(self):
        session = self.session(interactive=True)
        def answer(_prompt):
            self.assertIsNone(session.process)
            self.assertEqual(tool.json.loads((session.directory / "report.json").read_text())["status"], "failed")
            self.assertIn("测试汇总", self.output.getvalue())
            return "y"
        answers = iter(["r", "r"])
        def input_answer(prompt):
            return answer(prompt) if "是否清理" in prompt else next(answers)
        with mock.patch.object(session, "attempt", side_effect=tool.ProbeError("模拟失败")), \
                mock.patch("builtins.input", side_effect=input_answer):
            self.assertEqual(session.run(), 1)
        self.assertFalse(session.directory.exists())

    def test_successful_session_cleanup_preserves_success_exit_code(self):
        session = self.session(interactive=True)
        result = dict(mbps=10, retransmits=None, rtt_ms=None, cv_percent=None,
                      rate_source="receiver")
        with mock.patch.object(session, "attempt", return_value=result), \
                mock.patch("builtins.input", return_value="y"):
            self.assertEqual(session.run(), 0)
        self.assertFalse(session.directory.exists())

    def test_terminal_cli_session_prompts_but_nonterminal_and_interrupt_do_not(self):
        for terminal, interrupted in ((True, False), (False, False), (True, True)):
            session = self.session()
            error = tool.Cancelled() if interrupted else tool.ProbeError("模拟失败")
            with self.subTest(terminal=terminal, interrupted=interrupted), \
                    mock.patch.object(session, "attempt", side_effect=error), \
                    mock.patch.object(tool.sys.stdin, "isatty", return_value=terminal), \
                    mock.patch.object(tool.sys.stdout, "isatty", return_value=terminal), \
                    mock.patch("builtins.input", return_value="") as prompt:
                self.assertEqual(session.run(), 130 if interrupted else 1)
            self.assertEqual(prompt.call_count, int(terminal and not interrupted))
            self.assertEqual(session.directory.exists(), not (terminal and not interrupted))

    def test_cleanup_cli_skips_dependencies_and_session_and_uses_custom_directory(self):
        with mock.patch.object(tool.sys, "platform", "linux"), \
                mock.patch.object(tool.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(tool.sys.stdout, "isatty", return_value=True), \
                mock.patch.object(tool, "install_signal_handlers"), \
                mock.patch.object(tool, "ensure_iperf3") as dependencies, \
                mock.patch.object(tool, "Session") as session, \
                mock.patch.object(tool, "cleanup_history") as cleanup:
            self.assertEqual(tool.main(["--cleanup", "--output-dir", str(self.base)]), 0)
        cleanup.assert_called_once_with(str(self.base))
        dependencies.assert_not_called()
        session.assert_not_called()

    def test_cleanup_cli_rejects_nonterminal_without_deleting(self):
        with mock.patch.object(tool.sys, "platform", "linux"), \
                mock.patch.object(tool.sys.stdin, "isatty", return_value=False), \
                mock.patch.object(tool, "install_signal_handlers"), \
                mock.patch.object(tool, "cleanup_history") as cleanup, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(tool.main(["--cleanup"]), 1)
        cleanup.assert_not_called()

    def test_menu_history_returns_to_start_menu_without_requesting_host(self):
        with mock.patch("builtins.input", side_effect=["2", "0"]) as prompt, \
                mock.patch.object(tool, "cleanup_history") as cleanup, \
                self.assertRaises(tool.Cancelled):
            tool.menu()
        cleanup.assert_called_once_with()
        self.assertEqual(prompt.call_count, 2)


if __name__ == "__main__":
    unittest.main()
