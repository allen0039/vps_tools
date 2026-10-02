import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("iperf_dependencies", ROOT / "iperf3_tool.py")
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.installed = False
        self.available = {"apt-get", "dnf", "yum", "zypper", "apk", "pacman", "sudo"}
        self.commands = []
        self.release = 'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu Linux"\n'
        patches = [mock.patch.object(tool.shutil, "which", side_effect=self.which),
                   mock.patch.object(tool.os, "geteuid", return_value=0),
                   mock.patch.object(tool.Path, "read_text", side_effect=lambda: self.release),
                   mock.patch.object(tool.subprocess, "run", side_effect=self.run_package),
                   contextlib.redirect_stdout(io.StringIO())]
        for patch in patches:
            patch.__enter__()
            self.addCleanup(patch.__exit__, None, None, None)

    def which(self, name):
        if name == "iperf3":
            return "/usr/bin/iperf3" if self.installed else None
        return "/usr/bin/" + name if name in self.available else None

    def run_package(self, command, **kwargs):
        self.commands.append((command, kwargs))
        if command[-1] == "iperf3":
            self.installed = True
        return subprocess.CompletedProcess(command, 0)

    def test_installed_dependency_never_uses_package_manager(self):
        self.installed = True
        tool.ensure_iperf3()
        self.assertEqual(self.commands, [])

    def test_ubuntu_preseeds_no_daemon_and_uses_sudo_for_every_step(self):
        with mock.patch.object(tool.os, "geteuid", return_value=1000):
            tool.ensure_iperf3()
        self.assertEqual([item[0] for item in self.commands], [
            ["sudo", "--", "apt-get", "update"],
            ["sudo", "--", "debconf-set-selections"],
            ["sudo", "--", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "iperf3"]])
        self.assertEqual(self.commands[1][1]["input"], "iperf3 iperf3/start_daemon boolean false\n")

    def test_native_manager_is_selected_even_when_apt_is_available(self):
        cases = [("rocky", "rhel centos", ["dnf", "install", "-y", "iperf3"]),
                 ("custom", "fedora", ["dnf", "install", "-y", "iperf3"]),
                 ("opensuse-leap", "suse", ["zypper", "--non-interactive", "install", "iperf3"]),
                 ("alpine", "", ["apk", "add", "--no-cache", "iperf3"]),
                 ("manjaro", "arch", ["pacman", "-S", "--needed", "--noconfirm", "iperf3"])]
        for identity, like, expected in cases:
            with self.subTest(identity=identity):
                self.installed = False
                self.commands.clear()
                self.release = 'ID={}\nID_LIKE="{}"\n'.format(identity, like)
                tool.ensure_iperf3()
                self.assertEqual([item[0] for item in self.commands], [expected])

    def test_old_rhel_falls_back_to_yum(self):
        self.release = "ID=centos\nID_LIKE=rhel\n"
        self.available.remove("dnf")
        tool.ensure_iperf3()
        self.assertEqual(self.commands[0][0], ["yum", "install", "-y", "iperf3"])

    def test_missing_os_release_falls_back_to_available_manager(self):
        self.available = {"apk"}
        with mock.patch.object(tool.Path, "read_text", side_effect=FileNotFoundError):
            tool.ensure_iperf3()
        self.assertEqual(self.commands[0][0], ["apk", "add", "--no-cache", "iperf3"])

    def test_no_privilege_or_manager_fails_without_installation(self):
        self.available.remove("sudo")
        with mock.patch.object(tool.os, "geteuid", return_value=1000), \
                self.assertRaisesRegex(tool.ProbeError, "root 或 sudo"):
            tool.ensure_iperf3()
        self.available.clear()
        with self.assertRaisesRegex(tool.ProbeError, "包管理器"):
            tool.ensure_iperf3()
        self.assertEqual(self.commands, [])

    def test_package_failure_stops_remaining_installation(self):
        with mock.patch.object(tool.subprocess, "run", return_value=subprocess.CompletedProcess([], 42)) as run, \
                self.assertRaisesRegex(tool.ProbeError, "退出码 42"):
            tool.ensure_iperf3()
        self.assertEqual(run.call_count, 1)

    def test_successful_package_command_must_provide_executable(self):
        with mock.patch.object(tool.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                self.assertRaisesRegex(tool.ProbeError, "仍未找到 iperf3"):
            tool.ensure_iperf3()

    def test_main_continues_into_session_after_installation(self):
        with mock.patch.object(tool.sys, "platform", "linux"), \
                mock.patch.object(tool, "install_signal_handlers"), \
                mock.patch.object(tool, "Session") as session:
            session.return_value.run.return_value = 0
            self.assertEqual(tool.main(["--host", "203.0.113.10"]), 0)
            self.assertTrue(self.installed)
            session.return_value.run.assert_called_once_with()

    def test_main_reports_installation_failure_without_starting_session(self):
        with mock.patch.object(tool.sys, "platform", "linux"), \
                mock.patch.object(tool, "ensure_iperf3", side_effect=tool.ProbeError("安装失败")), \
                mock.patch.object(tool, "Session") as session, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(tool.main(["--host", "203.0.113.10"]), 1)
            self.assertIn("安装失败", errors.getvalue())
            session.assert_not_called()

    def test_help_version_and_invalid_arguments_do_not_install(self):
        for argument in ("--help", "--version"):
            with self.assertRaises(SystemExit) as result:
                tool.main([argument])
            self.assertEqual(result.exception.code, 0)
        with mock.patch.object(tool.sys, "platform", "linux"), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(tool.main(["--host", "host;id"]), 1)
        self.assertEqual(self.commands, [])


class BootstrapTests(unittest.TestCase):
    def test_shell_installs_missing_python_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name, body in {
                "uname": "printf 'Linux\\n'",
                "sudo": 'shift; exec "$@"',
                "apt-get": 'printf "%s\\n" "$*" >> "$BOOT_LOG"; if [ "$1" = install ]; then touch "$BOOT_READY"; fi',
                "python3": 'if [ "$1" = -c ]; then test -f "$BOOT_READY"; else printf "%s\\n" "$@" >> "$BOOT_LOG"; fi',
            }.items():
                script = base / name
                script.write_text("#!/bin/bash\n" + body + "\n")
                script.chmod(0o755)
            env = dict(os.environ, PATH=str(base) + os.pathsep + os.environ["PATH"],
                       BOOT_LOG=str(base / "log"), BOOT_READY=str(base / "ready"))
            # 仅模拟 os-release；所有安装命令都由临时脚本截获。
            command = '''source() {
                if [[ $1 == /etc/os-release ]]; then ID=ubuntu; ID_LIKE=debian; PRETTY_NAME=Ubuntu;
                else builtin source "$@"; fi
            }
            source "$1" --host "example.com" --streams "1,4,8"
            '''
            result = subprocess.run(["bash", "-c", command, "test", str(ROOT / "iperf3-tool.sh")],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((base / "log").read_text().splitlines(),
                             ["update", "install -y python3", str(ROOT / "iperf3_tool.py"),
                              "--host", "example.com", "--streams", "1,4,8"])


if __name__ == "__main__":
    unittest.main()
