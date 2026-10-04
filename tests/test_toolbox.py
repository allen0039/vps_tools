import os
import pathlib
import pty
import select
import subprocess
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ToolboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.env = dict(os.environ, VPS_TOOLS_BIN_DIR=str(self.base),
                        VPS_TOOLS_SBIN_DIR=str(self.base), VPS_TOOLS_LIB_DIR=str(self.base))

    def run_cli(self, *args):
        return subprocess.run(["bash", str(ROOT / "vpstools.sh"), *args],
                              env=self.env, cwd="/tmp", text=True, capture_output=True)

    def mock(self, name, body):
        path = self.base / name
        path.write_text("#!/usr/bin/env bash\n" + body + "\n")
        path.chmod(0o755)

    def test_forward_arguments_without_shell_expansion(self):
        self.mock("dnstool", "printf '<%s>\\n' \"$@\"")
        result = self.run_cli("run", "dns", "set", "custom", "$(touch nope)", "two words")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "<set>\n<custom>\n<$(touch nope)>\n<two words>\n")

    def test_firewall_dispatch_and_child_exit_status(self):
        self.mock("safe-ssh-port", "printf '%s\\n' \"$@\"; exit 17")
        result = self.run_cli("run", "firewall")
        self.assertEqual(result.stdout, "firewall\n")
        self.assertEqual(result.returncode, 17)

    def test_netcheck_dispatch_and_exit_status(self):
        self.mock("netcheck", "printf '%s\\n' \"$@\"; exit 1")
        result = self.run_cli("run", "netcheck", "check", "example.com", "--json")
        self.assertEqual(result.stdout, "check\nexample.com\n--json\n")
        self.assertEqual(result.returncode, 1)

    def test_iperf_dispatch_preserves_arguments_and_status(self):
        self.mock("iperfprobe", "printf '%s\\n' \"$@\"; exit 130")
        result = self.run_cli("run", "iperf", "--host", "2001:db8::1", "--streams", "1,4,8")
        self.assertEqual(result.stdout, "--host\n2001:db8::1\n--streams\n1,4,8\n")
        self.assertEqual(result.returncode, 130)

    def test_fail2ban_dispatch_preserves_ip_and_exit_status(self):
        self.mock("f2btool", "printf '%s\\n' \"$@\"; exit 17")
        result = self.run_cli("run", "fail2ban", "unban", "2001:db8::1")
        self.assertEqual(result.stdout, "unban\n2001:db8::1\n")
        self.assertEqual(result.returncode, 17)

    def test_tcp_dispatch_preserves_arguments_and_exit_status(self):
        self.mock("tcptool", 'printf "<%s>\\n" "$@"; exit 17')
        for name in ("tcp", "tcptool"):
            result = self.run_cli("run", name, "apply", "two words.conf", "--yes")
            self.assertEqual(result.stdout, "<apply>\n<two words.conf>\n<--yes>\n")
            self.assertEqual(result.returncode, 17)
        self.assertIn("tcp        已安装", self.run_cli("list").stdout)

    def test_missing_tool_and_unknown_command(self):
        self.assertEqual(self.run_cli("run", "dns").returncode, 1)
        self.assertEqual(self.run_cli("run", "unknown").returncode, 2)
        self.assertEqual(self.run_cli("bogus").returncode, 2)
        self.assertEqual(self.run_cli("update", "bogus").returncode, 2)

    def test_ipv6_dispatch_preserves_arguments_environment_and_status(self):
        self.mock("ipv6tool", 'printf "%s\\n" "$@" "$SSH_CONNECTION"; exit 17')
        self.env["SSH_CONNECTION"] = "2001:db8::1 12345 2001:db8::2 22"
        result = self.run_cli("run", "ipv6", "priority", "ipv4")
        self.assertEqual(result.stdout, "priority\nipv4\n2001:db8::1 12345 2001:db8::2 22\n")
        self.assertEqual(result.returncode, 17)

    def test_ipv6_installation_status(self):
        self.assertIn("ipv6       未安装", self.run_cli("list").stdout)
        self.mock("ipv6tool", "exit 99")
        self.assertIn("ipv6       已安装", self.run_cli("list").stdout)

    def test_list_does_not_launch_tools(self):
        self.mock("dnstool", "exit 99")
        result = self.run_cli("list")
        self.assertEqual(result.returncode, 0)
        self.assertIn("已安装", result.stdout)
        self.assertIn("未安装", result.stdout)

    def test_noninteractive_menu_does_not_hang(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertIn("交互终端", result.stderr)

    def test_installed_entry_works_outside_repository(self):
        installed = self.base / "vpstools"
        installed.write_bytes((ROOT / "vpstools.sh").read_bytes())
        installed.chmod(0o755)
        result = subprocess.run([str(installed), "--help"], cwd="/tmp", env=self.env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vpstools run", result.stdout)

    def test_update_calls_saved_installer_with_selected_channel(self):
        self.mock("install.sh", 'printf "INSTALL_ARGS <%s>\\n" "$@"')
        self.mock("sudo", '[[ ${1:-} != -- ]] || shift; exec "$@"')
        self.env["PATH"] = str(self.base) + os.pathsep + os.environ["PATH"]
        result = self.run_cli("update", "gitee")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "INSTALL_ARGS <--channel>\nINSTALL_ARGS <gitee>\n")

    def test_menu_returns_after_child_failure_and_agent_requires_confirmation(self):
        self.mock("dnstool", "echo DNS_CHILD_FAILED; exit 7")
        self.mock("restart-mmw-agent", "echo AGENT_MUST_NOT_RUN")
        self.mock("ipv6tool", "echo IPV6_CHILD; exit 7")
        self.mock("tcptool", "echo TCP_CHILD; exit 7")
        self.mock("sudo", '[[ ${1:-} != -- ]] || shift; exec "$@"')
        self.env["PATH"] = str(self.base) + os.pathsep + os.environ["PATH"]
        master, slave = pty.openpty()
        proc = subprocess.Popen(["bash", str(ROOT / "vpstools.sh")], env=self.env,
                                stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        output = b""
        try:
            os.write(master, b"3\n6\nn\n7\n11\n12\n0\n")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        output += os.read(master, 65536)
                    except OSError:
                        break
                elif proc.poll() is not None:
                    break
            proc.wait(timeout=2)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)
        text = output.decode()
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn("DNS_CHILD_FAILED", text)
        self.assertIn("IPV6_CHILD", text)
        self.assertIn("TCP_CHILD", text)
        self.assertIn("13. 安装 / 更新全部工具", text)
        self.assertGreaterEqual(text.count("VPS Tools 工具箱"), 4)
        self.assertNotIn("AGENT_MUST_NOT_RUN", text)

    def test_local_bundle_stages_every_required_file(self):
        result = subprocess.run(["bash", "-c", 'source "$1/install.sh"; prepare_sources; '
                                 'for f in "${FILES[@]}"; do test -s "$STAGE/$f" || exit 9; done',
                                 "test", str(ROOT)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("本地", result.stdout)

    def test_bad_remote_payload_rejected_before_install(self):
        # 不联网，不调用系统安装器：模拟有效提交信息和被替换为 HTML 的下载文件。
        result = subprocess.run(["bash", "-c", '''
source "$1/install.sh"
SOURCE_DIR="$2"
download() {
    if [[ $1 == *commits/main* ]]; then
        printf '{"sha":"0123456789012345678901234567890123456789"}' > "$2"
    else
        printf '<html>error</html>' > "$2"
    fi
}
prepare_sources
printf INSTALL_MUST_NOT_START
''', "test", str(ROOT), str(self.base)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("不是 Bash", result.stderr)
        self.assertNotIn("INSTALL_MUST_NOT_START", result.stdout)

    def test_install_only_uses_bbr_installer_and_never_runs_swap_or_agent(self):
        for folder, file in [("safe-ssh-port", "safe-ssh-port.sh"),
                             ("dns_tool", "dns_tool.sh"), ("bbr-tune", "install.sh"),
                             ("system_tool", "install.sh"), ("tcp-tool", "install.sh")]:
            path = self.base / folder / file
            path.parent.mkdir()
            path.write_text('#!/usr/bin/env bash\nprintf "%s %s\\n" "' + folder + '" "$*"\n')
        # 拦截 install，避免写入系统；其余文件只作为部署来源，绝不能执行。
        result = subprocess.run(["bash", "-c", '''
source "$1/install.sh"
STAGE="$2"
install() { printf 'COPY %s\\n' "$*"; }
install_tools
''', "test", str(ROOT), str(self.base)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bbr-tune --install-only", result.stdout)
        self.assertIn("safe-ssh-port install", result.stdout)
        self.assertIn("dns_tool install", result.stdout)
        self.assertIn("/usr/local/bin/vpstools", result.stdout)
        self.assertIn("/usr/local/bin/iperfprobe", result.stdout)
        self.assertIn("/usr/local/sbin/f2btool", result.stdout)
        self.assertIn("system_tool ", result.stdout)
        self.assertIn("tcp-tool ", result.stdout)


if __name__ == "__main__":
    unittest.main()
