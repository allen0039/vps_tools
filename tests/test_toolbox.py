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

    def run_menu(self, choices):
        self.mock("sudo", 'while [[ ${1:-} == --* ]]; do shift; done; exec "$@"')
        self.env["PATH"] = str(self.base) + os.pathsep + os.environ["PATH"]
        master, slave = pty.openpty()
        proc = subprocess.Popen(["bash", str(ROOT / "vpstools.sh")], env=self.env,
                                stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        output = b""
        try:
            os.write(master, choices.encode())
            deadline = time.monotonic() + 8
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
        return text

    def test_homepage_has_categories_and_fixed_maintenance_entries(self):
        text = self.run_menu("0\n")
        for label in ("1. 系统管理", "2. 网络检测与测速", "3. 网络调优",
                      "4. 服务管理", "5. 查看工具安装状态", "6. 安装 / 更新工具箱"):
            self.assertIn(label, text)
        self.assertNotIn("SSH 端口", text)
        self.assertNotIn("TCP 参数导入", text)

    def test_system_category_routes_all_tools_and_returns_after_failure(self):
        commands = ("safe-ssh-port", "sshkeytool", "sshpasswdtool", "f2btool",
                    "dnstool", "ipv6tool", "swaptool")
        for command in commands:
            self.mock(command, 'printf "CHILD ' + command + ' <%s>\\n" "$*"; exit 7')
        text = self.run_menu("1\n1\n2\n3\n4\n5\n6\n7\n8\n0\n0\n")
        for command in commands:
            self.assertIn("CHILD " + command, text)
        self.assertIn("CHILD safe-ssh-port <firewall>", text)
        self.assertGreaterEqual(text.count("VPS Tools > 系统管理"), 9)
        self.assertEqual(text.count("VPS Tools 工具箱"), 2)
        self.assertIn("SSH 与访问防护", text)
        self.assertIn("网络基础配置", text)
        self.assertIn("系统资源", text)

    def test_network_and_tuning_categories_route_and_return(self):
        for command in ("netcheck", "iperfprobe", "bbr-tune", "tcptool"):
            self.mock(command, "echo CHILD_" + command)
        text = self.run_menu("2\n1\n2\n0\n3\n1\n2\n0\n0\n")
        for command in ("netcheck", "iperfprobe", "bbr-tune", "tcptool"):
            self.assertIn("CHILD_" + command, text)
        self.assertEqual(text.count("VPS Tools > 网络检测与测速"), 3)
        self.assertEqual(text.count("VPS Tools > 网络调优"), 3)

    def test_service_restart_requires_confirmation_and_returns_to_category(self):
        self.mock("restart-mmw-agent", "echo AGENT_CHILD")
        text = self.run_menu("4\n1\n\n1\nn\n1\ny\n0\n0\n")
        self.assertEqual(text.count("AGENT_CHILD"), 1)
        self.assertEqual(text.count("VPS Tools > 服务管理"), 4)

    def test_missing_tools_and_invalid_choices_stay_in_category(self):
        text = self.run_menu("1\n6\n9\n01\n-1\nabc\n1+1\n0\n0\n")
        self.assertIn("DNS 设置与恢复 [未安装]", text)
        self.assertIn("请选择", text)
        self.assertIn("请返回主菜单", text)
        self.assertEqual(text.count("无效选项"), 5)
        self.assertEqual(text.count("VPS Tools 工具箱"), 2)

    def test_eof_in_category_exits_without_reopening_homepage(self):
        text = self.run_menu("1\n\x04")
        self.assertEqual(text.count("VPS Tools 工具箱"), 1)
        self.assertEqual(text.count("VPS Tools > 系统管理"), 1)

    def test_menu_update_relaunches_installed_entry_and_forwards_channel(self):
        self.mock("install.sh", 'printf "CHANNEL %s\\n" "$*"')
        self.mock("vpstools", 'printf "REOPENED %s\\n" "$*"')
        text = self.run_menu("6\n2\n")
        self.assertIn("CHANNEL --channel gitee", text)
        self.assertIn("REOPENED menu", text)

    def test_menu_update_failure_returns_home_and_status_does_not_launch_tools(self):
        self.mock("install.sh", "echo INSTALL_FAILED; exit 7")
        self.mock("dnstool", "echo DNS_MUST_NOT_RUN")
        text = self.run_menu("6\n1\n5\n0\n")
        self.assertIn("INSTALL_FAILED", text)
        self.assertIn("安装未完成", text)
        self.assertIn("已安装", text)
        self.assertNotIn("DNS_MUST_NOT_RUN", text)
        self.assertEqual(text.count("VPS Tools 工具箱"), 3)

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
                             ("system_tool", "install.sh"), ("tcp-tool", "install.sh"),
                             ("ssh-key", "install.sh"), ("ssh-password", "install.sh")]:
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
        self.assertIn("ssh-key ", result.stdout)
        self.assertIn("ssh-password ", result.stdout)

    def test_sshkey_dispatch_preserves_authentication_environment(self):
        self.mock("sshkeytool", 'printf "%s\\n" "$@" "$SSH_CONNECTION" "$SSH_USER_AUTH"; exit 17')
        self.env.update(SSH_CONNECTION="192.0.2.1 40000 192.0.2.2 21919", SSH_USER_AUTH="/tmp/auth-info")
        result = self.run_cli("run", "sshkey", "confirm", "a" * 32)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(result.stdout, "confirm\n" + "a" * 32 + "\n192.0.2.1 40000 192.0.2.2 21919\n/tmp/auth-info\n")
        self.assertIn("sshkey     已安装", self.run_cli("list").stdout)

    def test_temporary_password_dispatch_preserves_context_and_exit_status(self):
        self.mock("sshpasswdtool", 'printf "<%s>\\n" "$@" "$SSH_CONNECTION"; exit 17')
        self.env["SSH_CONNECTION"] = "2001:db8::1 12345 2001:db8::2 21919"
        for name in ("sshpass", "sshpasswdtool"):
            result = self.run_cli("run", name, "enable", "--minutes", "30", "--yes")
            self.assertEqual(result.returncode, 17)
            self.assertEqual(result.stdout, "<enable>\n<--minutes>\n<30>\n<--yes>\n"
                             "<2001:db8::1 12345 2001:db8::2 21919>\n")


if __name__ == "__main__":
    unittest.main()
