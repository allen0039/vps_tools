import os
import select
import shlex
import subprocess
import textwrap
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "safe-ssh-port.sh"


class OccupiedPortsTest(unittest.TestCase):
    def run_bash(self, body: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", f"source {shlex.quote(str(SCRIPT))}\n{body}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def test_menu_lists_tcp_udp_loopback_ipv6_and_processes(self):
        result = self.run_bash(textwrap.dedent("""
            SS_BIN=mock_ss
            mock_ss() {
                case "$*" in
                    '-H -ltnp') cat <<'EOF'
LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=83,fd=7))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=10,fd=3))
LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=10,fd=4))
EOF
                        ;;
                    '-H -lunp') cat <<'EOF'
UNCONN 0 0 [::1]:5353 [::]:* users:(("mdns",pid=40,fd=5))
UNCONN 0 0 0.0.0.0:22 0.0.0.0:*
EOF
                        ;;
                    *) return 1 ;;
                esac
            }
            prepare_iptables_for_firewall_menu() { :; }
            show_firewall_port_overview() { :; }
            show_access_control_overview() { :; }
            show_latest_firewall_operation() { :; }
            firewall_menu <<< $'12\\n\\n0\\n'
        """))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("12. 查看已占用端口", result.stdout)
        self.assertIn("请选择 [0-12]", result.stdout)
        self.assertIn("22/tcp", result.stdout)
        self.assertIn("22/udp", result.stdout)
        self.assertIn("127.0.0.1", result.stdout)
        self.assertIn("::1", result.stdout)
        self.assertIn("postgres (PID 83)", result.stdout)
        self.assertIn("sshd (PID 10)", result.stdout)
        self.assertIn("未知", result.stdout)
        self.assertLess(result.stdout.index("22/tcp"), result.stdout.index("5432/tcp"))

    def test_results_stay_visible_until_enter_then_menu_returns(self):
        body = textwrap.dedent("""
            SS_BIN=mock_ss
            mock_ss() { printf 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\\n'; }
            prepare_iptables_for_firewall_menu() { :; }
            show_firewall_port_overview() { :; }
            show_access_control_overview() { :; }
            show_latest_firewall_operation() { :; }
            firewall_menu
        """)
        process = subprocess.Popen(
            ["bash", "-c", f"source {shlex.quote(str(SCRIPT))}\n{body}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            process.stdin.write(b"12\n")
            process.stdin.flush()
            output = bytearray()
            deadline = time.monotonic() + 5
            prompt = "按回车返回防火墙菜单...".encode()
            while prompt not in output and time.monotonic() < deadline:
                if select.select([process.stdout], [], [], 0.1)[0]:
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    output.extend(chunk)
            self.assertIn(prompt, output)
            self.assertIn(b"22/tcp", output)
            self.assertEqual(output.count("请选择 [0-12]".encode()), 1)
            self.assertIsNone(process.poll())
            remaining, stderr = process.communicate(b"\n0\n", timeout=5)
            output.extend(remaining)
            self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertEqual(output.count("请选择 [0-12]".encode()), 2)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()

    def test_empty_and_failed_reads_can_return_to_menu(self):
        for command, expected in (
            (":", "未发现 TCP/UDP 监听端口"),
            ("return 1", "无法读取监听端口"),
        ):
            with self.subTest(command=command):
                result = self.run_bash(textwrap.dedent(f"""
                    SS_BIN=mock_ss
                    mock_ss() {{ {command}; }}
                    prepare_iptables_for_firewall_menu() {{ :; }}
                    show_firewall_port_overview() {{ :; }}
                    show_access_control_overview() {{ :; }}
                    show_latest_firewall_operation() {{ :; }}
                    firewall_menu <<< $'12\\n\\n0\\n'
                """))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(expected, result.stdout + result.stderr)
                self.assertIn("按回车返回防火墙菜单...", result.stdout)
                self.assertEqual(result.stdout.count("请选择 [0-12]"), 2)

    def test_read_failure_does_not_claim_no_ports(self):
        result = self.run_bash(textwrap.dedent("""
            SS_BIN=mock_ss
            mock_ss() { return 1; }
            show_occupied_ports
        """))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("无法读取监听端口", result.stderr)
        self.assertNotIn("未发现 TCP/UDP", result.stdout)


if __name__ == "__main__":
    unittest.main()
