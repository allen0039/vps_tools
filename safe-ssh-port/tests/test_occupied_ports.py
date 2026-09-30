import shlex
import subprocess
import textwrap
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
            firewall_menu <<< $'12\\n0\\n'
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
