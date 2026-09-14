import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "safe-ssh-port" / "safe-ssh-port.sh"


class FirewallHistoryTest(unittest.TestCase):
    def run_bash(self, body: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", body],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )

    def test_bash_syntax(self):
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_open_protocol_defaults_to_tcp_udp_and_close_defaults_to_tcp(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            prompt_firewall_protocols open <<< ''
            [[ $SELECTED_PROTOCOLS == 'tcp udp' ]]
            prompt_firewall_protocols close <<< ''
            [[ $SELECTED_PROTOCOLS == tcp ]]
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("TCP + UDP（推荐）", result.stdout)
        self.assertIn("默认 3", result.stdout)
        self.assertIn("TCP（默认）", result.stdout)
        self.assertIn("默认 1", result.stdout)

    def test_firewall_records_group_tcp_and_udp_by_port(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            ufw() {{
                printf '%s\n' \
                    'Status: active' \
                    '48901/tcp ALLOW Anywhere' \
                    '48902/tcp ALLOW Anywhere' \
                    '48901/udp ALLOW Anywhere' \
                    '48902/udp ALLOW Anywhere'
            }}
            records=$(firewall_rule_records ufw)
            expected=$'IPv4 ACCEPT tcp 48901\nIPv4 ACCEPT udp 48901\nIPv4 ACCEPT tcp 48902\nIPv4 ACCEPT udp 48902'
            [[ $records == "$expected" ]]
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_firewall_overview_collapses_matching_families_and_keeps_single_stack(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            records=$(printf '%s\n' \
                'IPv6 ACCEPT udp 31122' \
                'IPv4 ACCEPT tcp 31122' \
                'IPv6 ACCEPT tcp 31122' \
                'IPv4 ACCEPT udp 31122' \
                'IPv4 ACCEPT tcp 8080' \
                'IPv6 ACCEPT tcp 8443' \
                '双栈 DROP tcp 9000' \
                'IPv4 DROP tcp 9000' | collapse_firewall_rule_families)
            expected=$'IPv4 ACCEPT tcp 8080\nIPv6 ACCEPT tcp 8443\n双栈 ACCEPT tcp 31122\n双栈 ACCEPT udp 31122\n双栈 DROP tcp 9000'
            [[ $records == "$expected" ]]
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_country_cidr_validation_uses_mawk_compatible_quantifiers(self):
        script = SCRIPT.read_text(encoding="utf-8")
        country_set_builder = script[
            script.index("build_country_temp_set()") : script.index(
                "rollback_activated_country_set()"
            )
        ]
        self.assertNotIn("{1,2}", country_set_builder)
        self.assertNotIn("{1,3}", country_set_builder)
        self.assertIn("[0-9][0-9]?", country_set_builder)
        self.assertIn("[0-9][0-9]?[0-9]?", country_set_builder)

    def test_country_cidr_validation_accepts_prefix_lengths_on_both_families(self):
        with tempfile.TemporaryDirectory() as directory:
            temp_dir = Path(directory)
            ipv4_file = temp_dir / "ipv4.zone"
            ipv6_file = temp_dir / "ipv6.zone"
            restored_file = temp_dir / "restored.txt"
            ipv4_file.write_text("1.0.0.0/8\n203.0.113.0/24\n", encoding="utf-8")
            ipv6_file.write_text("2001:db8::/9\n2001:db8:1::/128\n", encoding="utf-8")
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                restored_file={restored_file!s}
                ipset() {{
                    case "$1" in
                        create|destroy) return 0 ;;
                        restore) cat "$3" >> "$restored_file" ;;
                        *) return 1 ;;
                    esac
                }}
                build_country_temp_set {ipv4_file!s} 4 test_ipv4
                build_country_temp_set {ipv6_file!s} 6 test_ipv6
                expected=$'add test_ipv4 1.0.0.0/8\nadd test_ipv4 203.0.113.0/24\nadd test_ipv6 2001:db8::/9\nadd test_ipv6 2001:db8:1::/128'
                [[ $(cat "$restored_file") == "$expected" ]]
                """
            )
            result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_note_prompt_trims_blank_and_rejects_control_characters(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            prompt_firewall_note <<< '  游戏服务  '
            [[ $SELECTED_FIREWALL_NOTE == 游戏服务 ]]
            prompt_firewall_note <<< $'服务\tA\n中文备注'
            [[ $SELECTED_FIREWALL_NOTE == 中文备注 ]]
            too_long=$(printf '%081d' 0 | tr 0 a)
            note_inputs=$(printf '%s\n有效备注\n' "$too_long")
            prompt_firewall_note <<< "$note_inputs"
            [[ $SELECTED_FIREWALL_NOTE == 有效备注 ]]
            prompt_firewall_note <<< ''
            [[ -z $SELECTED_FIREWALL_NOTE ]]
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("备注不能包含控制字符", result.stdout)
        self.assertIn("备注不能超过 80 个字符", result.stdout)

    def test_notes_and_history_are_atomic_state_and_history_is_limited(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory) / "state"
            note_file = state_dir / "notes.tsv"
            history_file = state_dir / "history.tsv"
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                STATE_DIR={state_dir!s}
                FIREWALL_NOTE_FILE={note_file!s}
                FIREWALL_HISTORY_FILE={history_file!s}
                firewall_update_port_notes open 31122 'tcp udp' 游戏服务
                firewall_port_note 31122 tcp
                [[ $FIREWALL_LOOKED_UP_NOTE == 游戏服务 ]]
                firewall_port_note 31122 udp
                [[ $FIREWALL_LOOKED_UP_NOTE == 游戏服务 ]]
                firewall_update_port_notes close 31122 tcp
                ! firewall_port_note 31122 tcp
                firewall_port_note 31122 udp
                [[ $FIREWALL_LOOKED_UP_NOTE == 游戏服务 ]]
                for port in $(seq 1 21); do
                    firewall_record_operation success open "$port" tcp iptables "备注$port"
                done
                [[ $(wc -l < {history_file!s}) == 20 ]]
                state_mode=$(stat -c '%a' {state_dir!s} 2>/dev/null || stat -f '%Lp' {state_dir!s})
                note_mode=$(stat -c '%a' {note_file!s} 2>/dev/null || stat -f '%Lp' {note_file!s})
                history_mode=$(stat -c '%a' {history_file!s} 2>/dev/null || stat -f '%Lp' {history_file!s})
                [[ $state_mode == 700 ]]
                [[ $note_mode == 600 ]]
                [[ $history_mode == 600 ]]
                FIREWALL_LAST_RESULT=
                show_latest_firewall_operation
                show_firewall_operation_history <<< ''
                """
            )
            result = self.run_bash(body)
            restored = self.run_bash(
                textwrap.dedent(
                    f"""
                    source {SCRIPT!s}
                    STATE_DIR={state_dir!s}
                    FIREWALL_NOTE_FILE={note_file!s}
                    FIREWALL_HISTORY_FILE={history_file!s}
                    show_latest_firewall_operation
                    """
                )
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        self.assertIn("端口：21", result.stdout)
        self.assertIn("备注：备注21", result.stdout)
        self.assertNotIn("备注：备注1\n", result.stdout)
        self.assertIn("端口：21", restored.stdout)
        self.assertIn("备注：备注21", restored.stdout)

    def test_open_records_note_and_overview_shows_live_rule_note(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory) / "state"
            note_file = state_dir / "notes.tsv"
            history_file = state_dir / "history.tsv"
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                STATE_DIR={state_dir!s}
                FIREWALL_NOTE_FILE={note_file!s}
                FIREWALL_HISTORY_FILE={history_file!s}
                detect_firewall_backend() {{ printf 'ufw\\n'; }}
                ufw() {{ :; }}
                firewall_open_interactive <<< $'31122\\n\\n游戏服务\\n'
                firewall_port_note 31122 tcp
                [[ $FIREWALL_LOOKED_UP_NOTE == 游戏服务 ]]
                firewall_port_note 31122 udp
                [[ $FIREWALL_LOOKED_UP_NOTE == 游戏服务 ]]
                detect_firewall_backend() {{ printf 'iptables\\n'; }}
                protected_ssh_ports() {{ printf '22\\n'; }}
                firewall_rule_records() {{
                    printf '%s\\n' \
                        'IPv4 ACCEPT tcp 31122' \
                        'IPv6 ACCEPT tcp 31122' \
                        'IPv4 ACCEPT udp 31122' \
                        'IPv6 ACCEPT udp 31122'
                }}
                iptables() {{
                    case "$*" in
                        '-S INPUT') printf '%s\\n' '-P INPUT DROP' ;;
                        '-S ALLENTOOL_INPUT'|'-C INPUT -j ALLENTOOL_INPUT') return 0 ;;
                        *) return 2 ;;
                    esac
                }}
                ip6tables() {{ return 4; }}
                show_firewall_port_overview
                """
            )
            result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("准备开放：31122/tcp+udp，备注：游戏服务", result.stdout)
        self.assertIn("已开放端口 31122（tcp+udp）", result.stdout)
        self.assertEqual(result.stdout.count("备注：游戏服务"), 3)
        self.assertIn("双栈  31122/tcp", result.stdout)
        self.assertIn("双栈  31122/udp", result.stdout)

    def test_failed_open_is_recorded_without_creating_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory) / "state"
            note_file = state_dir / "notes.tsv"
            history_file = state_dir / "history.tsv"
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                STATE_DIR={state_dir!s}
                FIREWALL_NOTE_FILE={note_file!s}
                FIREWALL_HISTORY_FILE={history_file!s}
                detect_firewall_backend() {{ printf 'iptables\\n'; }}
                firewall_apply_port() {{ return 1; }}
                firewall_open_interactive <<< $'31122\\n\\n失败备注\\n'
                [[ ! -e {note_file!s} ]]
                show_latest_firewall_operation
                """
            )
            result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("结果：失败", result.stdout)
        self.assertIn("备注：失败备注", result.stdout)

    def test_backend_write_failure_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory) / "state"
            note_file = state_dir / "notes.tsv"
            history_file = state_dir / "history.tsv"
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                STATE_DIR={state_dir!s}
                FIREWALL_NOTE_FILE={note_file!s}
                FIREWALL_HISTORY_FILE={history_file!s}
                detect_firewall_backend() {{ printf 'ufw\\n'; }}
                ufw() {{
                    [[ $* == *'allow 31122/tcp'* ]] && return 1
                    return 0
                }}
                firewall_open_interactive <<< $'31122\\n1\\n失败备注\\n'
                [[ ! -e {note_file!s} ]]
                show_latest_firewall_operation
                """
            )
            result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("结果：失败", result.stdout)
        self.assertNotIn("已开放端口", result.stdout)


if __name__ == "__main__":
    unittest.main()
