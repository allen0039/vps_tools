import json
import shlex
import subprocess
import sys
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

    def test_open_and_close_protocols_default_to_tcp_udp(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            prompt_firewall_protocols open <<< ''
            [[ $SELECTED_PROTOCOLS == 'tcp udp' ]]
            prompt_firewall_protocols close <<< ''
            [[ $SELECTED_PROTOCOLS == 'tcp udp' ]]
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("TCP + UDP（推荐）", result.stdout)
        self.assertIn("默认 3", result.stdout)
        self.assertIn("TCP + UDP（默认）", result.stdout)
        self.assertEqual(result.stdout.count("默认 3"), 2)

    def test_close_listening_port_reads_confirmation_from_user_once(self):
        cases = [
            ("tcp 1234", "1", "tcp", "tcp"),
            ("udp 1234", "2", "udp", "udp"),
            ("tcp 1234\nudp 1234\ntcp 9999", "", "tcp udp", "tcp+udp"),
        ]
        for listeners, choice, protocols, label in cases:
            with self.subTest(protocols=protocols), tempfile.TemporaryDirectory() as directory:
                inputs = f"1234\n{choice}\ny\n"
                body = textwrap.dedent(
                    f"""
                    source {SCRIPT!s}
                    STATE_DIR={directory!s}
                    FIREWALL_NOTE_FILE=$STATE_DIR/notes.tsv
                    FIREWALL_HISTORY_FILE=$STATE_DIR/history.tsv
                    protected_ssh_ports() {{ printf '22\\n'; }}
                    public_listeners() {{ printf '%s\\n' {shlex.quote(listeners)}; }}
                    detect_firewall_backend() {{ printf 'iptables\\n'; }}
                    firewall_apply_port() {{ printf 'APPLIED %s %s %s\\n' "$1" "$2" "$3"; }}
                    firewall_update_port_notes open 1234 'tcp udp' service
                    firewall_close_interactive <<< {shlex.quote(inputs)}
                    firewall_load_latest_operation
                    [[ $FIREWALL_LAST_RESULT == success && $FIREWALL_LAST_ACTION == close ]]
                    [[ $FIREWALL_LAST_PROTOCOLS == '{protocols}' ]]
                    for protocol in {protocols}; do
                        ! firewall_port_note 1234 "$protocol"
                    done
                    """
                )
                result = self.run_bash(body)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"APPLIED close 1234 {protocols}", result.stdout)
            self.assertIn(f"端口 1234/{label} 当前正在公网监听", result.stdout)
            self.assertEqual(result.stdout.count("仍要关闭吗？"), 1)
            self.assertNotIn("请输入 y、n", result.stdout)

    def test_declining_close_listener_confirmation_does_not_apply_rules(self):
        for confirmation in ("n", "", None):
            with self.subTest(confirmation=confirmation), tempfile.TemporaryDirectory() as directory:
                inputs = "1234\n\n" + (f"{confirmation}\n" if confirmation is not None else "")
                body = textwrap.dedent(
                    f"""
                    source {SCRIPT!s}
                    STATE_DIR={directory!s}
                    FIREWALL_NOTE_FILE=$STATE_DIR/notes.tsv
                    FIREWALL_HISTORY_FILE=$STATE_DIR/history.tsv
                    protected_ssh_ports() {{ printf '22\\n'; }}
                    public_listeners() {{ printf 'tcp 1234\\nudp 1234\\n'; }}
                    firewall_apply_port() {{ printf 'UNEXPECTED\\n'; }}
                    firewall_update_port_notes open 1234 'tcp udp' service
                    firewall_close_interactive < <(printf '%s' {shlex.quote(inputs)})
                    [[ ! -e $FIREWALL_HISTORY_FILE ]]
                    firewall_port_note 1234 tcp
                    [[ $FIREWALL_LOOKED_UP_NOTE == service ]]
                    firewall_port_note 1234 udp
                    [[ $FIREWALL_LOOKED_UP_NOTE == service ]]
                    """
                )
                result = self.run_bash(body)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("已取消关闭端口 1234", result.stdout)
            self.assertNotIn("UNEXPECTED", result.stdout)

    def test_close_current_ssh_port_is_still_refused(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            protected_ssh_ports() {{ printf '1234\\n'; }}
            public_listeners() {{ printf 'UNEXPECTED\\n'; }}
            firewall_apply_port() {{ printf 'UNEXPECTED\\n'; }}
            firewall_close_interactive <<< $'1234\\n\\ny\\n'
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("是当前 SSH 端口，拒绝关闭", result.stderr)
        self.assertNotIn("UNEXPECTED", result.stdout)

    def test_iptables_close_precedes_managed_allow_and_open_removes_deny(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = Path(directory) / "calls"
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                iptables_target_chain() {{ printf 'ALLENTOOL_INPUT\\n'; }}
                iptables_remove_tagged_rule() {{ printf 'remove %s %s %s %s\\n' "$1" "$2" "$4" "$5" >> {calls!s}; }}
                iptables_remove_lockdown_allow_rule() {{ printf 'remove-lockdown %s %s\\n' "$1" "$4" >> {calls!s}; }}
                persist_iptables_rules() {{ :; }}
                iptables() {{ printf 'iptables %s\\n' "$*" >> {calls!s}; }}
                ip6tables() {{ printf 'ip6tables %s\\n' "$*" >> {calls!s}; }}
                iptables_apply_tagged_port close 31122 'tcp udp'
                iptables_apply_tagged_port open 31122 tcp
                """
            )
            result = self.run_bash(body)
            lines = calls.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("iptables -I INPUT 1 -p tcp --dport 31122 -m comment --comment allentool-managed -j DROP", lines)
        self.assertIn("ip6tables -I INPUT 1 -p udp --dport 31122 -m comment --comment allentool-managed -j DROP", lines)
        self.assertIn("remove iptables INPUT 31122 DROP", lines)
        self.assertIn("iptables -I ALLENTOOL_INPUT 1 -p tcp --dport 31122 -m comment --comment allentool-managed -j ACCEPT", lines)

    def test_ufw_close_inserts_deny_before_broad_allow(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            detect_firewall_backend() {{ printf 'ufw\\n'; }}
            ufw() {{ printf 'ufw %s\\n' "$*"; }}
            firewall_apply_port close 31122 'tcp udp'
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ufw insert 1 deny 31122/tcp", result.stdout)
        self.assertIn("ufw insert 1 deny 31122/udp", result.stdout)

    def test_iptables_overview_includes_input_deny_with_managed_chain(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            iptables() {{
                case "$*" in
                    '-S INPUT') printf '%s\\n' '-A INPUT -p tcp --dport 31122 -j DROP' '-A INPUT -j ALLENTOOL_INPUT' ;;
                    '-S ALLENTOOL_INPUT') printf '%s\\n' '-A ALLENTOOL_INPUT -p udp --dport 31122 -j ACCEPT' ;;
                    '-C INPUT -j ALLENTOOL_INPUT') return 0 ;;
                esac
            }}
            iptables_rule_records_for_command iptables IPv4
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("IPv4 DROP tcp 31122", result.stdout)
        self.assertIn("IPv4 ACCEPT udp 31122", result.stdout)

    def test_iptables_port_status_follows_rule_order_and_managed_jump(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            iptables() {{
                case "$*" in
                    '-S INPUT') printf '%s\\n' \
                        '-A INPUT -p tcp --dport 1234 -j DROP' \
                        '-A INPUT -p tcp --dport 2222 -j ACCEPT' \
                        '-A INPUT -p tcp --dport 2222 -j REJECT' \
                        '-A INPUT -j ALLENTOOL_INPUT' \
                        '-A INPUT -p tcp --dport 54040 -j ACCEPT' ;;
                    '-S ALLENTOOL_INPUT') printf '%s\\n' \
                        '-A ALLENTOOL_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' \
                        '-A ALLENTOOL_INPUT -i lo -j ACCEPT' \
                        '-A ALLENTOOL_INPUT -s 192.0.2.1/32 -p tcp --dport 9000 -j ACCEPT' \
                        '-A ALLENTOOL_INPUT -p tcp --dport 1234 -j ACCEPT' \
                        '-A ALLENTOOL_INPUT -p tcp --dport 8080 -j ACCEPT' \
                        '-A ALLENTOOL_INPUT -p tcp --dport 9000 -j REJECT --reject-with tcp-reset' \
                        '-A ALLENTOOL_INPUT -j DROP' \
                        '-A ALLENTOOL_INPUT -p tcp --dport 8443 -j ACCEPT' ;;
                    '-C INPUT -j ALLENTOOL_INPUT') return 0 ;;
                esac
            }}
            iptables_rule_records_for_command iptables IPv4 | sort -k4,4n
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "IPv4 DROP tcp 1234",
                "IPv4 ACCEPT tcp 2222",
                "IPv4 ACCEPT tcp 8080",
                "IPv4 REJECT tcp 9000",
            ],
        )

    def test_iptables_broad_allow_hides_later_explicit_deny(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            iptables() {{
                case "$*" in
                    '-S INPUT') printf '%s\\n' \
                        '-A INPUT -p tcp -m comment --comment "allow all tcp" -j ACCEPT' \
                        '-A INPUT -p tcp --dport 1234 -j DROP' \
                        '-A INPUT -p udp --dport 1234 -j DROP' ;;
                    *) return 1 ;;
                esac
            }}
            iptables_rule_records_for_command iptables IPv4
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "IPv4 DROP udp 1234")

    def test_close_then_reopen_replaces_state_on_both_families(self):
        fixture = Path(__file__).parent / "fixtures" / "iptables.py"
        rule = ["-p", "tcp", "--dport", "1234", "-m", "comment", "--comment", "allentool-managed", "-j", "ACCEPT"]
        state = {
            "INPUT": [rule, ["-j", "ALLENTOOL_INPUT"]],
            "ALLENTOOL_INPUT": [
                ["-p", "tcp", "--dport", "1234", "-j", "ACCEPT"],
                ["-p", "udp", "--dport", "1234", "-j", "ACCEPT"],
                ["-j", "DROP"],
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            temp_dir = Path(directory)
            for name in ("ipv4", "ipv6"):
                (temp_dir / name).write_text(json.dumps(state))
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                STATE_DIR={temp_dir!s}
                FIREWALL_NOTE_FILE=$STATE_DIR/notes.tsv
                detect_firewall_backend() {{ printf 'iptables\\n'; }}
                protected_ssh_ports() {{ printf '22\\n'; }}
                persist_iptables_rules() {{ :; }}
                iptables() {{ {shlex.quote(sys.executable)} {shlex.quote(str(fixture))} {temp_dir!s}/ipv4 "$@"; }}
                ip6tables() {{ {shlex.quote(sys.executable)} {shlex.quote(str(fixture))} {temp_dir!s}/ipv6 "$@"; }}
                firewall_apply_port close 1234 'tcp udp'
                show_firewall_port_overview > {temp_dir!s}/closed
                firewall_apply_port open 1234 'tcp udp'
                firewall_apply_port open 1234 'tcp udp'
                show_firewall_port_overview > {temp_dir!s}/opened
                firewall_apply_port close 1234 tcp
                show_firewall_port_overview > {temp_dir!s}/mixed
                """
            )
            result = self.run_bash(body)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            closed = (temp_dir / "closed").read_text()
            opened = (temp_dir / "opened").read_text()
            mixed = (temp_dir / "mixed").read_text()
            final_states = [json.loads((temp_dir / name).read_text()) for name in ("ipv4", "ipv6")]
        for overview in (closed, opened, mixed):
            self.assertEqual(overview.count("1234/tcp"), 1)
            self.assertEqual(overview.count("1234/udp"), 1)
        closed_allow, closed_deny = closed.split("明确关闭的端口：")
        opened_allow, opened_deny = opened.split("明确关闭的端口：")
        mixed_allow, mixed_deny = mixed.split("明确关闭的端口：")
        self.assertNotIn("1234/", closed_allow)
        self.assertIn("双栈  1234/tcp", closed_deny)
        self.assertIn("双栈  1234/udp", closed_deny)
        self.assertIn("双栈  1234/tcp", opened_allow)
        self.assertIn("双栈  1234/udp", opened_allow)
        self.assertNotIn("1234/", opened_deny)
        self.assertIn("1234/udp", mixed_allow)
        self.assertNotIn("1234/tcp", mixed_allow)
        self.assertIn("1234/tcp", mixed_deny)
        self.assertNotIn("1234/udp", mixed_deny)
        for final_state in final_states:
            self.assertNotIn(rule, final_state["INPUT"])
            self.assertEqual(len(final_state["INPUT"]), 2)
            self.assertEqual(len(final_state["ALLENTOOL_INPUT"]), 2)

    def test_iptables_allow_all_removes_managed_deny_without_bypassing_source_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = Path(directory) / "calls"
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                iptables_target_chain() {{ printf 'ALLENTOOL_INPUT\\n'; }}
                iptables_remove_tagged_rule() {{ printf 'remove %s %s %s %s\\n' "$1" "$2" "$4" "$5" >> {calls!s}; }}
                persist_iptables_rules() {{ :; }}
                iptables() {{
                    case "$*" in
                        '-S INPUT') printf '%s\\n' '-A INPUT -p tcp --dport 31122 -m comment --comment "allentool-managed" -j DROP' ;;
                        *'-C '*|'-C '*) return 1 ;;
                        *) printf 'iptables %s\\n' "$*" >> {calls!s} ;;
                    esac
                }}
                ip6tables() {{
                    case "$*" in
                        *'-C '*|'-C '*) return 1 ;;
                        *) printf 'ip6tables %s\\n' "$*" >> {calls!s} ;;
                    esac
                }}
                iptables_apply_allow_all
                """
            )
            result = self.run_bash(body)
            lines = calls.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("remove iptables INPUT 31122 DROP", lines)
        self.assertIn("iptables -I ALLENTOOL_INPUT 1 -m comment --comment allentool-managed-allow-all -j ACCEPT", lines)
        self.assertFalse(any("-I INPUT" in line for line in lines))

    def test_firewalld_close_uses_higher_priority_than_allow_all(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            detect_firewall_backend() {{ printf 'firewalld\\n'; }}
            firewall-cmd() {{ printf 'firewall-cmd %s\\n' "$*"; }}
            firewall_apply_port close 31122 tcp
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('priority="-101" port port="31122" protocol="tcp" drop', result.stdout)

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

    def test_ufw_conflicting_port_rules_show_the_first_verdict(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            ufw() {{
                printf '%s\\n' \
                    '1234/tcp DENY Anywhere' \
                    '1234/tcp ALLOW Anywhere' \
                    '1234/tcp (v6) ALLOW Anywhere (v6)' \
                    '1234/tcp (v6) DENY Anywhere (v6)'
            }}
            records=$(firewall_rule_records ufw)
            collapse_firewall_rule_families <<< "$records"
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["IPv6 ACCEPT tcp 1234", "IPv4 DROP tcp 1234"],
        )

    def test_firewalld_port_deny_priority_and_family_override_allow(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            firewall-cmd() {{
                case "$*" in
                    --list-ports) printf '1234/tcp 8080/udp\\n' ;;
                    --list-rich-rules) printf '%s\\n' \
                        'rule family="ipv4" priority="-101" port port="1234" protocol="tcp" drop' \
                        'rule priority="1" port port="8080" protocol="udp" drop' \
                        'rule port port="9000" protocol="tcp" reject' \
                        'rule source address="192.0.2.1" port port="8080" protocol="udp" drop' ;;
                esac
            }}
            records=$(firewall_rule_records firewalld)
            collapse_firewall_rule_families <<< "$records"
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "IPv6 ACCEPT tcp 1234",
                "双栈 ACCEPT udp 8080",
                "IPv4 DROP tcp 1234",
                "双栈 DROP tcp 9000",
            ],
        )

    def test_ufw_broad_allow_hides_stale_deny_but_keeps_earlier_explicit_deny(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            ufw() {{
                printf '%s\\n' \
                    '9000/tcp DENY IN Anywhere' \
                    'Anywhere ALLOW IN Anywhere' \
                    '1234/tcp DENY Anywhere' \
                    '1234/udp DENY Anywhere' \
                    '1234/tcp (v6) DENY 2001:db8::1' \
                    '1234/tcp (v6) ALLOW Anywhere (v6)'
            }}
            firewall_rule_records ufw
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["IPv4 DROP tcp 9000", "IPv6 ACCEPT tcp 1234"],
        )

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

    def test_allow_all_requires_yes_and_records_success(self):
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
                firewall_apply_allow_all() {{ return 0; }}
                firewall_allow_all_interactive <<< $'yes\\n'
                [[ $(tail -n 1 {history_file!s}) == *$'\\tallow-all\\tall\\ttcp udp\\tufw\\t'* ]]
                """
            )
            result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("已放行所有 IPv4/IPv6 入站端口", result.stdout)

    def test_allow_all_cancel_does_not_apply_backend(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            firewall_apply_allow_all() {{ printf 'unexpected\\n'; return 1; }}
            firewall_allow_all_interactive <<< $'no\\n'
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("已取消", result.stdout)
        self.assertNotIn("unexpected", result.stdout)

    def test_ssh_only_records_lockdown_and_preserved_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            history_file = Path(directory) / "history.tsv"
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                STATE_DIR={directory!s}
                FIREWALL_HISTORY_FILE={history_file!s}
                detect_firewall_backend() {{ printf 'iptables\\n'; }}
                protected_ssh_ports() {{ printf '21919\\n'; }}
                build_lockdown_chain() {{ :; }}
                persist_iptables_rules() {{ :; }}
                iptables() {{ :; }}
                ip6tables() {{ :; }}
                firewall_lockdown_interactive ssh <<< 'y'
                show_latest_firewall_operation
                """
            )
            result = self.run_bash(body)
            self.assertTrue(history_file.exists(), result.stdout + result.stderr)
            history = history_file.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("\tsuccess\tssh-only\tother\ttcp udp\tiptables\t保留：21919/tcp", history)
        self.assertIn("操作：仅保留 SSH 入站", result.stdout)
        self.assertIn("备注：保留：21919/tcp", result.stdout)

    def test_lockdown_failure_records_partial_application(self):
        with tempfile.TemporaryDirectory() as directory:
            history_file = Path(directory) / "history.tsv"
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                STATE_DIR={directory!s}
                FIREWALL_HISTORY_FILE={history_file!s}
                detect_firewall_backend() {{ printf 'iptables\\n'; }}
                protected_ssh_ports() {{ printf '21919\\n'; }}
                public_listeners() {{ printf 'tcp 8080\\n'; }}
                build_lockdown_chain() {{ [[ $1 != ip6tables ]]; }}
                persist_iptables_rules() {{ :; }}
                iptables() {{ :; }}
                ip6tables() {{ :; }}
                firewall_lockdown_interactive listeners <<< 'y' || true
                show_latest_firewall_operation
                """
            )
            result = self.run_bash(body)
            self.assertTrue(history_file.exists(), result.stdout + result.stderr)
            history = history_file.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("\tfailed\tssh-listeners\tother\ttcp udp\tiptables\t", history)
        self.assertIn("8080/tcp", history)
        self.assertIn("可能部分应用", result.stdout)
        self.assertIn("结果：失败", result.stdout)

    def test_cancelled_lockdown_does_not_record_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            history_file = Path(directory) / "history.tsv"
            body = textwrap.dedent(
                f"""
                source {SCRIPT!s}
                STATE_DIR={directory!s}
                FIREWALL_HISTORY_FILE={history_file!s}
                detect_firewall_backend() {{ printf 'iptables\\n'; }}
                protected_ssh_ports() {{ printf '21919\\n'; }}
                firewall_lockdown_interactive ssh <<< 'n'
                [[ ! -e {history_file!s} ]]
                """
            )
            result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_overview_lists_ports_once_and_keeps_policy_in_detailed_status(self):
        body = textwrap.dedent(
            f"""
            source {SCRIPT!s}
            detect_firewall_backend() {{ printf 'iptables\\n'; }}
            protected_ssh_ports() {{ printf '21919\\n'; }}
            public_listeners() {{ :; }}
            firewall_rule_records() {{ printf 'IPv4 ACCEPT tcp 21919\\n'; }}
            iptables() {{
                case "$*" in
                    '-S INPUT') printf '%s\\n' '-P INPUT ACCEPT' '-A INPUT -j ALLENTOOL_INPUT' ;;
                    '-S ALLENTOOL_INPUT') printf '%s\\n' '-N ALLENTOOL_INPUT' '-A ALLENTOOL_INPUT -p tcp --dport 21919 -j ACCEPT' '-A ALLENTOOL_INPUT -j DROP' ;;
                    '-C INPUT -j ALLENTOOL_INPUT') return 0 ;;
                esac
            }}
            ip6tables() {{ return 1; }}
            show_firewall_port_overview
            """
        )
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("当前入站保护清单", result.stdout)
        self.assertNotIn("默认入站策略", result.stdout)
        self.assertNotIn("其他宿主机新入站", result.stdout)
        self.assertIn("已放行的端口：", result.stdout)
        self.assertIn("IPv4  21919/tcp", result.stdout)
        self.assertEqual(result.stdout.count("IPv4  21919/tcp"), 1)
        detailed = self.run_bash(body.replace("show_firewall_port_overview", "show_firewall_status"))
        self.assertEqual(detailed.returncode, 0, detailed.stdout + detailed.stderr)
        self.assertIn("IPv4 默认入站策略: ACCEPT", detailed.stdout)
        self.assertIn("入站保护模式: 已启用（IPv4）", detailed.stdout)
        self.assertIn("IPv4 INPUT 原始规则", detailed.stdout)


if __name__ == "__main__":
    unittest.main()
