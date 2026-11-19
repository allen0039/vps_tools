"""Unit tests for leikwan_tools (zero external dependencies, runs on Python 3.9+ and 3.11+)."""

from __future__ import annotations

import hashlib
import io
import json
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
import os
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from leikwan_tools import MANAGED_MARKER, REALM_RELEASES  # noqa: E402
from leikwan_tools.cli import main  # noqa: E402
from leikwan_tools.config import (  # noqa: E402
    ConfigError,
    DdnsProfileConfig,
    LineConfig,
    load_global_config,
    load_rule_config,
    normalize_ddns_fqdn,
    normalize_ddns_subdomain,
    parse_global_config_dict,
    parse_rule_config_dict,
    render_realm_toml,
    render_rule_toml,
)
from leikwan_tools.ddns import (  # noqa: E402
    AliDnsProvider,
    CloudflareProvider,
    DdnsError,
    DdnsProviderError,
    DnspodProvider,
    WebhookProvider,
    _alidns_percent_encode,
    _build_alidns_signed_url,
    classify_ipv6_isp,
    inspect_ddns_profile,
    load_credential_file,
    parse_ip6_addr_candidates,
    parse_ping_rtt_ms,
    redact_url,
    status_ddns,
    test_ddns_profile,
    update_ddns,
)
from leikwan_tools.ingress import (  # noqa: E402
    STATUS_DNS_CANDIDATE,
    STATUS_LANDING_VERIFIED,
    STATUS_TCP_REACHABLE,
    DnsQueryResult,
    DnsRecord,
    build_dns_a_query,
    check_fixed_ip_staleness,
    evaluate_fixed_ip_policy,
    parse_dns_a_response,
    probe_candidate,
    query_dns_a_via_server,
)
from leikwan_tools.manager import ApplyError, PreflightReport, apply_rule  # noqa: E402
from leikwan_tools.ownership import (  # noqa: E402
    OwnershipError,
    check_conservative_legacy_rule,
    ensure_safe_subpath,
    uninstall_tool,
    validate_rule_name,
    verify_launcher_owned,
    verify_legacy_template_owned,
    write_install_artifacts,
)
from leikwan_tools.realm import RealmBinaryInfo, RealmError, install_realm_binary, parse_realm_version  # noqa: E402
from leikwan_tools.system import (  # noqa: E402
    FileLock,
    LockTimeoutError,
    PreflightError,
    RouteGetResult,
    check_policy_rule_matches,
    find_port_conflicts,
    format_port_conflict_error,
    parse_ip_addr_ipv4,
    parse_ip_link_states,
    parse_ip_rules,
    parse_route_get_output,
    parse_ss_listeners,
    systemd_is_active,
    verify_egress_route,
)
from leikwan_tools.toml_compat import TomlParseError, _fallback_loads, loads_toml  # noqa: E402
from leikwan_tools.updater import (  # noqa: E402
    UpdateCheckInfo,
    UpdateError,
    UpdateResult,
    _build_install_args,
    _compare_versions,
    _discover_remote_files,
    _extract_version_from_init,
    _filter_update_tree_paths,
    _parse_commit_metadata,
    _validate_staged_files,
    perform_update,
)


class TestInteractiveShortcut(unittest.TestCase):
    def test_menu_edit_preserves_rule_settings_and_uses_confirmed_snapshot(self) -> None:
        cfg = load_global_config(str(REPO_ROOT / "examples" / "config.example.toml"))
        old = replace(
            load_rule_config(str(REPO_ROOT / "examples" / "rule-rfc-hk.example.toml")),
            tcp_timeout=11,
            ingress_fixed_ip="1.1.1.1",
        )
        answers = ["2", "3", old.name, "", "", "", "", "192.0.2.22", "", "9929", "y", "0", "0"]
        with (
            patch("builtins.input", side_effect=answers),
            patch("leikwan_tools.cli.load_global_config", return_value=cfg),
            patch("leikwan_tools.cli.list_managed_rules", return_value=[old]),
            patch("leikwan_tools.cli.plan_rule") as plan,
            patch("leikwan_tools.cli.apply_rule") as apply,
            patch("leikwan_tools.cli._print_plan"),
            patch("leikwan_tools.cli._print_apply"),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(["menu"]), 0)
        desired = replace(old, remote_ip="192.0.2.22", line="9929")
        plan.assert_called_once_with(cfg, desired)
        apply.assert_called_once_with(cfg, desired, expected_rule=old, create_only=False)

    def test_shortcut_opens_menu_and_accepts_cli_arguments(self) -> None:
        launcher = REPO_ROOT / "bin" / "leikwan_tools"
        with tempfile.TemporaryDirectory() as td:
            shortcut = Path(td) / "lqtool"
            shortcut.write_bytes(launcher.read_bytes())
            env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
            menu = subprocess.run(
                [sys.executable, str(shortcut)],
                input="invalid\n0\n",
                capture_output=True,
                text=True,
                env=env,
                check=True,
            )
            self.assertIn("leikwan_tools 利群转发助手 v0.1.3", menu.stdout)
            self.assertIn("转发规则管理", menu.stdout)
            self.assertNotIn("预览规则部署", menu.stdout)
            self.assertNotIn("应用规则文件", menu.stdout)
            self.assertIn("无效选项", menu.stdout)
            version = subprocess.run(
                [sys.executable, str(shortcut), "--version"],
                capture_output=True,
                text=True,
                env=env,
                check=True,
            )
            self.assertEqual(version.stdout.strip(), "leikwan_tools 0.1.3")

    def test_menu_delete_lists_rules_requires_confirmation_and_returns_after_error(self) -> None:
        cfg = load_global_config(str(REPO_ROOT / "examples" / "config.example.toml"))
        r1 = replace(load_rule_config(str(REPO_ROOT / "examples" / "rule-rfc-hk.example.toml")), name="rule-one")
        r2 = replace(r1, name="rule-two")
        answers = ["2", "5", "", "5", "rule-two", "y", "0", "0"]
        with patch("builtins.input", side_effect=answers), patch(
            "leikwan_tools.cli.load_global_config", return_value=cfg
        ), patch(
            "leikwan_tools.cli.list_managed_rules", return_value=[r1, r2]
        ), patch(
            "leikwan_tools.cli.delete_rule", side_effect=ApplyError("test failure")
        ) as delete, patch(
            "sys.stdout", new_callable=io.StringIO
        ), patch(
            "sys.stderr", new_callable=io.StringIO
        ) as stderr:
            self.assertEqual(main(["--config", "/tmp/test-leikwan.toml", "menu"]), 0)
        self.assertEqual(delete.call_count, 1)
        self.assertEqual(delete.call_args.args[1], "rule-two")
        self.assertIn("test failure", stderr.getvalue())

    def test_menu_toggle_pause_and_resume(self) -> None:
        cfg = load_global_config(str(REPO_ROOT / "examples" / "config.example.toml"))
        rule = load_rule_config(str(REPO_ROOT / "examples" / "rule-rfc-hk.example.toml"))
        answers = ["2", "4", "1", "y", "4", "1", "y", "0", "0"]
        with (
            patch("builtins.input", side_effect=answers),
            patch("leikwan_tools.cli.load_global_config", return_value=cfg),
            patch("leikwan_tools.cli.list_managed_rules", return_value=[rule]),
            patch("leikwan_tools.cli.systemd_is_active", side_effect=[True, False]),
            patch(
                "leikwan_tools.cli.disable_rule",
                return_value={"rule_name": rule.name, "unit_name": f"leikwan_tools-realm@{rule.name}.service"},
            ) as disable,
            patch("leikwan_tools.cli.plan_rule") as plan,
            patch("leikwan_tools.cli.apply_rule") as apply,
            patch("leikwan_tools.cli._print_plan"),
            patch("leikwan_tools.cli._print_apply"),
            redirect_stdout(io.StringIO()) as stdout,
        ):
            self.assertEqual(main(["menu"]), 0)
        disable.assert_called_once_with(cfg, rule.name)
        plan.assert_called_once_with(cfg, rule)
        apply.assert_called_once_with(cfg, rule, expected_rule=rule, create_only=False)
        self.assertIn("已暂停", stdout.getvalue())

    def test_menu_system_submenu_navigation(self) -> None:
        cfg = load_global_config(str(REPO_ROOT / "examples" / "config.example.toml"))
        with (
            patch("builtins.input", side_effect=["5", "2", "0", "0"]),
            patch("leikwan_tools.cli.load_global_config", return_value=cfg),
            patch(
                "leikwan_tools.cli.check_prereqs",
                return_value={"ok": True, "realm_ok": True, "realm": "/usr/local/bin/realm", "lines": []},
            ) as check,
            redirect_stdout(io.StringIO()) as stdout,
        ):
            self.assertEqual(main(["--config", "/tmp/test-leikwan.toml", "menu"]), 0)
        check.assert_called_once()
        self.assertIn("初始化与环境排查", stdout.getvalue())
        self.assertIn("Realm 检查: 通过", stdout.getvalue())

    def test_menu_list_forwards_shows_egress_name(self) -> None:
        cfg = load_global_config(str(REPO_ROOT / "examples" / "config.example.toml"))
        rule = load_rule_config(str(REPO_ROOT / "examples" / "rule-rfc-hk.example.toml"))
        with (
            patch("builtins.input", side_effect=["2", "1", "0", "0"]),
            patch("leikwan_tools.cli.load_global_config", return_value=cfg),
            patch("leikwan_tools.cli.list_managed_rules", return_value=[rule]),
            patch("leikwan_tools.cli.systemd_is_active", return_value=True),
            redirect_stdout(io.StringIO()) as stdout,
        ):
            self.assertEqual(main(["menu"]), 0)
        out = stdout.getvalue()
        self.assertIn("当前共有 1 条已配置转发", out)
        self.assertIn("[运行中] rfc-hk", out)
        self.assertIn("cn2（CN2 GIA 出口线路 | eth1 / 10.8.0.146）", out)
        self.assertIn("客户端入口", out)
        self.assertIn("本机监听", out)
        self.assertIn("落地目标", out)

    def test_menu_update_check_cancel_and_apply(self) -> None:
        info = UpdateCheckInfo(
            channel="gitee",
            channel_label="Gitee",
            repo="allen0039/vps_tools",
            branch="main",
            current_version="0.1.2",
            remote_version="0.1.3",
            commit_sha="a" * 40,
            short_sha="aaaaaaa",
            tree_sha="b" * 40,
            commit_message="Release v0.1.3",
            status="upgrade",
            update_available=True,
        )
        res = UpdateResult(
            channel="gitee",
            channel_label="Gitee",
            repo="allen0039/vps_tools",
            branch="main",
            commit_sha="a" * 40,
            short_sha="aaaaaaa",
            previous_version="0.1.2",
            remote_version="0.1.3",
            installed_version="0.1.3",
            files_updated=12,
            install_args=["--skip-realm-install"],
            version_changed=True,
        )
        # First cancel on "n", then confirm on "y"
        answers = ["6", "2", "n", "6", "2", "y", "0"]
        with (
            patch("builtins.input", side_effect=answers),
            patch("leikwan_tools.cli.check_for_update", return_value=info) as m_check,
            patch("leikwan_tools.cli.perform_update", return_value=res) as m_upd,
            redirect_stdout(io.StringIO()) as stdout,
        ):
            self.assertEqual(main(["menu"]), 0)
        self.assertEqual(m_check.call_count, 2)
        m_upd.assert_called_once_with(channel="gitee", prechecked=info)
        out = stdout.getvalue()
        self.assertIn("6. 从仓库检查并更新工具", out)
        self.assertIn("发现新版本 v0.1.3", out)
        self.assertIn("已从 v0.1.2 更新到 v0.1.3", out)


class TestTomlCompat(unittest.TestCase):
    def test_roundtrip_both_parsers(self) -> None:
        sample = """
        # Top comment
        [tool]
        realm_bin = ""
        rules_dir = "/etc/leikwan_tools/rules.d"
        [lines.9929]
        interface = "eth0"
        source_ip = "10.7.0.146"
        gateway = "10.7.0.1"
        table = 101
        description = "Line #1 with # hash inside quotes"
        [[endpoints]]
        listen = "10.7.0.146:10001"
        remote = "192.0.2.10:54141"
        through = "10.7.0.146"
        tags = ["a", "b", "c"]
        enabled = true
        """
        d1 = loads_toml(sample)
        d2 = _fallback_loads(sample)
        self.assertEqual(d1, d2)
        self.assertEqual(d2["lines"]["9929"]["table"], 101)
        self.assertEqual(d2["lines"]["9929"]["description"], "Line #1 with # hash inside quotes")
        self.assertEqual(d2["endpoints"][0]["tags"], ["a", "b", "c"])
        self.assertIs(d2["endpoints"][0]["enabled"], True)

    def test_fallback_rejects_duplicate_keys(self) -> None:
        with self.assertRaises(TomlParseError):
            _fallback_loads("[a]\nx = 1\nx = 2\n")


class TestConfigValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.example_cfg = (REPO_ROOT / "examples" / "config.example.toml").read_text(encoding="utf-8")
        self.example_rule = (REPO_ROOT / "examples" / "rule-zouter-jp.example.toml").read_text(encoding="utf-8")

    def test_example_configs_validate_and_roundtrip(self) -> None:
        gcfg = parse_global_config_dict(loads_toml(self.example_cfg))
        self.assertIn("9929", gcfg.lines)
        self.assertIn("cn2", gcfg.lines)

        rule = parse_rule_config_dict(loads_toml(self.example_rule))
        self.assertEqual(rule.name, "zouter-jp")
        self.assertEqual(rule.public_port, 54141)
        self.assertEqual(rule.listen_port, 10001)
        self.assertEqual(rule.remote_port, 54141)

        rule_toml = render_rule_toml(rule)
        reparsed = parse_rule_config_dict(loads_toml(rule_toml))
        self.assertEqual(reparsed, rule)

        realm_toml = render_realm_toml(rule, gcfg.lines["cn2"])
        parsed_realm = loads_toml(realm_toml)
        self.assertFalse(parsed_realm["network"]["no_tcp"])
        self.assertFalse(parsed_realm["network"]["use_udp"])
        self.assertEqual(parsed_realm["endpoints"][0]["listen"], "10.7.0.146:10001")
        self.assertEqual(parsed_realm["endpoints"][0]["remote"], "192.0.2.10:54141")
        self.assertEqual(parsed_realm["endpoints"][0]["through"], "10.8.0.146")

    def test_independent_ports_and_validation_errors(self) -> None:
        data = loads_toml(self.example_rule)
        data["ingress"]["public_port"] = 41001
        data["forward"]["listen_port"] = 10099
        data["forward"]["remote_port"] = 24443
        rule = parse_rule_config_dict(data)
        self.assertEqual((rule.public_port, rule.listen_port, rule.remote_port), (41001, 10099, 24443))

        # Reject 0.0.0.0 listen_ip
        bad = loads_toml(self.example_rule)
        bad["forward"]["listen_ip"] = "0.0.0.0"
        with self.assertRaises(ConfigError):
            parse_rule_config_dict(bad)

        # Reject IPv6
        bad = loads_toml(self.example_rule)
        bad["forward"]["remote_ip"] = "2001:db8::1"
        with self.assertRaises(ConfigError):
            parse_rule_config_dict(bad)

        # Reject invalid port / bool port
        bad = loads_toml(self.example_rule)
        bad["forward"]["listen_port"] = True
        with self.assertRaises(ConfigError):
            parse_rule_config_dict(bad)

        bad["forward"]["listen_port"] = 70000
        with self.assertRaises(ConfigError):
            parse_rule_config_dict(bad)

    def test_public_ipv6_listens_directly_and_preserves_ipv4_egress(self) -> None:
        data = loads_toml(self.example_rule)
        data["ingress"] = {"public_port": 54141}
        data["forward"].update(listen_ip="2408:820c:7508:34d4:0:0:0:10", listen_port=54141)
        rule = parse_rule_config_dict(data)
        self.assertTrue(rule.direct_ipv6)
        self.assertEqual(rule.dial_addr, "2408:820c:7508:34d4::10")
        self.assertEqual(rule, parse_rule_config_dict(loads_toml(render_rule_toml(rule))))

        cfg = load_global_config(str(REPO_ROOT / "examples" / "config.example.toml"))
        endpoint = loads_toml(render_realm_toml(rule, cfg.lines["9929"], "eth0"))["endpoints"][0]
        self.assertEqual(endpoint["listen"], "[2408:820c:7508:34d4::10]:54141")
        self.assertEqual(endpoint["through"], "10.7.0.146")
        self.assertEqual(endpoint["interface"], "eth0")
        self.assertNotIn("listen_interface", endpoint)

        data["forward"]["listen_port"] = 10001
        with self.assertRaises(ConfigError):
            parse_rule_config_dict(data)
        data["forward"].update(listen_ip="::ffff:10.7.0.146", listen_port=54141)
        with self.assertRaises(ConfigError):
            parse_rule_config_dict(data)

        # Reject path traversal in rule.name
        bad = loads_toml(self.example_rule)
        bad["rule"]["name"] = "../evil"
        with self.assertRaises(ConfigError):
            parse_rule_config_dict(bad)


class TestRoutingAndPorts(unittest.TestCase):
    def test_link_and_addr_parsers(self) -> None:
        link_out = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP mode DEFAULT\n"
            "3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc fq state DOWN mode DEFAULT\n"
        )
        links = parse_ip_link_states(link_out)
        self.assertEqual(links["eth0"][0], "UP")
        self.assertIn("UP", links["eth0"][1])
        self.assertEqual(links["eth1"][0], "DOWN")

        addr_out = (
            "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
            "2: eth0    inet 10.7.0.146/24 brd 10.7.0.255 scope global eth0\\       valid_lft forever\n"
            "3: eth1    inet 10.8.0.146/24 brd 10.8.0.255 scope global eth1\\       valid_lft forever\n"
        )
        addrs = parse_ip_addr_ipv4(addr_out)
        self.assertEqual(addrs["eth0"], ["10.7.0.146"])
        self.assertEqual(addrs["eth1"], ["10.8.0.146"])

    def test_route_get_and_policy_rule_verification(self) -> None:
        rt_tables = {"main": "254", "9929": "101", "cn2": "102"}
        route_out = "192.0.2.10 from 10.8.0.146 via 10.8.0.1 dev eth1 table 102 uid 0\n    cache\n"
        parsed = parse_route_get_output("192.0.2.10", "10.8.0.146", route_out, rt_tables=rt_tables)
        self.assertEqual(parsed.dev, "eth1")
        self.assertEqual(parsed.via, "10.8.0.1")
        self.assertEqual(parsed.table, "102")

        rules_out = (
            "0:\tfrom all lookup local\n"
            "100:\tfrom 10.7.0.146 lookup 101\n"
            "101:\tfrom 10.8.0.0/24 lookup cn2\n"
            "32766:\tfrom all lookup main\n"
        )
        rules = parse_ip_rules(rules_out, rt_tables=rt_tables)
        self.assertIsNotNone(check_policy_rule_matches("10.8.0.146", 102, rules))
        self.assertIsNone(check_policy_rule_matches("10.9.0.146", 102, rules))

        line_cn2 = LineConfig(name="cn2", interface="eth1", source_ip="10.8.0.146", gateway="10.8.0.1", table=102)

        def fake_run(cmd, timeout=15.0):
            class Res:
                def __init__(self, rc, out):
                    self.returncode = rc
                    self.stdout = out
                    self.stderr = ""

            if cmd[:4] == ["ip", "-4", "route", "get"]:
                return Res(0, route_out)
            if cmd[:4] == ["ip", "-4", "rule", "show"]:
                return Res(0, rules_out)
            raise AssertionError(cmd)

        with patch("leikwan_tools.system.run_cmd", side_effect=fake_run), patch(
            "leikwan_tools.system._load_rt_tables", return_value=rt_tables
        ):
            ok_res = verify_egress_route(line_cn2, "192.0.2.10")
            self.assertEqual(ok_res.table, "102")

        # Fallback to main table (no `table 102` in output) must be rejected!
        bad_route_out = "192.0.2.10 from 10.8.0.146 via 10.7.0.1 dev eth0 uid 0\n"

        def fake_run_fallback(cmd, timeout=15.0):
            class Res:
                def __init__(self, rc, out):
                    self.returncode = rc
                    self.stdout = out
                    self.stderr = ""

            if cmd[:4] == ["ip", "-4", "route", "get"]:
                return Res(0, bad_route_out)
            return Res(0, rules_out)

        with patch("leikwan_tools.system.run_cmd", side_effect=fake_run_fallback), patch(
            "leikwan_tools.system._load_rt_tables", return_value=rt_tables
        ):
            with self.assertRaises(PreflightError) as ctx:
                verify_egress_route(line_cn2, "192.0.2.10")
            self.assertIn("严禁静默切到其他线路", str(ctx.exception))
            self.assertIn("禁止退回主路由表", str(ctx.exception))

    def test_ss_port_conflict_exact_and_wildcard(self) -> None:
        ss_v4 = (
            'LISTEN 0 128 10.7.0.146:10001 0.0.0.0:* users:(("realm",pid=222,fd=7))\n'
            'LISTEN 0 128 0.0.0.0:10005 0.0.0.0:* users:(("python3",pid=333,fd=3))\n'
            'LISTEN 0 128 *:10006 0.0.0.0:* users:(("nc",pid=444,fd=3))\n'
        )
        ss_v6 = 'LISTEN 0 128 [::]:10007 [::]:* users:(("caddy",pid=555,fd=9))\n'
        listeners = parse_ss_listeners(ss_v4, "ipv4") + parse_ss_listeners(ss_v6, "ipv6")

        # Exact match allowed for own MainPID
        self.assertEqual(
            find_port_conflicts("10.7.0.146", 10001, listeners, allowed_pids={222}, bindv6only=0),
            [],
        )
        # Exact match blocked for foreign PID
        c1 = find_port_conflicts("10.7.0.146", 10001, listeners, allowed_pids={999}, bindv6only=0)
        self.assertEqual(len(c1), 1)
        self.assertEqual(c1[0].conflict_type, "精确地址冲突")
        self.assertIn("pid=222", format_port_conflict_error("10.7.0.146", 10001, c1))

        # 0.0.0.0 wildcard blocks specific IPv4
        c2 = find_port_conflicts("10.7.0.146", 10005, listeners, bindv6only=0)
        self.assertEqual(len(c2), 1)
        self.assertEqual(c2[0].conflict_type, "通配端口冲突")

        # * wildcard blocks specific IPv4
        c3 = find_port_conflicts("10.7.0.146", 10006, listeners, bindv6only=0)
        self.assertEqual(len(c3), 1)

        # [::] dual-stack wildcard blocks specific IPv4 when bindv6only=0, ignored when bindv6only=1
        c4 = find_port_conflicts("10.7.0.146", 10007, listeners, bindv6only=0)
        self.assertEqual(len(c4), 1)
        self.assertIn("IPv6 双栈", c4[0].conflict_type)
        self.assertEqual(find_port_conflicts("10.7.0.146", 10007, listeners, bindv6only=1), [])


class TestRealmAndLock(unittest.TestCase):
    def test_parse_realm_version(self) -> None:
        self.assertEqual(parse_realm_version("realm 2.9.6\n"), (2, 9, 6))
        self.assertEqual(parse_realm_version("realm v2.7.0"), (2, 7, 0))
        with self.assertRaises(RealmError):
            parse_realm_version("unknown")

    def test_install_realm_rejects_bad_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bad_tar = Path(td) / "bad.tar.gz"
            with tarfile.open(bad_tar, "w:gz") as tf:
                data = b"not-realm"
                info = tarfile.TarInfo("realm")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            with self.assertRaises(RealmError) as ctx:
                install_realm_binary(
                    target_path=str(Path(td) / "realm"),
                    tarball_path=str(bad_tar),
                    arch="x86_64",
                    state_dir=td,
                )
            self.assertIn("SHA-256 校验失败", str(ctx.exception))
            self.assertIn("x86_64", REALM_RELEASES)

    def test_file_lock_contention(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            lock_path = str(Path(td) / "test.lock")
            entered = threading.Event()
            release = threading.Event()

            def holder() -> None:
                with FileLock(lock_path, timeout=2.0):
                    entered.set()
                    release.wait(timeout=2.0)

            t = threading.Thread(target=holder)
            t.start()
            entered.wait(timeout=2.0)
            try:
                with self.assertRaises(LockTimeoutError):
                    with FileLock(lock_path, timeout=0.2):
                        pass
            finally:
                release.set()
                t.join(timeout=2.0)


class TestIngressDnsAndProbing(unittest.TestCase):
    def test_truncated_udp_dns_retries_over_tcp(self) -> None:
        txid = 0x1234
        dns_query = build_dns_a_query("ingress.example.com", txid)
        truncated = bytes.fromhex("123483800001000000000000")
        header = bytes.fromhex("123481800001000100000000")
        answer = bytes.fromhex("c00c000100010000003c000401010101")
        dns_response = header + dns_query[12:] + answer
        with (
            patch("leikwan_tools.ingress.os.urandom", return_value=b"\x12\x34"),
            patch("leikwan_tools.ingress.socket.socket") as open_udp,
            patch("leikwan_tools.ingress.socket.create_connection") as open_tcp,
        ):
            udp = open_udp.return_value.__enter__.return_value
            udp.recv.return_value = truncated
            tcp = open_tcp.return_value.__enter__.return_value
            tcp.makefile.return_value.__enter__.return_value = io.BytesIO(
                len(dns_response).to_bytes(2, "big") + dns_response
            )
            records = query_dns_a_via_server("ingress.example.com", "127.0.0.1")
        self.assertEqual(records, [DnsRecord("1.1.1.1", 60)])
        udp.connect.assert_called_once_with(("127.0.0.1", 53))
        tcp.sendall.assert_called_once_with(len(dns_query).to_bytes(2, "big") + dns_query)

    def test_dns_wire_query_and_compressed_response(self) -> None:
        txid = 0x1234
        q = build_dns_a_query("paid-v4.bgp1.leikwanhost.com", txid)
        # Build synthetic DNS response echoing question + 2 compressed A answers
        header = bytes([0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        question = q[12:]
        ans1 = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([203, 0, 113, 10])
        ans2 = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([203, 0, 113, 11])
        records = parse_dns_a_response(header + question + ans1 + ans2, txid)
        self.assertEqual([r.ip for r in records], ["203.0.113.10", "203.0.113.11"])
        self.assertEqual(records[0].ttl, 60)

    def test_probe_three_tier_classification(self) -> None:
        import socketserver

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                data = self.rfile.readline()
                if b"PING" in data:
                    self.wfile.write(b"LANDING=zouter-jp-mock\n")
                else:
                    self.wfile.write(b"LANDING=decoy\n")

        class ReuseServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True

        srv = ReuseServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            # Tier 3: landing verified
            r_ok = probe_candidate(
                "127.0.0.1", port, in_dns=True, send_payload="PING\\n", expect_pattern="LANDING=zouter-jp-mock"
            )
            self.assertEqual(r_ok.stage, STATUS_LANDING_VERIFIED)
            self.assertTrue(r_ok.landing_verified)

            # Tier 2: TCP reachable but wrong landing identity
            r_mismatch = probe_candidate(
                "127.0.0.1", port, in_dns=True, send_payload="HELLO\\n", expect_pattern="LANDING=zouter-jp-mock"
            )
            self.assertEqual(r_mismatch.stage, STATUS_TCP_REACHABLE)
            self.assertTrue(r_mismatch.tcp_reachable)
            self.assertFalse(r_mismatch.landing_verified)

            # Tier 2: TCP reachable without expect
            r_tcp_only = probe_candidate("127.0.0.1", port, in_dns=True)
            self.assertEqual(r_tcp_only.stage, STATUS_TCP_REACHABLE)
            self.assertFalse(r_tcp_only.landing_verified)
        finally:
            srv.shutdown()
            srv.server_close()

        # Tier 1: closed port -> DNS candidate only
        r_closed = probe_candidate("127.0.0.1", port, in_dns=True, timeout=0.5)
        self.assertEqual(r_closed.stage, STATUS_DNS_CANDIDATE)
        self.assertFalse(r_closed.tcp_reachable)

    def test_fixed_ip_staleness_warning(self) -> None:
        dns = DnsQueryResult(
            domain="paid-v4.bgp1.leikwanhost.com",
            resolver="udp://203.0.113.1:53",
            queried_at_local="2026-11-19 11:30:00 +0800",
            queried_at_utc="2026-11-19 03:30:00 UTC",
            records=[DnsRecord(ip="203.0.113.10", ttl=60)],
        )
        self.assertIsNone(check_fixed_ip_staleness("203.0.113.10", dns.domain, dns))
        warn = check_fixed_ip_staleness("203.0.113.11", dns.domain, dns)
        self.assertIsNotNone(warn)
        self.assertIn("203.0.113.11", warn)
        self.assertIn("已保留现有固定 IP 设置", warn)


class TestR2ConfigAndRoutePinning(unittest.TestCase):
    def test_realm_toml_binds_through_and_interface(self) -> None:
        gcfg = parse_global_config_dict(
            loads_toml((REPO_ROOT / "examples" / "config.example.toml").read_text(encoding="utf-8"))
        )
        rule = parse_rule_config_dict(
            loads_toml((REPO_ROOT / "examples" / "rule-zouter-jp.example.toml").read_text(encoding="utf-8"))
        )
        rendered = render_realm_toml(rule, gcfg.lines["cn2"])
        parsed = loads_toml(rendered)
        self.assertEqual(parsed["endpoints"][0]["through"], "10.8.0.146")
        self.assertEqual(parsed["endpoints"][0]["interface"], "eth1")

    def test_reject_foreign_systemd_template(self) -> None:
        raw = (REPO_ROOT / "examples" / "config.example.toml").read_text(encoding="utf-8")
        data = loads_toml(raw)
        data["tool"]["systemd_unit_template"] = "foreign-other@.service"
        with self.assertRaises(ConfigError):
            parse_global_config_dict(data)

    def test_route_get_rejects_oif_mismatch(self) -> None:
        line_cn2 = LineConfig(name="cn2", interface="eth1", source_ip="10.8.0.146", gateway="10.8.0.1", table=102)
        rt_tables = {"main": "254", "102": "102"}
        good_from = "192.0.2.10 from 10.8.0.146 via 10.8.0.1 dev eth1 table 102 uid 0\n"
        rules_out = "102:\tfrom 10.8.0.146 lookup 102\n"

        def fake_run(cmd, timeout=15.0):
            class Res:
                def __init__(self, rc, out, err=""):
                    self.returncode = rc
                    self.stdout = out
                    self.stderr = err

            if cmd[:4] == ["ip", "-4", "rule"]:
                return Res(0, rules_out)
            if "oif" in cmd:
                return Res(2, "", "RTNETLINK answers: Network is unreachable")
            return Res(0, good_from)

        with patch("leikwan_tools.system.run_cmd", side_effect=fake_run), patch(
            "leikwan_tools.system._load_rt_tables", return_value=rt_tables
        ):
            with self.assertRaises(PreflightError) as ctx:
                verify_egress_route(line_cn2, "192.0.2.10")
            self.assertIn("指定出口网卡路由探测失败", str(ctx.exception))


class TestR2OwnershipAndRollback(unittest.TestCase):
    def test_legacy_template_upgrade_fingerprint_rejects_foreign_unit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            unit = Path(td) / "leikwan_tools-realm@.service"
            unit.write_text(
                "[Unit]\n"
                "Description=leikwan_tools Realm IPv4 TCP Relay (%i)\n"
                "[Service]\n"
                "Type=simple\n"
                "ExecStart=/usr/local/lib/leikwan_tools/realm-exec.sh %i\n"
                "Restart=on-failure\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n",
                encoding="utf-8",
            )
            self.assertEqual(verify_legacy_template_owned(str(unit)), (True, "legacy-template"))

            unit.write_text(
                "[Unit]\n"
                "Description=leikwan_tools Realm IPv4 TCP Relay (%i)\n"
                "[Service]\n"
                "ExecStart=/usr/local/lib/foreign/realm-exec.sh %i\n",
                encoding="utf-8",
            )
            owned, reason = verify_legacy_template_owned(str(unit))
            self.assertFalse(owned)
            self.assertIn("内容不匹配", reason)

    def test_safe_subpath_rejects_symlink_and_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            outside = Path(td) / "outside.txt"
            root.mkdir()
            outside.write_text("secret", encoding="utf-8")
            link = root / "escape.toml"
            link.symlink_to(outside)
            with self.assertRaises(OwnershipError):
                ensure_safe_subpath(root, link)
            with self.assertRaises(OwnershipError):
                ensure_safe_subpath(root, outside)
            with self.assertRaises(ConfigError):
                validate_rule_name("../bad")

    def test_install_realm_refuses_foreign_binary_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            foreign = Path(td) / "realm"
            foreign.write_text("existing-foreign-binary", encoding="utf-8")
            bad_tar = Path(td) / "any.tar.gz"
            bad_tar.write_bytes(b"unused")
            with self.assertRaises(RealmError) as ctx:
                install_realm_binary(
                    target_path=str(foreign),
                    tarball_path=str(bad_tar),
                    state_dir=td,
                    manifest_path=str(Path(td) / "missing-manifest.json"),
                )
            self.assertIn("拒绝覆盖", str(ctx.exception))
            self.assertEqual(foreign.read_text(encoding="utf-8"), "existing-foreign-binary")

    def test_shared_dir_uninstall_preserves_unrelated_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            lib_dir = base / "lib"
            cfg_dir = base / "shared_cfg"
            st_dir = base / "shared_state"
            (lib_dir / "leikwan_tools").mkdir(parents=True)
            (cfg_dir / "rules.d").mkdir(parents=True)
            (cfg_dir / "examples").mkdir(parents=True)
            (st_dir / "realm").mkdir(parents=True)
            (st_dir / "state").mkdir(parents=True)

            sentinel_state = st_dir / "unrelated-sentinel.txt"
            sentinel_cfg = cfg_dir / "unrelated-config.txt"
            sentinel_state.write_text("keep-state-sentinel\n", encoding="utf-8")
            sentinel_cfg.write_text("keep-cfg-sentinel\n", encoding="utf-8")

            cfg_file = cfg_dir / "config.toml"
            cfg_file.write_text("# dummy", encoding="utf-8")
            ex_file = cfg_dir / "examples" / "config.example.toml"
            ex_file.write_text("# ex", encoding="utf-8")
            shortcut = base / "lqtool"
            shortcut.write_text(f"#!/usr/bin/env python3\n{MANAGED_MARKER}\n", encoding="utf-8")

            manifest = write_install_artifacts(
                install_lib_dir=str(lib_dir),
                config_dir=str(cfg_dir),
                state_dir=str(st_dir),
                config_file=str(cfg_file),
                lock_file=str(base / "test.lock"),
                realm_bin_path="/usr/local/bin/realm",
                realm_managed_install=False,
                example_files=[str(ex_file)],
                created_config_file=True,
            )
            self.assertEqual(manifest["config_dir"], str(cfg_dir.resolve()))

            with patch("leikwan_tools.ownership.TEMPLATE_UNIT_PATH", str(base / "missing.service")), patch(
                "leikwan_tools.ownership.BIN_LAUNCHER_PATH", str(base / "missing-bin")
            ), patch(
                "leikwan_tools.ownership.SHORTCUT_PATH", str(shortcut)
            ), patch("leikwan_tools.ownership.systemd_daemon_reload"):
                res = uninstall_tool(
                    purge=True,
                    config_dir_arg=str(cfg_dir),
                    state_dir_arg=str(st_dir),
                    install_lib_dir=str(lib_dir),
                    manifest_path=str(lib_dir / "install-manifest.json"),
                )
            self.assertTrue(sentinel_state.is_file())
            self.assertEqual(sentinel_state.read_text(encoding="utf-8"), "keep-state-sentinel\n")
            self.assertTrue(sentinel_cfg.is_file())
            self.assertEqual(sentinel_cfg.read_text(encoding="utf-8"), "keep-cfg-sentinel\n")
            self.assertFalse(cfg_file.exists())
            self.assertFalse(shortcut.exists())
            self.assertIn(str(shortcut), res["removed_files"])
            self.assertIn("保留复用的外部 Realm 二进制", "\n".join(res["skipped_items"]))

    def test_shortcut_ownership_rejects_foreign_file_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            shortcut = Path(td) / "lqtool"
            with patch("leikwan_tools.ownership.SHORTCUT_PATH", str(shortcut)):
                shortcut.write_text("import leikwan_tools.cli\n", encoding="utf-8")
                self.assertFalse(verify_launcher_owned(str(shortcut))[0])
                shortcut.unlink()
                shortcut.symlink_to(REPO_ROOT / "bin" / "leikwan_tools")
                self.assertFalse(verify_launcher_owned(str(shortcut))[0])

    def test_conservative_legacy_proof_requires_all_markers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rdir = Path(td) / "rules.d"
            sdir = Path(td) / "state"
            rdir.mkdir()
            (sdir / "realm").mkdir(parents=True)
            (sdir / "state").mkdir(parents=True)

            # Missing managed markers -> must return False
            (rdir / "legacy1.toml").write_text('[rule]\nname = "legacy1"\n', encoding="utf-8")
            (sdir / "realm" / "legacy1.toml").write_text("# wrong header\n", encoding="utf-8")
            (sdir / "state" / "legacy1.json").write_text('{"rule_name":"legacy1"}', encoding="utf-8")
            with patch("leikwan_tools.ownership.is_standalone_unmanaged_unit", return_value=(False, "")):
                ok, _ = check_conservative_legacy_rule(str(rdir), str(sdir), "legacy1")
                self.assertFalse(ok)

                # With all valid markers -> returns True
                (rdir / "legacy1.toml").write_text("# Managed by leikwan_tools (rule: legacy1)\n", encoding="utf-8")
                (sdir / "realm" / "legacy1.toml").write_text(
                    "# Generated by leikwan_tools for rule: legacy1\n", encoding="utf-8"
                )
                (sdir / "state" / "legacy1.json").write_text(
                    '{"rule_name":"legacy1","unit_name":"leikwan_tools-realm@legacy1.service"}',
                    encoding="utf-8",
                )
                ok2, _ = check_conservative_legacy_rule(str(rdir), str(sdir), "legacy1")
                self.assertTrue(ok2)

    def test_staged_rollback_unit_fault_injections(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rules_dir = base / "rules.d"
            state_dir = base / "state"
            rules_dir.mkdir()
            (state_dir / "realm").mkdir(parents=True)
            (state_dir / "state").mkdir(parents=True)
            cfg_path = base / "config.toml"
            cfg_path.write_text(
                f'[tool]\nrules_dir = "{rules_dir}"\nstate_dir = "{state_dir}"\n'
                f'lock_file = "{base / "lock"}"\n'
                '[lines.cn2]\ninterface = "eth1"\nsource_ip = "10.8.0.146"\ngateway = "10.8.0.1"\ntable = 102\n',
                encoding="utf-8",
            )
            rule_file = base / "rule.toml"
            rule_file.write_text(
                '[rule]\nname = "r1"\nline = "cn2"\n'
                '[ingress]\npublic_port = 54141\n'
                '[forward]\nlisten_ip = "10.7.0.146"\nlisten_port = 10001\nremote_ip = "192.0.2.10"\nremote_port = 54141\n',
                encoding="utf-8",
            )
            from leikwan_tools.config import load_global_config

            gcfg = load_global_config(str(cfg_path))
            fake_realm = RealmBinaryInfo("/usr/local/bin/realm", "2.9.6", (2, 9, 6), "abc", "reused")
            fake_line = gcfg.lines["cn2"]
            fake_rt = RouteGetResult("192.0.2.10", "10.8.0.146", "eth1", "10.8.0.1", "102", "10.8.0.146", "ok", ["ip"])

            def make_report():
                from leikwan_tools.config import load_rule_config

                return PreflightReport(
                    rule=load_rule_config(str(rule_file)),
                    line=fake_line,
                    realm_info=fake_realm,
                    listen_interface="eth0",
                    route_result=fake_rt,
                    unit_name="leikwan_tools-realm@r1.service",
                )

            # Case A: Stage 2 start fails AND journalctl fails AND stop raises while unit is confirmed inactive -> cleans all files!
            with patch("leikwan_tools.manager.preflight_rule", side_effect=lambda *a, **kw: make_report()), patch(
                "leikwan_tools.manager.systemd_enable"
            ), patch("leikwan_tools.manager.systemd_reset_failed"), patch(
                "leikwan_tools.manager.systemd_show", return_value={"NRestarts": "0"}
            ), patch("leikwan_tools.manager.systemd_restart", side_effect=RuntimeError("boom-start")), patch(
                "leikwan_tools.manager.systemd_journal_tail", side_effect=RuntimeError("boom-journal")
            ), patch("leikwan_tools.manager.systemd_stop", side_effect=RuntimeError("boom-stop")), patch(
                "leikwan_tools.manager.systemd_disable"
            ), patch("leikwan_tools.manager.systemd_is_active", return_value=False):
                with self.assertRaises(ApplyError) as ctx:
                    apply_rule(gcfg, str(rule_file))
                self.assertIn("已确认 leikwan_tools-realm@r1.service 未在运行；已清理文件", str(ctx.exception))
                self.assertFalse((rules_dir / "r1.toml").exists())
                self.assertFalse((state_dir / "realm" / "r1.toml").exists())

            # Case B: Stage 2 start/stop fail AND status query is unknown -> keeps runtime files & ownership!
            with patch("leikwan_tools.manager.preflight_rule", side_effect=lambda *a, **kw: make_report()), patch(
                "leikwan_tools.manager.systemd_enable"
            ), patch("leikwan_tools.manager.systemd_reset_failed"), patch(
                "leikwan_tools.manager.systemd_show", return_value={"NRestarts": "0"}
            ), patch("leikwan_tools.manager.systemd_restart", side_effect=RuntimeError("boom-start")), patch(
                "leikwan_tools.manager.systemd_journal_tail", return_value=""
            ), patch("leikwan_tools.manager.systemd_stop", side_effect=RuntimeError("boom-stop")), patch(
                "leikwan_tools.manager.systemd_disable"
            ), patch("leikwan_tools.manager.systemd_is_active", return_value=None):
                with self.assertRaises(ApplyError) as ctx:
                    apply_rule(gcfg, str(rule_file))
                self.assertIn("回滚未完全完成", str(ctx.exception))
                self.assertTrue((state_dir / "realm" / "r1.toml").exists())
                self.assertTrue((state_dir / "managed-rules.json").exists())

            # Case C: Update existing active rule where first write fails -> zero systemctl stop/restart calls!
            (rules_dir / "r1.toml").write_text("# Managed by leikwan_tools (rule: r1)\n", encoding="utf-8")
            (state_dir / "realm" / "r1.toml").write_text("# old realm toml\n", encoding="utf-8")
            with patch("leikwan_tools.manager.preflight_rule", side_effect=lambda *a, **kw: make_report()), patch(
                "leikwan_tools.manager.systemd_is_enabled", return_value=True
            ), patch("leikwan_tools.manager.systemd_is_active", return_value=True), patch(
                "leikwan_tools.manager.systemd_show", return_value={"ActiveState": "active", "SubState": "running", "MainPID": "777"}
            ), patch("leikwan_tools.manager.atomic_write_text", side_effect=OSError("disk-full")), patch(
                "leikwan_tools.manager.systemd_stop"
            ) as m_stop, patch("leikwan_tools.manager.systemd_restart") as m_restart:
                with self.assertRaises(ApplyError) as ctx:
                    apply_rule(gcfg, str(rule_file))
                self.assertIn("首次写入即失败", str(ctx.exception))
                m_stop.assert_not_called()
                m_restart.assert_not_called()

    def test_systemd_is_active_distinguishes_inactive_from_unknown(self) -> None:
        class Result:
            def __init__(self, returncode: int, stdout: str) -> None:
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = ""

        results = iter(
            [
                Result(0, "active\n"),
                Result(3, "inactive\n"),
                Result(1, ""),
            ]
        )
        with patch("leikwan_tools.system.run_cmd", side_effect=lambda *args, **kwargs: next(results)):
            self.assertIs(systemd_is_active("demo.service"), True)
            self.assertIs(systemd_is_active("demo.service"), False)
            self.assertIsNone(systemd_is_active("demo.service"))


class TestR2TlsAndFixedIpPolicy(unittest.TestCase):
    def test_tls_plain_tcp_fails_nonzero(self) -> None:
        import socketserver

        class PlainHandler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                self.wfile.write(b"NOT_TLS\n")

        class ReuseServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True

        srv = ReuseServer(("127.0.0.1", 0), PlainHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            res = probe_candidate("127.0.0.1", port, in_dns=True, tls=True, tls_sni="example.com")
            self.assertTrue(res.tcp_reachable)
            self.assertIs(res.tls_ok, False)
            self.assertEqual(res.exit_code, 3)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_fixed_ip_policy_unified_rules(self) -> None:
        dns_ok = DnsQueryResult(
            domain="paid-v4.bgp1.leikwanhost.com",
            resolver="udp://203.0.113.1:53",
            queried_at_local="2026-11-19 12:00:00 +0800",
            queried_at_utc="2026-11-19 04:00:00 UTC",
            records=[DnsRecord(ip="203.0.113.10", ttl=60)],
        )
        dns_err = DnsQueryResult(
            domain="paid-v4.bgp1.leikwanhost.com",
            resolver="udp://203.0.113.1:53",
            queried_at_local="2026-11-19 12:00:00 +0800",
            queried_at_utc="2026-11-19 04:00:00 UTC",
            records=[],
            error="timed out",
        )
        with patch("leikwan_tools.ingress.query_dns_a", return_value=dns_ok):
            r1 = evaluate_fixed_ip_policy("paid-v4.bgp1.leikwanhost.com", "203.0.113.99", "")
            self.assertFalse(r1.allowed)
            r2 = evaluate_fixed_ip_policy("paid-v4.bgp1.leikwanhost.com", "203.0.113.99", "", allow_non_dns=True)
            self.assertTrue(r2.allowed)
            self.assertTrue(r2.forced_override)
            # Preserved existing IP that disappeared from DNS -> allowed + warning
            r3 = evaluate_fixed_ip_policy("paid-v4.bgp1.leikwanhost.com", "203.0.113.99", "203.0.113.99")
            self.assertTrue(r3.allowed)
            self.assertIn("消失", r3.warning or "")

        with patch("leikwan_tools.ingress.query_dns_a", return_value=dns_err):
            r4 = evaluate_fixed_ip_policy("paid-v4.bgp1.leikwanhost.com", "203.0.113.10", "")
            self.assertFalse(r4.allowed)
            self.assertTrue(r4.dns_failed)
            r5 = evaluate_fixed_ip_policy("paid-v4.bgp1.leikwanhost.com", "203.0.113.10", "203.0.113.10")
            self.assertTrue(r5.allowed)
            self.assertIn("DNS 查询失败", r5.warning or "")


class TestSelfUpdate(unittest.TestCase):
    def test_parse_commit_metadata_github_and_gitee(self) -> None:
        gh = {
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "commit": {
                "message": "Update menu\n\nDetails",
                "tree": {"sha": "fedcba9876543210fedcba9876543210fedcba98"},
            },
        }
        sha, tree_sha, msg = _parse_commit_metadata(gh)
        self.assertEqual(sha, "0123456789abcdef0123456789abcdef01234567")
        self.assertEqual(tree_sha, "fedcba9876543210fedcba9876543210fedcba98")
        self.assertEqual(msg, "Update menu")

        gitee = {
            "name": "main",
            "commit": {
                "sha": "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
                "commit": {"message": "Gitee release"},
            },
        }
        sha2, tree_sha2, msg2 = _parse_commit_metadata(gitee)
        self.assertEqual(sha2, "abcdef0123456789abcdef0123456789abcdef01")
        self.assertEqual(tree_sha2, sha2)
        self.assertEqual(msg2, "Gitee release")

        with self.assertRaises(UpdateError):
            _parse_commit_metadata({"sha": "not-a-sha"})

    def test_extract_version_and_compare(self) -> None:
        self.assertEqual(_extract_version_from_init('"""doc"""\n__version__ = "0.1.3"\n'), "0.1.3")
        with self.assertRaises(UpdateError):
            _extract_version_from_init("x = 1\n")
        with self.assertRaises(UpdateError):
            _extract_version_from_init("def broken(:\n")

        self.assertEqual(_compare_versions("0.1.2", "0.1.3"), ("upgrade", True))
        self.assertEqual(_compare_versions("0.1.2", "0.1.10"), ("upgrade", True))
        self.assertEqual(_compare_versions("0.1.2", "0.1.2"), ("same", False))
        self.assertEqual(_compare_versions("0.1.3", "0.1.2"), ("ahead", False))
        self.assertEqual(_compare_versions("0.1.2", "dev-snapshot"), ("unknown", True))

    def test_tree_filter_and_truncated_fallback(self) -> None:
        entries = [
            {"path": "vpstools.sh", "type": "blob", "mode": "100755"},
            {"path": "leikwan_tools/install.sh", "type": "blob", "mode": "100755"},
            {"path": "leikwan_tools/bin/leikwan_tools", "type": "blob", "mode": "100755"},
            {"path": "leikwan_tools/leikwan_tools/__init__.py", "type": "blob", "mode": "100644"},
            {"path": "leikwan_tools/leikwan_tools/__pycache__/cli.cpython-311.pyc", "type": "blob", "mode": "100644"},
            {"path": "leikwan_tools/tests/test_unit.py", "type": "blob", "mode": "100644"},
            {"path": "leikwan_tools/docs/R2_FIX_REPORT.md", "type": "blob", "mode": "100644"},
            {"path": "leikwan_tools/test-results/out.txt", "type": "blob", "mode": "100644"},
            {"path": "leikwan_tools/bin/symlink_bin", "type": "blob", "mode": "120000"},
        ]
        filtered = _filter_update_tree_paths(entries)
        self.assertEqual(
            filtered,
            [
                ("bin/leikwan_tools", "100755"),
                ("install.sh", "100755"),
                ("leikwan_tools/__init__.py", "100644"),
            ],
        )

        with self.assertRaises(UpdateError):
            _filter_update_tree_paths([{"path": "leikwan_tools/../evil.py", "type": "blob", "mode": "100644"}])

        sub_sha = "1" * 40
        responses = iter(
            [
                {"truncated": True, "tree": []},
                {"tree": [{"path": "leikwan_tools", "type": "tree", "sha": sub_sha}]},
                {
                    "truncated": False,
                    "tree": [
                        {"path": "install.sh", "type": "blob", "mode": "100755"},
                        {"path": "bin/leikwan_tools", "type": "blob", "mode": "100755"},
                        {"path": "leikwan_tools/__init__.py", "type": "blob", "mode": "100644"},
                        {"path": "leikwan_tools/cli.py", "type": "blob", "mode": "100644"},
                        {"path": "systemd/leikwan_tools-realm@.service", "type": "blob", "mode": "100644"},
                        {"path": "systemd/leikwan_tools-ddns.service", "type": "blob", "mode": "100644"},
                        {"path": "systemd/leikwan_tools-ddns.timer", "type": "blob", "mode": "100644"},
                    ],
                },
            ]
        )
        with patch("leikwan_tools.updater._http_get_json", side_effect=lambda *a, **kw: next(responses)):
            discovered = _discover_remote_files("github", "2" * 40)
        self.assertEqual(len(discovered), 7)
        self.assertIn(("leikwan_tools/cli.py", "100644"), discovered)

    def test_validate_staged_files_rejects_bad_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "leikwan_tools").mkdir()
            (root / "install.sh").write_text("#!/usr/bin/env bash\necho ok\n", encoding="utf-8")
            (root / "leikwan_tools" / "__init__.py").write_text('__version__ = "0.1.3"\n', encoding="utf-8")
            _validate_staged_files(root, ["install.sh", "leikwan_tools/__init__.py"])

            (root / "leikwan_tools" / "bad.py").write_text("def oops(:\n", encoding="utf-8")
            with self.assertRaises(UpdateError):
                _validate_staged_files(root, ["leikwan_tools/bad.py"])

            (root / "bad.sh").write_text("#!/usr/bin/env bash\nif then fi\n", encoding="utf-8")
            with self.assertRaises(UpdateError):
                _validate_staged_files(root, ["bad.sh"])

    def test_build_install_args_and_perform_update(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            realm_bin = Path(td) / "realm"
            realm_bin.write_text("#!/bin/sh\n", encoding="utf-8")
            args_reused = _build_install_args(
                {
                    "config_dir": "/opt/cfg",
                    "state_dir": "/opt/state",
                    "realm": {"managed_install": False, "binary_path": str(realm_bin)},
                }
            )
            self.assertEqual(
                args_reused,
                ["--config-dir", "/opt/cfg", "--state-dir", "/opt/state", "--realm-bin", str(realm_bin)],
            )
            args_skip = _build_install_args(
                {
                    "config_dir": "/etc/leikwan_tools",
                    "state_dir": "/var/lib/leikwan_tools",
                    "realm": {"managed_install": False, "binary_path": ""},
                }
            )
            self.assertEqual(
                args_skip,
                ["--config-dir", "/etc/leikwan_tools", "--state-dir", "/var/lib/leikwan_tools", "--skip-realm-install"],
            )

        with patch("leikwan_tools.updater.platform.system", return_value="Linux"), patch(
            "leikwan_tools.updater.os.geteuid", return_value=1000
        ):
            with self.assertRaises(UpdateError) as ctx:
                perform_update()
            self.assertIn("root 权限", str(ctx.exception))

        info = UpdateCheckInfo(
            channel="github",
            channel_label="GitHub",
            repo="allen0039/vps_tools",
            branch="main",
            current_version="0.1.2",
            remote_version="0.1.3",
            commit_sha="c" * 40,
            short_sha="ccccccc",
            tree_sha="d" * 40,
            commit_message="Bump to 0.1.3",
            status="upgrade",
            update_available=True,
        )
        remote_blobs = {
            "install.sh": b"#!/usr/bin/env bash\necho ok\n",
            "bin/leikwan_tools": b"#!/usr/bin/env python3\nprint('ok')\n",
            "leikwan_tools/__init__.py": b'__version__ = "0.1.3"\n',
            "leikwan_tools/cli.py": b"def main():\n    return 0\n",
            "systemd/leikwan_tools-realm@.service": b"[Unit]\nDescription=x\n[Service]\nExecStart=/bin/true\n",
        }

        def fake_get_bytes(url: str, timeout: float = 20.0, accept: str = "*/*", *, channel: str = "") -> bytes:
            for rel, content in remote_blobs.items():
                if f"/{rel}?" in url or url.endswith(f"/{rel}"):
                    return content
            raise AssertionError(f"unexpected url: {url}")

        recorded_cmds = []

        def fake_run(cmd, capture_output=True, text=True, timeout=15):
            recorded_cmds.append(cmd)
            class Proc:
                def __init__(self, rc, out):
                    self.returncode = rc
                    self.stdout = out
                    self.stderr = ""

            if cmd[0] == "bash" and cmd[1] == "-n":
                return Proc(0, "")
            if cmd[0] == "bash" and cmd[1].endswith("install.sh"):
                return Proc(0, "installed\n")
            if cmd == ["/usr/local/bin/leikwan_tools", "--version"]:
                return Proc(0, "leikwan_tools 0.1.3\n")
            raise AssertionError(cmd)

        manifest = {
            "config_dir": "/opt/cfg",
            "state_dir": "/opt/state",
            "realm": {"managed_install": False, "binary_path": ""},
        }
        with (
            patch("leikwan_tools.updater.platform.system", return_value="Linux"),
            patch("leikwan_tools.updater.os.geteuid", return_value=0),
            patch("leikwan_tools.updater.check_for_update", return_value=info),
            patch(
                "leikwan_tools.updater._discover_remote_files",
                return_value=[(rel, "100755" if rel.endswith(".sh") or rel.startswith("bin/") else "100644") for rel in sorted(remote_blobs)],
            ),
            patch("leikwan_tools.updater._http_get_bytes", side_effect=fake_get_bytes),
            patch("leikwan_tools.updater.load_install_manifest", return_value=manifest),
            patch("leikwan_tools.updater.subprocess.run", side_effect=fake_run),
        ):
            res = perform_update(channel="github", current_version="0.1.2")

        self.assertEqual(res.installed_version, "0.1.3")
        self.assertTrue(res.version_changed)
        self.assertEqual(res.files_updated, 5)
        self.assertEqual(
            res.install_args,
            ["--config-dir", "/opt/cfg", "--state-dir", "/opt/state", "--skip-realm-install"],
        )
        install_cmd = [c for c in recorded_cmds if c[0] == "bash" and c[1].endswith("install.sh")][0]
        self.assertEqual(install_cmd[2:], res.install_args)

    def test_cli_update_check_and_apply(self) -> None:
        info = UpdateCheckInfo(
            channel="github",
            channel_label="GitHub",
            repo="allen0039/vps_tools",
            branch="main",
            current_version="0.1.2",
            remote_version="0.1.3",
            commit_sha="e" * 40,
            short_sha="eeeeeee",
            tree_sha="f" * 40,
            commit_message="Add feature",
            status="upgrade",
            update_available=True,
        )
        buf = io.StringIO()
        with patch("leikwan_tools.cli.check_for_update", return_value=info) as m_check, redirect_stdout(buf):
            self.assertEqual(main(["--json", "update", "--check"]), 0)
        m_check.assert_called_once_with(channel="github", timeout=20.0)
        parsed = json.loads(buf.getvalue())
        self.assertEqual(parsed["remote_version"], "0.1.3")
        self.assertTrue(parsed["update_available"])

        res = UpdateResult(
            channel="gitee",
            channel_label="Gitee",
            repo="allen0039/vps_tools",
            branch="main",
            commit_sha="e" * 40,
            short_sha="eeeeeee",
            previous_version="0.1.2",
            remote_version="0.1.3",
            installed_version="0.1.3",
            files_updated=10,
            install_args=[],
            version_changed=True,
        )
        buf2 = io.StringIO()
        with patch("leikwan_tools.cli.perform_update", return_value=res) as m_upd, redirect_stdout(buf2):
            self.assertEqual(main(["update", "--channel", "gitee"]), 0)
        m_upd.assert_called_once_with(channel="gitee", timeout=20.0)
        self.assertIn("已从 v0.1.2 更新到 v0.1.3", buf2.getvalue())


class TestDdnsSubsystem(unittest.TestCase):
    def setUp(self) -> None:
        self.base_cfg_toml = (REPO_ROOT / "examples" / "config.example.toml").read_text(encoding="utf-8")

    def test_ddns_config_validation_and_both_toml_parsers(self) -> None:
        # Backward compatibility: existing configs without [ddns] load cleanly with ddns disabled
        g_no_ddns = parse_global_config_dict(loads_toml(self.base_cfg_toml))
        self.assertFalse(g_no_ddns.ddns.enabled)
        self.assertEqual(g_no_ddns.ddns.profiles, {})

        ddns_toml = (
            self.base_cfg_toml
            + """
[ddns]
enabled = true
interval_seconds = 120
verify_interval_seconds = 600
probe_target = "2400:3200::1"
probe_timeout_seconds = 1

[ddns.ct]
enabled = true
interface = "eth0"
provider = "cloudflare"
record_type = "AAAA"
zone = "example.com"
host = "ct"
credential_file = "/etc/leikwan_tools/secrets/ddns-ct.env"

[ddns.cu]
enabled = true
interface = "eth1"
provider = "dnspod"
record_type = "AAAA"
zone = "example.com"
host = "cu"
ttl = 300
record_line = "联通"
credential_file = "/etc/leikwan_tools/secrets/ddns-cu.env"
"""
        )
        d1 = loads_toml(ddns_toml)
        d2 = _fallback_loads(ddns_toml)
        self.assertEqual(d1, d2)
        gcfg = parse_global_config_dict(d2)
        self.assertTrue(gcfg.ddns.enabled)
        self.assertEqual(gcfg.ddns.profiles["ct"].isp, "ct")
        self.assertEqual(gcfg.ddns.profiles["ct"].fqdn, "ct.example.com")
        self.assertEqual(gcfg.ddns.profiles["cu"].isp, "cu")
        self.assertEqual(gcfg.ddns.profiles["cu"].ttl, 300)
        self.assertEqual(gcfg.ddns.profiles["cu"].record_line, "联通")

        # Reject A record explicitly
        bad_a = loads_toml(ddns_toml)
        bad_a["ddns"]["ct"]["record_type"] = "A"
        with self.assertRaises(ConfigError) as ctx_a:
            parse_global_config_dict(bad_a)
        self.assertIn("仅支持 IPv6 AAAA", str(ctx_a.exception))

        # Reject plaintext secret in config.toml
        bad_secret = loads_toml(ddns_toml)
        bad_secret["ddns"]["ct"]["token"] = "cf-secret-token"
        with self.assertRaises(ConfigError) as ctx_sec:
            parse_global_config_dict(bad_secret)
        self.assertIn("credential_file", str(ctx_sec.exception))

        # Reject duplicate zone+host+record_type even across different host notations ("ct" vs "ct.example.com.")
        bad_dup = loads_toml(ddns_toml)
        bad_dup["ddns"]["cu"]["host"] = "ct.example.com."
        with self.assertRaises(ConfigError) as ctx_dup:
            parse_global_config_dict(bad_dup)
        self.assertIn("冲突", str(ctx_dup.exception))

        # Do NOT fall back to ingress.default_domain when zone is missing
        bad_no_zone = loads_toml(ddns_toml)
        del bad_no_zone["ddns"]["ct"]["zone"]
        with self.assertRaises(ConfigError) as ctx_nz:
            parse_global_config_dict(bad_no_zone)
        self.assertIn("不得复用 [ingress].default_domain", str(ctx_nz.exception))

    def test_ipv6_candidate_filtering_classification_and_probing(self) -> None:
        ip_output = """
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000
    inet6 240e:3b4:1::dead/64 scope global deprecated
       valid_lft 100sec preferred_lft 0sec
    inet6 240e:3b4:1::bad1/64 scope global tentative
       valid_lft 3600sec preferred_lft 3600sec
    inet6 240e:3b4:1::bad2/64 scope global dadfailed
       valid_lft 3600sec preferred_lft 3600sec
    inet6 240e:3b4:1::zero/64 scope global dynamic
       valid_lft 3600sec preferred_lft 0sec
    inet6 240e:3b4:1::10/64 scope global dynamic noprefixroute
       valid_lft 2591990sec preferred_lft 604790sec
    inet6 240e:3b4:1::20/64 scope global dynamic
       valid_lft 2591990sec preferred_lft 604790sec
    inet6 2408:820c:1::30/64 scope global dynamic
       valid_lft 2591990sec preferred_lft 604790sec
    inet6 2409:8000::1/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fd00::1/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::1/64 scope link
       valid_lft forever preferred_lft forever
    inet6 not-an-ipv6/64 scope global
       valid_lft forever preferred_lft forever
"""
        ct_cands, ct_filtered = parse_ip6_addr_candidates(ip_output, "ct")
        self.assertEqual(ct_cands, ["240e:3b4:1::10", "240e:3b4:1::20"])
        reasons = {f.raw: f.reason for f in ct_filtered}
        self.assertIn("deprecated", reasons["240e:3b4:1::dead/64"])
        self.assertIn("tentative", reasons["240e:3b4:1::bad1/64"])
        self.assertIn("dadfailed", reasons["240e:3b4:1::bad2/64"])
        self.assertIn("preferred_lft 为 0", reasons["240e:3b4:1::zero/64"])
        self.assertIn("联通", reasons["2408:820c:1::30"])
        self.assertIn("忽略", reasons["2409:8000::1"])
        self.assertIn("非公网全局", reasons["fd00::1/64"])
        self.assertIn("scope link", reasons["fe80::1/64"])
        self.assertIn("不可解析为合法 IPv6", reasons["not-an-ipv6/64"])

        # Prefix classification is independent of interface name
        self.assertEqual(classify_ipv6_isp("240e:1234::1"), "ct")
        self.assertEqual(classify_ipv6_isp("2408:5678::1"), "cu")
        self.assertIsNone(classify_ipv6_isp("2409:8000::1"))

        # RTT parser handles both Linux iputils and single-line ping outputs
        self.assertEqual(parse_ping_rtt_ms("rtt min/avg/max/mdev = 11.200/14.500/18.100/2.000 ms"), 14.5)
        self.assertEqual(parse_ping_rtt_ms("64 bytes from 2400:3200::1: time=9.42 ms"), 9.42)

        gcfg = parse_global_config_dict(
            loads_toml(
                self.base_cfg_toml
                + """
[ddns]
enabled = true
probe_target = "2400:3200::1"
probe_timeout_seconds = 1

[ddns.ct]
enabled = true
interface = "eth0"
provider = "cloudflare"
zone = "example.com"
host = "ct"
credential_file = "/tmp/ct.env"

[ddns.cu]
enabled = true
interface = "eth1"
provider = "cloudflare"
zone = "example.com"
host = "cu"
credential_file = "/tmp/cu.env"
"""
            )
        )

        executed_cmds = []

        def fake_run_cmd(cmd, timeout=15.0):
            executed_cmds.append(cmd)
            class Res:
                def __init__(self, rc, out, err=""):
                    self.returncode = rc
                    self.stdout = out
                    self.stderr = err

            if cmd[:3] == ["ip", "-6", "addr"] and "eth0" in cmd:
                return Res(0, ip_output)
            if cmd[:3] == ["ip", "-6", "addr"] and "eth1" in cmd:
                return Res(
                    0,
                    "3: eth1    inet6 2408:820c:1::99/64 scope global \\       valid_lft forever preferred_lft forever\n",
                )
            if cmd[0] == "ping":
                src = cmd[cmd.index("-I") + 1]
                self.assertNotIn("/", src)  # Never pass CIDR to ping!
                if src == "240e:3b4:1::10":
                    return Res(0, "rtt min/avg/max/mdev = 28.1/28.1/28.1/0.0 ms\n")
                if src == "240e:3b4:1::20":
                    return Res(0, "rtt min/avg/max/mdev = 9.3/9.3/9.3/0.0 ms\n")
                if src == "2408:820c:1::99":
                    return Res(1, "", "100% packet loss")
            raise AssertionError(cmd)

        with patch("leikwan_tools.ddns.run_cmd", side_effect=fake_run_cmd):
            res_ct = inspect_ddns_profile(gcfg, gcfg.ddns.profiles["ct"])
            res_cu = inspect_ddns_profile(gcfg, gcfg.ddns.profiles["cu"])

        # Non-destructive: never calls `ip -6 addr del`
        self.assertFalse(any("del" in c for c in executed_cmds))
        # Picks lowest RTT reachable candidate for CT
        self.assertEqual(res_ct.selected_ip, "240e:3b4:1::20")
        self.assertEqual(res_ct.selected_rtt_ms, 9.3)
        # Failed probe for CU returns empty IP
        self.assertEqual(res_cu.selected_ip, "")
        self.assertFalse(res_cu.candidates[0].probe_ok)

    def test_credential_permissions_cf_modes_and_secret_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cred = Path(td) / "ddns.env"
            cred.write_text('CF_API_TOKEN="super-secret-cf-token-12345"\n', encoding="utf-8")
            os.chmod(cred, 0o644)
            with self.assertRaises(DdnsError) as ctx_perm:
                load_credential_file(str(cred))
            self.assertIn("chmod 600", str(ctx_perm.exception))

            os.chmod(cred, 0o600)
            kv, sec_vals = load_credential_file(str(cred))
            self.assertEqual(kv["CF_API_TOKEN"], "super-secret-cf-token-12345")
            self.assertIn("super-secret-cf-token-12345", sec_vals)

            link = Path(td) / "link.env"
            link.symlink_to(cred)
            with self.assertRaises(DdnsError):
                load_credential_file(str(link))

        prof = DdnsProfileConfig(
            name="ct",
            enabled=True,
            isp="ct",
            interface="eth0",
            provider="cloudflare",
            zone="example.com",
            host="ct",
            credential_file="/etc/leikwan_tools/secrets/ct.env",
        )
        cf = CloudflareProvider()
        h_tok = cf._resolve_headers(prof, {"CF_API_TOKEN": "tok123"})
        self.assertEqual(h_tok["Authorization"], "Bearer tok123")
        h_gk = cf._resolve_headers(prof, {"CF_EMAIL": "a@b.com", "CF_GLOBAL_API_KEY": "gk123"})
        self.assertEqual(h_gk["X-Auth-Key"], "gk123")
        with self.assertRaises(DdnsError):
            cf._resolve_headers(prof, {"CF_API_TOKEN": "tok123", "CF_EMAIL": "a@b.com", "CF_GLOBAL_API_KEY": "gk123"})

        redacted = redact_url("https://user:pass@hook.example.com/webhook/my-secret-path?token=abc999&ip=240e::1")
        self.assertNotIn("pass", redacted)
        self.assertNotIn("abc999", redacted)
        self.assertNotIn("my-secret-path", redacted)
        self.assertIn("***@hook.example.com", redacted)

    def test_cloudflare_provider_lifecycle_and_dedup(self) -> None:
        self.assertEqual(normalize_ddns_fqdn("example.com", "@"), "example.com")
        self.assertEqual(normalize_ddns_fqdn("example.com", ""), "example.com")
        self.assertEqual(normalize_ddns_fqdn("example.com", "example.com."), "example.com")
        self.assertEqual(normalize_ddns_fqdn("example.com", "ct"), "ct.example.com")
        self.assertEqual(normalize_ddns_fqdn("example.com", "ct.example.com."), "ct.example.com")

        prof = DdnsProfileConfig(
            name="ct",
            enabled=True,
            isp="ct",
            interface="eth0",
            provider="cloudflare",
            zone="example.com",
            host="ct",
            credential_file="/tmp/cf.env",
        )
        cf = CloudflareProvider()
        creds = {"CF_API_TOKEN": "cf-secret-token"}
        calls = []

        def fake_http_json(method, url, headers=None, body=None, timeout=15.0, secrets_values=()):
            calls.append((method, url, json.loads(body.decode("utf-8")) if body else None))
            if method == "GET" and "/zones?name=" in url:
                return 200, {"success": True, "result": [{"id": "zone-1"}]}
            if method == "GET" and "/dns_records?" in url:
                return 200, {
                    "success": True,
                    "result": [
                        {"id": "rec-1", "content": "240e::1", "proxied": False},
                        {"id": "rec-dup", "content": "240e::2", "proxied": False},
                    ],
                }
            if method == "DELETE":
                return 200, {"success": True, "result": {"id": "rec-dup"}}
            if method == "PUT":
                return 200, {"success": True, "result": {"id": "rec-1"}}
            if method == "POST":
                return 200, {"success": True, "result": {"id": "rec-new"}}
            raise AssertionError((method, url))

        with patch("leikwan_tools.ddns._http_json", side_effect=fake_http_json):
            res_upd = cf.sync_record(prof, "240e::99", creds)
        self.assertEqual(res_upd.action, "updated")
        self.assertEqual(res_upd.deleted_duplicates, ["rec-dup"])
        put_payload = [c[2] for c in calls if c[0] == "PUT"][0]
        self.assertFalse(put_payload["proxied"])
        self.assertEqual(put_payload["name"], "ct.example.com")
        self.assertEqual(put_payload["content"], "240e::99")

        # Unchanged IP skips PUT/POST
        def fake_http_noop(method, url, headers=None, body=None, timeout=15.0, secrets_values=()):
            if method == "GET" and "/zones?name=" in url:
                return 200, {"success": True, "result": [{"id": "zone-1"}]}
            if method == "GET" and "/dns_records?" in url:
                return 200, {"success": True, "result": [{"id": "rec-1", "content": "240e::99", "proxied": False}]}
            raise AssertionError((method, url))

        with patch("leikwan_tools.ddns._http_json", side_effect=fake_http_noop):
            res_noop = cf.sync_record(prof, "240e::99", creds)
        self.assertEqual(res_noop.action, "noop")

        # Empty records creates via POST
        post_calls = []

        def fake_http_create(method, url, headers=None, body=None, timeout=15.0, secrets_values=()):
            post_calls.append(method)
            if method == "GET" and "/zones?name=" in url:
                return 200, {"success": True, "result": [{"id": "zone-1"}]}
            if method == "GET" and "/dns_records?" in url:
                return 200, {"success": True, "result": []}
            if method == "POST":
                return 200, {"success": True, "result": {"id": "rec-created"}}
            raise AssertionError((method, url))

        with patch("leikwan_tools.ddns._http_json", side_effect=fake_http_create):
            res_create = cf.sync_record(prof, "240e::99", creds)
        self.assertEqual(res_create.action, "created")
        self.assertEqual(res_create.record_id, "rec-created")
        self.assertIn("POST", post_calls)

    def test_dnspod_alidns_and_webhook_providers(self) -> None:
        # 1) DNSPod: Create on code 10, noop on same IP, Modify on changed IP with custom TTL & line
        dp_prof = DdnsProfileConfig(
            name="cu",
            enabled=True,
            isp="cu",
            interface="eth1",
            provider="dnspod",
            zone="example.com",
            host="cu",
            ttl=300,
            record_line="联通",
            credential_file="/tmp/dp.env",
        )
        dp = DnspodProvider()
        dp_creds = {"DNSPOD_TOKEN": "12345,secret-dp-token"}
        dp_calls = []

        def fake_dp_json(method, url, headers=None, body=None, timeout=15.0, secrets_values=()):
            self.assertTrue(url.startswith("https://dnsapi.cn/"))
            dp_calls.append((url, body.decode("utf-8")))
            if url.endswith("/Record.List"):
                return 200, {"status": {"code": "10", "message": "No records"}}
            if url.endswith("/Record.Create"):
                return 200, {"status": {"code": "1"}, "record": {"id": "dp-1"}}
            raise AssertionError(url)

        with patch("leikwan_tools.ddns._http_json", side_effect=fake_dp_json):
            dp_created = dp.sync_record(dp_prof, "2408::1", dp_creds)
        self.assertEqual(dp_created.action, "created")
        self.assertEqual(dp_created.record_id, "dp-1")
        self.assertIn("ttl=300", dp_calls[1][1])

        def fake_dp_modify(method, url, headers=None, body=None, timeout=15.0, secrets_values=()):
            if url.endswith("/Record.List"):
                return 200, {"status": {"code": "1"}, "records": [{"id": "dp-1", "name": "cu", "type": "AAAA", "value": "2408::1"}]}
            if url.endswith("/Record.Modify"):
                return 200, {"status": {"code": "1"}, "record": {"id": "dp-1"}}
            raise AssertionError(url)

        with patch("leikwan_tools.ddns._http_json", side_effect=fake_dp_modify):
            self.assertEqual(dp.sync_record(dp_prof, "2408::1", dp_creds).action, "noop")
            self.assertEqual(dp.sync_record(dp_prof, "2408::2", dp_creds).action, "updated")

        # 2) AliDNS: RFC3986 encoding + deterministic HMAC-SHA1 signature + exact RR filtering + CRUD
        self.assertEqual(_alidns_percent_encode("a b~*"), "a%20b~%2A")
        signed_url = _build_alidns_signed_url(
            {"Action": "DescribeDomainRecords", "DomainName": "example.com"},
            "testid",
            "testsecret",
            timestamp="2016-03-29T12:00:00Z",
            nonce="123456",
        )
        self.assertTrue(signed_url.startswith("https://alidns.aliyuncs.com/?"))
        self.assertIn("&Signature=", signed_url)
        # Compute independent HMAC-SHA1 check for the exact canonicalized string
        import base64 as _b64
        import hashlib as _hl
        import hmac as _hm
        import urllib.parse as _up

        qs_part, sig_part = signed_url.split("?", 1)[1].rsplit("&Signature=", 1)
        expected_sig = _b64.b64encode(
            _hm.new(b"testsecret&", f"GET&%2F&{_up.quote(qs_part, safe='-_.~')}".encode(), _hl.sha1).digest()
        ).decode()
        self.assertEqual(_up.unquote(sig_part), expected_sig)

        ali_prof = DdnsProfileConfig(
            name="ct",
            enabled=True,
            isp="ct",
            interface="eth0",
            provider="alidns",
            zone="example.com",
            host="ct",
            credential_file="/tmp/ali.env",
        )
        ali = AliDnsProvider()
        ali_creds = {"ALIDNS_ACCESS_KEY_ID": "testid", "ALIDNS_ACCESS_KEY_SECRET": "testsecret"}

        def fake_ali_create(method, url, headers=None, body=None, timeout=15.0, secrets_values=()):
            self.assertTrue(url.startswith("https://alidns.aliyuncs.com/"))
            if "Action=DescribeDomainRecords" in url:
                # Include fuzzy match ct2 that must be ignored for RR="ct"!
                return 200, {
                    "DomainRecords": {
                        "Record": [{"RecordId": "other", "RR": "ct2", "Type": "AAAA", "Value": "240e::999"}]
                    }
                }
            if "Action=AddDomainRecord" in url:
                return 200, {"RecordId": "ali-new"}
            raise AssertionError(url)

        with patch("leikwan_tools.ddns._http_json", side_effect=fake_ali_create):
            ali_created = ali.sync_record(ali_prof, "240e::10", ali_creds)
        self.assertEqual(ali_created.action, "created")
        self.assertEqual(ali_created.record_id, "ali-new")

        def fake_ali_update(method, url, headers=None, body=None, timeout=15.0, secrets_values=()):
            if "Action=DescribeDomainRecords" in url:
                return 200, {
                    "DomainRecords": {
                        "Record": [{"RecordId": "ali-1", "RR": "ct", "Type": "AAAA", "Value": "240e::10"}]
                    }
                }
            if "Action=UpdateDomainRecord" in url:
                return 200, {"RecordId": "ali-1"}
            raise AssertionError(url)

        with patch("leikwan_tools.ddns._http_json", side_effect=fake_ali_update):
            self.assertEqual(ali.sync_record(ali_prof, "240e::10", ali_creds).action, "noop")
            self.assertEqual(ali.sync_record(ali_prof, "240e::20", ali_creds).action, "updated")

        # 3) Webhook: {ip} substitution, accepts all 2xx, rejects 500 with redacted URL
        wh_prof = DdnsProfileConfig(
            name="cu",
            enabled=True,
            isp="cu",
            interface="eth1",
            provider="webhook",
            credential_file="/tmp/wh.env",
        )
        wh = WebhookProvider()
        wh_creds = {"WEBHOOK_URL": "https://hook.example.com/ddns?token=supersecret999&ip={ip}"}
        seen_urls = []

        def fake_wh_req(method, url, headers=None, body=None, timeout=15.0, secrets_values=()):
            seen_urls.append(url)
            if len(seen_urls) == 1:
                return 204, b""
            if len(seen_urls) == 2:
                return 201, b"ok"
            return 500, b"err"

        with patch("leikwan_tools.ddns._http_request", side_effect=fake_wh_req):
            r204 = wh.sync_record(wh_prof, "2408::55", wh_creds, secrets_values=["supersecret999"])
            r201 = wh.sync_record(wh_prof, "2408::55", wh_creds, secrets_values=["supersecret999"])
            self.assertEqual(r204.action, "triggered")
            self.assertEqual(r201.action, "triggered")
            self.assertNotIn("supersecret999", r204.detail)
            with self.assertRaises(DdnsProviderError) as ctx_500:
                wh.sync_record(wh_prof, "2408::55", wh_creds, secrets_values=["supersecret999"])
            self.assertNotIn("supersecret999", str(ctx_500.exception))
        self.assertEqual(seen_urls[0], "https://hook.example.com/ddns?token=supersecret999&ip=2408::55")

    def test_ddns_cache_periodic_verify_failure_isolation_and_uninstall(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            state_dir = base / "state"
            cfg_dir = base / "cfg"
            secrets_dir = cfg_dir / "secrets"
            cfg_dir.mkdir(parents=True)
            secrets_dir.mkdir(parents=True)
            (state_dir / "realm").mkdir(parents=True)
            (state_dir / "state").mkdir(parents=True)

            ct_cred = secrets_dir / "ct.env"
            ct_cred.write_text("CF_API_TOKEN=cf-secret-xyz\n", encoding="utf-8")
            os.chmod(ct_cred, 0o600)
            cu_cred = secrets_dir / "cu.env"
            cu_cred.write_text("WEBHOOK_URL=https://hook.example.com/u?token=wh-secret-abc&ip={ip}\n", encoding="utf-8")
            os.chmod(cu_cred, 0o600)

            cfg_file = cfg_dir / "config.toml"
            cfg_file.write_text(
                f'[tool]\nrules_dir = "{cfg_dir / "rules.d"}"\nstate_dir = "{state_dir}"\n'
                f'lock_file = "{base / "tool.lock"}"\n'
                '[lines.9929]\ninterface = "eth0"\nsource_ip = "10.7.0.146"\ngateway = "10.7.0.1"\ntable = 101\n'
                '[ddns]\nenabled = true\nverify_interval_seconds = 600\n'
                '[ddns.ct]\nenabled = true\ninterface = "eth0"\nprovider = "cloudflare"\nzone = "example.com"\nhost = "ct"\n'
                f'credential_file = "{ct_cred}"\n'
                '[ddns.cu]\nenabled = true\ninterface = "eth1"\nprovider = "webhook"\n'
                f'credential_file = "{cu_cred}"\n',
                encoding="utf-8",
            )
            gcfg = load_global_config(str(cfg_file))

            # Run 1: Initial sync for both CT and CU
            sync_calls = []

            class FakeCF:
                supports_remote_verify = True
                def sync_record(self, prof, ip, creds, timeout=15.0, secrets_values=()):
                    sync_calls.append(("ct", ip))
                    from leikwan_tools.ddns import ProviderSyncResult
                    return ProviderSyncResult("created", "cf-id-1", ip, [], "ok")

            class FakeWH:
                supports_remote_verify = False
                def sync_record(self, prof, ip, creds, timeout=15.0, secrets_values=()):
                    sync_calls.append(("cu", ip))
                    from leikwan_tools.ddns import ProviderSyncResult
                    return ProviderSyncResult("triggered", "", ip, [], "ok")

            def fake_inspect(cfg, prof):
                from leikwan_tools.ddns import ProfileInspectResult
                ip_val = "240e::10" if prof.name == "ct" else "2408::20"
                return ProfileInspectResult(prof.name, True, prof.isp, prof.interface, prof.provider, "AAAA", prof.zone, prof.host, prof.fqdn, "2400:3200::1", 1, ip_val, 5.0, [], [])

            with (
                patch("leikwan_tools.ddns.inspect_ddns_profile", side_effect=fake_inspect),
                patch("leikwan_tools.ddns.get_ddns_provider", side_effect=lambda name: FakeCF() if name == "cloudflare" else FakeWH()),
                patch("leikwan_tools.ddns.time.time", return_value=1000.0),
            ):
                r1 = update_ddns(gcfg)
            self.assertTrue(r1["ok"])
            self.assertEqual(sync_calls, [("ct", "240e::10"), ("cu", "2408::20")])

            # Run 2: Same IP within 600s -> both skipped_cached
            sync_calls.clear()
            with (
                patch("leikwan_tools.ddns.inspect_ddns_profile", side_effect=fake_inspect),
                patch("leikwan_tools.ddns.get_ddns_provider", side_effect=lambda name: FakeCF() if name == "cloudflare" else FakeWH()),
                patch("leikwan_tools.ddns.time.time", return_value=1200.0),
            ):
                r2 = update_ddns(gcfg)
            self.assertEqual(sync_calls, [])
            self.assertEqual([x["action"] for x in r2["results"]], ["skipped_cached", "skipped_cached"])

            # Run 3: Same IP after >600s -> CT runs remote verify, Webhook NEVER runs remote verify!
            sync_calls.clear()
            with (
                patch("leikwan_tools.ddns.inspect_ddns_profile", side_effect=fake_inspect),
                patch("leikwan_tools.ddns.get_ddns_provider", side_effect=lambda name: FakeCF() if name == "cloudflare" else FakeWH()),
                patch("leikwan_tools.ddns.time.time", return_value=1700.0),
            ):
                r3 = update_ddns(gcfg)
            self.assertEqual(sync_calls, [("ct", "240e::10")])
            self.assertEqual(r3["results"][1]["action"], "skipped_cached")

            # Run 4: CT fails while CU changes IP -> CT preserves last_success_ip=240e::10, CU updates independently
            class FailCF:
                supports_remote_verify = True
                def sync_record(self, prof, ip, creds, timeout=15.0, secrets_values=()):
                    raise DdnsProviderError("API failed with secret cf-secret-xyz")

            def fake_inspect_changed(cfg, prof):
                from leikwan_tools.ddns import ProfileInspectResult
                ip_val = "240e::99" if prof.name == "ct" else "2408::88"
                return ProfileInspectResult(prof.name, True, prof.isp, prof.interface, prof.provider, "AAAA", prof.zone, prof.host, prof.fqdn, "2400:3200::1", 1, ip_val, 5.0, [], [])

            with (
                patch("leikwan_tools.ddns.inspect_ddns_profile", side_effect=fake_inspect_changed),
                patch("leikwan_tools.ddns.get_ddns_provider", side_effect=lambda name: FailCF() if name == "cloudflare" else FakeWH()),
                patch("leikwan_tools.ddns.time.time", return_value=1800.0),
            ):
                r4 = update_ddns(gcfg)
            self.assertFalse(r4["ok"])
            self.assertEqual(r4["results"][0]["action"], "error")
            self.assertNotIn("cf-secret-xyz", r4["results"][0]["error"])
            self.assertEqual(r4["results"][1]["action"], "triggered")
            ct_state = json.loads((state_dir / "ddns" / "ct.json").read_text(encoding="utf-8"))
            self.assertEqual(ct_state["last_success_ip"], "240e::10")
            self.assertNotIn("cf-secret-xyz", ct_state["last_error"])

            # Run 5: Empty selected IP -> skipped_no_ip, preserves last_success_ip
            def fake_inspect_empty(cfg, prof):
                from leikwan_tools.ddns import ProfileInspectResult
                return ProfileInspectResult(prof.name, True, prof.isp, prof.interface, prof.provider, "AAAA", prof.zone, prof.host, prof.fqdn, "2400:3200::1", 1, "", None, [], [])

            with patch("leikwan_tools.ddns.inspect_ddns_profile", side_effect=fake_inspect_empty):
                r5 = update_ddns(gcfg, profile_name="ct")
            self.assertEqual(r5["results"][0]["action"], "skipped_no_ip")
            ct_state_after = json.loads((state_dir / "ddns" / "ct.json").read_text(encoding="utf-8"))
            self.assertEqual(ct_state_after["last_success_ip"], "240e::10")

            # Uninstall preserves foreign file in ddns/ and user secrets in secrets/, cleans owned state JSONs
            foreign_ddns = state_dir / "ddns" / "foreign.json"
            foreign_ddns.write_text('{"other": true}\n', encoding="utf-8")
            lib_dir = base / "lib"
            (lib_dir / "leikwan_tools").mkdir(parents=True)
            write_install_artifacts(
                install_lib_dir=str(lib_dir),
                config_dir=str(cfg_dir),
                state_dir=str(state_dir),
                config_file=str(cfg_file),
                lock_file=str(base / "tool.lock"),
                realm_bin_path="/usr/local/bin/realm",
                realm_managed_install=False,
                example_files=[],
                created_config_file=True,
            )
            with patch("leikwan_tools.ownership.TEMPLATE_UNIT_PATH", str(base / "missing.service")), patch(
                "leikwan_tools.ownership.BIN_LAUNCHER_PATH", str(base / "missing-bin")
            ), patch("leikwan_tools.ownership.SHORTCUT_PATH", str(base / "missing-lq")), patch(
                "leikwan_tools.ownership.systemd_daemon_reload"
            ):
                uninstall_tool(
                    purge=False,
                    config_dir_arg=str(cfg_dir),
                    state_dir_arg=str(state_dir),
                    install_lib_dir=str(lib_dir),
                    manifest_path=str(lib_dir / "install-manifest.json"),
                )
            self.assertFalse((state_dir / "ddns" / "ct.json").exists())
            self.assertFalse((state_dir / "ddns" / "cu.json").exists())
            self.assertTrue(foreign_ddns.is_file())
            self.assertTrue(ct_cred.is_file())

    def test_cli_ddns_subcommands_and_json_output(self) -> None:
        from leikwan_tools.ddns import FilteredAddress, ProbedCandidate, ProfileInspectResult

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            state_dir = base / "state"
            cred = base / "ct.env"
            cred.write_text("CF_API_TOKEN=cli-secret-9876\n", encoding="utf-8")
            os.chmod(cred, 0o600)
            cfg_file = base / "config.toml"
            cfg_file.write_text(
                f'[tool]\nrules_dir = "{base / "rules.d"}"\nstate_dir = "{state_dir}"\n'
                f'lock_file = "{base / "lock"}"\n'
                '[lines.9929]\ninterface = "eth0"\nsource_ip = "10.7.0.146"\ngateway = "10.7.0.1"\ntable = 101\n'
                '[ddns]\nenabled = true\n'
                '[ddns.ct]\nenabled = true\ninterface = "eth0"\nprovider = "cloudflare"\nzone = "example.com"\nhost = "ct"\n'
                f'credential_file = "{cred}"\n',
                encoding="utf-8",
            )

            insp = ProfileInspectResult(
                profile="ct",
                enabled=True,
                isp="ct",
                interface="eth0",
                provider="cloudflare",
                record_type="AAAA",
                zone="example.com",
                host="ct",
                fqdn="ct.example.com",
                probe_target="2400:3200::1",
                probe_timeout_seconds=1,
                selected_ip="240e::10",
                selected_rtt_ms=11.5,
                candidates=[ProbedCandidate("240e::10", "ct", "eth0", True, 11.5, "RTT=11.50ms")],
                filtered_out=[FilteredAddress("240e::dead/64", "deprecated 地址")],
            )
            out_insp = io.StringIO()
            with patch("leikwan_tools.ddns.inspect_ddns_profile", return_value=insp), redirect_stdout(out_insp):
                self.assertEqual(main(["--config", str(cfg_file), "ddns", "inspect", "--profile", "ct"]), 0)
            self.assertIn("仅支持 IPv6 AAAA", out_insp.getvalue())
            self.assertIn("240e::10", out_insp.getvalue())
            self.assertNotIn("cli-secret-9876", out_insp.getvalue())

            out_test = io.StringIO()
            with (
                patch("leikwan_tools.ddns.inspect_ddns_profile", return_value=insp),
                patch.object(CloudflareProvider, "query_remote", return_value={"fqdn": "ct.example.com", "record_count": 1, "record_id": "r1", "remote_ip": "240e::10"}),
                redirect_stdout(out_test),
            ):
                self.assertEqual(main(["--config", str(cfg_file), "ddns", "test", "--profile", "ct"]), 0)
            self.assertIn("凭据校验   : 通过", out_test.getvalue())
            self.assertNotIn("cli-secret-9876", out_test.getvalue())

            out_upd = io.StringIO()
            with (
                patch("leikwan_tools.ddns.inspect_ddns_profile", return_value=insp),
                patch.object(
                    CloudflareProvider,
                    "sync_record",
                    side_effect=lambda *a, **kw: __import__("leikwan_tools.ddns", fromlist=["ProviderSyncResult"]).ProviderSyncResult("updated", "r1", "240e::10", [], "ok"),
                ),
                redirect_stdout(out_upd),
            ):
                self.assertEqual(main(["--config", str(cfg_file), "--json", "ddns", "update", "--profile", "ct"]), 0)
            upd_json = json.loads(out_upd.getvalue())
            self.assertTrue(upd_json["ok"])
            self.assertEqual(upd_json["results"][0]["selected_ip"], "240e::10")

            out_st = io.StringIO()
            with redirect_stdout(out_st):
                self.assertEqual(main(["--config", str(cfg_file), "ddns", "status"]), 0)
            self.assertIn("240e::10", out_st.getvalue())
            self.assertNotIn("cli-secret-9876", out_st.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
