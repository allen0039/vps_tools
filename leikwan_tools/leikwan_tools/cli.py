"""Command-line interface for leikwan_tools."""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from datetime import datetime, timezone
from ipaddress import IPv4Address, ip_address
import json
import os
from pathlib import Path
import re
import socket
import sys
from typing import Any, Dict, List, Optional

from . import (
    DEFAULT_INGRESS_DOMAIN,
    DEFAULT_STATE_DIR,
    MANAGED_REALM_BIN,
    __version__,
)
from .config import (
    DDNS_AUTO_INTERFACE,
    DDNS_PROFILE_NAME_RE,
    VALID_DDNS_PROVIDERS,
    ConfigError,
    DdnsProfileConfig,
    GlobalConfig,
    RuleConfig,
    format_endpoint,
    load_global_config,
    load_rule_config,
    normalize_ddns_fqdn,
    parse_rule_config_dict,
    validate_ipv4,
    validate_ipv6,
)
from .ddns import (
    ISP_LABELS,
    DdnsError,
    ProfileInspectResult,
    inspect_ddns,
    inspect_ddns_profile,
    save_ddns_config,
    status_ddns,
    test_ddns_profile,
    update_ddns,
)
from .ingress import (
    DnsQueryResult,
    IngressError,
    check_fixed_ip_staleness,
    probe_candidate,
    protocol_preservation_notes,
    query_dns_a,
)
from .manager import (
    ApplyError,
    apply_rule,
    check_prereqs,
    delete_rule,
    disable_rule,
    list_managed_rules,
    plan_rule,
    select_rule_ingress_ip,
    status_rules,
    unselect_rule_ingress_ip,
    verify_startup_rule,
)
from .network import DEFAULT_DNS, network_command
from .ownership import (
    BIN_LAUNCHER_PATH,
    SHORTCUT_PATH,
    OwnershipError,
    ensure_safe_subpath,
    resolve_default_config_path,
    validate_rule_name,
)
from .realm import RealmError, install_realm_binary
from .routing import apply_routing, plan_routing
from .system import (
    LockTimeoutError,
    PUBLIC_ROUTE_PROBE_IPV6,
    PreflightError,
    SystemErrorBase,
    systemd_is_active,
    unit_name_for_rule,
)
from .updater import (
    DEFAULT_UPDATE_CHANNEL,
    UPDATE_CHANNELS,
    UpdateCheckInfo,
    UpdateError,
    UpdateResult,
    check_for_update,
    perform_update,
)

_MENU_ERRORS = (
    ConfigError,
    PreflightError,
    ApplyError,
    RealmError,
    IngressError,
    OwnershipError,
    LockTimeoutError,
    SystemErrorBase,
    UpdateError,
    DdnsError,
    OSError,
)


def _maybe_load_global(config_path: str) -> Optional[GlobalConfig]:
    if Path(config_path).is_file():
        return load_global_config(config_path)
    return None


def _resolve_rule_for_ingress(rule_arg: str, config_path: str) -> RuleConfig:
    """Resolve --rule from either a file path or a managed rule name."""
    p = Path(rule_arg)
    if p.is_file():
        return load_rule_config(str(p))
    validate_rule_name(rule_arg)
    global_cfg = load_global_config(config_path)
    rules_dir = Path(global_cfg.tool.rules_dir)
    stored = ensure_safe_subpath(rules_dir, rules_dir / f"{rule_arg}.toml")
    if not stored.is_file():
        raise ConfigError(f"未找到规则文件或已托管规则: {rule_arg!r}")
    return load_rule_config(str(stored), default_domain=global_cfg.ingress.default_domain)


def _print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def _print_plan(res: Dict[str, Any]) -> None:
    action_labels = {
        "CREATE": "新建",
        "UPDATE": "更新并重启",
        "UPDATE_METADATA": "仅更新客户端入口",
        "NOOP": "无变更",
    }
    action_zh = action_labels.get(res["action"], res["action"])
    line_info = res["line"]
    line_family = res.get("line_family") or line_info.get("family") or ("ipv6" if ":" in str(res["through"]) else "ipv4")
    gw_part = f", 网关={line_info['gateway']}" if line_info.get("gateway") else ""
    tbl_part = f", 表={line_info['table']}" if line_info.get("table") is not None else ""
    print(f"=== 变更预览 [{res['action']}]（{action_zh}） 转发: {res['rule_name']} ===")
    print(
        f"出口线路   : {line_info['name']} ({line_family.upper()}, 网卡={line_info['interface']}, "
        f"源IP={res['through']}{gw_part}{tbl_part})"
    )
    dial = format_endpoint(res["dial_hint"], res["public_port"])
    bound_in_iface = res.get("bound_listen_interface", "")
    listen_desc = f"{res['listen']} (入口网卡={bound_in_iface})" if bound_in_iface else res["listen"]
    print(f"客户端入口 : {dial} -> 本机监听 {listen_desc} -> 落地 {res['remote']}")
    print(f"systemd单元: {res['unit_name']}")
    print(f"Realm 版本 : {res['realm']['version']} ({res['realm']['origin']}) @ {res['realm']['path']}")
    print(f"路由校验   : {res['route_check']['command']}（仅内核查路，不代表落地 TCP 可达）")
    print(f"             {res['route_check']['raw_output']}")
    if res.get("return_route"):
        print(f"入口回程   : {res['return_route']}")
    if res.get("forced_non_dns"):
        print("覆盖标记   : 已通过 --allow-non-dns 显式强制覆盖固定公网 IP 校验")
    if res.get("stale_ip_warning"):
        print(f"警告       : {res['stale_ip_warning']}")
    print("将写入文件 :")
    for k, v in res["target_paths"].items():
        print(f"  - {k}: {v}")
    print("\n--- 生成的 Realm 配置预览 ---")
    print(res["rendered_realm_toml"].rstrip())


def _print_apply(res: Dict[str, Any]) -> None:
    label_map = {
        "created": "已创建并启用",
        "updated": "已更新并重启",
        "metadata-updated": "已更新客户端入口元数据（未重启 Realm）",
        "noop": "幂等跳过（配置与运行状态一致）",
    }
    label = label_map.get(res["status"], res["status"])
    bound_in_iface = res.get("bound_listen_interface", "")
    listen_desc = f"{res['listen']}@{bound_in_iface}" if bound_in_iface else res["listen"]
    print(f"[{label}] 规则={res['rule_name']} 单元={res['unit_name']} PID={res['main_pid']}")
    print(
        f"转发链路 : 客户端({format_endpoint(res['dial_addr'], res['public_port'])}) -> 本机({listen_desc}) "
        f"-> 经({res['through']}@{res['egress_interface']}) -> 落地({res['remote']})"
    )
    print(f"出口线路 : {res['line']} | Realm {res['realm_version']} ({res['realm_bin']})")
    if res.get("route_output"):
        print(f"路由实测 : {res['route_output']}（仅内核查路）")
    if res.get("forced_non_dns"):
        print("覆盖标记 : 已通过 --allow-non-dns 显式强制覆盖固定公网 IP")
    if res.get("stale_ip_warning"):
        print(f"入口警告 : {res['stale_ip_warning']}")


def _format_line_display(
    line_name: str,
    description: str = "",
    interface: str = "",
    source_ip: str = "",
) -> str:
    details = []
    if description:
        details.append(description)
    if interface and source_ip:
        details.append(f"{interface} / {source_ip}")
    elif interface:
        details.append(interface)
    if not details:
        return f"{line_name}（主配置未定义此线路）"
    return f"{line_name}（{' | '.join(details)}）"


def _format_rule_status_summary(item: Dict[str, Any]) -> str:
    active_state = item["active_state"]
    sub_state = item["sub_state"]
    if active_state == "active" and sub_state == "running":
        if item["listening_ok"]:
            return f"运行中（监听正常，PID={item['main_pid']}，重启={item['n_restarts']}）"
        return f"异常（进程运行中但监听端口异常，PID={item['main_pid']}，重启={item['n_restarts']}）"
    if not item["enabled"] and active_state in ("inactive", "dead"):
        return f"已暂停（未开机自启，状态={active_state}/{sub_state}）"
    return f"未运行（状态={active_state}/{sub_state}，重启={item['n_restarts']}）"


def _print_status_list(items: List[Dict[str, Any]]) -> None:
    if not items:
        print("当前没有已部署的托管规则（可进入「2. 转发规则管理 -> 2. 新建转发」添加）。")
        return
    for idx, item in enumerate(items):
        if idx > 0:
            print("-" * 72)
        dial = format_endpoint(item["dial_addr"], item["public_port"])
        autostart = "已开启" if item["enabled"] else "未开启"
        line_desc = _format_line_display(
            item["line"],
            item.get("line_description", ""),
            item["egress_interface"],
            item["through"],
        )
        bound_in_iface = item.get("listen_interface", "")
        listen_desc = f"{item['listen']} (入口网卡={bound_in_iface})" if bound_in_iface else item["listen"]
        print(f"转发名称   : {item['rule_name']}  ({item['description'] or '无备注'})")
        print(f"当前状态   : {_format_rule_status_summary(item)} | 开机自启: {autostart}")
        print(f"出口线路   : {line_desc}")
        print(f"客户端连接 : {dial}")
        print(f"本机监听   : {listen_desc}")
        print(
            f"转发路径   : 入口 {dial} -> 本机监听 {listen_desc} "
            f"-> 出口 {item['line']}({item['through']}@{item['egress_interface']}) -> 落地 {item['remote']}"
        )
        if item["ingress_domain"]:
            print(
                f"固定公网IP : {item['ingress_fixed_ip'] or '(未固定，使用域名解析)'}  "
                f"[域名: {item['ingress_domain']}]"
            )
        print(f"出口路由   : {'正常' if item['route_ok'] else '异常'}（仅内核查路，不代表落地 TCP 可达） | {item['route_detail']}")
        pending = item.get("pending_network", {})
        if pending.get("line_removed"):
            print(f"待应用     : 主配置已移除出口线路 {item['line']}")
        if "line" in pending:
            line = pending["line"]
            print(
                f"待应用出口 : {line['source_ip']}@{line['interface']} | "
                f"网关={line['gateway'] or '未指定'} | 表={line['table'] or '未指定'}"
            )
        if "listen_interface" in pending:
            print(f"待应用入口 : 监听网卡={pending['listen_interface'] or '未指定'}")
        print(f"运行服务   : Realm {item['realm_version']} @ {item['realm_bin']} | systemd={item['unit_name']}")
        if item.get("stale_ip_warning"):
            print(f"入口警告   : {item['stale_ip_warning']}")


def _cmd_ingress_query(args: argparse.Namespace) -> int:
    global_cfg = _maybe_load_global(args.config)
    domain = args.domain or (global_cfg.ingress.default_domain if global_cfg else DEFAULT_INGRESS_DOMAIN)
    dns_server = args.dns_server or (global_cfg.ingress.dns_server if global_cfg else "")
    port = args.port
    fixed_ip = ""

    if args.rule:
        rule = _resolve_rule_for_ingress(args.rule, args.config)
        if rule.direct_ipv6 and not args.domain:
            direct_port = rule.public_port if port is None else port
            endpoint = format_endpoint(rule.dial_addr, direct_port)
            if args.json:
                _print_json({"domain": "", "dial_address": endpoint, "port": direct_port, "candidates": []})
            else:
                print(f"公网 IPv6 直连入口 {endpoint}，可用 ingress verify --rule {rule.name} 验证。")
            return 0
        if not args.domain:
            domain = rule.ingress_domain
        if port is None:
            port = rule.public_port
        fixed_ip = rule.ingress_fixed_ip

    dns_res = query_dns_a(domain=domain, dns_server=dns_server, timeout=args.timeout)
    stale_warning = check_fixed_ip_staleness(fixed_ip, domain, dns_res)

    candidates: List[Dict[str, Any]] = []
    worst_tls_rc = 0
    for rec in dns_res.records:
        if port is not None:
            pr = probe_candidate(
                ip=rec.ip,
                port=port,
                in_dns=True,
                timeout=args.timeout,
                send_payload=args.verify_send or "",
                expect_pattern=args.verify_expect or "",
                tls=args.tls,
                tls_sni=args.tls_sni or "",
                tls_verify_cert=(True if args.tls_verify_cert else None),
                tls_insecure=args.tls_insecure,
                tls_cafile=args.tls_cafile or "",
            )
            if pr.tls_requested and pr.exit_code in (3, 4):
                worst_tls_rc = pr.exit_code
            candidates.append(
                {
                    "ip": rec.ip,
                    "ttl": rec.ttl,
                    "port": port,
                    "stage": pr.stage,
                    "tcp_reachable": pr.tcp_reachable,
                    "landing_verified": pr.landing_verified,
                    "rtt_ms": pr.rtt_ms,
                    "tls_status": pr.tls_status,
                    "cert_status": pr.cert_status,
                    "app_status": pr.app_status,
                    "detail": pr.detail,
                    "response_preview": pr.response_preview,
                    "exit_code": pr.exit_code,
                }
            )
        else:
            candidates.append(
                {
                    "ip": rec.ip,
                    "ttl": rec.ttl,
                    "port": None,
                    "stage": "DNS 候选",
                    "tcp_reachable": None,
                    "landing_verified": False,
                    "rtt_ms": None,
                    "tls_status": "未启用",
                    "cert_status": "未启用",
                    "app_status": "未校验",
                    "detail": "仅查询 DNS A 记录（未测端口连通性）",
                    "response_preview": "",
                    "exit_code": 0,
                }
            )

    payload = {
        "domain": domain,
        "resolver": dns_res.resolver,
        "queried_at_local": dns_res.queried_at_local,
        "queried_at_utc": dns_res.queried_at_utc,
        "dns_error": dns_res.error,
        "fixed_ip": fixed_ip,
        "stale_ip_warning": stale_warning,
        "port": port,
        "candidates": candidates,
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"查询域名   : {domain}")
        print(f"查询时间   : {dns_res.queried_at_local} ({dns_res.queried_at_utc})")
        print(f"解析器     : {dns_res.resolver}")
        if fixed_ip:
            print(f"当前固定IP : {fixed_ip}")
        if stale_warning:
            print(f"警告       : {stale_warning}")
        if dns_res.error and not dns_res.records:
            print(f"查询失败   : {dns_res.error}")
            return 1
        if not candidates:
            print("结果       : 未返回任何 IPv4 A 记录")
            return 0

        print("\n候选公网 IP 列表:")
        for idx, c in enumerate(candidates, start=1):
            ttl_str = f"TTL={c['ttl']}s" if c["ttl"] is not None else "TTL=未知"
            rtt_str = f"RTT={c['rtt_ms']}ms" if c["rtt_ms"] is not None else ""
            port_str = f":{c['port']}" if c["port"] else ""
            print(f"  {idx}. {c['ip']}{port_str}  [{c['stage']}]  ({ttl_str} {rtt_str}) - {c['detail']}")
            if c["tls_status"] != "未启用":
                print(f"     TLS={c['tls_status']} | 证书={c['cert_status']} | 应用={c['app_status']}")
            if c["response_preview"]:
                print(f"     回包预览: {c['response_preview']}")

        if port:
            print("\n客户端可用命令提示:")
            print("  固定选择: leikwan_tools ingress select --rule <规则名> --ip <候选IP>")
            print(
                f"  客户端验证: leikwan_tools ingress verify --host <候选IP> --port {port} "
                f'--send "PING\\n" --expect "<你的落地标识>"'
            )

    if dns_res.error and not dns_res.records:
        return 1
    if (args.tls or args.tls_sni or args.tls_verify_cert or args.tls_cafile or args.tls_insecure) and candidates and all(c["exit_code"] != 0 for c in candidates):
        return worst_tls_rc or 3
    return 0


def _cmd_ingress_verify(args: argparse.Namespace) -> int:
    global_cfg = _maybe_load_global(args.config)
    domain = args.domain or (global_cfg.ingress.default_domain if global_cfg else DEFAULT_INGRESS_DOMAIN)
    dns_server = args.dns_server or (global_cfg.ingress.dns_server if global_cfg else "")
    port = args.port

    if args.rule:
        rule = _resolve_rule_for_ingress(args.rule, args.config)
        if not args.domain:
            domain = rule.ingress_domain
        if port is None:
            port = rule.public_port
        if not args.host and not args.all_candidates:
            args.host = rule.dial_addr

    if port is None:
        raise ConfigError("必须指定 --port 或通过 --rule 指定规则以获取公网端口")

    direct = not args.all_candidates and args.host and ":" in args.host
    if direct:
        now = datetime.now(timezone.utc)
        dns_res = DnsQueryResult("", "", now.astimezone().isoformat(), now.isoformat(), [])
    elif domain:
        dns_res = query_dns_a(domain=domain, dns_server=dns_server, timeout=args.timeout)
    else:
        raise ConfigError("IPv6 直连规则使用 --host 或 --rule 验证")
    targets: List[str] = []
    if args.all_candidates:
        targets = list(dns_res.ips)
        if not targets:
            raise IngressError(f"未能从 {domain} 解析到任何 A 记录 ({dns_res.error})")
    elif args.host:
        try:
            targets = [str(ip_address(args.host))]
        except ValueError:
            if direct:
                raise ConfigError(f"无效的 IPv6 地址: {args.host!r}") from None
            host_dns = query_dns_a(domain=args.host, dns_server=dns_server, timeout=args.timeout)
            targets = list(host_dns.ips)
            if not targets:
                raise IngressError(f"未能解析目标域名 {args.host}: {host_dns.error}")
    else:
        raise ConfigError("请提供 --host <IP或域名> 或 --all-candidates")

    results = []
    for ip in targets:
        pr = probe_candidate(
            ip=ip,
            port=port,
            in_dns=(ip in dns_res.ips),
            timeout=args.timeout,
            send_payload=args.send or "",
            expect_pattern=args.expect or "",
            tls=args.tls,
            tls_sni=args.tls_sni or "",
            tls_verify_cert=(True if args.tls_verify_cert else None),
            tls_insecure=args.tls_insecure,
            tls_cafile=args.tls_cafile or "",
        )
        results.append(asdict(pr))

    payload = {
        "domain": domain,
        "queried_at_local": dns_res.queried_at_local,
        "queried_at_utc": dns_res.queried_at_utc,
        "dns_candidates": dns_res.ips,
        "port": port,
        "results": results,
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"验证时间   : {dns_res.queried_at_local} ({dns_res.queried_at_utc})")
        if not direct:
            print(f"参考域名   : {domain} (当前 DNS A 记录: {', '.join(dns_res.ips) or '无'})")
        for r in results:
            rtt = f" RTT={r['rtt_ms']}ms" if r["rtt_ms"] is not None else ""
            tcp_str = "连通" if r["tcp_reachable"] else "失败"
            print(f"  - {format_endpoint(r['ip'], r['port'])} => [{r['stage']}]{rtt} | {r['detail']}")
            print(
                f"    分层状态: TCP={tcp_str} | TLS={r['tls_status']} | "
                f"证书({r['cert_verify_mode']})={r['cert_status']} | 应用={r['app_status']}"
            )
            if r["response_preview"]:
                print(f"    回包预览: {r['response_preview']}")
            if r["tls_subject"] or r["tls_san"]:
                print(f"    TLS 证书: subject={r['tls_subject']} san={r['tls_san']}")
        if not direct:
            print("\n" + "\n".join(protocol_preservation_notes(results[0]["ip"], port, domain)))

    if any(r["exit_code"] == 0 for r in results):
        return 0
    for code in (4, 3, 2, 1):
        if any(r["exit_code"] == code for r in results):
            return code
    return 1


def _confirm(message: str) -> bool:
    return input(f"{message}？[y/N] ").strip().lower() == "y"


def _menu_pick(
    items: list[str],
    prompt: str,
    default: str = "",
    labels: Optional[list[str]] = None,
) -> str:
    display_items = labels if labels is not None else items
    for number, label in enumerate(display_items, 1):
        print(f"  {number}. {label}")
    hint = f"，回车保留 {default}" if default else "，回车取消"
    value = input(f"{prompt}（输入编号，0 返回{hint}）：").strip()
    if not value:
        return default
    if value == "0":
        return ""
    if value in items:
        return value
    if value.isascii() and value.isdecimal() and len(value) <= len(str(len(items))):
        number = int(value)
        if 1 <= number <= len(items):
            return items[number - 1]
    raise ConfigError(f"无效选项: {value}")


def _rule_active_state(cfg: GlobalConfig, rule: RuleConfig) -> Optional[bool]:
    unit_name = unit_name_for_rule(cfg.tool.systemd_unit_template, rule.name)
    try:
        return systemd_is_active(unit_name)
    except (SystemErrorBase, OSError):
        return None


def _format_line_brief(cfg: GlobalConfig, line_name: str) -> str:
    lc = cfg.lines.get(line_name)
    if lc and lc.description:
        return f"{line_name}({lc.description})"
    return line_name


def _menu_rule(cfg: GlobalConfig, prompt: str = "选择转发规则") -> Optional[RuleConfig]:
    managed = list_managed_rules(cfg)
    if not managed:
        print("当前还没有已配置的转发规则。")
        return None
    rules = {rule.name: rule for rule in managed}
    labels = [
        f"{rule.name}  (出口: {_format_line_brief(cfg, rule.line)} | 入口: {format_endpoint(rule.dial_addr, rule.public_port)} -> 落地: {rule.remote_endpoint})"
        for rule in managed
    ]
    return rules.get(_menu_pick(list(rules), prompt, labels=labels))


def _menu_field(label: str, default: Any = "") -> str:
    hint = f" [{default}]" if default else ""
    return input(f"{label}{hint}：").strip() or str(default)


def _menu_domain(value: str, label: str = "入口域名") -> str:
    try:
        hostname = value.removesuffix(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConfigError(f"{label}无效: {value!r}") from exc
    labels = hostname.split(".")
    if len(hostname) > 253 or len(labels) < 2 or labels[-1].isdigit() or any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels
    ):
        raise ConfigError(f"{label}无效: {value!r}")
    return value


def _menu_port(label: str, default: Any = "") -> int:
    value = _menu_field(label, default)
    if not re.fullmatch(r"[0-9]{1,5}", value):
        raise ConfigError(f"{label}必须填写 1–65535 的端口")
    return int(value)


def _menu_forward(cfg: GlobalConfig, *, edit: bool) -> None:
    old = _menu_rule(cfg, prompt="选择要修改的转发") if edit else None
    if edit and old is None:
        return
    name = old.name if old else _menu_field("转发名称（如 rfc-hk，仅字母数字/._-，留空返回）")
    if not name:
        return
    validate_rule_name(name)
    if not edit and (Path(cfg.tool.rules_dir) / f"{name}.toml").exists():
        raise ConfigError(f"转发 {name!r} 已存在，请使用「修改转发」")
    default_entry = cfg.ingress.default_domain
    if old:
        default_entry = old.listen_ip if old.direct_ipv6 else old.ingress_domain
        if old.ddns_profile in cfg.ddns.profiles:
            default_entry = cfg.ddns.profiles[old.ddns_profile].fqdn or default_entry
    entry = _menu_field("入口地址（映射域名、IPv6 DDNS 域名或本机公网 IPv6）", default_entry)
    direct = ":" in entry
    domain = "" if direct else _menu_domain(entry)
    ddns_profile = ""
    matches = [profile for profile in cfg.ddns.profiles.values() if domain and profile.fqdn.lower() == domain.rstrip(".").lower()]
    if matches:
        if len(matches) != 1:
            raise ConfigError("多个 DDNS 配置对应此域名，请先消除歧义")
        profile = matches[0]
        if not cfg.ddns.enabled or not profile.enabled:
            raise ConfigError(f"请先启用 DDNS 配置 {profile.name} 和全局 DDNS，再绑定自动跟随")
        inspection = inspect_ddns_profile(cfg, profile)
        if inspection.error or not inspection.selected_ip:
            raise ConfigError(inspection.error or f"{profile.name} 未探测到可用的本机公网 IPv6")
        entry, ddns_profile = inspection.selected_ip, profile.name
        print(f"IPv6 直连：{domain} → {entry}；监听地址将自动跟随 DDNS 配置 {profile.name}。")
        direct, domain = True, ""
    elif domain and domain.rstrip(".").lower() not in (
        DEFAULT_INGRESS_DOMAIN.lower(), cfg.ingress.default_domain.rstrip(".").lower(),
    ) and _confirm(
        "此域名是否用于本机 IPv6 DDNS 直连（y：解析 IPv6；N：IPv4 端口映射）"
    ):
        try:
            records = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ConfigError(f"无法解析 {domain} 的 IPv6 地址，请检查 AAAA 记录：{exc}") from exc
        addresses = {record[4][0] for record in records}
        if len(addresses) != 1:
            raise ConfigError(f"{domain} 未解析到唯一 IPv6 地址，请直接填写要监听的本机公网 IPv6")
        entry = validate_ipv6(addresses.pop(), "forward.listen_ip")
        print(f"IPv6 直连：{domain} → {entry}；规则绑定当前地址，AAAA 变化后需重新修改转发。")
        direct, domain = True, ""
    public_port = _menu_port("客户端连接的公网端口（外部端口）", old.public_port if old else "")
    listen_ip, listen_port = entry, public_port
    if not direct:
        old_ipv4 = old if old and not old.direct_ipv6 else None
        listen_ip = _menu_field("本机监听的内网 IPv4（利群面板映射指向的 VPS 内网地址）", old_ipv4.listen_ip if old_ipv4 else "")
        listen_port = _menu_port("本机监听的内网端口（利群面板映射指向的 VPS 内部端口）", old_ipv4.listen_port if old_ipv4 else "")
    remote_raw = _menu_field("落地服务器 IPv4（目标机地址）", old.remote_ip if old else "")
    remote_ip = validate_ipv4(remote_raw, "forward.remote_ip")
    remote_port = _menu_port("落地服务器端口（目标机端口）", old.remote_port if old else "")
    matching_lines = {lname: lc for lname, lc in cfg.lines.items() if not lc.is_ipv6}
    if not matching_lines:
        raise ConfigError(
            "主配置中没有可用的 IPv4 出口线路（请在 config.toml 添加对应的 [lines.<名称>]）"
        )
    line_names = list(matching_lines)
    line_labels = [
        f"{lname}（{lc.family.upper()}，网卡 {lc.interface}，源IP {lc.source_ip}"
        + (f"，网关 {lc.gateway}" if lc.gateway else "")
        + (f"，{lc.description}" if lc.description else "")
        + "）"
        for lname, lc in matching_lines.items()
    ]
    line = _menu_pick(
        line_names,
        "选择出口线路（仅显示匹配 IPv4 落地的线路）",
        old.line if old and old.line in matching_lines else "",
        labels=line_labels,
    )
    if not line:
        return
    rule = parse_rule_config_dict({
        "rule": {"name": name, "line": line},
        "ingress": {"domain": domain, "public_port": public_port, "ddns_profile": ddns_profile},
        "forward": {
            "listen_ip": listen_ip, "listen_port": listen_port, "remote_ip": remote_ip, "remote_port": remote_port,
        },
    })
    if old:
        rule = replace(
            rule,
            description=old.description,
            ingress_fixed_ip=old.ingress_fixed_ip if domain == old.ingress_domain else "",
            log_level=old.log_level,
            tcp_timeout=old.tcp_timeout,
            tcp_keepalive=old.tcp_keepalive,
            tcp_keepalive_probe=old.tcp_keepalive_probe,
        )
    _print_plan(plan_rule(cfg, rule))
    if _confirm("确认生效并启动此转发"):
        _print_apply(apply_rule(cfg, rule, expected_rule=old, create_only=not edit))
    else:
        print("已取消。")


def _menu_toggle_rule(cfg: GlobalConfig) -> None:
    managed = list_managed_rules(cfg)
    if not managed:
        print("当前还没有已配置的转发规则。")
        return
    rules = {rule.name: rule for rule in managed}
    states = {rule.name: _rule_active_state(cfg, rule) for rule in managed}
    labels = []
    for rule in managed:
        state = states[rule.name]
        badge = "运行中" if state is True else ("已暂停" if state is False else "状态未知")
        dial = format_endpoint(rule.dial_addr, rule.public_port)
        labels.append(
            f"[{badge}] {rule.name}  (出口: {_format_line_brief(cfg, rule.line)} | 入口: {dial} -> 落地: {rule.remote_endpoint})"
        )
    selected = _menu_pick(list(rules), "选择要暂停或恢复的转发", labels=labels)
    if not selected:
        return
    rule = rules[selected]
    active = states[selected]
    if active is None:
        action = _menu_pick(["暂停转发", "恢复并启动转发"], f"无法自动识别 {rule.name} 的运行状态，请选择操作")
        if not action:
            return
        pause = action == "暂停转发"
    else:
        pause = active
    if pause:
        if _confirm(f"确认暂停转发 {rule.name}（将停止服务并取消开机自启，保留配置以便随时恢复）"):
            res = disable_rule(cfg, rule.name)
            print(f"[已暂停] 转发={res['rule_name']} 单元={res['unit_name']}（配置已保留，可随时恢复）")
        else:
            print("已取消。")
        return
    _print_plan(plan_rule(cfg, rule))
    if _confirm(f"确认恢复并启动转发 {rule.name}"):
        _print_apply(apply_rule(cfg, rule, expected_rule=rule, create_only=False))
    else:
        print("已取消。")


def _menu_delete_rule(cfg: GlobalConfig) -> None:
    rule = _menu_rule(cfg, prompt="选择要删除的转发")
    if rule is None:
        return
    dial = format_endpoint(rule.dial_addr, rule.public_port)
    print(f"将删除转发：{rule.name}（入口 {dial} -> 本机监听 {rule.listen_endpoint} -> 落地 {rule.remote_endpoint}）")
    if not _confirm(f"确认彻底删除转发 {rule.name}（将停止服务并移除所有配置文件）"):
        print("已取消。")
        return
    res = delete_rule(cfg, rule.name)
    print(f"[已删除] 转发={res['rule_name']} 单元={res['unit_name']}")
    for f in res["removed_files"]:
        print(f"  已移除: {f}")


def _menu_ingress(cfg: GlobalConfig) -> None:
    rule = _menu_rule(cfg, prompt="选择要设置客户端入口的转发")
    if rule is None:
        return
    if rule.direct_ipv6:
        print(f"该转发使用公网 IPv6 直连（{rule.listen_endpoint}），无需固定公网 IPv4；如需修改入口请进入「修改转发」。")
        return
    resolver = validate_ipv4(
        _menu_field("DNS 服务器 IPv4（直接回车使用默认解析器）", cfg.ingress.dns_server),
        "dns_server", allow_empty=True,
    )
    result = query_dns_a(rule.ingress_domain, dns_server=resolver)
    print(f"{rule.ingress_domain} A 记录（解析器 {result.resolver}，时间 {result.queried_at_local}）")
    if result.error:
        print(f"查询失败：{result.error}")
    if not result.records:
        print("当前无 A 记录。")
    candidates = []
    for record in result.records:
        addr = IPv4Address(record.ip)
        if addr.is_global and not addr.is_multicast and not addr.is_reserved:
            candidates.append(record.ip)
            print(f"  {record.ip}  TTL={record.ttl if record.ttl is not None else '未知'}")
        else:
            print(f"  {record.ip}  非公网 IPv4，已排除")
    print(f"当前客户端入口：{rule.ingress_fixed_ip or rule.ingress_domain}:{rule.public_port}")
    restore_value = "恢复域名拨号"
    values = [*candidates, restore_value]
    labels = [f"{ip}:{rule.public_port}（固定此公网 IP）" for ip in candidates] + [
        "恢复使用域名连接（不固定 IP，随 DNS 自动解析）"
    ]
    selected = _menu_pick(values, "选择客户端连接方式", labels=labels)
    if not selected:
        return
    dial_addr = rule.ingress_domain if selected == restore_value else selected
    print(f"客户端将连接 {dial_addr}:{rule.public_port}")
    backups = [f"{ip}:{rule.public_port}" for ip in candidates if ip != selected]
    if backups:
        print(f"客户端备用地址 {'、'.join(backups)}")
    if not _confirm("确认保存此客户端入口设置"):
        print("已取消。")
        return
    if selected == restore_value:
        outcome = unselect_rule_ingress_ip(cfg, rule.name, expected_rule=rule)
    else:
        outcome = select_rule_ingress_ip(cfg, rule.name, selected, dns_server=resolver, expected_rule=rule)
    print(f"已设置 {outcome['dial_address']}（仅更新客户端入口记录，未重启 Realm，现有连接不受影响）")


def _print_routing(result: dict) -> None:
    status_val = result.get("status", "预览")
    hint_map = {
        "applied": "已初始化并启用开机自动恢复",
        "noop": "已就绪，无需重复修改",
        "unconfigured": "尚未配置双线源策略路由",
        "预览": "只读预览，尚未写入系统",
    }
    hint = hint_map.get(status_val, status_val)
    print(f"双线出口路由状态 : {status_val}（{hint}）")
    if status_val == "unconfigured":
        return
    for item in result["keep"]:
        print(f"  保留已有 {item['kind']} {item['source_ip']}@{item['interface']} 表 {item['table']}")
    for command in result["add"]:
        print(f"  即将新增 {' '.join(command)}")
    print(f"开机服务 {result['boot_unit']}，持久化记录 {result['state_file']}")


def _menu_routing(cfg: GlobalConfig) -> None:
    plan = plan_routing(cfg)
    _print_routing(plan)
    if _confirm("确认初始化并持久化双线出口路由（开机将自动恢复）"):
        _print_routing(apply_routing(cfg, expected=plan))
    else:
        print("已取消。")


def _menu_list_forwards(cfg: GlobalConfig) -> None:
    managed = list_managed_rules(cfg)
    if not managed:
        print("当前还没有已配置的转发规则（可选择「2. 新建转发」添加）。")
        return
    print(f"\n当前共有 {len(managed)} 条已配置转发：")
    for idx, rule in enumerate(managed, 1):
        state = _rule_active_state(cfg, rule)
        badge = "运行中" if state is True else ("已暂停" if state is False else "状态未知")
        lc = cfg.lines.get(rule.line)
        line_desc = _format_line_display(
            rule.line,
            lc.description if lc else "",
            lc.interface if lc else "",
            lc.source_ip if lc else "",
        )
        dial = format_endpoint(rule.dial_addr, rule.public_port)
        if rule.direct_ipv6:
            entry_note = "公网 IPv6 直连"
        elif rule.ingress_fixed_ip:
            entry_note = "已固定公网 IP"
        else:
            entry_note = "域名自动解析"
        print(f"  {idx}. [{badge}] {rule.name}")
        print(f"     出口线路   : {line_desc}")
        print(f"     客户端入口 : {dial}（{entry_note}）")
        print(f"     本机监听   : {rule.listen_endpoint}")
        print(f"     落地目标   : {rule.remote_endpoint}")


def _menu_rules_group(config_path: str) -> None:
    handlers = {
        "1": _menu_list_forwards,
        "2": lambda cfg: _menu_forward(cfg, edit=False),
        "3": lambda cfg: _menu_forward(cfg, edit=True),
        "4": _menu_toggle_rule,
        "5": _menu_delete_rule,
    }
    while True:
        print(f"\nleikwan_tools v{__version__} > 转发规则管理")
        print("  1. 查看已有转发")
        print("  2. 新建转发")
        print("  3. 修改转发")
        print("  4. 暂停 / 恢复转发")
        print("  5. 删除转发")
        print("  0. 返回主菜单")
        selected = input("请选择：").strip()
        if selected == "0":
            return
        handler = handlers.get(selected)
        if handler is None:
            print("无效选项，请重新输入。")
            continue
        try:
            handler(load_global_config(config_path))
        except _MENU_ERRORS as exc:
            print(f"错误: {exc}", file=sys.stderr)


_NETWORK_ACTIONS = {
    "ipv4-prefer": {"enable": "开启 IPv4 优先", "disable": "恢复原有地址优先级"},
    "dns": {"set": "设置系统 DNS", "restore": "恢复系统 DNS"},
    "ipv6": {"disable": "禁用 IPv6", "restore": "恢复 IPv6"},
    "bbr": {"enable": "开启 BBR / fq", "restore": "恢复拥塞控制和 qdisc"},
    "ipv6-lockdown": {"enable": "启用 / 更新 IPv6 入站收口", "restore": "撤销 IPv6 入站收口"},
}

_NETWORK_WARNINGS = {
    "dns": "系统 DNS 影响整机解析，不是 DDNS 配置。",
    "ipv6": "禁用 IPv6 会中断 IPv6 SSH 和直连转发，并使 IPv6 DDNS 无法继续探测。请通过 IPv4 SSH 或控制台操作。",
    "ipv6-lockdown": "请确认放行列表包含 IPv6 SSH 和直连 Realm 的 TCP 端口；建议保留控制台。",
}


def _print_system_network(result: dict) -> None:
    for label, value in result.items():
        if isinstance(value, dict):
            value = ", ".join(f"{key}={item if item is not None else '未知'}" for key, item in value.items())
        elif isinstance(value, list):
            value = ", ".join(map(str, value)) or "无"
        elif label == "IPv6 入站收口" and value == "":
            value = "未加载"
        if isinstance(value, str) and "\n" in value:
            print(f"{label}:\n{value}")
        else:
            print(f"{label}: {value or '未知或不可用'}")


def _menu_system_network(config_path: str) -> None:
    features = ["status", *_NETWORK_ACTIONS]
    labels = [
        "查看系统网络优化状态",
        "IPv4 优先：开启 / 关闭",
        "DNS 服务器：设置 / 恢复",
        "IPv6：禁用 / 恢复",
        "BBR / fq：开启 / 恢复",
        "IPv6 入站收口 nftables：启用 / 撤销",
    ]
    while True:
        print("\n系统网络优化")
        try:
            feature = _menu_pick(features, "请选择", labels=labels)
            if not feature:
                return
            command = ["--config", config_path, "system"]
            if feature == "status":
                main([*command, "network", "status"])
                continue
            actions = _NETWORK_ACTIONS[feature]
            action = _menu_pick(list(actions), "请选择操作", labels=list(actions.values()))
            if not action:
                continue
            if feature in _NETWORK_WARNINGS and action != "restore":
                print(_NETWORK_WARNINGS[feature])
            options = ["--yes"]
            if (feature, action) == ("dns", "set"):
                options.extend(["--", _menu_field("DNS IP（逗号分隔）", DEFAULT_DNS)])
            elif (feature, action) == ("ipv6-lockdown", "enable"):
                ports = input("允许的 TCP 端口（逗号分隔，如 22,8443；回车取消）：").strip()
                if not ports:
                    continue
                options.append(f"--tcp-ports={ports}")
            if _confirm(f"确认{actions[action]}"):
                main([*command, feature, action, *options])
        except _MENU_ERRORS as exc:
            print(f"错误: {exc}", file=sys.stderr)


def _menu_system_group(config_path: str) -> None:
    while True:
        print(f"\nleikwan_tools v{__version__} > 初始化与环境排查")
        print("  1. 初始化双线出口路由（首次装机时执行）")
        print("  2. 检查运行环境与线路状态")
        print("  3. 系统网络优化")
        print("  0. 返回主菜单")
        selected = input("请选择：").strip()
        if selected == "0":
            return
        if selected == "1":
            try:
                _menu_routing(load_global_config(config_path))
            except _MENU_ERRORS as exc:
                print(f"错误: {exc}", file=sys.stderr)
        elif selected == "2":
            main(["--config", config_path, "check-prereqs"])
        elif selected == "3":
            _menu_system_network(config_path)
        else:
            print("无效选项，请重新输入。")


def _print_update_check(info: UpdateCheckInfo) -> None:
    status_map = {
        "upgrade": f"发现新版本 v{info.remote_version}（当前 v{info.current_version}）",
        "same": f"当前已是最新版本 v{info.current_version}",
        "ahead": f"本地版本 (v{info.current_version}) 高于仓库版本 (v{info.remote_version})",
        "unknown": f"仓库版本为 v{info.remote_version}（当前 v{info.current_version}）",
    }
    print(f"更新渠道   : {info.channel_label} ({info.repo} @ {info.branch})")
    print(f"当前版本   : v{info.current_version}")
    print(f"仓库版本   : v{info.remote_version}  (提交 {info.short_sha})")
    if info.commit_message:
        print(f"最新提交   : {info.commit_message}")
    print(f"检查结论   : {status_map.get(info.status, info.status)}")


def _print_update_result(res: UpdateResult) -> None:
    if res.installed_version != res.previous_version:
        ver_msg = f"已从 v{res.previous_version} 更新到 v{res.installed_version}"
    else:
        ver_msg = f"已同步仓库最新提交 {res.short_sha}（版本号仍为 v{res.installed_version}）"
    print(f"[更新完成] {ver_msg}（来源：{res.channel_label}，已校验并更新 {res.files_updated} 个程序文件）")
    print("提示：原有主配置、转发规则、Realm 程序及运行中的转发连接均已保留。")


def _menu_update(config_path: str) -> bool:
    print(f"\n当前版本：v{__version__}")
    print("说明：将从仓库拉取最新程序文件并原地升级，现有转发配置与运行中的连接不受影响。")
    channel = _menu_pick(
        ["github", "gitee"],
        "选择更新渠道",
        default="github",
        labels=["GitHub（默认）", "Gitee（国内网络推荐）"],
    )
    if not channel:
        return False
    print(f"正在查询 {UPDATE_CHANNELS[channel]['label']} 仓库最新版本……")
    info = check_for_update(channel=channel)
    _print_update_check(info)
    if info.status == "upgrade":
        prompt = f"确认从 {info.channel_label} 拉取并更新到 v{info.remote_version}（不中断现有转发）"
    elif info.status == "ahead":
        prompt = f"仓库版本 (v{info.remote_version}) 低于当前版本 (v{info.current_version})，仍要覆盖安装"
    else:
        prompt = f"当前版本号已是 v{info.current_version}，仍要同步最新提交 {info.short_sha} 并重新安装"
    if not _confirm(prompt):
        print("已取消。")
        return False
    print("正在下载、校验并安装更新……")
    res = perform_update(channel=channel, prechecked=info)
    _print_update_result(res)
    return True


def _reexec_updated_menu(config_path: str) -> None:
    if sys.stdin.isatty() and sys.stdout.isatty():
        target = SHORTCUT_PATH if Path(sys.argv[0]).name == "lqtool" else BIN_LAUNCHER_PATH
        if not (os.path.isfile(target) and os.access(target, os.X_OK)):
            target = BIN_LAUNCHER_PATH
        if os.path.isfile(target) and os.access(target, os.X_OK):
            print("正在重新打开新版菜单……")
            os.execv(target, [target, "--config", config_path, "menu"])
    print("更新完成，请重新运行 lqtool 打开新版菜单。")


def _format_ddns_interface(interface: str, selected: str = "") -> str:
    if interface != DDNS_AUTO_INTERFACE:
        return interface
    return f"自动（{selected}）" if selected else "自动"


def _print_ddns_inspect(items: List[ProfileInspectResult]) -> None:
    print("协议说明   : 当前仅支持 IPv6 AAAA 记录（配置模型已预留 A 记录扩展）")
    print("安全模式   : 只读候选过滤（不删除系统网卡上的 deprecated / preferred_lft 0 地址）")
    for idx, item in enumerate(items):
        if idx > 0:
            print("-" * 72)
        isp_zh = ISP_LABELS.get(item.isp, item.isp)
        state_zh = "启用" if item.enabled else "已禁用"
        target_name = item.fqdn or "(Webhook 通知)"
        print(f"配置名     : {item.profile} ({isp_zh} | {state_zh} | {item.provider} {item.record_type} -> {target_name})")
        interface = _format_ddns_interface(item.interface, item.selected_interface)
        print(f"网卡与探测 : dev={interface} | ping -6 -c 1 -w {item.probe_timeout_seconds} -I <候选IP> {item.probe_target}")
        if item.error:
            print(f"扫描错误   : {item.error}")
            continue
        if item.selected_ip:
            rtt_str = f" (RTT={item.selected_rtt_ms:.2f}ms)" if item.selected_rtt_ms is not None else ""
            print(f"选中最佳IP : {item.selected_ip}{rtt_str}")
        else:
            print("选中最佳IP : (无可用公网 IPv6)")
        if item.candidates:
            print("探测候选   :")
            for cand in item.candidates:
                mark = "可用" if cand.probe_ok else "不可达"
                print(f"  - {cand.ip} @ {cand.interface} [{mark}] {cand.detail}")
        if item.filtered_out:
            print("已过滤地址 :")
            for skipped in item.filtered_out:
                print(f"  - {skipped.raw} ({skipped.reason})")


def _print_ddns_update(res: Dict[str, Any]) -> None:
    print("协议说明   : 当前仅支持 IPv6 AAAA 记录（配置模型已预留 A 记录扩展）")
    if not res.get("ddns_enabled", True):
        print("DDNS 状态  : 全局 [ddns].enabled = false，已跳过所有更新")
        return
    if not res["results"]:
        print("当前没有已配置的 DDNS 线路。")
        return
    for item in res["results"]:
        isp_zh = ISP_LABELS.get(item["isp"], item["isp"])
        target_name = item["fqdn"] or "(Webhook)"
        interface = _format_ddns_interface(item["interface"], item.get("selected_interface", ""))
        print(
            f"[{item['action']}] 配置={item['profile']} ({isp_zh}@{interface} | "
            f"{item['provider']} {item['record_type']} -> {target_name})"
        )
        if item.get("selected_ip"):
            rtt = f" RTT={item['selected_rtt_ms']:.2f}ms" if item.get("selected_rtt_ms") is not None else ""
            print(f"  选用 IPv6: {item['selected_ip']}{rtt}")
        if item.get("deleted_duplicates"):
            print(f"  清理重复 : {', '.join(item['deleted_duplicates'])}")
        print(f"  详情     : {item['detail']}")


def _print_ddns_test(res: Dict[str, Any]) -> None:
    print("协议说明   : 当前仅支持 IPv6 AAAA 记录（配置模型已预留 A 记录扩展）")
    insp = res["inspection"]
    isp_zh = ISP_LABELS.get(res["isp"], res["isp"])
    interface = _format_ddns_interface(res["interface"], insp.get("selected_interface", ""))
    print(
        f"DDNS 联调检查 [{res['profile']}]: {isp_zh}@{interface} | "
        f"{res['provider']} {res['record_type']} -> {res['fqdn'] or '(Webhook)'}"
    )
    print(f"凭据校验   : 通过 (0600 权限与字段校验合格)")
    if insp["error"]:
        print(f"地址扫描   : 失败 - {insp['error']}")
    elif insp["selected_ip"]:
        rtt = f" (RTT={insp['selected_rtt_ms']:.2f}ms)" if insp.get("selected_rtt_ms") is not None else ""
        print(f"最佳 IPv6  : {insp['selected_ip']}{rtt}")
    else:
        print("最佳 IPv6  : 未找到探测可达的公网 IPv6 候选")
    remote = res["remote"]
    if remote.get("supports_remote_verify") is False:
        print(f"远端校验   : Webhook 不支持远端查询，模板校验通过 ({remote.get('webhook_preview', '')})")
    else:
        print(
            f"远端记录   : {remote.get('fqdn', res['fqdn'])} -> "
            f"{remote.get('remote_ip') or '(尚无记录)'} "
            f"(记录数={remote.get('record_count', 0)}, id={remote.get('record_id') or '-'})"
        )


def _print_ddns_status(res: Dict[str, Any]) -> None:
    print("协议说明   : 当前仅支持 IPv6 AAAA 记录（配置模型已预留 A 记录扩展）")
    profiles = res.get("profiles") or []
    if not profiles:
        print("当前未配置独立 DDNS（主配置中无 [ddns.<名称>] 配置节）。")
        return
    print(
        f"全局状态   : {'启用' if res['ddns_enabled'] else '禁用'} | "
        f"扫描周期={res['interval_seconds']}s | 远端校对={res['verify_interval_seconds']}s | "
        f"探测目标={res['probe_target']} (超时 {res['probe_timeout_seconds']}s)"
    )
    for item in profiles:
        print("-" * 72)
        isp_zh = ISP_LABELS.get(item["isp"], item["isp"])
        state_zh = "启用" if item["enabled"] else "禁用"
        print(f"配置名称   : {item['profile']} ({isp_zh} | {state_zh})")
        interface = _format_ddns_interface(item["interface"], item.get("selected_interface", ""))
        print(f"接口/服务  : dev={interface} | {item['provider']} {item['record_type']} -> {item['fqdn'] or '(Webhook)'}")
        print(f"凭据文件   : {item['credential_file'] or '(未配置)'}")
        print(
            f"当前选择   : {item['selected_ip'] or '(无)'}"
            + (f" (RTT={item['selected_rtt_ms']:.2f}ms)" if item.get("selected_rtt_ms") is not None else "")
        )
        print(
            f"上次成功   : {item['last_success_ip'] or '(从未成功)'} "
            f"[时间={item['last_success_at_utc'] or '-'} | 记录ID={item['record_id'] or '-'}]"
        )
        print(
            f"最近动作   : {item['last_action'] or '(尚未运行)'} "
            f"[尝试={item['last_attempt_at_utc'] or '-'} | 远端核对={item['last_verified_at_utc'] or '-'}]"
        )
        if item.get("last_error"):
            print(f"最近错误   : {item['last_error']}")


def _menu_ddns_profile(cfg: GlobalConfig, *, allow_all: bool = False) -> str:
    profiles = cfg.ddns.profiles
    if not profiles:
        print("请先新建 DDNS 配置。")
        return ""
    labels = [
        f"{profile.name} | {ISP_LABELS[profile.isp]} @ {_format_ddns_interface(profile.interface)} | "
        f"{profile.fqdn or '(Webhook)'} | {'启用' if profile.enabled else '暂停'}"
        for profile in profiles.values()
    ]
    names = list(profiles)
    if allow_all:
        names.insert(0, "*")
        labels.insert(0, "全部线路")
    return _menu_pick(names, "选择 DDNS 配置", labels=labels)


def _menu_ddns_edit(cfg: GlobalConfig, profile: Optional[DdnsProfileConfig] = None) -> None:
    if profile is None:
        name = input("配置名（如 ct、cu，留空返回）：").strip()
        if not name:
            return
        if not DDNS_PROFILE_NAME_RE.fullmatch(name) or name in cfg.ddns.profiles:
            raise ConfigError("配置名称非法或已存在")
    else:
        name = profile.name

    isp = _menu_pick(list(ISP_LABELS), "选择运营商", profile.isp if profile else "", list(ISP_LABELS.values()))
    if not isp:
        return
    if profile is None:
        interface = DDNS_AUTO_INTERFACE
        print(f"网卡：自动识别{ISP_LABELS[isp]} IPv6，无需填写网卡名。")
    else:
        interface = _menu_field("入口 IPv6 所在网卡（auto 自动识别）", profile.interface)
    provider = _menu_pick(
        list(VALID_DDNS_PROVIDERS), "选择 DNS 服务商", profile.provider if profile else ""
    )
    if not provider:
        return
    zone = _menu_field("DNS 托管域（如 example.com）", profile.zone if profile else "")
    host = _menu_field("主机记录（如 ct，根域填 @）", profile.host if profile else "@") if zone else ""
    if zone or provider != "webhook":
        zone = _menu_domain(zone, "DDNS 托管域").removesuffix(".").encode("idna").decode("ascii")
        host = host.removesuffix(".").encode("idna").decode("ascii")
        _menu_domain(normalize_ddns_fqdn(zone, host), "DDNS 记录域名")
    fields = {
        "cloudflare": [("CF_API_TOKEN", "Cloudflare API Token")],
        "dnspod": [("DNSPOD_TOKEN", "DNSPod Token（ID,Token）")],
        "alidns": [("ALIDNS_ACCESS_KEY_ID", "阿里云 AccessKey ID"), ("ALIDNS_ACCESS_KEY_SECRET", "阿里云 AccessKey Secret")],
        "webhook": [("WEBHOOK_URL", "Webhook URL（包含 {ip}）")],
    }
    keep_existing = bool(profile and profile.provider == provider and profile.credential_file)
    first_key, first_label = fields[provider][0]
    first_value = input(f"{first_label}{'（回车保留原凭据）' if keep_existing else ''}：").strip()
    credentials = None
    if first_value:
        credentials = {first_key: first_value}
        for key, label in fields[provider][1:]:
            value = input(f"{label}：").strip()
            if not value:
                raise ConfigError(f"{label}不能为空")
            credentials[key] = value
    elif not keep_existing:
        raise ConfigError(f"{first_label}不能为空")
    changes = {
        "isp": isp,
        "interface": interface,
        "provider": provider,
        "zone": zone,
        "host": host,
        "credential_file": profile.credential_file if keep_existing else "",
    }
    changes["enabled"] = True
    if credentials is not None:
        changes["auth_mode"] = "token" if provider == "cloudflare" else ""
    target = normalize_ddns_fqdn(zone, host) if zone else "(Webhook)"
    print(f"{name} | {ISP_LABELS[isp]} @ {_format_ddns_interface(interface)} | {provider} | AAAA → {target}")
    if not cfg.ddns.enabled:
        other_enabled = [item.name for item in cfg.ddns.profiles.values() if item.enabled and item.name != name]
        if other_enabled:
            print(f"开启全局 DDNS 后，以下已启用配置也会参与定时同步：{', '.join(other_enabled)}")
    if _confirm("保存并启用 DDNS，立即同步该记录"):
        save_ddns_config(
            cfg, profile_name=name, changes=changes, enabled=True, new_credentials=credentials
        )
        print("DDNS 配置已保存并启用，正在进行首次同步；后续由定时任务自动检测。")
        try:
            result = update_ddns(load_global_config(cfg.config_path), name, force=True)
            _print_ddns_update(result)
        except _MENU_ERRORS + (UnicodeError,) as exc:
            print(f"首次同步未完成：{exc}。配置已保存，定时器运行时将自动重试。", file=sys.stderr)


def _menu_ddns_toggle(cfg: GlobalConfig) -> None:
    global_action = "暂停" if cfg.ddns.enabled else "启用"
    profiles = cfg.ddns.profiles
    labels = [f"{global_action}全局 DDNS"]
    labels.extend(
        f"{'暂停' if profile.enabled else '启用'} {profile.name} | {profile.fqdn or '(Webhook)'}"
        for profile in profiles.values()
    )
    name = _menu_pick(["*", *profiles], "选择要启用或暂停的 DDNS", labels=labels)
    if not name:
        return
    if name == "*":
        if not _confirm(f"{global_action}全局 DDNS"):
            return
        save_ddns_config(cfg, enabled=not cfg.ddns.enabled)
        print(f"全局 DDNS 已{global_action}。")
        if not cfg.ddns.enabled and any(profile.enabled for profile in profiles.values()):
            print("正在立即同步已启用的 DDNS 配置。")
            _print_ddns_update(update_ddns(load_global_config(cfg.config_path), force=True))
        return

    profile = profiles[name]
    target_enabled = not profile.enabled
    action = "启用" if target_enabled else "暂停"
    enable_global = target_enabled and not cfg.ddns.enabled
    prompt = f"{action} DDNS 配置 {name}"
    if enable_global:
        prompt += "并开启全局 DDNS（其他已启用配置也将恢复定时同步）"
    if not _confirm(prompt):
        return
    save_ddns_config(cfg, profile_name=name, changes={"enabled": target_enabled}, enabled=True if enable_global else None)
    print(f"DDNS 配置 {name} 已{action}。")
    if target_enabled:
        print("正在立即同步该 DDNS 配置。")
        _print_ddns_update(update_ddns(load_global_config(cfg.config_path), name, force=True))


def _menu_ddns_group(config_path: str) -> None:
    while True:
        print(f"\nleikwan_tools v{__version__} > IPv6 DDNS 域名管理")
        print("  1. 查看配置与同步状态")
        print("  2. 新建 DDNS 配置")
        print("  3. 修改 DDNS 配置")
        print("  4. 探测网卡 IPv6")
        print("  5. 测试配置与凭据")
        print("  6. 立即同步 AAAA 记录")
        print("  7. 启用 / 暂停 DDNS")
        print("  8. 删除 DDNS 配置")
        print("  0. 返回主菜单")
        selected = input("请选择：").strip()
        if selected == "0":
            return
        if len(selected) != 1 or selected not in "12345678":
            print("无效选项，请重新输入。")
            continue
        try:
            cfg = load_global_config(config_path)
            if selected == "1":
                _print_ddns_status(status_ddns(cfg))
                continue
            if selected == "2":
                _menu_ddns_edit(cfg)
                continue
            if selected == "7":
                _menu_ddns_toggle(cfg)
                continue
            name = _menu_ddns_profile(cfg, allow_all=selected in ("4", "6"))
            if not name:
                continue
            if selected == "4":
                _print_ddns_inspect(inspect_ddns(cfg, None if name == "*" else name))
            elif selected == "6":
                if _confirm(f"同步 {'全部已启用线路' if name == '*' else name} 的 AAAA 记录"):
                    _print_ddns_update(update_ddns(cfg, None if name == "*" else name, force=True))
            else:
                profile = cfg.ddns.profiles[name]
                if selected == "3":
                    _menu_ddns_edit(cfg, profile)
                elif selected == "5":
                    _print_ddns_test(test_ddns_profile(cfg, name))
                elif selected == "8":
                    if _confirm(f"删除本地配置 {name}（保留远端记录和凭据文件）"):
                        save_ddns_config(cfg, profile_name=name)
                        print(f"DDNS 配置 {name} 已删除。")
        except _MENU_ERRORS + (UnicodeError,) as exc:
            print(f"错误: {exc}", file=sys.stderr)


def _run_menu(config_path: str) -> int:
    try:
        while True:
            print(f"\nleikwan_tools 利群转发助手 v{__version__}")
            print("  1. 查看转发状态")
            print("  2. 转发规则管理（查看 / 新建 / 修改 / 暂停恢复 / 删除）")
            print("  3. 查询官方公网入口 IP")
            print("  4. 查询并设置转发的客户端入口 IP")
            print("  5. 初始化与环境排查（双线路由 / 环境检查 / 系统网络优化）")
            print("  6. 从仓库检查并更新工具")
            print("  7. IPv6 DDNS 域名管理")
            print("  0. 退出")
            selected = input("请选择：").strip()
            if selected == "0":
                return 0
            if selected == "1":
                main(["--config", config_path, "status"])
            elif selected == "2":
                _menu_rules_group(config_path)
            elif selected == "3":
                main(["--config", config_path, "ingress", "query"])
            elif selected == "4":
                try:
                    _menu_ingress(load_global_config(config_path))
                except _MENU_ERRORS as exc:
                    print(f"错误: {exc}", file=sys.stderr)
            elif selected == "5":
                _menu_system_group(config_path)
            elif selected == "6":
                updated = False
                try:
                    updated = _menu_update(config_path)
                except _MENU_ERRORS as exc:
                    print(f"错误: {exc}", file=sys.stderr)
                if updated:
                    _reexec_updated_menu(config_path)
            elif selected == "7":
                _menu_ddns_group(config_path)
            else:
                print("无效选项，请重新输入。")
    except (EOFError, KeyboardInterrupt):
        print()
        return 0


def build_parser() -> argparse.ArgumentParser:
    default_cfg = resolve_default_config_path()
    parser = argparse.ArgumentParser(
        prog="leikwan_tools",
        description="独立「leikwan_tools」— 利群 VPS 多规则 Realm TCP 转发（支持 IPv4/IPv6 入口和 IPv4 落地）与公网入口管理工具",
    )
    parser.add_argument(
        "--config",
        default=default_cfg,
        help=f"主配置文件路径 (当前默认: {default_cfg})",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出结果")
    parser.add_argument("--version", action="version", version=f"leikwan_tools {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("menu", help="打开交互管理菜单")

    system = sub.add_parser("system", help="查看或手动调整系统网络设置")
    features = system.add_subparsers(dest="system_feature", required=True)
    network = features.add_parser("network", help="查看系统网络优化状态")
    network.add_subparsers(dest="system_action", required=True).add_parser("status", help="只读查看当前状态")
    for feature, actions in _NETWORK_ACTIONS.items():
        setting = features.add_parser(feature, help=" / ".join(actions.values()), epilog=_NETWORK_WARNINGS.get(feature))
        choices = setting.add_subparsers(dest="system_action", required=True)
        for action, label in actions.items():
            choice = choices.add_parser(action, help=label, epilog=_NETWORK_WARNINGS.get(feature))
            choice.add_argument("--yes", action="store_true", required=True, help="确认修改系统网络配置")
            if (feature, action) == ("dns", "set"):
                choice.add_argument("value", nargs="?", default=DEFAULT_DNS, help=f"逗号分隔的 DNS IP（默认 {DEFAULT_DNS}）")
            if (feature, action) == ("ipv6-lockdown", "enable"):
                choice.add_argument("--tcp-ports", dest="value", required=True, help="放行 TCP 端口（逗号分隔，包含 SSH 和业务端口）")

    p_routing = sub.add_parser("routing", help="预览或初始化 IPv4 源策略路由")
    routing_sub = p_routing.add_subparsers(dest="routing_cmd", required=True)
    routing_sub.add_parser("plan", help="只读预览源策略路由")
    p_routing_init = routing_sub.add_parser("init", help="应用并持久化主配置中的源策略路由")
    p_routing_init.add_argument("--yes", action="store_true", required=True, help="明确确认初始化")
    sub.add_parser("_restore-routing", help="内部命令：开机恢复已批准的源策略路由")

    p_plan = sub.add_parser("plan", aliases=["preview"], help="只读预览规则部署计划与前置校验")
    p_plan.add_argument("rule_file", help="规则 TOML 文件路径")
    p_plan.add_argument("--check-dns", action="store_true", help="同时核查固定公网 IP 是否仍在 DNS 中")
    p_plan.add_argument("--allow-non-dns", action="store_true", help="显式允许 fixed_ip 不在当前 DNS A 记录中")
    p_plan.add_argument("--dns-server", default="", help="指定 DNS IPv4 用于校验 fixed_ip")

    p_apply = sub.add_parser("apply", help="从规则文件应用/更新一条 TCP 转发规则（支持 IPv4/IPv6 入口和 IPv4 落地，幂等、带锁、失败回滚）")
    p_apply.add_argument("rule_file", help="规则 TOML 文件路径")
    p_apply.add_argument("--lock-timeout", type=float, default=15.0, help="并发写锁等待秒数 (默认 15)")
    p_apply.add_argument("--allow-non-dns", action="store_true", help="显式允许新设/变更的 fixed_ip 不在当前 DNS 中")
    p_apply.add_argument("--dns-server", default="", help="指定 DNS IPv4 用于校验 fixed_ip")

    p_status = sub.add_parser("status", help="查看单条或全部已部署规则状态")
    p_status.add_argument("rule_name", nargs="?", help="可选规则名；省略则列出全部规则")
    p_status.add_argument("--check-dns", action="store_true", help="同时检查固定公网 IP 是否从 DNS 消失")

    sub.add_parser("list", help="列出所有已托管规则")

    p_disable = sub.add_parser("disable", aliases=["stop"], help="停用指定规则并取消开机自启（保留配置文件）")
    p_disable.add_argument("rule_name", help="规则名")
    p_disable.add_argument("--lock-timeout", type=float, default=15.0)

    p_delete = sub.add_parser("delete", aliases=["remove", "rm"], help="彻底删除指定规则及其托管运行文件")
    p_delete.add_argument("rule_name", help="规则名")
    p_delete.add_argument("--lock-timeout", type=float, default=15.0)

    p_prereq = sub.add_parser("check-prereqs", help="只读检查 Realm 二进制、网卡、源 IP 与出口内核路由前置条件")
    p_prereq.add_argument("--probe-remote", default="192.0.2.10", help="用于 ip -4 route get 自检的测试目标 IPv4")
    p_prereq.add_argument("--probe-remote-v6", default=PUBLIC_ROUTE_PROBE_IPV6, help="用于 ip -6 route get 自检的测试目标 IPv6")

    p_vs = sub.add_parser("_verify-startup", help="内部命令：systemd ExecStartPre 启动前路由等待与核验")
    p_vs.add_argument("rule_name", help="规则名")
    p_vs.add_argument("--wait-timeout", type=float, default=None, help="等待策略路由就绪的秒数")

    p_realm = sub.add_parser("install-realm", help="验证并安装受管的官方 Realm 二进制")
    p_realm.add_argument("--tarball", default=None, help="本地离线 Realm 官方 .tar.gz 压缩包路径")
    p_realm.add_argument("--target", default=MANAGED_REALM_BIN, help=f"安装路径 (默认 {MANAGED_REALM_BIN})")
    p_realm.add_argument("--state-dir", default="")

    p_ing = sub.add_parser("ingress", help="公网入口域名 A 记录查询、IP 固定选择与客户端三态验证")
    ing_sub = p_ing.add_subparsers(dest="ingress_cmd", required=True)

    p_iq = ing_sub.add_parser("query", help="查询公网入口域名当前 A 记录并区分三态状态")
    p_iq.add_argument("--domain", default="", help=f"入口域名 (默认 {DEFAULT_INGRESS_DOMAIN})")
    p_iq.add_argument("--port", type=int, default=None, help="公网端口（提供后同时检测 TCP 可达性）")
    p_iq.add_argument("--rule", default="", help="已有规则名或规则 TOML 路径（自动读取域名、端口与固定 IP）")
    p_iq.add_argument("--dns-server", default="", help="指定查询使用的 DNS IPv4")
    p_iq.add_argument("--timeout", type=float, default=3.0)
    p_iq.add_argument("--verify-send", default="", help="可选：发送以校验落地的请求载荷")
    p_iq.add_argument("--verify-expect", default="", help="可选：预期落地返回的关键字或 re:<正则>")
    p_iq.add_argument("--tls", action="store_true", help="显式要求 TLS 握手校验")
    p_iq.add_argument("--tls-sni", default="", help="指定 TLS SNI 并发起握手与主机名校验")
    p_iq.add_argument("--tls-verify-cert", action="store_true", help="强制校验 TLS 证书（默认随 --tls/--tls-sni 开启）")
    p_iq.add_argument("--tls-insecure", action="store_true", help="跳过 TLS 证书与主机名校验（仍校验握手）")
    p_iq.add_argument("--tls-cafile", default="", help="自定义 CA 根证书 PEM 路径")

    p_is = ing_sub.add_parser("select", help="显式固定某条规则使用的公网入口 IP（不改动 Realm 监听）")
    p_is.add_argument("--rule", required=True, help="已托管规则名")
    p_is.add_argument("--ip", required=True, help="选定的公网 IPv4")
    p_is.add_argument("--domain", default="", help="可选覆盖入口域名")
    p_is.add_argument("--dns-server", default="")
    p_is.add_argument("--allow-non-dns", action="store_true", help="允许选择当前未在 DNS 结果中的 IP")
    p_is.add_argument("--probe", action="store_true", help="同时对该 IP 执行 TCP 端口探活")
    p_is.add_argument("--verify-send", default="")
    p_is.add_argument("--verify-expect", default="")
    p_is.add_argument("--tls", action="store_true")
    p_is.add_argument("--tls-sni", default="")
    p_is.add_argument("--tls-insecure", action="store_true")
    p_is.add_argument("--tls-cafile", default="")
    p_is.add_argument("--timeout", type=float, default=3.0)
    p_is.add_argument("--lock-timeout", type=float, default=15.0)

    p_iu = ing_sub.add_parser("unselect", help="清除规则的固定公网 IP（恢复使用域名拨号）")
    p_iu.add_argument("--rule", required=True, help="已托管规则名")
    p_iu.add_argument("--lock-timeout", type=float, default=15.0)

    p_iv = ing_sub.add_parser("verify", help="从客户端或本机网络验证入口 IP/域名是否到达指定落地")
    p_iv.add_argument("--host", default="", help="要验证的固定公网 IP 或域名")
    p_iv.add_argument("--all-candidates", action="store_true", help="依次验证域名返回的所有 A 记录候选 IP")
    p_iv.add_argument("--domain", default="", help=f"参考入口域名 (默认 {DEFAULT_INGRESS_DOMAIN})")
    p_iv.add_argument("--port", type=int, default=None, help="公网端口")
    p_iv.add_argument("--rule", default="", help="规则名或规则文件路径")
    p_iv.add_argument("--dns-server", default="")
    p_iv.add_argument("--send", default="", help="发送给服务端的探测数据 (支持 \\n 等转义)")
    p_iv.add_argument("--expect", default="", help="预期回包匹配字符串或 re:<正则>（确认到达指定落地）")
    p_iv.add_argument("--tls", action="store_true", help="显式要求 TLS 握手（失败返回非零）")
    p_iv.add_argument("--tls-sni", default="", help="以指定 TLS SNI 发起握手与主机名校验（失败返回非零）")
    p_iv.add_argument("--tls-verify-cert", action="store_true", help="强制校验 TLS 证书（默认随 --tls/--tls-sni 开启）")
    p_iv.add_argument("--tls-insecure", action="store_true", help="跳过 TLS 证书与主机名校验（仍要求 TLS 握手成功）")
    p_iv.add_argument("--tls-cafile", default="", help="自定义 CA 根证书 PEM 路径")
    p_iv.add_argument("--timeout", type=float, default=3.0)

    p_update = sub.add_parser("update", help="从 GitHub/Gitee 仓库检查或拉取最新版本并原地更新")
    p_update.add_argument(
        "--channel",
        choices=tuple(UPDATE_CHANNELS),
        default=DEFAULT_UPDATE_CHANNEL,
        help="下载渠道：github（默认）或 gitee",
    )
    p_update.add_argument("--check", action="store_true", help="仅检查仓库最新版本，不执行安装")
    p_update.add_argument("--timeout", type=float, default=20.0, help="单次网络请求超时秒数 (默认 20)")

    p_ddns = sub.add_parser("ddns", help="独立双线路 IPv6 DDNS 检查、测试、状态与同步（仅支持 AAAA）")
    ddns_sub = p_ddns.add_subparsers(dest="ddns_cmd", required=True)

    p_di = ddns_sub.add_parser("inspect", help="只读扫描网卡公网 IPv6 候选并主动 ping 探测最低 RTT")
    p_di.add_argument("--profile", default="", help="可选 DDNS 配置名（如 ct / cu）；省略则检查全部")

    p_du = ddns_sub.add_parser("update", help="按最优 IPv6 同步 DDNS（带缓存、600s 远端校验与并发锁）")
    p_du.add_argument("--profile", default="", help="可选 DDNS 配置名（如 ct / cu）；省略则同步全部")
    p_du.add_argument("--force", action="store_true", help="忽略本地缓存强制与远端核对/更新")
    p_du.add_argument("--lock-timeout", type=float, default=15.0, help="并发写锁等待秒数 (默认 15)")
    p_du.add_argument("--timeout", type=float, default=15.0, help="DNS API 请求超时秒数 (默认 15)")

    p_dt = ddns_sub.add_parser("test", help="验证指定 DDNS 配置、0600 凭据、IPv6 探测及只读远端连通性")
    p_dt.add_argument("--profile", required=True, help="要检查的 DDNS 配置名（如 ct / cu）")
    p_dt.add_argument("--timeout", type=float, default=15.0, help="DNS API 请求超时秒数 (默认 15)")

    p_ds = ddns_sub.add_parser("status", help="查看独立 DDNS 配置与持久化运行状态")
    p_ds.add_argument("--profile", default="", help="可选 DDNS 配置名（如 ct / cu）；省略则显示全部")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "menu":
            return _run_menu(args.config)

        if args.command == "system":
            feature = "status" if args.system_feature == "network" else args.system_feature
            result = network_command(feature, args.system_action, getattr(args, "value", ""))
            if args.json:
                _print_json(result)
            else:
                _print_system_network(result)
            return 0

        if args.command in ("routing", "_restore-routing"):
            cfg = load_global_config(args.config)
            if args.command == "routing" and args.routing_cmd == "plan":
                result = plan_routing(cfg)
            else:
                result = apply_routing(cfg, restore=args.command == "_restore-routing")
            if args.json:
                _print_json(result)
            else:
                _print_routing(result)
            return 0

        if args.command in ("plan", "preview"):
            cfg = load_global_config(args.config)
            res = plan_rule(
                cfg,
                args.rule_file,
                check_dns=args.check_dns,
                allow_non_dns=args.allow_non_dns,
                dns_server=args.dns_server,
            )
            if args.json:
                _print_json(res)
            else:
                _print_plan(res)
            return 0

        if args.command == "apply":
            cfg = load_global_config(args.config)
            res = apply_rule(
                cfg,
                args.rule_file,
                lock_timeout=args.lock_timeout,
                allow_non_dns=args.allow_non_dns,
                dns_server=args.dns_server,
            )
            if args.json:
                _print_json(res)
            else:
                _print_apply(res)
            return 0

        if args.command == "status":
            cfg = load_global_config(args.config)
            items = status_rules(cfg, rule_name=args.rule_name, check_dns=args.check_dns)
            if args.json:
                _print_json(items)
            else:
                _print_status_list(items)
            return 0

        if args.command == "list":
            cfg = load_global_config(args.config)
            rules = list_managed_rules(cfg)
            if args.json:
                _print_json([asdict(r) for r in rules])
            else:
                if not rules:
                    print("当前没有已托管规则。")
                for r in rules:
                    dial = format_endpoint(r.dial_addr, r.public_port)
                    print(
                        f"{r.name}: 出口线路={_format_line_brief(cfg, r.line)} | 拨号={dial} | "
                        f"监听={r.listen_endpoint} -> 落地={r.remote_endpoint}"
                    )
            return 0

        if args.command in ("disable", "stop"):
            cfg = load_global_config(args.config)
            res = disable_rule(cfg, args.rule_name, lock_timeout=args.lock_timeout)
            if args.json:
                _print_json(res)
            else:
                print(
                    f"[已停用] 规则={res['rule_name']} 单元={res['unit_name']} "
                    f"active={res['active_state']} (已保留配置: {res['kept_config']})"
                )
            return 0

        if args.command in ("delete", "remove", "rm"):
            cfg = load_global_config(args.config)
            res = delete_rule(cfg, args.rule_name, lock_timeout=args.lock_timeout)
            if args.json:
                _print_json(res)
            else:
                print(f"[已删除] 规则={res['rule_name']} 单元={res['unit_name']}")
                for f in res["removed_files"]:
                    print(f"  已移除: {f}")
            return 0

        if args.command == "check-prereqs":
            cfg = load_global_config(args.config)
            res = check_prereqs(
                cfg,
                probe_remote=args.probe_remote,
                probe_remote_v6=args.probe_remote_v6,
            )
            if args.json:
                _print_json(res)
            else:
                print(f"Realm 检查: {'通过' if res['realm_ok'] else '失败'} -> {res['realm']}")
                print("说明      : 以下路由校验仅核对内核查路与本机接口/源地址，不代表远端落地 TCP 端口可达。")
                for line in res["lines"]:
                    if line["ok"]:
                        extras = []
                        if line.get("gateway"):
                            extras.append(f"gw {line['gateway']}")
                        if line.get("table") is not None:
                            extras.append(f"table {line['table']}")
                        extra_str = f" -> {', '.join(extras)}" if extras else ""
                        print(
                            f"线路 {line['line']} [通过]: {line['interface']} ({line['source_ip']}{extra_str}) "
                            f"| {line['route_output']}"
                        )
                    else:
                        print(f"线路 {line['line']} [失败]: {line['error']}")
            return 0 if res["ok"] else 1

        if args.command == "_verify-startup":
            cfg = load_global_config(args.config)
            res = verify_startup_rule(cfg, args.rule_name, wait_timeout=args.wait_timeout)
            if args.json:
                _print_json(res)
            else:
                extras = []
                if res.get("gateway"):
                    extras.append(f"gw {res['gateway']}")
                if res.get("table") is not None:
                    extras.append(f"table {res['table']}")
                extra_str = f" -> {', '.join(extras)}" if extras else ""
                print(
                    f"[启动前校验通过] 规则={res['rule_name']} 线路={res['line']} "
                    f"({res['source_ip']}@{res['interface']}{extra_str})"
                )
                print(f"入口回程 {res['return_route']}")
            return 0

        if args.command == "install-realm":
            state_dir = args.state_dir
            if not state_dir:
                cfg = _maybe_load_global(args.config)
                state_dir = cfg.tool.state_dir if cfg else DEFAULT_STATE_DIR
            info = install_realm_binary(
                target_path=args.target,
                tarball_path=args.tarball,
                state_dir=state_dir,
            )
            if args.json:
                _print_json(asdict(info))
            else:
                print(f"[Realm 已安装] 版本={info.version_text} 路径={info.path} SHA256={info.sha256}")
            return 0

        if args.command == "ingress":
            if args.ingress_cmd == "query":
                return _cmd_ingress_query(args)
            if args.ingress_cmd == "select":
                cfg = load_global_config(args.config)
                res = select_rule_ingress_ip(
                    cfg,
                    rule_name=args.rule,
                    ip=args.ip,
                    domain=args.domain or None,
                    dns_server=args.dns_server,
                    allow_non_dns=args.allow_non_dns,
                    probe=args.probe,
                    verify_send=args.verify_send,
                    verify_expect=args.verify_expect,
                    tls=args.tls,
                    tls_sni=args.tls_sni,
                    tls_cafile=args.tls_cafile,
                    tls_insecure=args.tls_insecure,
                    timeout=args.timeout,
                    lock_timeout=args.lock_timeout,
                )
                if args.json:
                    _print_json(res)
                else:
                    print(f"[已固定入口 IP] 规则={res['rule_name']} | 域名={res['domain']}")
                    print(f"查询时间   : {res['queried_at_local']} ({res['queried_at_utc']})")
                    print(
                        f"当前 A 记录: {', '.join(res['dns_ips']) or '(空)'} "
                        f"(所选 IP 在 DNS 中: {'是' if res['in_dns'] else '否'})"
                    )
                    if res.get("forced_override"):
                        print("覆盖标记   : 已通过 --allow-non-dns 显式强制覆盖固定公网 IP")
                    if res.get("warning"):
                        print(f"提示       : {res['warning']}")
                    print(f"Realm 监听 : {res['realm_listen']} (保持不变，未重启 Realm)")
                    if res["probe"]:
                        pr = res["probe"]
                        print(
                            f"入口探测   : [{pr['stage']}] {pr['detail']} "
                            f"(TLS={pr['tls_status']}, 证书={pr['cert_status']})"
                        )
                    for note in res["protocol_notes"]:
                        print(note)
                if res["probe"] and res["probe"]["exit_code"] != 0:
                    return int(res["probe"]["exit_code"])
                return 0
            if args.ingress_cmd == "unselect":
                cfg = load_global_config(args.config)
                res = unselect_rule_ingress_ip(cfg, rule_name=args.rule, lock_timeout=args.lock_timeout)
                if args.json:
                    _print_json(res)
                else:
                    print(
                        f"[已取消固定公网 IP] 规则={res['rule_name']}，客户端恢复拨号 {res['dial_address']} (未改动 Realm)"
                    )
                return 0
            if args.ingress_cmd == "verify":
                return _cmd_ingress_verify(args)

        if args.command == "ddns":
            cfg = load_global_config(args.config)
            if args.ddns_cmd == "inspect":
                items = inspect_ddns(cfg, profile_name=args.profile or None)
                if args.json:
                    _print_json(
                        {
                            "supported_record_types": ["AAAA"],
                            "profiles": [asdict(item) for item in items],
                        }
                    )
                else:
                    _print_ddns_inspect(items)
                return 1 if any(item.error for item in items) else 0
            if args.ddns_cmd == "update":
                res = update_ddns(
                    cfg,
                    profile_name=args.profile or None,
                    force=args.force,
                    lock_timeout=args.lock_timeout,
                    api_timeout=args.timeout,
                )
                if args.json:
                    _print_json(res)
                else:
                    _print_ddns_update(res)
                return 0 if res["ok"] else 1
            if args.ddns_cmd == "test":
                res = test_ddns_profile(cfg, profile_name=args.profile, api_timeout=args.timeout)
                if args.json:
                    _print_json(res)
                else:
                    _print_ddns_test(res)
                return 0 if res["ok"] else 1
            if args.ddns_cmd == "status":
                res = status_ddns(cfg, profile_name=args.profile or None)
                if args.json:
                    _print_json(res)
                else:
                    _print_ddns_status(res)
                return 0

        if args.command == "update":
            if args.check:
                info = check_for_update(channel=args.channel, timeout=args.timeout)
                if args.json:
                    _print_json(asdict(info))
                else:
                    _print_update_check(info)
                return 0
            res = perform_update(channel=args.channel, timeout=args.timeout)
            if args.json:
                _print_json(asdict(res))
            else:
                _print_update_result(res)
            return 0

        parser.print_help()
        return 2
    except (
        ConfigError,
        PreflightError,
        ApplyError,
        RealmError,
        IngressError,
        OwnershipError,
        LockTimeoutError,
        SystemErrorBase,
        UpdateError,
        DdnsError,
    ) as exc:
        if args.json:
            _print_json({"error": str(exc)})
        else:
            print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
