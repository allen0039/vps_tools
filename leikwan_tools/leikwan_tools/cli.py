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
import sys
from typing import Any, Dict, List, Optional

from . import (
    DEFAULT_INGRESS_DOMAIN,
    DEFAULT_STATE_DIR,
    MANAGED_REALM_BIN,
    __version__,
)
from .config import (
    ConfigError,
    GlobalConfig,
    RuleConfig,
    format_endpoint,
    load_global_config,
    load_rule_config,
    parse_rule_config_dict,
    validate_ipv4,
)
from .ddns import (
    ISP_LABELS,
    DdnsError,
    ProfileInspectResult,
    inspect_ddns,
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
    print(f"=== 变更预览 [{res['action']}]（{action_zh}） 转发: {res['rule_name']} ===")
    print(
        f"出口线路   : {res['line']['name']} (网卡={res['line']['interface']}, "
        f"源IP={res['through']}, 网关={res['line']['gateway']}, 表={res['line']['table']})"
    )
    dial = format_endpoint(res["dial_hint"], res["public_port"])
    print(f"客户端入口 : {dial} -> 本机监听 {res['listen']} -> 落地 {res['remote']}")
    print(f"systemd单元: {res['unit_name']}")
    print(f"Realm 版本 : {res['realm']['version']} ({res['realm']['origin']}) @ {res['realm']['path']}")
    print(f"路由校验   : {res['route_check']['command']}")
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
    print(f"[{label}] 规则={res['rule_name']} 单元={res['unit_name']} PID={res['main_pid']}")
    print(
        f"转发链路 : 客户端({format_endpoint(res['dial_addr'], res['public_port'])}) -> 本机({res['listen']}) "
        f"-> 经({res['through']}@{res['egress_interface']}) -> 落地({res['remote']})"
    )
    print(f"出口线路 : {res['line']} | Realm {res['realm_version']} ({res['realm_bin']})")
    if res.get("route_output"):
        print(f"路由实测 : {res['route_output']}")
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
        print(f"转发名称   : {item['rule_name']}  ({item['description'] or '无备注'})")
        print(f"当前状态   : {_format_rule_status_summary(item)} | 开机自启: {autostart}")
        print(f"出口线路   : {line_desc}")
        print(f"客户端连接 : {dial}")
        print(
            f"转发路径   : 入口 {dial} -> 本机监听 {item['listen']} "
            f"-> 出口 {item['line']}({item['through']}@{item['egress_interface']}) -> 落地 {item['remote']}"
        )
        if item["ingress_domain"]:
            print(
                f"固定公网IP : {item['ingress_fixed_ip'] or '(未固定，使用域名解析)'}  "
                f"[域名: {item['ingress_domain']}]"
            )
        print(f"出口路由   : {'正常' if item['route_ok'] else '异常'} | {item['route_detail']}")
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
        f"{rule.name}  (出口: {_format_line_brief(cfg, rule.line)} | 入口: {format_endpoint(rule.dial_addr, rule.public_port)} -> 落地: {rule.remote_ip}:{rule.remote_port})"
        for rule in managed
    ]
    return rules.get(_menu_pick(list(rules), prompt, labels=labels))


def _menu_field(label: str, default: Any = "") -> str:
    hint = f" [{default}]" if default else ""
    return input(f"{label}{hint}：").strip() or str(default)


def _menu_domain(value: str) -> str:
    try:
        hostname = value.removesuffix(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConfigError(f"入口域名无效: {value!r}") from exc
    labels = hostname.split(".")
    if len(hostname) > 253 or len(labels) < 2 or labels[-1].isdigit() or any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels
    ):
        raise ConfigError(f"入口域名无效: {value!r}")
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
    entry = _menu_field("入口地址（默认官方域名；IPv6 直连请填本机公网 IPv6）", default_entry)
    direct = ":" in entry
    domain = "" if direct else _menu_domain(entry)
    public_port = _menu_port("客户端连接的公网端口（外部端口）", old.public_port if old else "")
    listen_ip, listen_port = entry, public_port
    if not direct:
        old_ipv4 = old if old and not old.direct_ipv6 else None
        listen_ip = _menu_field("本机监听的内网 IPv4（利群面板映射指向的 VPS 内网地址）", old_ipv4.listen_ip if old_ipv4 else "")
        listen_port = _menu_port("本机监听的内网端口（利群面板映射指向的 VPS 内部端口）", old_ipv4.listen_port if old_ipv4 else "")
    remote_ip = _menu_field("落地服务器 IPv4（目标机地址）", old.remote_ip if old else "")
    remote_port = _menu_port("落地服务器端口（目标机端口）", old.remote_port if old else "")
    line_names = list(cfg.lines)
    line_labels = [
        f"{lname}（网卡 {lc.interface}，源IP {lc.source_ip}" + (f"，{lc.description}" if lc.description else "") + "）"
        for lname, lc in cfg.lines.items()
    ]
    line = _menu_pick(
        line_names,
        "选择出口线路",
        old.line if old and old.line in cfg.lines else "",
        labels=line_labels,
    )
    if not line:
        return
    rule = parse_rule_config_dict({
        "rule": {"name": name, "line": line},
        "ingress": {"domain": domain, "public_port": public_port},
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
            f"[{badge}] {rule.name}  (出口: {_format_line_brief(cfg, rule.line)} | 入口: {dial} -> 落地: {rule.remote_ip}:{rule.remote_port})"
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
    print(f"将删除转发：{rule.name}（入口 {dial} -> 本机监听 {rule.listen_endpoint} -> 落地 {rule.remote_ip}:{rule.remote_port}）")
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
        print(f"     落地目标   : {rule.remote_ip}:{rule.remote_port}")


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


def _menu_system_group(config_path: str) -> None:
    while True:
        print(f"\nleikwan_tools v{__version__} > 初始化与环境排查")
        print("  1. 初始化双线出口路由（首次装机时执行）")
        print("  2. 检查运行环境与线路状态")
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
        print(f"网卡与探测 : dev={item.interface} | ping -6 -c 1 -w {item.probe_timeout_seconds} -I <候选IP> {item.probe_target}")
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
                print(f"  - {cand.ip} [{mark}] {cand.detail}")
        if item.filtered_out:
            print("已过滤地址 :")
            for skipped in item.filtered_out:
                print(f"  - {skipped.raw} ({skipped.reason})")


def _print_ddns_update(res: Dict[str, Any]) -> None:
    print("协议说明   : 当前仅支持 IPv6 AAAA 记录（配置模型已预留 A 记录扩展）")
    if not res.get("ddns_enabled", True):
        print("DDNS 状态  : 全局 [ddns].enabled = false，已跳过所有更新")
        return
    for item in res["results"]:
        isp_zh = ISP_LABELS.get(item["isp"], item["isp"])
        target_name = item["fqdn"] or "(Webhook)"
        print(
            f"[{item['action']}] 配置={item['profile']} ({isp_zh}@{item['interface']} | "
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
    print(
        f"DDNS 联调检查 [{res['profile']}]: {isp_zh}@{res['interface']} | "
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
        print(f"接口/服务  : dev={item['interface']} | {item['provider']} {item['record_type']} -> {item['fqdn'] or '(Webhook)'}")
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


def _run_menu(config_path: str) -> int:
    try:
        while True:
            print(f"\nleikwan_tools 利群转发助手 v{__version__}")
            print("  1. 查看转发状态")
            print("  2. 转发规则管理（查看 / 新建 / 修改 / 暂停恢复 / 删除）")
            print("  3. 查询官方公网入口 IP")
            print("  4. 查询并设置转发的客户端入口 IP")
            print("  5. 初始化与环境排查（双线路由 / 环境检查）")
            print("  6. 从仓库检查并更新工具")
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
            else:
                print("无效选项，请重新输入。")
    except (EOFError, KeyboardInterrupt):
        print()
        return 0


def build_parser() -> argparse.ArgumentParser:
    default_cfg = resolve_default_config_path()
    parser = argparse.ArgumentParser(
        prog="leikwan_tools",
        description="独立「leikwan_tools」— 利群 VPS 多规则 Realm IPv4 TCP 转发与公网入口管理工具",
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

    p_apply = sub.add_parser("apply", help="从规则文件应用/更新一条 IPv4 TCP 转发规则（幂等、带锁、失败回滚）")
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

    p_prereq = sub.add_parser("check-prereqs", help="只读检查 Realm 二进制、网卡、源 IP 与源策略路由前置条件")
    p_prereq.add_argument("--probe-remote", default="192.0.2.10", help="用于 ip route get 自检的测试目标 IPv4")

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
                        f"监听={r.listen_endpoint} -> 落地={r.remote_ip}:{r.remote_port}"
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
            res = check_prereqs(cfg, probe_remote=args.probe_remote)
            if args.json:
                _print_json(res)
            else:
                print(f"Realm 检查: {'通过' if res['realm_ok'] else '失败'} -> {res['realm']}")
                for line in res["lines"]:
                    if line["ok"]:
                        print(
                            f"线路 {line['line']} [通过]: {line['interface']} ({line['source_ip']} -> "
                            f"gw {line['gateway']}, table {line['table']}) | {line['route_output']}"
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
                print(
                    f"[启动前校验通过] 规则={res['rule_name']} 线路={res['line']} "
                    f"({res['source_ip']}@{res['interface']} -> gw {res['gateway']}, table {res['table']})"
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
