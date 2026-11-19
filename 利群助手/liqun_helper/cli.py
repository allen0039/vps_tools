"""Command-line interface for liqun-helper."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from . import (
    DEFAULT_INGRESS_DOMAIN,
    DEFAULT_STATE_DIR,
    MANAGED_REALM_BIN,
    __version__,
)
from .config import ConfigError, GlobalConfig, RuleConfig, load_global_config, load_rule_config
from .ingress import (
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
from .ownership import OwnershipError, ensure_safe_subpath, resolve_default_config_path, validate_rule_name
from .realm import RealmError, install_realm_binary
from .system import LockTimeoutError, PreflightError, SystemErrorBase


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
    print(f"=== 预览结果 [{res['action']}] 规则: {res['rule_name']} ===")
    print(
        f"出口线路   : {res['line']['name']} (网卡={res['line']['interface']}, "
        f"源IP={res['through']}, 网关={res['line']['gateway']}, 表={res['line']['table']})"
    )
    print(f"客户端入口 : {res['dial_hint']}:{res['public_port']} -> 本机监听 {res['listen']} -> 落地 {res['remote']}")
    print(f"systemd单元: {res['unit_name']}")
    print(f"Realm 版本 : {res['realm']['version']} ({res['realm']['origin']}) @ {res['realm']['path']}")
    print(f"路由校验   : {res['route_check']['command']}")
    print(f"             {res['route_check']['raw_output']}")
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
        f"转发链路 : 客户端({res['dial_addr']}:{res['public_port']}) -> 本机({res['listen']}) "
        f"-> 经({res['through']}@{res['egress_interface']}) -> 落地({res['remote']})"
    )
    print(f"出口线路 : {res['line']} | Realm {res['realm_version']} ({res['realm_bin']})")
    if res.get("route_output"):
        print(f"路由实测 : {res['route_output']}")
    if res.get("forced_non_dns"):
        print("覆盖标记 : 已通过 --allow-non-dns 显式强制覆盖固定公网 IP")
    if res.get("stale_ip_warning"):
        print(f"入口警告 : {res['stale_ip_warning']}")


def _print_status_list(items: List[Dict[str, Any]]) -> None:
    if not items:
        print("当前没有已部署的托管规则（安装默认不启用任何示例规则）。")
        return
    for idx, item in enumerate(items):
        if idx > 0:
            print("-" * 72)
        print(f"规则名     : {item['rule_name']}  ({item['description'] or '无描述'})")
        print(
            f"运行状态   : enabled={item['enabled']} active={item['active_state']}({item['sub_state']}) "
            f"PID={item['main_pid']} restarts={item['n_restarts']} listening_ok={item['listening_ok']}"
        )
        print(
            f"转发路径   : 拨号 {item['dial_addr']}:{item['public_port']} -> 监听 {item['listen']} "
            f"-> 线路 {item['line']}({item['through']}@{item['egress_interface']}) -> 落地 {item['remote']}"
        )
        print(
            f"固定公网IP : {item['ingress_fixed_ip'] or '(未固定，使用域名解析)'}  "
            f"[域名: {item['ingress_domain']}]"
        )
        print(f"路由状态   : {'正常' if item['route_ok'] else '异常'} | {item['route_detail']}")
        print(f"Realm 实例 : {item['realm_version']} @ {item['realm_bin']} | systemd={item['unit_name']}")
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
                    "detail": "仅执行 DNS A 记录查询（未指定 --port 或 --rule 探测端口）",
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
            print("  固定选择: liqun-helper ingress select --rule <规则名> --ip <候选IP>")
            print(
                f"  客户端验证: liqun-helper ingress verify --host <候选IP> --port {port} "
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
            args.host = rule.ingress_fixed_ip or rule.ingress_domain

    if port is None:
        raise ConfigError("必须指定 --port 或通过 --rule 指定规则以获取公网端口")

    dns_res = query_dns_a(domain=domain, dns_server=dns_server, timeout=args.timeout)
    targets: List[str] = []
    if args.all_candidates:
        targets = list(dns_res.ips)
        if not targets:
            raise IngressError(f"未能从 {domain} 解析到任何 A 记录 ({dns_res.error})")
    elif args.host:
        try:
            import ipaddress

            ipaddress.IPv4Address(args.host)
            targets = [args.host]
        except ValueError:
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
        print(f"参考域名   : {domain} (当前 DNS A 记录: {', '.join(dns_res.ips) or '无'})")
        for r in results:
            rtt = f" RTT={r['rtt_ms']}ms" if r["rtt_ms"] is not None else ""
            tcp_str = "连通" if r["tcp_reachable"] else "失败"
            print(f"  - {r['ip']}:{r['port']} => [{r['stage']}]{rtt} | {r['detail']}")
            print(
                f"    分层状态: TCP={tcp_str} | TLS={r['tls_status']} | "
                f"证书({r['cert_verify_mode']})={r['cert_status']} | 应用={r['app_status']}"
            )
            if r["response_preview"]:
                print(f"    回包预览: {r['response_preview']}")
            if r["tls_subject"] or r["tls_san"]:
                print(f"    TLS 证书: subject={r['tls_subject']} san={r['tls_san']}")
        print("\n" + "\n".join(protocol_preservation_notes(results[0]["ip"], port, domain)))

    if any(r["exit_code"] == 0 for r in results):
        return 0
    for code in (4, 3, 2, 1):
        if any(r["exit_code"] == code for r in results):
            return code
    return 1


def build_parser() -> argparse.ArgumentParser:
    default_cfg = resolve_default_config_path()
    parser = argparse.ArgumentParser(
        prog="liqun-helper",
        description="独立「利群助手」— 利群 VPS 多规则 Realm IPv4 TCP 转发与公网入口管理工具",
    )
    parser.add_argument(
        "--config",
        default=default_cfg,
        help=f"主配置文件路径 (当前默认: {default_cfg})",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出结果")
    parser.add_argument("--version", action="version", version=f"liqun-helper {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

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

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
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
                    dial = r.ingress_fixed_ip or r.ingress_domain
                    print(
                        f"{r.name}: 线路={r.line} | 拨号={dial}:{r.public_port} | "
                        f"监听={r.listen_ip}:{r.listen_port} -> 落地={r.remote_ip}:{r.remote_port}"
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
    ) as exc:
        if args.json:
            _print_json({"error": str(exc)})
        else:
            print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
