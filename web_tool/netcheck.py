#!/usr/bin/env python3
"""按需运行的网络检测工具，仅使用 Python 标准库。"""

import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

VERSION = "0.2.0"
SCRIPT = os.path.realpath(__file__)
ACTIVE_PROCESSES = set()
PROCESS_LOCK = threading.Lock()
CANCELLED = threading.Event()


def elapsed(start):
    return round((time.monotonic() - start) * 1000, 2)


def failure(message, **fields):
    return dict(ok=False, error=str(message), **fields)


def run_process(args, timeout, **kwargs):
    if CANCELLED.is_set():
        raise OSError("检测已取消")
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, **kwargs)
    with PROCESS_LOCK:
        ACTIVE_PROCESSES.add(proc)
        if CANCELLED.is_set():
            proc.kill()
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
    except BaseException:
        # 包括超时和 Ctrl+C，始终清理进程并回收它。
        proc.kill()
        proc.communicate()
        raise
    finally:
        with PROCESS_LOCK:
            ACTIVE_PROCESSES.discard(proc)


def host_value(value):
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("域名格式无效")
    if len(host) > 253 or not host or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise ValueError("请输入有效域名或 IP；网址请用于 http 或 check 命令")
    return host


def url_value(value):
    value = value.strip()
    if len(value) > 8192:
        raise ValueError("网址过长（上限 8192 个字符）")
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ValueError("网址不能包含空格或控制字符")
    if "://" not in value:
        # 裸 IPv6 地址也可以作为 HTTPS 目标。
        try:
            if ipaddress.ip_address(value).version == 6:
                value = "[" + value + "]"
        except ValueError:
            pass
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("只支持 HTTP / HTTPS 网址")
    if parts.username is not None or parts.password is not None:
        raise ValueError("网址不支持内嵌用户名或密码")
    host = host_value(parts.hostname)
    port = parts.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("端口必须在 1–65535 之间")
    authority = "[" + host + "]" if ":" in host else host
    if port is not None:
        authority += ":" + str(port)
    return urlunsplit((parts.scheme, authority,
                       quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~"),
                       quote(parts.query, safe="%/?@:!$&'()*+,;=-._~"), ""))


def worker(kind, payload, timeout):
    """隔离可能阻塞的系统 DNS / HTTP 调用，超时即终止子进程。"""
    try:
        proc = run_process(
            [sys.executable, SCRIPT, "--_worker", kind, json.dumps(payload)],
            timeout=timeout,
        )
        if proc.returncode:
            return failure("检测子进程异常退出")
        return json.loads(proc.stdout)
    except subprocess.TimeoutExpired:
        return failure("检测超时（上限 %g 秒）" % timeout)
    except (OSError, ValueError) as exc:
        return failure(exc)


def resolve_native(host):
    start = time.monotonic()
    addresses = []
    for family, _, _, _, address in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        ip = address[0]
        if ip not in [item["ip"] for item in addresses]:
            addresses.append({"ip": ip, "family": "IPv6" if family == socket.AF_INET6 else "IPv4"})
    if not addresses:
        return failure("未解析到 IP 地址", host=host)
    return dict(ok=True, host=host, addresses=addresses, dns_ms=elapsed(start))


def resolve(host, timeout):
    try:
        address = ipaddress.ip_address(host)
        return dict(ok=True, host=host, addresses=[
            {"ip": str(address), "family": "IPv%d" % address.version}
        ], dns_ms=0, literal_ip=True)
    except ValueError:
        result = worker("dns", host, timeout)
        result["host"] = host
        return result


def dns_check(host, timeout):
    result = resolve(host, timeout)
    if result["ok"] and not result.get("literal_ip"):
        dig = shutil.which("dig")
        result["cnames"] = []
        if not dig:
            result["cname_note"] = "未安装 dig，跳过可选 CNAME 查询"
        else:
            try:
                proc = run_process(
                    [dig, "+short", "+tries=1", "+time=" + str(max(1, int(timeout))),
                     host, "CNAME"], timeout=timeout,
                )
                if proc.returncode == 0:
                    result["cnames"] = [line.rstrip(".") for line in proc.stdout.splitlines()
                                        if line and not line.startswith(";")]
                else:
                    result["cname_note"] = "CNAME 查询失败；A / AAAA 解析结果仍可用"
            except (OSError, subprocess.TimeoutExpired):
                result["cname_note"] = "CNAME 查询失败或超时；A / AAAA 解析结果仍可用"
    return result


def geo_native(config):
    ip = str(ipaddress.ip_address(config["ip"]))
    connection = http.client.HTTPSConnection("ipwho.is", timeout=config["timeout"])
    try:
        fields = "success,message,country,country_code,region,city,connection.isp,connection.org"
        connection.request("GET", "/" + quote(ip, safe=":") + "?lang=zh-CN&fields=" + fields,
                           headers={"User-Agent": "netcheck/" + VERSION,
                                    "Accept": "application/json", "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            return failure("归属地服务返回 HTTP %d" % response.status)
        body = response.read(65537)
        if len(body) > 65536:
            return failure("归属地响应超过大小上限")
        data = json.loads(body)
        if not isinstance(data, dict):
            return failure("归属地服务返回无效数据")
        if data.get("success") is not True:
            message = data.get("message")
            return failure(message if isinstance(message, str) else "未查询到归属地")
        location = {key: data[key].strip() if isinstance(data.get(key), str) else ""
                    for key in ("country", "country_code", "region", "city")}
        if not any(location[key] for key in ("country", "region", "city")):
            return failure("归属地服务未返回国家、地区或城市")
        network = data.get("connection")
        isp = ""
        if isinstance(network, dict):
            isp = next((network[key].strip() for key in ("isp", "org")
                        if isinstance(network.get(key), str) and network[key].strip()), "")
        return dict(ok=True, source="ipwho.is", isp=isp, **location)
    finally:
        connection.close()


def geo_ip(ip, timeout):
    address = ipaddress.ip_address(ip)
    public_address = (address.ipv4_mapped or address) if address.version == 6 else address
    if not public_address.is_global or public_address.is_multicast or public_address.is_reserved:
        return failure("内网或保留地址，无公网归属地", skipped=True)
    result = worker("geo", dict(ip=str(address), timeout=timeout), timeout)
    result.setdefault("source", "ipwho.is")
    return result


def annotate_locations(report, args):
    if args.no_geo:
        return
    items = list(report.get("dns", {}).get("addresses", []))
    items.extend(report.get("http", {}).get("hops", []))
    if not items:
        return
    addresses = list(dict.fromkeys(item["ip"] for item in items))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    try:
        locations = dict(zip(addresses, pool.map(lambda ip: geo_ip(ip, args.geo_timeout), addresses)))
    except KeyboardInterrupt:
        CANCELLED.set()
        with PROCESS_LOCK:
            for proc in ACTIVE_PROCESSES:
                proc.kill()
        raise
    finally:
        pool.shutdown(wait=True)
    for item in items:
        item["geo"] = locations[item["ip"]]


def parse_ping(output):
    packets = re.search(r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received", output)
    loss = re.search(r"([\d.]+)% packet loss", output)
    timing = re.search(r"(?:rtt|round-trip)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", output)
    result = {}
    if packets:
        result.update(sent=int(packets[1]), received=int(packets[2]))
    if loss:
        result["loss_pct"] = float(loss[1])
    if timing:
        result.update(min_ms=float(timing[1]), avg_ms=float(timing[2]), max_ms=float(timing[3]))
    return result


def ping_ip(ip, count, timeout):
    ipv6 = ipaddress.ip_address(ip).version == 6
    command = shutil.which("ping")
    if ipv6 and platform.system() == "Darwin":
        command = shutil.which("ping6")
    if not command:
        return failure("缺少系统 ping%s 命令" % ("6" if ipv6 else ""), ip=ip)
    args = [command, "-n", "-c", str(count)]
    if platform.system() == "Linux":
        if ipv6:
            args.append("-6")
        args.extend(["-W", str(max(1, int(timeout)))])
    elif platform.system() == "Darwin" and not ipv6:
        args.extend(["-W", str(int(timeout * 1000))])
    args.append(ip)
    budget = count * timeout + count + 2
    try:
        proc = run_process(args, timeout=budget, env=dict(os.environ, LC_ALL="C"))
        stats = parse_ping(proc.stdout)
        result = dict(ok=stats.get("received", 0) > 0, ip=ip, **stats)
        if not result["ok"]:
            result["error"] = proc.stderr.strip() or "未收到 ICMP 响应（目标可能禁用 Ping）"
        return result
    except subprocess.TimeoutExpired:
        return failure("Ping 超时（总上限 %g 秒）" % budget, ip=ip)
    except OSError as exc:
        return failure(exc, ip=ip)


def tcp_ip(ip, port, timeout):
    if CANCELLED.is_set():
        return failure("检测已取消", ip=ip, port=port)
    start = time.monotonic()
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect((ip, port))
        return dict(ok=True, ip=ip, port=port, connect_ms=elapsed(start))
    except OSError as exc:
        return failure(exc, ip=ip, port=port, connect_ms=elapsed(start))


def probe_addresses(dns, kind, args):
    addresses = dns["addresses"][:args.max_addresses]
    function = (lambda ip: ping_ip(ip, args.count, args.timeout)) if kind == "ping" else (
        lambda ip: tcp_ip(ip, args.port, args.timeout))
    # 同时运行最多 3 项，结果按系统解析顺序输出。
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    try:
        return list(pool.map(function, [item["ip"] for item in addresses]))
    except KeyboardInterrupt:
        CANCELLED.set()
        with PROCESS_LOCK:
            for proc in ACTIVE_PROCESSES:
                proc.kill()
        raise
    finally:
        pool.shutdown(wait=True)


def http_native(config):
    current = config["url"]
    timeout = config["timeout"]
    start = time.monotonic()
    hops = []
    for index in range(config["max_redirects"] + 1):
        parts = urlsplit(current)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        dns = resolve_native(host)
        connected = None
        last_error = "未解析到地址"
        for item in dns.get("addresses", [])[:config["max_addresses"]]:
            conn = None
            try:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                tcp_start = time.monotonic()
                sock = socket.socket(socket.AF_INET6 if item["family"] == "IPv6" else socket.AF_INET,
                                     socket.SOCK_STREAM)
                conn.sock = sock  # 出错时由 conn.close() 释放。
                sock.settimeout(timeout)
                sock.connect((item["ip"], port))
                tcp_ms = elapsed(tcp_start)
                tls_ms = None
                if parts.scheme == "https":
                    tls_start = time.monotonic()
                    conn.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                    tls_ms = elapsed(tls_start)
                connected = (conn, item["ip"], tcp_ms, tls_ms)
                break
            except OSError as exc:
                last_error = str(exc)
                if conn:
                    conn.close()
        if connected is None:
            return failure(last_error, url=current, hops=hops, total_ms=elapsed(start))
        conn, ip, tcp_ms, tls_ms = connected
        try:
            path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            headers_start = time.monotonic()
            conn.request("HEAD", path, headers={"User-Agent": "netcheck/" + VERSION,
                                                "Connection": "close"})
            response = conn.getresponse()
            hop = dict(url=current, ip=ip, status=response.status, dns_ms=dns["dns_ms"],
                       tcp_ms=tcp_ms, tls_ms=tls_ms, headers_ms=elapsed(headers_start))
            hops.append(hop)
            location = response.getheader("Location")
            if response.status in (301, 302, 303, 307, 308) and location:
                if index == config["max_redirects"]:
                    return failure("超过重定向次数上限", url=current, hops=hops, total_ms=elapsed(start))
                current = url_value(urljoin(current, location))
                continue
            result = dict(ok=response.status < 400, url=current, status=response.status,
                          method="HEAD", hops=hops, total_ms=elapsed(start))
            if not result["ok"]:
                result["error"] = "HTTP 状态码 %d" % response.status
                if response.status in (405, 501):
                    result["error"] += "：服务器不支持 HEAD，未下载正文"
            return result
        finally:
            conn.close()
    return failure("网站检测失败")


def http_check(url, args):
    result = worker("http", dict(url=url, timeout=args.timeout, max_redirects=args.max_redirects,
                                 max_addresses=args.max_addresses), args.timeout)
    result.setdefault("url", url)
    return result


def execute(args):
    start = time.monotonic()
    report = dict(command=args.command, target=args.target)
    if args.command == "http":
        report["http"] = http_check(url_value(args.target), args)
    else:
        host = host_value(urlsplit(url_value(args.target)).hostname) if args.command == "check" else host_value(args.target)
        report["dns"] = dns_check(host, args.timeout) if args.command == "dns" else resolve(host, args.timeout)
        dns = report["dns"]
        if dns["ok"] and args.command != "dns":
            report["tested_addresses"] = len(dns["addresses"][:args.max_addresses])
            report["skipped_addresses"] = max(0, len(dns["addresses"]) - args.max_addresses)
            if args.command in ("ping", "check"):
                report["ping"] = probe_addresses(dns, "ping", args)
            if args.command in ("tcp", "check"):
                if args.command == "check" and args.port is None:
                    parts = urlsplit(url_value(args.target))
                    args.port = parts.port or (443 if parts.scheme == "https" else 80)
                report["tcp"] = probe_addresses(dns, "tcp", args)
            if args.command == "check":
                report["http"] = http_check(url_value(args.target), args)
    annotate_locations(report, args)
    checks = []
    for key in ("dns", "http"):
        if key in report:
            checks.append(report[key]["ok"])
    for key in ("ping", "tcp"):
        checks.extend(item["ok"] for item in report.get(key, []))
    report.update(ok=all(checks), total_ms=elapsed(start))
    return report


def safe_text(value):
    # 远端返回内容及错误信息不能在 SSH 终端注入控制序列。
    return "".join(char if char.isprintable() else " " for char in str(value))


def geo_suffix(item):
    geo = item.get("geo")
    if not geo:
        return ""
    if not geo["ok"]:
        return "（归属地：%s%s）" % ("" if geo.get("skipped") else "查询失败：", safe_text(geo["error"]))
    parts = list(dict.fromkeys(geo[key] for key in ("country", "region", "city") if geo.get(key)))
    location = safe_text(" ".join(parts))
    isp = "；ISP：" + safe_text(geo["isp"]) if geo.get("isp") else ""
    return "（归属地：%s%s）" % (location, isp)


def display(report, as_json=False):
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    print("\n目标：" + safe_text(report["target"]))
    dns = report.get("dns")
    if dns:
        if dns["ok"]:
            print("解析：%g ms%s" % (dns["dns_ms"], "（输入为 IP，未查询 DNS）" if dns.get("literal_ip") else "（系统解析器）"))
            for item in dns["addresses"]:
                print("  %-4s %s%s" % (item["family"], item["ip"], geo_suffix(item)))
            for cname in dns.get("cnames", []):
                print("  CNAME " + safe_text(cname))
            if dns.get("cname_note"):
                print("  " + dns["cname_note"])
        else:
            print("解析失败：" + safe_text(dns["error"]))
    if report.get("skipped_addresses"):
        print("本次仅检测前 %d 个 IP，跳过 %d 个；可用 --max-addresses 调整。" % (
            report["tested_addresses"], report["skipped_addresses"]))
    for item in report.get("ping", []):
        if item["ok"]:
            print("Ping %s：最小 / 平均 / 最大 %s / %s / %s ms，丢包 %s%%" % (
                item["ip"], item.get("min_ms", "—"), item.get("avg_ms", "—"), item.get("max_ms", "—"), item.get("loss_pct", "—")))
        else:
            print("Ping %s：%s" % (item["ip"], safe_text(item["error"])))
    for item in report.get("tcp", []):
        print("TCP %s:%d：%s" % (item["ip"], item["port"],
              "%g ms" % item["connect_ms"] if item["ok"] else safe_text(item["error"])))
    if "http" in report:
        result = report["http"]
        for hop in result.get("hops", []):
            print("HTTP %d  %s（IP：%s）%s" % (hop["status"], safe_text(hop["url"]), hop["ip"], geo_suffix(hop)))
            print("  DNS %g ms / TCP %g ms / TLS %s / 响应头 %g ms" % (
                hop["dns_ms"], hop["tcp_ms"],
                "%g ms" % hop["tls_ms"] if hop["tls_ms"] is not None else "—", hop["headers_ms"]))
        if not result["ok"]:
            print("网站检测：" + safe_text(result["error"]))
        print("网站检测使用 HEAD，不读取页面正文。")
    print("总耗时：%g ms；%s" % (report["total_ms"], "检测完成" if report["ok"] else "存在未通过的项目"))
    if any(not item["ok"] for item in report.get("ping", [])):
        print("提示：Ping 不通不代表网站不可用，请结合 TCP 和 HTTP 结果判断。")
    locations = list(report.get("dns", {}).get("addresses", [])) + report.get("http", {}).get("hops", [])
    if any(item.get("geo") and not item["geo"].get("skipped") for item in locations):
        print("提示：归属地为 IP 数据库估算；CDN / Anycast 地址不代表源站位置。")


def bounded_number(low, high, convert):
    def parse(value):
        try:
            number = convert(value)
            if not low <= number <= high:
                raise ValueError
            return number
        except ValueError:
            raise argparse.ArgumentTypeError("取值范围：%s–%s" % (low, high))
    return parse


def parser():
    main = argparse.ArgumentParser(prog="netcheck", description="轻量 VPS 网络检测；无参数打开中文菜单")
    main.add_argument("--version", action="version", version="netcheck " + VERSION)
    sub = main.add_subparsers(dest="command", required=True)
    for name, help_text in [("dns", "域名解析"), ("ping", "Ping 延迟与丢包"),
                            ("tcp", "TCP 端口检测"), ("http", "HTTP / HTTPS 响应头检测"),
                            ("check", "综合检测")]:
        item = sub.add_parser(name, help=help_text, description=help_text)
        item.add_argument("target", help="域名或 IP；http / check 也支持完整网址")
        item.add_argument("--timeout", type=bounded_number(0.1, 10, float), default=5,
                          help="超时秒数，默认 5；HTTP 为整项总上限")
        item.add_argument("--json", action="store_true", help="输出 JSON，方便脚本调用")
        item.add_argument("--no-geo", action="store_true", help="不向第三方查询 IP 归属地")
        item.add_argument("--geo-timeout", type=bounded_number(0.1, 10, float), default=3,
                          help="每个 IP 的归属地查询总上限，默认 3 秒")
        item.set_defaults(count=5, port=443, max_addresses=3, max_redirects=3)
        if name in ("ping", "check"):
            item.add_argument("--count", type=bounded_number(1, 20, int), default=5, help="Ping 次数，默认 5")
        if name in ("tcp", "check"):
            item.add_argument("--port", type=bounded_number(1, 65535, int),
                              default=None if name == "check" else 443,
                              help="TCP 端口；tcp 默认 443，check 默认网址端口")
        if name != "dns":
            item.add_argument("--max-addresses", type=bounded_number(1, 8, int), default=3,
                              help="最多探测的 IP 数，默认 3；同时执行最多 3 项")
        if name in ("http", "check"):
            item.add_argument("--max-redirects", type=bounded_number(0, 5, int), default=3,
                              help="最多跟随的 HTTP 重定向次数，默认 3")
    return main


def run_command(argv):
    args = parser().parse_args(argv)
    if not args.json:
        print("正在检测，请稍候…（Ctrl+C 取消）", flush=True)
    try:
        report = execute(args)
    except ValueError as exc:
        report = dict(command=args.command, target=args.target, ok=False, error=str(exc), total_ms=0)
        if not args.json:
            print("参数错误：" + safe_text(exc), file=sys.stderr)
            return 2
        display(report, True)
        return 2
    display(report, args.json)
    return 0 if report["ok"] else 1


def menu():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("菜单需要交互终端；可执行 netcheck --help 查看命令。", file=sys.stderr)
        return 2
    while True:
        print("\nNetcheck %s · 轻量网络检测\n1. 域名解析\n2. Ping 延迟与丢包\n3. TCP 端口检测\n4. HTTP / HTTPS 检测\n5. 一键综合检测\n0. 退出" % VERSION)
        choice = input("请选择：").strip()
        if choice == "0":
            return 0
        command = {"1": "dns", "2": "ping", "3": "tcp", "4": "http", "5": "check"}.get(choice)
        if not command:
            print("无效选项，请重新输入。")
            continue
        target = input("目标域名、IP%s：" % (" 或网址" if command in ("http", "check") else "")).strip()
        if not target:
            continue
        argv = [command, target]
        if command == "tcp":
            argv += ["--port", input("端口 [443]：").strip() or "443"]
        try:
            run_command(argv)
        except SystemExit:
            # 参数无效时返回菜单，避免退出整个工具箱。
            pass


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--_worker":
        try:
            payload = json.loads(sys.argv[3])
            if sys.argv[2] == "dns":
                result = resolve_native(payload)
            elif sys.argv[2] == "http":
                result = http_native(payload)
            elif sys.argv[2] == "geo":
                result = geo_native(payload)
            else:
                result = failure("未知检测类型")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            result = failure(exc)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    try:
        return run_command(sys.argv[1:]) if len(sys.argv) > 1 else menu()
    except EOFError:
        return 0
    except KeyboardInterrupt:
        print("\n检测已取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
