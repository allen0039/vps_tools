"""Public ingress DNS A-record query, unified fixed-IP policy, TLS/app probing, and client dial guidance."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from . import DEFAULT_INGRESS_DOMAIN

STATUS_DNS_CANDIDATE = "DNS 候选"
STATUS_TCP_REACHABLE = "TCP 端口可达"
STATUS_LANDING_VERIFIED = "已验证到达指定落地"
STATUS_NON_DNS = "非 DNS 候选目标"


class IngressError(RuntimeError):
    """Raised when public ingress DNS query or probe inputs are invalid."""


@dataclass(frozen=True)
class DnsRecord:
    """Single IPv4 A record with optional TTL."""

    ip: str
    ttl: Optional[int] = None


@dataclass(frozen=True)
class DnsQueryResult:
    """DNS lookup snapshot including local/UTC timestamps."""

    domain: str
    resolver: str
    queried_at_local: str
    queried_at_utc: str
    records: List[DnsRecord]
    error: str = ""

    @property
    def ips(self) -> List[str]:
        return [r.ip for r in self.records]


@dataclass(frozen=True)
class FixedIpCheckResult:
    """Unified validation result for fixed public IP selection or TOML apply."""

    fixed_ip: str
    domain: str
    allowed: bool
    dns_result: DnsQueryResult
    dns_failed: bool
    in_dns: bool
    forced_override: bool
    preserved_existing: bool
    warning: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class ProbeResult:
    """Result of probing a single public ingress IP:port candidate across TCP, TLS, Cert, and App layers."""

    ip: str
    port: int
    in_dns: bool
    stage: str
    tcp_reachable: bool
    landing_verified: bool
    rtt_ms: Optional[float]
    detail: str
    response_preview: str = ""
    tls_subject: str = ""
    tls_san: List[str] = ()  # type: ignore[assignment]
    tls_requested: bool = False
    tls_ok: Optional[bool] = None
    tls_status: str = "未启用"
    cert_verify_mode: str = "未启用"
    cert_ok: Optional[bool] = None
    cert_status: str = "未启用"
    app_status: str = "未校验"
    exit_code: int = 0


def _encode_dns_name(domain: str) -> bytes:
    """Encode domain name in DNS wire format (RFC 1035)."""
    stripped = domain.strip().rstrip(".")
    if not stripped:
        raise IngressError("域名不能为空")
    labels = stripped.split(".")
    out = bytearray()
    for label in labels:
        raw = label.encode("idna")
        if not (1 <= len(raw) <= 63):
            raise IngressError(f"域名标签长度非法: {label!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_dns_a_query(domain: str, txid: int) -> bytes:
    """Build a standard RFC 1035 UDP DNS A-record query packet."""
    header = struct.pack("!HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(domain) + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def _skip_dns_name(packet: bytes, offset: int) -> int:
    """Advance offset past a potentially compressed DNS domain name."""
    visited = 0
    pos = offset
    while pos < len(packet):
        length = packet[pos]
        if length == 0:
            return pos + 1
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(packet):
                raise IngressError("DNS 响应名称指针截断")
            return pos + 2
        pos += 1 + length
        visited += 1
        if visited > 128:
            raise IngressError("DNS 响应名称指针循环")
    raise IngressError("DNS 响应解析越界")


def parse_dns_a_response(packet: bytes, expected_txid: int) -> List[DnsRecord]:
    """Parse A records from an RFC 1035 DNS response packet."""
    if len(packet) < 12:
        raise IngressError("DNS 响应包长度不足 12 字节")
    txid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if txid != (expected_txid & 0xFFFF):
        raise IngressError(f"DNS 事务 ID 不匹配: {txid} != {expected_txid & 0xFFFF}")
    rcode = flags & 0x000F
    if rcode != 0:
        if rcode == 3:
            return []
        raise IngressError(f"DNS 查询返回错误码 RCODE={rcode}")

    pos = 12
    for _ in range(qdcount):
        pos = _skip_dns_name(packet, pos)
        if pos + 4 > len(packet):
            raise IngressError("DNS 问题段截断")
        pos += 4

    records: List[DnsRecord] = []
    seen = set()
    for _ in range(ancount):
        pos = _skip_dns_name(packet, pos)
        if pos + 10 > len(packet):
            raise IngressError("DNS 应答段头截断")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[pos : pos + 10])
        pos += 10
        if pos + rdlength > len(packet):
            raise IngressError("DNS 应答段 RDATA 越界")
        rdata = packet[pos : pos + rdlength]
        pos += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            ip_str = str(ipaddress.IPv4Address(rdata))
            if ip_str not in seen:
                seen.add(ip_str)
                records.append(DnsRecord(ip=ip_str, ttl=ttl))
    return records


def query_dns_a_via_server(domain: str, dns_server: str, timeout: float = 3.0) -> List[DnsRecord]:
    """Query all IPv4 A records directly from a specific DNS server over UDP/53."""
    txid = int.from_bytes(os.urandom(2), "big")
    query = build_dns_a_query(domain, txid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(4096)
        return parse_dns_a_response(data, txid)
    finally:
        sock.close()


def _system_ipv4_nameservers() -> List[str]:
    """Read IPv4 nameservers from /etc/resolv.conf."""
    resolv = Path("/etc/resolv.conf")
    if not resolv.is_file():
        return []
    servers: List[str] = []
    try:
        for line in resolv.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                try:
                    ipaddress.IPv4Address(parts[1])
                    servers.append(parts[1])
                except ipaddress.AddressValueError:
                    continue
    except OSError:
        return []
    return servers


def query_dns_a(
    domain: str = DEFAULT_INGRESS_DOMAIN,
    dns_server: str = "",
    timeout: float = 3.0,
) -> DnsQueryResult:
    """Query current IPv4 A records with explicit local and UTC timestamps."""
    now_utc = datetime.now(timezone.utc)
    now_local = now_utc.astimezone()
    ts_utc = now_utc.strftime("%Y-%m-%d %H:%M:%S %Z")
    ts_local = now_local.strftime("%Y-%m-%d %H:%M:%S %z")

    if dns_server:
        try:
            records = query_dns_a_via_server(domain, dns_server, timeout=timeout)
            return DnsQueryResult(
                domain=domain,
                resolver=f"udp://{dns_server}:53",
                queried_at_local=ts_local,
                queried_at_utc=ts_utc,
                records=records,
            )
        except Exception as exc:
            return DnsQueryResult(
                domain=domain,
                resolver=f"udp://{dns_server}:53",
                queried_at_local=ts_local,
                queried_at_utc=ts_utc,
                records=[],
                error=str(exc),
            )

    last_err = ""
    for ns in _system_ipv4_nameservers():
        try:
            records = query_dns_a_via_server(domain, ns, timeout=timeout)
            return DnsQueryResult(
                domain=domain,
                resolver=f"udp://{ns}:53 (/etc/resolv.conf)",
                queried_at_local=ts_local,
                queried_at_utc=ts_utc,
                records=records,
            )
        except Exception as exc:
            last_err = str(exc)

    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        seen = set()
        records = []
        for info in infos:
            ip_str = info[4][0]
            if ip_str not in seen:
                seen.add(ip_str)
                records.append(DnsRecord(ip=ip_str, ttl=None))
        return DnsQueryResult(
            domain=domain,
            resolver="system-getaddrinfo",
            queried_at_local=ts_local,
            queried_at_utc=ts_utc,
            records=records,
        )
    except OSError as exc:
        err = f"{last_err}; {exc}" if last_err else str(exc)
        return DnsQueryResult(
            domain=domain,
            resolver="system-getaddrinfo",
            queried_at_local=ts_local,
            queried_at_utc=ts_utc,
            records=[],
            error=err,
        )


def check_fixed_ip_staleness(fixed_ip: str, domain: str, dns_result: DnsQueryResult) -> Optional[str]:
    """Return a clear confirmation warning if a pinned public IP disappeared from DNS or DNS lookup failed."""
    if not fixed_ip:
        return None
    if dns_result.error and not dns_result.ips:
        return (
            f"DNS 查询失败，无法确认固定公网 IP {fixed_ip} 是否仍在 {domain} 的 A 记录中 "
            f"({dns_result.error})；已保留现有固定 IP 设置。"
        )
    if fixed_ip not in dns_result.ips:
        current = ", ".join(dns_result.ips) if dns_result.ips else "(空)"
        return (
            f"固定公网 IP {fixed_ip} 已从 {domain} 当前 DNS A 记录中消失"
            f"（当前记录: {current}），请人工确认是否切换；已保留现有固定 IP 设置，未自动改动。"
        )
    return None


def evaluate_fixed_ip_policy(
    domain: str,
    new_fixed_ip: str,
    prev_fixed_ip: str = "",
    dns_server: str = "",
    allow_non_dns: bool = False,
    timeout: float = 3.0,
) -> FixedIpCheckResult:
    """Unified validation rule for both `ingress select` and TOML `plan`/`apply`."""
    dns_res = query_dns_a(domain=domain, dns_server=dns_server, timeout=timeout)
    dns_failed = bool(dns_res.error and not dns_res.ips)

    if not new_fixed_ip:
        return FixedIpCheckResult(
            fixed_ip="",
            domain=domain,
            allowed=True,
            dns_result=dns_res,
            dns_failed=dns_failed,
            in_dns=False,
            forced_override=False,
            preserved_existing=False,
        )

    in_dns = new_fixed_ip in dns_res.ips

    # Keeping an already configured fixed IP unchanged: preserve & warn on disappearance/DNS failure.
    if prev_fixed_ip and new_fixed_ip == prev_fixed_ip:
        warn = check_fixed_ip_staleness(new_fixed_ip, domain, dns_res)
        return FixedIpCheckResult(
            fixed_ip=new_fixed_ip,
            domain=domain,
            allowed=True,
            dns_result=dns_res,
            dns_failed=dns_failed,
            in_dns=in_dns,
            forced_override=False,
            preserved_existing=True,
            warning=warn,
        )

    # First-time setting or changing fixed_ip: enforce candidate membership unless --allow-non-dns.
    if dns_failed:
        if allow_non_dns:
            return FixedIpCheckResult(
                fixed_ip=new_fixed_ip,
                domain=domain,
                allowed=True,
                dns_result=dns_res,
                dns_failed=True,
                in_dns=False,
                forced_override=True,
                preserved_existing=False,
                warning=(
                    f"DNS 查询失败 ({dns_res.error})，但已通过 --allow-non-dns 强制覆盖固定公网 IP 为 {new_fixed_ip}"
                ),
            )
        return FixedIpCheckResult(
            fixed_ip=new_fixed_ip,
            domain=domain,
            allowed=False,
            dns_result=dns_res,
            dns_failed=True,
            in_dns=False,
            forced_override=False,
            preserved_existing=False,
            error=(
                f"DNS 查询失败，无法校验固定公网 IP {new_fixed_ip} 是否属于 {domain} 当前 A 记录 "
                f"(解析器={dns_res.resolver}, 错误={dns_res.error})；如需强制覆盖请显式加 --allow-non-dns。"
            ),
        )

    if not in_dns:
        current = ", ".join(dns_res.ips) if dns_res.ips else "(空)"
        if allow_non_dns:
            return FixedIpCheckResult(
                fixed_ip=new_fixed_ip,
                domain=domain,
                allowed=True,
                dns_result=dns_res,
                dns_failed=False,
                in_dns=False,
                forced_override=True,
                preserved_existing=False,
                warning=(
                    f"固定公网 IP {new_fixed_ip} 不在 {domain} 当前 DNS A 记录 ({current}) 中，"
                    "已按显式 --allow-non-dns 强制覆盖。"
                ),
            )
        return FixedIpCheckResult(
            fixed_ip=new_fixed_ip,
            domain=domain,
            allowed=False,
            dns_result=dns_res,
            dns_failed=False,
            in_dns=False,
            forced_override=False,
            preserved_existing=False,
            error=(
                f"所选固定公网 IP {new_fixed_ip} 不在 {domain} 当前 DNS A 记录中 ({current})；"
                "如需强制覆盖请显式加 --allow-non-dns。"
            ),
        )

    return FixedIpCheckResult(
        fixed_ip=new_fixed_ip,
        domain=domain,
        allowed=True,
        dns_result=dns_res,
        dns_failed=False,
        in_dns=True,
        forced_override=False,
        preserved_existing=False,
    )


def _encode_send_payload(payload: str) -> bytes:
    """Encode probe payload supporting \\n, \\r, \\t, \\\\ escapes while preserving UTF-8."""
    escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\"}
    out: List[str] = []
    i = 0
    while i < len(payload):
        if payload[i] == "\\" and i + 1 < len(payload) and payload[i + 1] in escapes:
            out.append(escapes[payload[i + 1]])
            i += 2
        else:
            out.append(payload[i])
            i += 1
    return "".join(out).encode("utf-8")


def _match_expect(response_text: str, expect_pattern: str) -> bool:
    """Match response against literal substring or `re:<pattern>` regex."""
    if expect_pattern.startswith("re:"):
        return re.search(expect_pattern[3:], response_text) is not None
    return expect_pattern in response_text


def _classify_ssl_error(exc: ssl.SSLError, verify_hostname: bool) -> Tuple[str, str, int]:
    """Return (tls_status, cert_status, exit_code) for SSL failure."""
    msg = str(exc)
    low = msg.lower()
    if isinstance(exc, ssl.SSLCertVerificationError) or "certificate verify failed" in low:
        if "hostname mismatch" in low or "ip address mismatch" in low or getattr(exc, "verify_code", None) == 62:
            return "握手/校验失败", f"失败(主机名不匹配: {msg})", 4
        return "握手/校验失败", f"失败(证书不受信任: {msg})", 4
    return f"握手失败 ({msg})", "未完成（TLS 握手失败）" if verify_hostname else "跳过校验(--tls-insecure)", 3


def probe_candidate(
    ip: str,
    port: int,
    in_dns: bool = True,
    timeout: float = 3.0,
    send_payload: str = "",
    expect_pattern: str = "",
    tls: bool = False,
    tls_sni: str = "",
    tls_verify_cert: Optional[bool] = None,
    tls_insecure: bool = False,
    tls_cafile: str = "",
) -> ProbeResult:
    """Probe TCP reachability, optional TLS + certificate/hostname verification, and optional app response."""
    if tls_verify_cert is True and tls_insecure:
        raise IngressError("不能同时指定 --tls-verify-cert 与 --tls-insecure")
    tls_requested = bool(tls or tls_sni or tls_verify_cert or tls_cafile or tls_insecure)
    if tls_insecure:
        verify_cert = False
    elif tls_verify_cert is not None:
        verify_cert = bool(tls_verify_cert)
    else:
        verify_cert = tls_requested

    verify_hostname = bool(verify_cert and tls_sni)
    if not tls_requested:
        cert_mode = "未启用"
    elif not verify_cert:
        cert_mode = "跳过校验(--tls-insecure)"
    elif verify_hostname:
        cert_mode = f"校验 CA 与主机名 ({tls_sni})"
    else:
        cert_mode = "仅校验 CA（未指定 --tls-sni）"

    base_stage = STATUS_DNS_CANDIDATE if in_dns else STATUS_NON_DNS
    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))
        rtt_ms = round((time.monotonic() - start) * 1000.0, 2)
    except OSError as exc:
        sock.close()
        return ProbeResult(
            ip=ip,
            port=port,
            in_dns=in_dns,
            stage=base_stage,
            tcp_reachable=False,
            landing_verified=False,
            rtt_ms=None,
            detail=f"TCP 端口不可达 ({exc})",
            tls_requested=tls_requested,
            tls_ok=False if tls_requested else None,
            tls_status="未执行（TCP 不可达）" if tls_requested else "未启用",
            cert_verify_mode=cert_mode,
            cert_ok=False if (tls_requested and verify_cert) else None,
            cert_status="未执行（TCP 不可达）" if tls_requested else "未启用",
            app_status="未执行（TCP 不可达）" if (send_payload or expect_pattern) else "未校验",
            exit_code=1,
        )

    tls_subject = ""
    tls_san: List[str] = []
    tls_ok: Optional[bool] = None
    tls_status = "未启用"
    cert_ok: Optional[bool] = None
    cert_status = "未启用"
    stream: Any = sock

    try:
        if tls_requested:
            try:
                if verify_cert:
                    cafile = tls_cafile or None
                    ctx = ssl.create_default_context(cafile=cafile)
                    ctx.check_hostname = verify_hostname
                    ctx.verify_mode = ssl.CERT_REQUIRED
                else:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                wrap_kwargs: Dict[str, Any] = {}
                if tls_sni:
                    wrap_kwargs["server_hostname"] = tls_sni
                tls_sock = ctx.wrap_socket(sock, **wrap_kwargs)
                stream = tls_sock
                cert = tls_sock.getpeercert(binary_form=False) or {}
                subj = cert.get("subject", ())
                tls_subject = ", ".join(f"{k}={v}" for rdn in subj for k, v in rdn)
                tls_san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                tls_ok = True
                tls_status = f"握手成功 (protocol={tls_sock.version()})"
                if verify_cert:
                    cert_ok = True
                    cert_status = "校验通过" if verify_hostname else "CA 校验通过（未做主机名校验）"
                else:
                    cert_ok = None
                    cert_status = "已跳过(--tls-insecure)"
            except ssl.SSLError as ssl_exc:
                t_status, c_status, code = _classify_ssl_error(ssl_exc, verify_hostname=verify_cert)
                return ProbeResult(
                    ip=ip,
                    port=port,
                    in_dns=in_dns,
                    stage=STATUS_TCP_REACHABLE,
                    tcp_reachable=True,
                    landing_verified=False,
                    rtt_ms=rtt_ms,
                    detail=f"TCP 端口可达，但 TLS/证书检查失败: {ssl_exc}",
                    tls_subject=tls_subject,
                    tls_san=tls_san,
                    tls_requested=True,
                    tls_ok=False,
                    tls_status=t_status,
                    cert_verify_mode=cert_mode,
                    cert_ok=False if verify_cert else None,
                    cert_status=c_status,
                    app_status="未执行（TLS 失败）" if (send_payload or expect_pattern) else "未校验",
                    exit_code=code,
                )
            except OSError as io_exc:
                return ProbeResult(
                    ip=ip,
                    port=port,
                    in_dns=in_dns,
                    stage=STATUS_TCP_REACHABLE,
                    tcp_reachable=True,
                    landing_verified=False,
                    rtt_ms=rtt_ms,
                    detail=f"TCP 端口可达，但 TLS 握手 I/O 失败 ({io_exc})",
                    tls_requested=True,
                    tls_ok=False,
                    tls_status=f"握手失败 ({io_exc})",
                    cert_verify_mode=cert_mode,
                    cert_ok=False if verify_cert else None,
                    cert_status="未完成（TLS 握手失败）" if verify_cert else "已跳过(--tls-insecure)",
                    app_status="未执行（TLS 失败）" if (send_payload or expect_pattern) else "未校验",
                    exit_code=3,
                )

        if send_payload or expect_pattern:
            if send_payload:
                stream.sendall(_encode_send_payload(send_payload))
            chunks: List[bytes] = []
            total = 0
            stream.settimeout(timeout)
            while total < 4096:
                try:
                    data = stream.recv(4096 - total)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if expect_pattern and _match_expect(b"".join(chunks).decode("utf-8", errors="replace"), expect_pattern):
                    break

            resp_text = b"".join(chunks).decode("utf-8", errors="replace").strip()
            if expect_pattern:
                if _match_expect(resp_text, expect_pattern):
                    return ProbeResult(
                        ip=ip,
                        port=port,
                        in_dns=in_dns,
                        stage=STATUS_LANDING_VERIFIED,
                        tcp_reachable=True,
                        landing_verified=True,
                        rtt_ms=rtt_ms,
                        detail="TCP 连通且应用响应匹配指定落地标识",
                        response_preview=resp_text[:160],
                        tls_subject=tls_subject,
                        tls_san=tls_san,
                        tls_requested=tls_requested,
                        tls_ok=tls_ok,
                        tls_status=tls_status,
                        cert_verify_mode=cert_mode,
                        cert_ok=cert_ok,
                        cert_status=cert_status,
                        app_status="匹配预期落地",
                        exit_code=0,
                    )
                return ProbeResult(
                    ip=ip,
                    port=port,
                    in_dns=in_dns,
                    stage=STATUS_TCP_REACHABLE,
                    tcp_reachable=True,
                    landing_verified=False,
                    rtt_ms=rtt_ms,
                    detail="端口可达但落地身份未确认（响应未匹配预期落地标识）",
                    response_preview=resp_text[:160],
                    tls_subject=tls_subject,
                    tls_san=tls_san,
                    tls_requested=tls_requested,
                    tls_ok=tls_ok,
                    tls_status=tls_status,
                    cert_verify_mode=cert_mode,
                    cert_ok=cert_ok,
                    cert_status=cert_status,
                    app_status="不匹配预期落地",
                    exit_code=2,
                )

            return ProbeResult(
                ip=ip,
                port=port,
                in_dns=in_dns,
                stage=STATUS_TCP_REACHABLE,
                tcp_reachable=True,
                landing_verified=False,
                rtt_ms=rtt_ms,
                detail="端口可达但落地身份未确认（未提供 --expect 落地断言）",
                response_preview=resp_text[:160],
                tls_subject=tls_subject,
                tls_san=tls_san,
                tls_requested=tls_requested,
                tls_ok=tls_ok,
                tls_status=tls_status,
                cert_verify_mode=cert_mode,
                cert_ok=cert_ok,
                cert_status=cert_status,
                app_status="收到回包（未提供 --expect 断言）",
                exit_code=0,
            )

        tls_note = "；TLS 握手成功，但尚未做应用层落地断言" if tls_requested else ""
        return ProbeResult(
            ip=ip,
            port=port,
            in_dns=in_dns,
            stage=STATUS_TCP_REACHABLE,
            tcp_reachable=True,
            landing_verified=False,
            rtt_ms=rtt_ms,
            detail=f"TCP 端口可达，落地身份未确认{tls_note}",
            tls_subject=tls_subject,
            tls_san=tls_san,
            tls_requested=tls_requested,
            tls_ok=tls_ok,
            tls_status=tls_status,
            cert_verify_mode=cert_mode,
            cert_ok=cert_ok,
            cert_status=cert_status,
            app_status="未校验",
            exit_code=0,
        )
    except OSError as exc:
        return ProbeResult(
            ip=ip,
            port=port,
            in_dns=in_dns,
            stage=STATUS_TCP_REACHABLE,
            tcp_reachable=True,
            landing_verified=False,
            rtt_ms=rtt_ms,
            detail=f"TCP 握手成功，但后续读写失败，落地身份未确认 ({exc})",
            tls_subject=tls_subject,
            tls_san=tls_san,
            tls_requested=tls_requested,
            tls_ok=tls_ok,
            tls_status=tls_status,
            cert_verify_mode=cert_mode,
            cert_ok=cert_ok,
            cert_status=cert_status,
            app_status=f"读写失败 ({exc})",
            exit_code=2 if expect_pattern else 0,
        )
    finally:
        try:
            stream.close()
        except OSError:
            pass


def protocol_preservation_notes(dial_addr: str, public_port: int, domain: str) -> List[str]:
    """Return concrete instructions on keeping TLS SNI / Host intact when pinning dial IP."""
    return [
        f"客户端拨号地址/端口: {dial_addr}:{public_port}",
        "分开设置拨号 IP 与协议参数说明（禁止把 TLS SNI / Host 改成拨号 IP）:",
        "  - Clash / Mihomo: server 填固定公网 IP，port 填公网端口；servername / sni / ws-opts.headers.Host 保持原落地域名不变。",
        "  - sing-box: server 填固定公网 IP，server_port 填公网端口；tls.server_name (含 Reality server_name) 与 transport.headers.Host 保持原域名不变。",
        "  - Xray / v2ray: address 填固定公网 IP，port 填公网端口；streamSettings.tlsSettings.serverName (或 realitySettings.serverName) 与 ws/http/grpc host 保持原域名不变。",
        f"  - 说明: 固定公网 IP 仅影响客户端拨号目标与连通性诊断，不改动 VPS 上 Realm 的监听配置（域名来源: {domain}）。",
    ]
