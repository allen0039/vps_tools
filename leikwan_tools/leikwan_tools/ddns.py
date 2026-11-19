"""Independent dual-ISP IPv6 DDNS subsystem for leikwan_tools."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request

from .config import (
    ConfigError,
    DdnsProfileConfig,
    GlobalConfig,
    load_global_config,
    parse_global_config_dict,
)
from .ownership import ensure_safe_subpath, resolve_lock_file
from .system import FileLock, SystemErrorBase, atomic_write_text, run_cmd
from .toml_compat import TomlParseError, dump_toml_string, loads_toml, without_toml_table

CT_IPV6_NETWORK = ipaddress.IPv6Network("240e::/16")
CU_IPV6_NETWORK = ipaddress.IPv6Network("2408::/16")
ISP_LABELS = {"ct": "电信", "cu": "联通"}

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
DNSPOD_API_BASE = "https://dnsapi.cn"
ALIDNS_API_BASE = "https://alidns.aliyuncs.com/"

_SECRET_CRED_KEYS = frozenset(
    {
        "CF_API_TOKEN",
        "CLOUDFLARE_API_TOKEN",
        "API_TOKEN",
        "CF_GLOBAL_API_KEY",
        "CLOUDFLARE_API_KEY",
        "CF_API_KEY",
        "GLOBAL_API_KEY",
        "DNSPOD_TOKEN",
        "DNSPOD_LOGIN_TOKEN",
        "DNSPOD_KEY",
        "DNSPOD_SECRET",
        "ALIDNS_ACCESS_KEY_ID",
        "ALIDNS_ACCESS_KEY_SECRET",
        "ACCESS_KEY_ID",
        "ACCESS_KEY_SECRET",
        "WEBHOOK_URL",
        "DDNS_WEBHOOK_URL",
        "TOKEN",
        "SECRET",
        "KEY",
        "URL",
    }
)
_SENSITIVE_PATH_MARKERS = frozenset({"token", "tokens", "secret", "secrets", "key", "hook", "webhook"})
_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_PING_SUMMARY_RE = re.compile(r"=\s*([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)")
_PING_TIME_RE = re.compile(r"\btime[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms\b", re.IGNORECASE)
_CRED_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class DdnsError(RuntimeError):
    """Raised when DDNS inspection, credential loading, or synchronization fails."""


class DdnsProviderError(DdnsError):
    """Raised when a DDNS provider API request returns an error or unexpected response."""


@dataclass(frozen=True)
class FilteredAddress:
    """An IPv6 address candidate skipped during interface scanning."""

    raw: str
    reason: str


@dataclass(frozen=True)
class ProbedCandidate:
    """Active ping probe result for a single eligible IPv6 candidate."""

    ip: str
    isp: str
    interface: str
    probe_ok: bool
    rtt_ms: Optional[float]
    detail: str


@dataclass(frozen=True)
class ProfileInspectResult:
    """Candidate scan, filter, probe, and lowest-RTT selection result for one DDNS profile."""

    profile: str
    enabled: bool
    isp: str
    interface: str
    provider: str
    record_type: str
    zone: str
    host: str
    fqdn: str
    probe_target: str
    probe_timeout_seconds: int
    selected_ip: str
    selected_rtt_ms: Optional[float]
    candidates: List[ProbedCandidate]
    filtered_out: List[FilteredAddress]
    error: str = ""


@dataclass(frozen=True)
class ProviderSyncResult:
    """Result returned by a DDNS provider query or record synchronization."""

    action: str  # "created" | "updated" | "noop" | "triggered"
    record_id: str
    remote_ip: str
    deleted_duplicates: List[str]
    detail: str


def redact_url(url: str) -> str:
    """Redact credentials, query parameter values, and sensitive path tokens from a URL."""
    try:
        split = urllib.parse.urlsplit(url)
    except ValueError:
        return "<redacted-url>"
    if not split.scheme or not split.netloc:
        return "<redacted-url>"

    netloc = split.netloc
    if "@" in netloc:
        _, hostpart = netloc.rsplit("@", 1)
        netloc = f"***@{hostpart}"

    path_parts = split.path.split("/")
    masked_parts: List[str] = []
    mask_next = False
    for part in path_parts:
        if mask_next and part:
            masked_parts.append("***")
            mask_next = False
            continue
        masked_parts.append(part)
        if part.lower() in _SENSITIVE_PATH_MARKERS:
            mask_next = True
    masked_path = "/".join(masked_parts)

    masked_query = ""
    if split.query:
        q_items: List[str] = []
        for item in split.query.split("&"):
            if not item:
                continue
            if "=" in item:
                k, _ = item.split("=", 1)
                q_items.append(f"{k}=***")
            else:
                q_items.append("***")
        masked_query = "&".join(q_items)

    return urllib.parse.urlunsplit((split.scheme, netloc, masked_path, masked_query, ""))


def sanitize_secrets(text: str, secrets_values: Sequence[str] = ()) -> str:
    """Mask known secrets and sensitive URL parameters from logs, errors, and persisted state."""
    if not text:
        return ""
    cleaned = _URL_IN_TEXT_RE.sub(lambda m: redact_url(m.group(0)), text)
    candidates: List[str] = []
    for raw in secrets_values:
        if not raw or len(raw) < 4:
            continue
        candidates.append(raw)
        encoded = urllib.parse.quote(raw, safe="")
        if encoded and encoded != raw:
            candidates.append(encoded)
    for token in sorted(set(candidates), key=len, reverse=True):
        cleaned = cleaned.replace(token, "***")
    return cleaned


def _collect_secret_values(creds: Dict[str, str]) -> List[str]:
    secrets_list: List[str] = []
    for key, val in creds.items():
        if not val:
            continue
        if key.upper() in _SECRET_CRED_KEYS:
            secrets_list.append(val)
            if "," in val:
                for part in val.split(","):
                    part = part.strip()
                    if len(part) >= 4:
                        secrets_list.append(part)
            if val.lower().startswith(("http://", "https://")):
                try:
                    qs = urllib.parse.parse_qs(urllib.parse.urlsplit(val).query, keep_blank_values=False)
                    for vals in qs.values():
                        for qv in vals:
                            if qv and "{ip}" not in qv and len(qv) >= 4:
                                secrets_list.append(qv)
                except ValueError:
                    pass
    return secrets_list


def load_credential_file(path: str) -> Tuple[Dict[str, str], List[str]]:
    """Load KEY=VALUE credentials safely from a 0600-protected file without shell execution."""
    if not path or not path.strip():
        raise DdnsError("凭据文件路径不能为空")
    p = Path(path)
    if p.is_symlink():
        raise DdnsError(f"拒绝读取符号链接凭据文件: {path}")
    if not p.exists() or not p.is_file():
        raise DdnsError(f"凭据文件不存在: {path}")

    st = os.stat(p)
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise DdnsError(f"凭据文件权限过宽 ({oct(mode)})，必须限制为 0600: 请执行 chmod 600 {path}")

    try:
        content = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DdnsError(f"无法读取凭据文件 ({path}): {exc}") from exc

    creds: Dict[str, str] = {}
    for lineno, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            raise DdnsError(f"凭据文件格式错误 ({path}:{lineno}): 必须为 KEY=VALUE 格式")
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not _CRED_KEY_RE.match(key):
            raise DdnsError(f"凭据文件键名非法 ({path}:{lineno}): {key!r}")
        if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
            val = val[1:-1]
        creds[key] = val

    return creds, _collect_secret_values(creds)


def classify_ipv6_isp(ip_str: str) -> Optional[str]:
    """Classify an IPv6 address by telecom/unicom prefix (never by interface name)."""
    try:
        addr = ipaddress.IPv6Address(ip_str)
    except ipaddress.AddressValueError:
        return None
    if addr in CT_IPV6_NETWORK:
        return "ct"
    if addr in CU_IPV6_NETWORK:
        return "cu"
    return None


def _parse_preferred_lft(line: str) -> Optional[int]:
    match = re.search(r"\bpreferred_lft\s+(\S+)", line)
    if not match:
        return None
    raw = match.group(1).strip().lower()
    if raw == "forever":
        return 1
    if raw.endswith("sec"):
        raw = raw[:-3]
    try:
        return int(raw)
    except ValueError:
        return None


def _canonicalize_ip6_cmp(ip_a: str, ip_b: str) -> bool:
    try:
        return ipaddress.IPv6Address(ip_a.strip()) == ipaddress.IPv6Address(ip_b.strip())
    except ipaddress.AddressValueError:
        return ip_a.strip().lower() == ip_b.strip().lower()


def _evaluate_ip6_candidate(
    raw_token: str,
    inet6_line: str,
    pref_lft: Optional[int],
    target_isp: str,
    eligible: List[str],
    seen_eligible: set,
    filtered_out: List[FilteredAddress],
) -> None:
    ip_part = raw_token.split("/", 1)[0]
    scope_match = re.search(r"\bscope\s+(\S+)", inet6_line)
    scope_val = scope_match.group(1) if scope_match else ""
    if scope_val and scope_val != "global":
        filtered_out.append(FilteredAddress(raw_token, f"非 scope global (scope {scope_val})"))
        return

    for flag in ("deprecated", "tentative", "dadfailed"):
        if re.search(rf"\b{flag}\b", inet6_line):
            filtered_out.append(FilteredAddress(raw_token, f"{flag} 地址"))
            return

    if pref_lft is not None and pref_lft <= 0:
        filtered_out.append(FilteredAddress(raw_token, "preferred_lft 为 0"))
        return

    if "%" in ip_part:
        filtered_out.append(FilteredAddress(raw_token, "包含区域索引的链路地址"))
        return

    try:
        addr = ipaddress.IPv6Address(ip_part)
    except ipaddress.AddressValueError:
        filtered_out.append(FilteredAddress(raw_token, "不可解析为合法 IPv6"))
        return

    if addr.is_link_local:
        filtered_out.append(FilteredAddress(raw_token, "链路本地地址"))
        return
    if (
        addr.is_loopback
        or addr.is_unspecified
        or addr.is_multicast
        or addr.ipv4_mapped is not None
        or not addr.is_global
    ):
        filtered_out.append(FilteredAddress(raw_token, "非公网全局 IPv6 地址"))
        return

    canonical = str(addr)
    isp = classify_ipv6_isp(canonical)
    if isp is None:
        filtered_out.append(FilteredAddress(canonical, "非电信(240e:)/联通(2408:) 前缀，已忽略"))
        return
    if isp != target_isp:
        filtered_out.append(
            FilteredAddress(
                canonical,
                f"属于{ISP_LABELS.get(isp, isp)}前缀，与当前配置线路({ISP_LABELS.get(target_isp, target_isp)})不匹配",
            )
        )
        return

    if canonical not in seen_eligible:
        seen_eligible.add(canonical)
        eligible.append(canonical)


def parse_ip6_addr_candidates(output: str, target_isp: str) -> Tuple[List[str], List[FilteredAddress]]:
    """Parse `ip -6 addr show dev <iface> scope global` output without mutating system addresses."""
    eligible: List[str] = []
    seen_eligible: set = set()
    filtered_out: List[FilteredAddress] = []

    pending: Optional[Tuple[str, str]] = None

    def flush_pending(pref_lft: Optional[int]) -> None:
        nonlocal pending
        if pending is None:
            return
        raw_tok, inet_line = pending
        pending = None
        _evaluate_ip6_candidate(raw_tok, inet_line, pref_lft, target_isp, eligible, seen_eligible, filtered_out)

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.match(r"^\d+:\s+\S+", line) and " inet6 " not in f" {line} ":
            flush_pending(None)
            continue

        inet_match = re.search(r"\binet6\s+(\S+)(.*)$", line)
        if inet_match:
            flush_pending(None)
            raw_token = inet_match.group(1)
            if "preferred_lft" in line:
                _evaluate_ip6_candidate(
                    raw_token,
                    line,
                    _parse_preferred_lft(line),
                    target_isp,
                    eligible,
                    seen_eligible,
                    filtered_out,
                )
            else:
                pending = (raw_token, line)
            continue

        if pending is not None and ("valid_lft" in line or "preferred_lft" in line):
            flush_pending(_parse_preferred_lft(line))

    flush_pending(None)
    return eligible, filtered_out


def parse_ping_rtt_ms(output: str) -> Optional[float]:
    """Parse average or single-packet RTT (ms) from ping -6 output."""
    summary = _PING_SUMMARY_RE.search(output)
    if summary:
        try:
            return float(summary.group(2))
        except ValueError:
            pass
    single = _PING_TIME_RE.search(output)
    if single:
        try:
            return float(single.group(1))
        except ValueError:
            pass
    return None


def probe_ipv6_candidate(candidate_ip: str, probe_target: str, timeout_seconds: int) -> Tuple[bool, Optional[float], str]:
    """Actively probe probe_target binding source to candidate_ip (`ping -6 -c 1 -w <t> -I <ip> <target>`)."""
    cmd = ["ping", "-6", "-c", "1", "-w", str(timeout_seconds), "-I", candidate_ip, probe_target]
    proc = run_cmd(cmd, timeout=max(float(timeout_seconds) + 3.0, 5.0))
    rtt = parse_ping_rtt_ms(proc.stdout)
    if proc.returncode == 0 and rtt is not None:
        return True, round(rtt, 3), f"RTT={rtt:.2f}ms"
    stderr = proc.stderr.strip()
    stdout_lines = proc.stdout.strip().splitlines()
    err = stderr or (stdout_lines[-1] if stdout_lines else "")
    detail = err or f"ping 失败 (exit={proc.returncode})"
    return False, None, detail


def inspect_ddns_profile(global_cfg: GlobalConfig, profile: DdnsProfileConfig) -> ProfileInspectResult:
    """Non-destructively scan interface IPv6 candidates, probe them, and select lowest RTT."""
    target = profile.probe_target or global_cfg.ddns.probe_target
    timeout_s = profile.probe_timeout_seconds or global_cfg.ddns.probe_timeout_seconds

    try:
        res = run_cmd(["ip", "-6", "addr", "show", "dev", profile.interface, "scope", "global"])
    except SystemErrorBase as exc:
        return ProfileInspectResult(
            profile=profile.name,
            enabled=profile.enabled,
            isp=profile.isp,
            interface=profile.interface,
            provider=profile.provider,
            record_type=profile.record_type,
            zone=profile.zone,
            host=profile.host,
            fqdn=profile.fqdn,
            probe_target=target,
            probe_timeout_seconds=timeout_s,
            selected_ip="",
            selected_rtt_ms=None,
            candidates=[],
            filtered_out=[],
            error=str(exc),
        )

    if res.returncode != 0:
        err = res.stderr.strip() or res.stdout.strip() or f"exit {res.returncode}"
        return ProfileInspectResult(
            profile=profile.name,
            enabled=profile.enabled,
            isp=profile.isp,
            interface=profile.interface,
            provider=profile.provider,
            record_type=profile.record_type,
            zone=profile.zone,
            host=profile.host,
            fqdn=profile.fqdn,
            probe_target=target,
            probe_timeout_seconds=timeout_s,
            selected_ip="",
            selected_rtt_ms=None,
            candidates=[],
            filtered_out=[],
            error=f"查询网卡 {profile.interface} IPv6 失败: {err}",
        )

    eligible_ips, filtered = parse_ip6_addr_candidates(res.stdout, profile.isp)
    probed: List[ProbedCandidate] = []
    for ip_str in eligible_ips:
        ok, rtt, detail = probe_ipv6_candidate(ip_str, target, timeout_s)
        probed.append(
            ProbedCandidate(
                ip=ip_str,
                isp=profile.isp,
                interface=profile.interface,
                probe_ok=ok,
                rtt_ms=rtt,
                detail=detail,
            )
        )

    reachable = [c for c in probed if c.probe_ok and c.rtt_ms is not None]
    if reachable:
        best = min(reachable, key=lambda c: c.rtt_ms if c.rtt_ms is not None else float("inf"))
        selected_ip = best.ip
        selected_rtt = best.rtt_ms
    else:
        selected_ip = ""
        selected_rtt = None

    return ProfileInspectResult(
        profile=profile.name,
        enabled=profile.enabled,
        isp=profile.isp,
        interface=profile.interface,
        provider=profile.provider,
        record_type=profile.record_type,
        zone=profile.zone,
        host=profile.host,
        fqdn=profile.fqdn,
        probe_target=target,
        probe_timeout_seconds=timeout_s,
        selected_ip=selected_ip,
        selected_rtt_ms=selected_rtt,
        candidates=probed,
        filtered_out=filtered,
        error="",
    )


def _http_request(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: float = 15.0,
    secrets_values: Sequence[str] = (),
) -> Tuple[int, bytes]:
    req_headers = {"User-Agent": "leikwan_tools/ddns", **(headers or {})}
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.getcode()), resp.read()
    except urllib.error.HTTPError as exc:
        raw_body = b""
        try:
            raw_body = exc.read()
        except Exception:
            pass
        return int(exc.code), raw_body
    except urllib.error.URLError as exc:
        msg = sanitize_secrets(f"请求失败 ({exc.reason}): {redact_url(url)}", secrets_values)
        raise DdnsProviderError(msg) from exc
    except (TimeoutError, OSError) as exc:
        msg = sanitize_secrets(f"网络请求超时或异常 ({exc}): {redact_url(url)}", secrets_values)
        raise DdnsProviderError(msg) from exc


def _http_json(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: float = 15.0,
    secrets_values: Sequence[str] = (),
) -> Tuple[int, Dict[str, Any]]:
    status, raw = _http_request(
        method,
        url,
        headers=headers,
        body=body,
        timeout=timeout,
        secrets_values=secrets_values,
    )
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DdnsProviderError(
            sanitize_secrets(f"接口返回非 JSON 响应 (HTTP {status}): {redact_url(url)}", secrets_values)
        ) from exc
    if not isinstance(parsed, dict):
        raise DdnsProviderError(f"接口返回 JSON 结构异常 (HTTP {status})")
    return status, parsed


class DdnsProvider:
    """Abstract base class for extensible DDNS providers."""

    name: str = ""
    supports_remote_verify: bool = True

    def validate_credentials(self, profile: DdnsProfileConfig, creds: Dict[str, str]) -> None:
        raise NotImplementedError

    def query_remote(
        self,
        profile: DdnsProfileConfig,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> Dict[str, Any]:
        raise NotImplementedError

    def sync_record(
        self,
        profile: DdnsProfileConfig,
        target_ip: str,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> ProviderSyncResult:
        raise NotImplementedError


class CloudflareProvider(DdnsProvider):
    """Cloudflare DNS v4 provider supporting API Token and explicit Global API Key modes."""

    name = "cloudflare"
    supports_remote_verify = True

    def _resolve_headers(self, profile: DdnsProfileConfig, creds: Dict[str, str]) -> Dict[str, str]:
        mode = (profile.auth_mode or creds.get("CF_AUTH_MODE", "")).strip().lower()
        if mode not in ("", "token", "global_key"):
            raise DdnsError(f"Cloudflare 认证模式无效: {mode!r}（仅支持 token 或 global_key）")

        token = (
            creds.get("CF_API_TOKEN")
            or creds.get("CLOUDFLARE_API_TOKEN")
            or creds.get("API_TOKEN")
            or ""
        ).strip()
        email = (creds.get("CF_EMAIL") or creds.get("CLOUDFLARE_EMAIL") or "").strip()
        global_key = (
            creds.get("CF_GLOBAL_API_KEY")
            or creds.get("CLOUDFLARE_API_KEY")
            or creds.get("CF_API_KEY")
            or creds.get("GLOBAL_API_KEY")
            or ""
        ).strip()

        if mode == "token":
            if not token:
                raise DdnsError("Cloudflare token 模式缺少 CF_API_TOKEN")
            return {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}

        if mode == "global_key":
            if not (email and global_key):
                raise DdnsError("Cloudflare global_key 模式需要同时提供 CF_EMAIL 与 CF_GLOBAL_API_KEY")
            return {"Content-Type": "application/json", "X-Auth-Email": email, "X-Auth-Key": global_key}

        has_global = bool(email or global_key)
        if token and has_global:
            raise DdnsError(
                "Cloudflare 凭据同时存在 API Token 与 Global API Key 字段，请在配置设置 auth_mode = \"token\" 或 \"global_key\""
            )
        if token:
            return {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
        if email and global_key:
            return {"Content-Type": "application/json", "X-Auth-Email": email, "X-Auth-Key": global_key}
        if has_global:
            raise DdnsError("Cloudflare Global API Key 模式需要同时提供 CF_EMAIL 与 CF_GLOBAL_API_KEY")
        raise DdnsError("缺少 Cloudflare 凭据（请配置 CF_API_TOKEN，或同时配置 CF_EMAIL 与 CF_GLOBAL_API_KEY）")

    def validate_credentials(self, profile: DdnsProfileConfig, creds: Dict[str, str]) -> None:
        self._resolve_headers(profile, creds)

    @staticmethod
    def _cf_error(payload: Dict[str, Any], status: int, secrets_values: Sequence[str]) -> str:
        errors = payload.get("errors") or payload.get("messages") or []
        detail = ""
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict):
                detail = str(first.get("message") or first.get("code") or "")
            else:
                detail = str(first)
        return sanitize_secrets(f"Cloudflare API 错误 (HTTP {status}): {detail or '未知错误'}", secrets_values)

    def _get_zone_and_records(
        self,
        profile: DdnsProfileConfig,
        headers: Dict[str, str],
        *,
        timeout: float,
        secrets_values: Sequence[str],
    ) -> Tuple[str, List[Dict[str, Any]]]:
        zone_url = f"{CLOUDFLARE_API_BASE}/zones?name={urllib.parse.quote(profile.zone)}"
        z_status, z_data = _http_json(
            "GET", zone_url, headers=headers, timeout=timeout, secrets_values=secrets_values
        )
        if z_status >= 400 or not z_data.get("success"):
            raise DdnsProviderError(self._cf_error(z_data, z_status, secrets_values))
        zones = z_data.get("result") or []
        if not zones or not isinstance(zones[0], dict) or not zones[0].get("id"):
            raise DdnsProviderError(f"Cloudflare 未找到域名 {profile.zone} 对应的 Zone")
        zone_id = str(zones[0]["id"])

        rec_url = (
            f"{CLOUDFLARE_API_BASE}/zones/{urllib.parse.quote(zone_id)}/dns_records"
            f"?type={urllib.parse.quote(profile.record_type)}&name={urllib.parse.quote(profile.fqdn)}"
        )
        r_status, r_data = _http_json(
            "GET", rec_url, headers=headers, timeout=timeout, secrets_values=secrets_values
        )
        if r_status >= 400 or not r_data.get("success"):
            raise DdnsProviderError(self._cf_error(r_data, r_status, secrets_values))
        records = r_data.get("result") or []
        return zone_id, [r for r in records if isinstance(r, dict)]

    def query_remote(
        self,
        profile: DdnsProfileConfig,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> Dict[str, Any]:
        headers = self._resolve_headers(profile, creds)
        zone_id, records = self._get_zone_and_records(
            profile, headers, timeout=timeout, secrets_values=secrets_values
        )
        return {
            "zone_id": zone_id,
            "fqdn": profile.fqdn,
            "record_count": len(records),
            "record_id": str(records[0].get("id", "")) if records else "",
            "remote_ip": str(records[0].get("content", "")) if records else "",
            "proxied": bool(records[0].get("proxied", False)) if records else None,
        }

    def sync_record(
        self,
        profile: DdnsProfileConfig,
        target_ip: str,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> ProviderSyncResult:
        headers = self._resolve_headers(profile, creds)
        zone_id, records = self._get_zone_and_records(
            profile, headers, timeout=timeout, secrets_values=secrets_values
        )

        deleted_dups: List[str] = []
        if len(records) > 1:
            for dup in records[1:]:
                dup_id = str(dup.get("id", "")).strip()
                if not dup_id:
                    continue
                del_url = (
                    f"{CLOUDFLARE_API_BASE}/zones/{urllib.parse.quote(zone_id)}"
                    f"/dns_records/{urllib.parse.quote(dup_id)}"
                )
                d_status, d_data = _http_json(
                    "DELETE", del_url, headers=headers, timeout=timeout, secrets_values=secrets_values
                )
                if d_status >= 400 or not d_data.get("success"):
                    raise DdnsProviderError(self._cf_error(d_data, d_status, secrets_values))
                deleted_dups.append(dup_id)

        if records:
            primary = records[0]
            rid = str(primary.get("id", "")).strip()
            current_ip = str(primary.get("content", "")).strip()
            current_proxied = bool(primary.get("proxied", False))
            if (
                current_ip
                and _canonicalize_ip6_cmp(current_ip, target_ip)
                and current_proxied == profile.proxied
            ):
                return ProviderSyncResult(
                    action="noop",
                    record_id=rid,
                    remote_ip=target_ip,
                    deleted_duplicates=deleted_dups,
                    detail=f"Cloudflare 记录已是最新 ({profile.fqdn} -> {target_ip})",
                )
            method = "PUT"
            url = (
                f"{CLOUDFLARE_API_BASE}/zones/{urllib.parse.quote(zone_id)}"
                f"/dns_records/{urllib.parse.quote(rid)}"
            )
            action = "updated"
        else:
            method = "POST"
            url = f"{CLOUDFLARE_API_BASE}/zones/{urllib.parse.quote(zone_id)}/dns_records"
            action = "created"

        payload = json.dumps(
            {
                "type": profile.record_type,
                "name": profile.fqdn,
                "content": target_ip,
                "ttl": profile.ttl,
                "proxied": profile.proxied,
            }
        ).encode("utf-8")
        u_status, u_data = _http_json(
            method, url, headers=headers, body=payload, timeout=timeout, secrets_values=secrets_values
        )
        if u_status >= 400 or not u_data.get("success"):
            raise DdnsProviderError(self._cf_error(u_data, u_status, secrets_values))
        res_obj = u_data.get("result") or {}
        new_id = str(res_obj.get("id", "")) if isinstance(res_obj, dict) else ""
        return ProviderSyncResult(
            action=action,
            record_id=new_id or (str(records[0].get("id", "")) if records else ""),
            remote_ip=target_ip,
            deleted_duplicates=deleted_dups,
            detail=f"Cloudflare 已{'创建' if action == 'created' else '更新'} {profile.fqdn} -> {target_ip}",
        )


class DnspodProvider(DdnsProvider):
    """DNSPod HTTPS API provider using ID,Token credentials."""

    name = "dnspod"
    supports_remote_verify = True

    def _resolve_login_token(self, creds: Dict[str, str]) -> str:
        token = (creds.get("DNSPOD_TOKEN") or creds.get("DNSPOD_LOGIN_TOKEN") or "").strip()
        if not token:
            dp_id = (creds.get("DNSPOD_ID") or "").strip()
            dp_key = (creds.get("DNSPOD_KEY") or creds.get("DNSPOD_SECRET") or "").strip()
            if dp_id and dp_key:
                token = f"{dp_id},{dp_key}"
        if "," not in token:
            raise DdnsError("DNSPod 凭据必须为 ID,Token 格式 (DNSPOD_TOKEN 或 DNSPOD_ID + DNSPOD_KEY)")
        left, right = token.split(",", 1)
        if not left.strip() or not right.strip():
            raise DdnsError("DNSPod 凭据中的 ID 或 Token 不能为空")
        return f"{left.strip()},{right.strip()}"

    def validate_credentials(self, profile: DdnsProfileConfig, creds: Dict[str, str]) -> None:
        self._resolve_login_token(creds)

    def _post_form(
        self,
        endpoint: str,
        params: Dict[str, str],
        *,
        timeout: float,
        secrets_values: Sequence[str],
    ) -> Dict[str, Any]:
        body = urllib.parse.urlencode(params).encode("utf-8")
        status, data = _http_json(
            "POST",
            f"{DNSPOD_API_BASE}/{endpoint}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
            timeout=timeout,
            secrets_values=secrets_values,
        )
        if status >= 400:
            raise DdnsProviderError(f"DNSPod API 请求失败 (HTTP {status})")
        return data

    def _list_matching_records(
        self,
        profile: DdnsProfileConfig,
        login_token: str,
        *,
        timeout: float,
        secrets_values: Sequence[str],
    ) -> List[Dict[str, Any]]:
        data = self._post_form(
            "Record.List",
            {
                "login_token": login_token,
                "format": "json",
                "domain": profile.zone,
                "sub_domain": profile.subdomain,
                "record_type": profile.record_type,
            },
            timeout=timeout,
            secrets_values=secrets_values,
        )
        status_obj = data.get("status") or {}
        code = str(status_obj.get("code", ""))
        if code == "10":
            return []
        if code != "1":
            msg = status_obj.get("message") or "未知错误"
            raise DdnsProviderError(sanitize_secrets(f"DNSPod 查询错误 ({code}): {msg}", secrets_values))
        records = data.get("records") or []
        return [
            r
            for r in records
            if isinstance(r, dict)
            and str(r.get("name", "")).rstrip(".").lower() == profile.subdomain.lower()
            and str(r.get("type", "")).strip().upper() == profile.record_type
        ]

    def query_remote(
        self,
        profile: DdnsProfileConfig,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> Dict[str, Any]:
        login_token = self._resolve_login_token(creds)
        records = self._list_matching_records(
            profile, login_token, timeout=timeout, secrets_values=secrets_values
        )
        return {
            "fqdn": profile.fqdn,
            "record_count": len(records),
            "record_id": str(records[0].get("id", "")) if records else "",
            "remote_ip": str(records[0].get("value", "")) if records else "",
        }

    def sync_record(
        self,
        profile: DdnsProfileConfig,
        target_ip: str,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> ProviderSyncResult:
        login_token = self._resolve_login_token(creds)
        records = self._list_matching_records(
            profile, login_token, timeout=timeout, secrets_values=secrets_values
        )
        if records:
            primary = records[0]
            rid = str(primary.get("id", "")).strip()
            current_ip = str(primary.get("value", "")).strip()
            if current_ip and _canonicalize_ip6_cmp(current_ip, target_ip):
                return ProviderSyncResult(
                    action="noop",
                    record_id=rid,
                    remote_ip=target_ip,
                    deleted_duplicates=[],
                    detail=f"DNSPod 记录已是最新 ({profile.fqdn} -> {target_ip})",
                )
            endpoint = "Record.Modify"
            action = "updated"
            params = {
                "login_token": login_token,
                "format": "json",
                "domain": profile.zone,
                "sub_domain": profile.subdomain,
                "record_type": profile.record_type,
                "record_id": rid,
                "value": target_ip,
                "ttl": str(profile.ttl),
                "record_line": profile.record_line,
            }
        else:
            endpoint = "Record.Create"
            action = "created"
            params = {
                "login_token": login_token,
                "format": "json",
                "domain": profile.zone,
                "sub_domain": profile.subdomain,
                "record_type": profile.record_type,
                "value": target_ip,
                "ttl": str(profile.ttl),
                "record_line": profile.record_line,
            }

        res = self._post_form(endpoint, params, timeout=timeout, secrets_values=secrets_values)
        status_obj = res.get("status") or {}
        code = str(status_obj.get("code", ""))
        if code != "1":
            msg = status_obj.get("message") or "未知错误"
            raise DdnsProviderError(sanitize_secrets(f"DNSPod 更新错误 ({code}): {msg}", secrets_values))
        rec_obj = res.get("record") or {}
        new_id = str(rec_obj.get("id", "")) if isinstance(rec_obj, dict) else ""
        return ProviderSyncResult(
            action=action,
            record_id=new_id or (str(records[0].get("id", "")) if records else ""),
            remote_ip=target_ip,
            deleted_duplicates=[],
            detail=f"DNSPod 已{'创建' if action == 'created' else '更新'} {profile.fqdn} -> {target_ip}",
        )


def _alidns_percent_encode(value: Any) -> str:
    """RFC3986 percent-encoding required by Alibaba Cloud RPC v1.0 signatures."""
    return urllib.parse.quote(str(value), safe="-_.~")


def _build_alidns_signed_url(
    action_params: Dict[str, str],
    access_key_id: str,
    access_key_secret: str,
    *,
    timestamp: Optional[str] = None,
    nonce: Optional[str] = None,
) -> str:
    """Build an HTTPS AliDNS RPC v1.0 GET request URL signed with HMAC-SHA1."""
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sig_nonce = nonce or secrets.token_hex(16)
    all_params: Dict[str, str] = {
        "Format": "JSON",
        "Version": "2015-01-01",
        "AccessKeyId": access_key_id,
        "SignatureMethod": "HMAC-SHA1",
        "Timestamp": ts,
        "SignatureVersion": "1.0",
        "SignatureNonce": sig_nonce,
        **action_params,
    }
    encoded_pairs = sorted(
        (_alidns_percent_encode(k), _alidns_percent_encode(v)) for k, v in all_params.items()
    )
    canonicalized_query = "&".join(f"{k}={v}" for k, v in encoded_pairs)
    string_to_sign = f"GET&%2F&{_alidns_percent_encode(canonicalized_query)}"
    digest = hmac.new(
        (access_key_secret + "&").encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    signature = base64.b64encode(digest).decode("ascii")
    return f"{ALIDNS_API_BASE}?{canonicalized_query}&Signature={_alidns_percent_encode(signature)}"


class AliDnsProvider(DdnsProvider):
    """Alibaba Cloud DNS (AliDNS) HTTPS RPC v1.0 provider."""

    name = "alidns"
    supports_remote_verify = True

    def _resolve_keys(self, creds: Dict[str, str]) -> Tuple[str, str]:
        ak_id = (creds.get("ALIDNS_ACCESS_KEY_ID") or creds.get("ACCESS_KEY_ID") or "").strip()
        ak_secret = (creds.get("ALIDNS_ACCESS_KEY_SECRET") or creds.get("ACCESS_KEY_SECRET") or "").strip()
        if not ak_id or not ak_secret:
            raise DdnsError("AliDNS 凭据需要提供 ALIDNS_ACCESS_KEY_ID 与 ALIDNS_ACCESS_KEY_SECRET")
        return ak_id, ak_secret

    def validate_credentials(self, profile: DdnsProfileConfig, creds: Dict[str, str]) -> None:
        self._resolve_keys(creds)

    def _call_rpc(
        self,
        action_params: Dict[str, str],
        ak_id: str,
        ak_secret: str,
        *,
        timeout: float,
        secrets_values: Sequence[str],
    ) -> Dict[str, Any]:
        url = _build_alidns_signed_url(action_params, ak_id, ak_secret)
        status, data = _http_json("GET", url, timeout=timeout, secrets_values=secrets_values)
        if status >= 400 or data.get("Code"):
            code = data.get("Code") or f"HTTP {status}"
            msg = data.get("Message") or "未知错误"
            raise DdnsProviderError(sanitize_secrets(f"AliDNS API 错误 ({code}): {msg}", secrets_values))
        return data

    def _describe_matching_records(
        self,
        profile: DdnsProfileConfig,
        ak_id: str,
        ak_secret: str,
        *,
        timeout: float,
        secrets_values: Sequence[str],
    ) -> List[Dict[str, Any]]:
        data = self._call_rpc(
            {
                "Action": "DescribeDomainRecords",
                "DomainName": profile.zone,
                "RRKeyWord": profile.subdomain,
                "Type": profile.record_type,
                "PageSize": "500",
            },
            ak_id,
            ak_secret,
            timeout=timeout,
            secrets_values=secrets_values,
        )
        records = (data.get("DomainRecords") or {}).get("Record") or []
        return [
            r
            for r in records
            if isinstance(r, dict)
            and str(r.get("RR", "")).strip().lower() == profile.subdomain.lower()
            and str(r.get("Type", "")).strip().upper() == profile.record_type
        ]

    def query_remote(
        self,
        profile: DdnsProfileConfig,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> Dict[str, Any]:
        ak_id, ak_secret = self._resolve_keys(creds)
        records = self._describe_matching_records(
            profile, ak_id, ak_secret, timeout=timeout, secrets_values=secrets_values
        )
        return {
            "fqdn": profile.fqdn,
            "record_count": len(records),
            "record_id": str(records[0].get("RecordId", "")) if records else "",
            "remote_ip": str(records[0].get("Value", "")) if records else "",
        }

    def sync_record(
        self,
        profile: DdnsProfileConfig,
        target_ip: str,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> ProviderSyncResult:
        ak_id, ak_secret = self._resolve_keys(creds)
        records = self._describe_matching_records(
            profile, ak_id, ak_secret, timeout=timeout, secrets_values=secrets_values
        )
        if records:
            primary = records[0]
            rid = str(primary.get("RecordId", "")).strip()
            current_ip = str(primary.get("Value", "")).strip()
            if current_ip and _canonicalize_ip6_cmp(current_ip, target_ip):
                return ProviderSyncResult(
                    action="noop",
                    record_id=rid,
                    remote_ip=target_ip,
                    deleted_duplicates=[],
                    detail=f"AliDNS 记录已是最新 ({profile.fqdn} -> {target_ip})",
                )
            action = "updated"
            rpc_params = {
                "Action": "UpdateDomainRecord",
                "RecordId": rid,
                "RR": profile.subdomain,
                "Type": profile.record_type,
                "Value": target_ip,
                "TTL": str(profile.ttl),
            }
        else:
            action = "created"
            rpc_params = {
                "Action": "AddDomainRecord",
                "DomainName": profile.zone,
                "RR": profile.subdomain,
                "Type": profile.record_type,
                "Value": target_ip,
                "TTL": str(profile.ttl),
            }

        res = self._call_rpc(rpc_params, ak_id, ak_secret, timeout=timeout, secrets_values=secrets_values)
        new_id = str(res.get("RecordId", "")).strip()
        return ProviderSyncResult(
            action=action,
            record_id=new_id or (str(records[0].get("RecordId", "")) if records else ""),
            remote_ip=target_ip,
            deleted_duplicates=[],
            detail=f"AliDNS 已{'创建' if action == 'created' else '更新'} {profile.fqdn} -> {target_ip}",
        )


class WebhookProvider(DdnsProvider):
    """Generic HTTP/HTTPS Webhook DDNS provider accepting any 2xx response."""

    name = "webhook"
    supports_remote_verify = False

    def _resolve_url_template(self, creds: Dict[str, str]) -> str:
        url = (creds.get("WEBHOOK_URL") or creds.get("DDNS_WEBHOOK_URL") or "").strip()
        if not url:
            raise DdnsError("Webhook 凭据文件缺少 WEBHOOK_URL")
        split = urllib.parse.urlsplit(url)
        if split.scheme.lower() not in ("http", "https") or not split.netloc:
            raise DdnsError(f"Webhook URL 格式无效: {redact_url(url)}")
        return url

    def validate_credentials(self, profile: DdnsProfileConfig, creds: Dict[str, str]) -> None:
        self._resolve_url_template(creds)

    def query_remote(
        self,
        profile: DdnsProfileConfig,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> Dict[str, Any]:
        template = self._resolve_url_template(creds)
        return {
            "supports_remote_verify": False,
            "webhook_preview": redact_url(template),
        }

    def sync_record(
        self,
        profile: DdnsProfileConfig,
        target_ip: str,
        creds: Dict[str, str],
        *,
        timeout: float = 15.0,
        secrets_values: Sequence[str] = (),
    ) -> ProviderSyncResult:
        template = self._resolve_url_template(creds)
        final_url = template.replace("{ip}", target_ip)
        status, _ = _http_request("GET", final_url, timeout=timeout, secrets_values=secrets_values)
        if not (200 <= status < 300):
            raise DdnsProviderError(
                sanitize_secrets(
                    f"Webhook 返回非 2xx 状态码 (HTTP {status}): {redact_url(final_url)}",
                    secrets_values,
                )
            )
        return ProviderSyncResult(
            action="triggered",
            record_id="",
            remote_ip=target_ip,
            deleted_duplicates=[],
            detail=f"Webhook 请求成功 (HTTP {status}): {redact_url(final_url)}",
        )


PROVIDERS: Dict[str, DdnsProvider] = {
    "cloudflare": CloudflareProvider(),
    "dnspod": DnspodProvider(),
    "alidns": AliDnsProvider(),
    "webhook": WebhookProvider(),
}


def get_ddns_provider(name: str) -> DdnsProvider:
    prov = PROVIDERS.get(name.lower())
    if prov is None:
        raise ConfigError(f"未知的 DDNS Provider: {name!r}")
    return prov


def _render_ddns_config(ddns: Dict[str, Any]) -> str:
    tables = [("ddns", ddns)]
    tables.extend(
        (f"ddns.{dump_toml_string(name)}", fields)
        for name, fields in ddns.items() if isinstance(fields, dict)
    )
    sections = []
    for name, fields in tables:
        lines = [f"[{name}]"]
        for key, value in fields.items():
            if isinstance(value, dict):
                continue
            if isinstance(value, str):
                rendered = dump_toml_string(value)
            elif isinstance(value, bool):
                rendered = str(value).lower()
            else:
                rendered = str(value)
            lines.append(f"{key} = {rendered}")
        sections.append("\n".join(lines))
    return "\n\n".join(sections) + "\n"


def save_ddns_config(
    expected: GlobalConfig,
    *,
    profile_name: Optional[str] = None,
    changes: Optional[Dict[str, Any]] = None,
    enabled: Optional[bool] = None,
) -> None:
    """Apply confirmed DDNS edits to the active TOML under the shared write lock."""
    path = Path(expected.config_path)
    with FileLock(resolve_lock_file(global_cfg=expected)):
        file_stat = path.lstat()
        if not stat.S_ISREG(file_stat.st_mode):
            raise ConfigError(f"主配置必须是普通文件，才能通过菜单修改: {path}")
        with path.open(encoding="utf-8", newline="") as config_file:
            original = config_file.read()
        try:
            data = loads_toml(original)
            if parse_global_config_dict(data, expected.config_path) != expected:
                raise ConfigError("主配置已发生变化，请重新进入操作并确认")
            ddns = data.setdefault("ddns", {"enabled": expected.ddns.enabled})
            if enabled is not None:
                ddns["enabled"] = enabled
            if profile_name is not None:
                if changes is None:
                    del ddns[profile_name]
                else:
                    profile = ddns.setdefault(profile_name, {})
                    if not isinstance(profile, dict):
                        raise ConfigError(f"DDNS 配置名与全局字段冲突: {profile_name}")
                    if "zone" in changes:
                        profile.pop("domain", None)
                    profile.update(changes)

            desired = parse_global_config_dict(data, expected.config_path)
            if desired == expected:
                return
            if profile_name is not None and changes and ("credential_file" in changes or changes.get("enabled")):
                profile_cfg = desired.ddns.profiles[profile_name]
                credentials, secret_values = load_credential_file(profile_cfg.credential_file)
                try:
                    get_ddns_provider(profile_cfg.provider).validate_credentials(profile_cfg, credentials)
                except (DdnsError, ValueError) as exc:
                    raise DdnsError(sanitize_secrets(str(exc), secret_values)) from exc

            retained = without_toml_table(original, "ddns")
            newline = "\r\n" if "\r\n" in original else "\n"
            if not retained.endswith("\n"):
                retained += newline
            if not retained.endswith(newline * 2):
                retained += newline
            updated = retained + _render_ddns_config(ddns).replace("\n", newline)
            if loads_toml(updated) != data:
                raise ConfigError("无法在保留主配置其余内容的情况下保存 DDNS")
        except TomlParseError as exc:
            raise ConfigError(f"保存 DDNS 配置时 TOML 解析失败: {path}") from exc
        atomic_write_text(
            path, updated, mode=stat.S_IMODE(file_stat.st_mode),
            owner=(file_stat.st_uid, file_stat.st_gid),
        )


def _ddns_state_path(global_cfg: GlobalConfig, profile_name: str) -> Path:
    state_root = Path(global_cfg.tool.state_dir)
    return ensure_safe_subpath(state_root, state_root / "ddns" / f"{profile_name}.json")


def _load_ddns_state(path: Path) -> Dict[str, Any]:
    if not path.exists() or path.is_symlink() or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_ddns_state(path: Path, payload: Dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n", mode=0o644)


def _profile_signature(profile: DdnsProfileConfig) -> str:
    fields = asdict(profile)
    for key in ("enabled", "probe_target", "probe_timeout_seconds", "verify_interval_seconds"):
        del fields[key]
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode("utf-8")).hexdigest()


def _select_profiles(global_cfg: GlobalConfig, profile_name: Optional[str]) -> List[DdnsProfileConfig]:
    profiles = global_cfg.ddns.profiles
    if not profiles:
        raise ConfigError("主配置尚未定义任何 [ddns.<名称>] 独立 DDNS 配置节")
    if profile_name:
        if profile_name not in profiles:
            avail = ", ".join(sorted(profiles))
            raise ConfigError(f"未找到 DDNS 配置 {profile_name!r}（已配置: {avail}）")
        return [profiles[profile_name]]
    return list(profiles.values())


def inspect_ddns(global_cfg: GlobalConfig, profile_name: Optional[str] = None) -> List[ProfileInspectResult]:
    """Scan and probe IPv6 ingress candidates across one or all configured DDNS profiles."""
    targets = _select_profiles(global_cfg, profile_name)
    return [inspect_ddns_profile(global_cfg, prof) for prof in targets]


def update_ddns(
    global_cfg: GlobalConfig,
    profile_name: Optional[str] = None,
    *,
    force: bool = False,
    lock_timeout: float = 15.0,
    api_timeout: float = 15.0,
) -> Dict[str, Any]:
    """Scan candidates and synchronize one or all DDNS profiles using state cache & FileLock."""
    if not profile_name and not global_cfg.ddns.profiles:
        return {"ddns_enabled": global_cfg.ddns.enabled, "ok": True, "results": []}
    targets = _select_profiles(global_cfg, profile_name)
    if not global_cfg.ddns.enabled:
        return {
            "ddns_enabled": False,
            "ok": True,
            "results": [
                {
                    "profile": prof.name,
                    "isp": prof.isp,
                    "interface": prof.interface,
                    "provider": prof.provider,
                    "record_type": prof.record_type,
                    "fqdn": prof.fqdn,
                    "selected_ip": "",
                    "selected_rtt_ms": None,
                    "action": "skipped_disabled",
                    "detail": "全局 [ddns].enabled = false，跳过更新",
                    "error": "",
                }
                for prof in targets
            ],
        }

    # Probe active profiles outside lock to minimize lock hold duration.
    inspections: Dict[str, ProfileInspectResult] = {}
    for prof in targets:
        if prof.enabled:
            inspections[prof.name] = inspect_ddns_profile(global_cfg, prof)

    lock_file = resolve_lock_file(global_cfg=global_cfg)
    results: List[Dict[str, Any]] = []
    any_error = False

    with FileLock(lock_file, timeout=lock_timeout):
        if global_cfg.config_path:
            latest = load_global_config(global_cfg.config_path)
            if latest.ddns != global_cfg.ddns or latest.tool != global_cfg.tool:
                raise ConfigError("DDNS 探测期间配置已变化，请重新运行同步")
        for prof in targets:
            state_path = _ddns_state_path(global_cfg, prof.name)
            prev = _load_ddns_state(state_path)
            signature = _profile_signature(prof)
            if prev.get("profile_signature") != signature:
                prev = {}
            now_dt = datetime.now(timezone.utc)
            now_iso = now_dt.isoformat()
            now_epoch = int(time.time())

            base_state: Dict[str, Any] = {
                "schema_version": 1,
                "profile": prof.name,
                "profile_signature": signature,
                "isp": prof.isp,
                "interface": prof.interface,
                "provider": prof.provider,
                "record_type": prof.record_type,
                "zone": prof.zone,
                "host": prof.host,
                "fqdn": prof.fqdn,
                "selected_ip": str(prev.get("selected_ip", "")),
                "selected_rtt_ms": prev.get("selected_rtt_ms"),
                "last_success_ip": str(prev.get("last_success_ip", "")),
                "last_success_at_utc": str(prev.get("last_success_at_utc", "")),
                "last_verified_at_utc": str(prev.get("last_verified_at_utc", "")),
                "last_verified_epoch": int(prev.get("last_verified_epoch", 0) or 0),
                "last_attempt_at_utc": now_iso,
                "last_action": str(prev.get("last_action", "")),
                "record_id": str(prev.get("record_id", "")),
                "last_error": str(prev.get("last_error", "")),
            }

            if not prof.enabled:
                results.append(
                    {
                        "profile": prof.name,
                        "isp": prof.isp,
                        "interface": prof.interface,
                        "provider": prof.provider,
                        "record_type": prof.record_type,
                        "fqdn": prof.fqdn,
                        "selected_ip": "",
                        "selected_rtt_ms": None,
                        "action": "skipped_disabled",
                        "detail": f"[ddns.{prof.name}].enabled = false，跳过更新",
                        "error": "",
                    }
                )
                continue

            insp = inspections[prof.name]
            base_state["selected_ip"] = insp.selected_ip
            base_state["selected_rtt_ms"] = insp.selected_rtt_ms

            if insp.error or not insp.selected_ip:
                err_msg = insp.error or f"网卡 {prof.interface} 未探测到可用的 {ISP_LABELS.get(prof.isp, prof.isp)} 公网 IPv6"
                base_state["last_action"] = "skipped_no_ip" if not insp.error else "error"
                base_state["last_error"] = err_msg if insp.error else ""
                _write_ddns_state(state_path, base_state)
                if insp.error:
                    any_error = True
                results.append(
                    {
                        "profile": prof.name,
                        "isp": prof.isp,
                        "interface": prof.interface,
                        "provider": prof.provider,
                        "record_type": prof.record_type,
                        "fqdn": prof.fqdn,
                        "selected_ip": "",
                        "selected_rtt_ms": None,
                        "action": base_state["last_action"],
                        "detail": err_msg,
                        "error": insp.error,
                    }
                )
                continue

            provider = get_ddns_provider(prof.provider)
            last_ip = base_state["last_success_ip"]
            last_verified = base_state["last_verified_epoch"]
            verify_interval = (
                prof.verify_interval_seconds
                if prof.verify_interval_seconds is not None
                else global_cfg.ddns.verify_interval_seconds
            )
            ip_same = bool(last_ip and _canonicalize_ip6_cmp(last_ip, insp.selected_ip))
            periodic_verify = (
                provider.supports_remote_verify
                and ip_same
                and (verify_interval == 0 or (now_epoch - last_verified) > verify_interval)
            )

            if ip_same and not force and not periodic_verify:
                base_state["last_action"] = "skipped_cached"
                base_state["last_error"] = ""
                _write_ddns_state(state_path, base_state)
                results.append(
                    {
                        "profile": prof.name,
                        "isp": prof.isp,
                        "interface": prof.interface,
                        "provider": prof.provider,
                        "record_type": prof.record_type,
                        "fqdn": prof.fqdn,
                        "selected_ip": insp.selected_ip,
                        "selected_rtt_ms": insp.selected_rtt_ms,
                        "action": "skipped_cached",
                        "detail": f"IPv6 未变化 ({insp.selected_ip})，命中本地缓存跳过 API 调用",
                        "error": "",
                    }
                )
                continue

            secrets_values: List[str] = []
            try:
                creds, secrets_values = load_credential_file(prof.credential_file)
                sync_res = provider.sync_record(
                    prof,
                    insp.selected_ip,
                    creds,
                    timeout=api_timeout,
                    secrets_values=secrets_values,
                )
                base_state["last_success_ip"] = insp.selected_ip
                base_state["last_success_at_utc"] = now_iso
                base_state["last_verified_at_utc"] = now_iso
                base_state["last_verified_epoch"] = now_epoch
                base_state["last_action"] = "verified_noop" if (periodic_verify and sync_res.action == "noop") else sync_res.action
                if sync_res.record_id:
                    base_state["record_id"] = sync_res.record_id
                base_state["last_error"] = ""
                _write_ddns_state(state_path, base_state)
                results.append(
                    {
                        "profile": prof.name,
                        "isp": prof.isp,
                        "interface": prof.interface,
                        "provider": prof.provider,
                        "record_type": prof.record_type,
                        "fqdn": prof.fqdn,
                        "selected_ip": insp.selected_ip,
                        "selected_rtt_ms": insp.selected_rtt_ms,
                        "action": base_state["last_action"],
                        "record_id": base_state["record_id"],
                        "deleted_duplicates": sync_res.deleted_duplicates,
                        "detail": sync_res.detail,
                        "error": "",
                    }
                )
            except (DdnsError, ConfigError) as exc:
                any_error = True
                safe_err = sanitize_secrets(str(exc), secrets_values)
                base_state["last_action"] = "error"
                base_state["last_error"] = safe_err
                _write_ddns_state(state_path, base_state)
                results.append(
                    {
                        "profile": prof.name,
                        "isp": prof.isp,
                        "interface": prof.interface,
                        "provider": prof.provider,
                        "record_type": prof.record_type,
                        "fqdn": prof.fqdn,
                        "selected_ip": insp.selected_ip,
                        "selected_rtt_ms": insp.selected_rtt_ms,
                        "action": "error",
                        "detail": f"更新失败: {safe_err}",
                        "error": safe_err,
                    }
                )

    return {
        "ddns_enabled": True,
        "ok": not any_error,
        "results": results,
    }


def test_ddns_profile(
    global_cfg: GlobalConfig,
    profile_name: str,
    *,
    api_timeout: float = 15.0,
) -> Dict[str, Any]:
    """Run read-only config, 0600 credential, IPv6 scan/probe, and provider connectivity test."""
    prof = _select_profiles(global_cfg, profile_name)[0]
    insp = inspect_ddns_profile(global_cfg, prof)
    creds, secrets_values = load_credential_file(prof.credential_file)
    provider = get_ddns_provider(prof.provider)
    provider.validate_credentials(prof, creds)
    remote_info = provider.query_remote(prof, creds, timeout=api_timeout, secrets_values=secrets_values)
    return {
        "ok": bool(not insp.error and insp.selected_ip),
        "profile": prof.name,
        "enabled": prof.enabled,
        "isp": prof.isp,
        "interface": prof.interface,
        "provider": prof.provider,
        "record_type": prof.record_type,
        "fqdn": prof.fqdn,
        "credential_ok": True,
        "inspection": asdict(insp),
        "remote": remote_info,
    }


def status_ddns(global_cfg: GlobalConfig, profile_name: Optional[str] = None) -> Dict[str, Any]:
    """Read-only status summary combining configured profiles and persisted state files."""
    if not global_cfg.ddns.profiles:
        return {
            "ddns_enabled": global_cfg.ddns.enabled,
            "interval_seconds": global_cfg.ddns.interval_seconds,
            "verify_interval_seconds": global_cfg.ddns.verify_interval_seconds,
            "probe_target": global_cfg.ddns.probe_target,
            "probe_timeout_seconds": global_cfg.ddns.probe_timeout_seconds,
            "profiles": [],
        }

    targets = _select_profiles(global_cfg, profile_name)
    items: List[Dict[str, Any]] = []
    for prof in targets:
        state = _load_ddns_state(_ddns_state_path(global_cfg, prof.name))
        signature = state.get("profile_signature")
        if signature and signature != _profile_signature(prof):
            state = {}
        items.append(
            {
                "profile": prof.name,
                "enabled": prof.enabled,
                "isp": prof.isp,
                "interface": prof.interface,
                "provider": prof.provider,
                "record_type": prof.record_type,
                "fqdn": prof.fqdn,
                "credential_file": prof.credential_file,
                "selected_ip": str(state.get("selected_ip", "")),
                "selected_rtt_ms": state.get("selected_rtt_ms"),
                "last_success_ip": str(state.get("last_success_ip", "")),
                "last_success_at_utc": str(state.get("last_success_at_utc", "")),
                "last_verified_at_utc": str(state.get("last_verified_at_utc", "")),
                "last_attempt_at_utc": str(state.get("last_attempt_at_utc", "")),
                "last_action": str(state.get("last_action", "")),
                "record_id": str(state.get("record_id", "")),
                "last_error": str(state.get("last_error", "")),
            }
        )

    return {
        "ddns_enabled": global_cfg.ddns.enabled,
        "interval_seconds": global_cfg.ddns.interval_seconds,
        "verify_interval_seconds": global_cfg.ddns.verify_interval_seconds,
        "probe_target": global_cfg.ddns.probe_target,
        "probe_timeout_seconds": global_cfg.ddns.probe_timeout_seconds,
        "profiles": items,
    }
