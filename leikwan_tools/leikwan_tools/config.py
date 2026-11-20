"""Configuration dataclasses, strict validation, and TOML rendering for leikwan_tools."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import re
from typing import Any, Dict, Optional

from . import (
    DEFAULT_COORDINATED_LOCK_FILE,
    DEFAULT_INGRESS_DOMAIN,
    DEFAULT_RULES_DIR,
    DEFAULT_STARTUP_ROUTE_WAIT_SECONDS,
    DEFAULT_STATE_DIR,
    FIXED_SYSTEMD_UNIT_TEMPLATE,
)
from .toml_compat import TomlParseError, dump_toml_string, loads_toml

RULE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$")
LINE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}$")
IFACE_NAME_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,32}$")
VALID_LOG_LEVELS = ("off", "error", "warn", "info", "debug", "trace")

DEFAULT_DDNS_INTERVAL_SECONDS = 120
DEFAULT_DDNS_VERIFY_INTERVAL_SECONDS = 600
DEFAULT_DDNS_PROBE_TARGET = "2400:3200::1"
DEFAULT_DDNS_PROBE_TIMEOUT_SECONDS = 1
DEFAULT_DDNS_TTL = 600
DDNS_SELECTION_LABELS = {"latest": "新址优先", "latency": "延迟优先"}
DDNS_AUTO_INTERFACE = "auto"
DEFAULT_DNSPOD_RECORD_LINE = "默认"
VALID_DDNS_PROVIDERS = ("cloudflare", "dnspod", "alidns", "webhook")
VALID_DDNS_ISPS = ("ct", "cu")
KNOWN_DDNS_RECORD_TYPES = ("AAAA", "A")
SUPPORTED_DDNS_RECORD_TYPES = ("AAAA",)
VALID_CF_AUTH_MODES = ("", "token", "global_key")
FORBIDDEN_DDNS_SECRET_KEYS = frozenset(
    {
        "token",
        "api_token",
        "api_key",
        "global_api_key",
        "secret",
        "access_key_secret",
        "login_token",
        "webhook_url",
        "url",
        "password",
    }
)
DDNS_PROFILE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}$")


class ConfigError(ValueError):
    """Raised when configuration or rule definition fails validation."""


def validate_ipv4(value: Any, field_name: str, allow_empty: bool = False) -> str:
    """Validate an explicit IPv4 address (forbidding 0.0.0.0, multicast, or IPv6)."""
    if value is None:
        if allow_empty:
            return ""
        raise ConfigError(f"{field_name} 不能为空")
    if not isinstance(value, str):
        raise ConfigError(f"{field_name} 必须是字符串，当前为 {type(value).__name__}")
    raw = value.strip()
    if not raw:
        if allow_empty:
            return ""
        raise ConfigError(f"{field_name} 不能为空")
    try:
        addr = ipaddress.IPv4Address(raw)
    except ipaddress.AddressValueError as exc:
        raise ConfigError(f"{field_name} 不是合法的 IPv4 地址: {raw!r}") from exc
    if addr.is_unspecified or addr.is_multicast:
        raise ConfigError(f"{field_name} 不能使用未指定地址或组播地址: {raw}")
    return str(addr)


def validate_port(value: Any, field_name: str) -> int:
    """Validate TCP port integer in 1..65535."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{field_name} 必须是 1-65535 的整数，当前为 {value!r}")
    if not (1 <= value <= 65535):
        raise ConfigError(f"{field_name} 超出范围 (1-65535): {value}")
    return value


def format_endpoint(address: str, port: int) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def format_realm_through(source_ip: str) -> str:
    """Format Realm endpoint.through literal; bracket IPv6 so ToSocketAddrs skips DNS stall."""
    return f"[{source_ip}]" if ":" in source_ip else source_ip


def validate_non_negative_int(value: Any, field_name: str) -> int:
    """Validate non-negative integer (rejecting bool)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(f"{field_name} 必须是非负整数，当前为 {value!r}")
    return value


def validate_bool(value: Any, field_name: str) -> bool:
    """Validate strict boolean value."""
    if not isinstance(value, bool):
        raise ConfigError(f"{field_name} 必须是布尔值 (true/false)，当前为 {value!r}")
    return value


def validate_positive_int(value: Any, field_name: str) -> int:
    """Validate positive integer >= 1 (rejecting bool)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(f"{field_name} 必须是大于等于 1 的正整数，当前为 {value!r}")
    return value


def validate_ipv6(value: Any, field_name: str) -> str:
    """Validate an explicit public/global IPv6 address (no scope ID, link-local, multicast, or IPv4-mapped)."""
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{field_name} 不能为空且必须是 IPv6 地址字符串")
    raw = value.strip()
    try:
        addr = ipaddress.IPv6Address(raw)
    except ipaddress.AddressValueError as exc:
        raise ConfigError(f"{field_name} 不是合法的 IPv6 地址: {raw!r}") from exc
    if (
        addr.is_unspecified
        or addr.is_multicast
        or addr.is_link_local
        or addr.is_loopback
        or addr.scope_id
        or addr.ipv4_mapped is not None
    ):
        raise ConfigError(f"{field_name} 必须是有效的公网 IPv6 地址: {raw!r}")
    return str(addr)


def validate_ipv6_gateway(value: Any, field_name: str, allow_empty: bool = True) -> str:
    """Validate an optional IPv6 gateway (allowing link-local fe80:: and global/doc IPv6, rejecting scope ID)."""
    if value is None:
        if allow_empty:
            return ""
        raise ConfigError(f"{field_name} 不能为空")
    if not isinstance(value, str):
        raise ConfigError(f"{field_name} 必须是字符串，当前为 {type(value).__name__}")
    raw = value.strip()
    if not raw:
        if allow_empty:
            return ""
        raise ConfigError(f"{field_name} 不能为空")
    try:
        addr = ipaddress.IPv6Address(raw)
    except ipaddress.AddressValueError as exc:
        raise ConfigError(f"{field_name} 不是合法的 IPv6 网关地址: {raw!r}") from exc
    if (
        addr.is_unspecified
        or addr.is_multicast
        or addr.is_loopback
        or addr.scope_id
        or addr.ipv4_mapped is not None
    ):
        raise ConfigError(f"{field_name} 不是有效的 IPv6 网关地址: {raw!r}")
    return str(addr)


def normalize_ddns_fqdn(zone: str, host: str) -> str:
    """Normalize (zone, host) into a canonical lowercase FQDN without trailing dot."""
    clean_zone = zone.strip().rstrip(".").lower()
    clean_host = host.strip().rstrip(".").lower()
    if not clean_zone:
        return clean_host
    if clean_host in ("", "@", clean_zone):
        return clean_zone
    if clean_host.endswith(f".{clean_zone}"):
        return clean_host
    return f"{clean_host}.{clean_zone}"


def normalize_ddns_subdomain(zone: str, host: str) -> str:
    """Normalize (zone, host) into a relative subdomain ('@' for zone apex)."""
    clean_zone = zone.strip().rstrip(".").lower()
    clean_host = host.strip().rstrip(".").lower()
    if clean_host in ("", "@", clean_zone):
        return "@"
    suffix = f".{clean_zone}"
    if clean_zone and clean_host.endswith(suffix):
        rel = clean_host[: -len(suffix)]
        return rel or "@"
    return clean_host


def validate_table_id(value: Any, field_name: str) -> int:
    """Validate Linux IPv4 routing table ID."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{field_name} 必须是整数路由表号，当前为 {value!r}")
    if value <= 0 or value > 2147483647 or value in (253, 255):
        raise ConfigError(f"{field_name} 路由表号无效: {value}")
    return value


@dataclass(frozen=True)
class ToolSettings:
    """Paths and runtime settings for leikwan_tools."""

    realm_bin: str = ""
    rules_dir: str = DEFAULT_RULES_DIR
    state_dir: str = DEFAULT_STATE_DIR
    systemd_unit_template: str = FIXED_SYSTEMD_UNIT_TEMPLATE
    lock_file: str = DEFAULT_COORDINATED_LOCK_FILE
    startup_route_wait_seconds: int = DEFAULT_STARTUP_ROUTE_WAIT_SECONDS


@dataclass(frozen=True)
class IngressSettings:
    """Public ingress lookup defaults."""

    default_domain: str = DEFAULT_INGRESS_DOMAIN
    dns_server: str = ""
    listen_interface: str = ""


@dataclass(frozen=True)
class LineConfig:
    """Configured outbound line (IPv4 source policy routing or IPv6 explicit NIC + source IPv6)."""

    name: str
    interface: str
    source_ip: str
    gateway: str = ""
    table: Optional[int] = None
    description: str = ""
    family: str = ""

    def __post_init__(self) -> None:
        inferred = "ipv6" if ":" in self.source_ip else "ipv4"
        if not self.family:
            object.__setattr__(self, "family", inferred)
        else:
            norm = self.family.strip().lower()
            if norm not in ("ipv4", "ipv6"):
                raise ConfigError(f"lines.{self.name}.family 无效: {self.family!r}（仅支持 ipv4 或 ipv6）")
            if norm != inferred:
                raise ConfigError(
                    f"lines.{self.name}.family ({norm}) 与 source_ip ({self.source_ip}) 地址族不匹配"
                )
            object.__setattr__(self, "family", norm)

    @property
    def is_ipv6(self) -> bool:
        return self.family == "ipv6"


@dataclass(frozen=True)
class DdnsProfileConfig:
    """Single ISP IPv6 DDNS profile with automatic or fixed interface selection."""

    name: str
    enabled: bool
    isp: str
    interface: str
    provider: str
    record_type: str = "AAAA"
    zone: str = ""
    host: str = ""
    credential_file: str = ""
    proxied: bool = False
    ttl: int = DEFAULT_DDNS_TTL
    record_line: str = DEFAULT_DNSPOD_RECORD_LINE
    auth_mode: str = ""
    probe_target: Optional[str] = None
    probe_timeout_seconds: Optional[int] = None
    verify_interval_seconds: Optional[int] = None
    selection_strategy: str = "latest"

    @property
    def fqdn(self) -> str:
        return normalize_ddns_fqdn(self.zone, self.host) if self.zone else ""

    @property
    def subdomain(self) -> str:
        return normalize_ddns_subdomain(self.zone, self.host) if self.zone else ""


@dataclass(frozen=True)
class DdnsSettings:
    """Independent dual-ISP IPv6 DDNS subsystem settings."""

    enabled: bool = False
    interval_seconds: int = DEFAULT_DDNS_INTERVAL_SECONDS
    verify_interval_seconds: int = DEFAULT_DDNS_VERIFY_INTERVAL_SECONDS
    probe_target: str = DEFAULT_DDNS_PROBE_TARGET
    probe_timeout_seconds: int = DEFAULT_DDNS_PROBE_TIMEOUT_SECONDS
    profiles: Dict[str, DdnsProfileConfig] = field(default_factory=dict)


@dataclass(frozen=True)
class GlobalConfig:
    """Top-level configuration loaded from config.toml."""

    tool: ToolSettings
    ingress: IngressSettings
    lines: Dict[str, LineConfig]
    config_path: str = ""
    ddns: DdnsSettings = field(default_factory=DdnsSettings)


@dataclass(frozen=True)
class RuleConfig:
    """Single TCP forwarding rule supporting IPv4/IPv6 ingress and IPv4/IPv6 destination."""

    name: str
    line: str
    public_port: int
    listen_ip: str
    listen_port: int
    remote_ip: str
    remote_port: int
    description: str = ""
    ingress_domain: str = DEFAULT_INGRESS_DOMAIN
    ingress_fixed_ip: str = ""
    log_level: str = "warn"
    tcp_timeout: int = 5
    tcp_keepalive: int = 15
    tcp_keepalive_probe: int = 3
    source_path: str = field(default="", compare=False)
    ddns_profile: str = ""

    @property
    def direct_ipv6(self) -> bool:
        return ":" in self.listen_ip

    @property
    def remote_is_ipv6(self) -> bool:
        return ":" in self.remote_ip

    @property
    def remote_family(self) -> str:
        return "ipv6" if self.remote_is_ipv6 else "ipv4"

    @property
    def remote_endpoint(self) -> str:
        return format_endpoint(self.remote_ip, self.remote_port)

    @property
    def listen_endpoint(self) -> str:
        return format_endpoint(self.listen_ip, self.listen_port)

    @property
    def dial_addr(self) -> str:
        return self.listen_ip if self.direct_ipv6 else self.ingress_fixed_ip or self.ingress_domain


def _require_str(mapping: Dict[str, Any], key: str, context: str, allow_empty: bool = False) -> str:
    val = mapping.get(key)
    if val is None:
        if allow_empty:
            return ""
        raise ConfigError(f"缺少必填字段 {context}.{key}")
    if not isinstance(val, str):
        raise ConfigError(f"{context}.{key} 必须是字符串")
    stripped = val.strip()
    if not stripped and not allow_empty:
        raise ConfigError(f"{context}.{key} 不能为空")
    return stripped


def _parse_ddns_settings(raw: Any) -> DdnsSettings:
    """Validate and parse the optional independent [ddns] subsystem section."""
    if raw is None:
        return DdnsSettings(enabled=False)
    if not isinstance(raw, dict):
        raise ConfigError("[ddns] 必须是配置表")

    allowed_top_keys = {
        "enabled",
        "interval_seconds",
        "verify_interval_seconds",
        "probe_target",
        "probe_timeout_seconds",
    }
    for key, val in raw.items():
        if isinstance(val, dict):
            continue
        if key.lower() in FORBIDDEN_DDNS_SECRET_KEYS:
            raise ConfigError(f"ddns.{key} 不允许在主配置文件中明文保存凭据，请改用凭据文件路径 credential_file (0600)")
        if key not in allowed_top_keys:
            raise ConfigError(f"未知的 [ddns] 配置项: {key!r}")

    ddns_enabled = validate_bool(raw.get("enabled", True), "ddns.enabled")
    interval_seconds = validate_positive_int(
        raw.get("interval_seconds", DEFAULT_DDNS_INTERVAL_SECONDS),
        "ddns.interval_seconds",
    )
    verify_interval_seconds = validate_non_negative_int(
        raw.get("verify_interval_seconds", DEFAULT_DDNS_VERIFY_INTERVAL_SECONDS),
        "ddns.verify_interval_seconds",
    )
    probe_target = validate_ipv6(
        raw.get("probe_target", DEFAULT_DDNS_PROBE_TARGET),
        "ddns.probe_target",
    )
    probe_timeout_seconds = validate_positive_int(
        raw.get("probe_timeout_seconds", DEFAULT_DDNS_PROBE_TIMEOUT_SECONDS),
        "ddns.probe_timeout_seconds",
    )

    profiles: Dict[str, DdnsProfileConfig] = {}
    seen_records: Dict[tuple, str] = {}
    allowed_profile_keys = {
        "enabled",
        "isp",
        "interface",
        "provider",
        "record_type",
        "zone",
        "domain",
        "host",
        "credential_file",
        "proxied",
        "ttl",
        "record_line",
        "auth_mode",
        "selection_strategy",
        "probe_target",
        "probe_timeout_seconds",
        "verify_interval_seconds",
    }

    for pname, prof_raw in raw.items():
        if not isinstance(prof_raw, dict):
            continue
        if not DDNS_PROFILE_NAME_RE.match(pname):
            raise ConfigError(f"DDNS 配置名称非法: {pname!r} (仅支持字母数字和 ._-) ")
        ctx = f"ddns.{pname}"

        for pkey in prof_raw:
            if pkey.lower() in FORBIDDEN_DDNS_SECRET_KEYS:
                raise ConfigError(
                    f"{ctx}.{pkey} 不允许在主配置文件中明文保存凭据，请保存到 0600 权限的 {ctx}.credential_file 中"
                )
            if pkey not in allowed_profile_keys:
                raise ConfigError(f"未知的 [{ctx}] 配置项: {pkey!r}")

        p_enabled = validate_bool(prof_raw.get("enabled", True), f"{ctx}.enabled")

        default_isp = pname.lower() if pname.lower() in VALID_DDNS_ISPS else ""
        isp_raw = prof_raw.get("isp", default_isp)
        if not isinstance(isp_raw, str) or not isp_raw.strip():
            raise ConfigError(f"缺少必填字段 {ctx}.isp（必须为 ct 或 cu）")
        isp = isp_raw.strip().lower()
        if isp not in VALID_DDNS_ISPS:
            raise ConfigError(f"{ctx}.isp 无效: {isp!r}（仅支持: {', '.join(VALID_DDNS_ISPS)}）")

        iface = _require_str(prof_raw, "interface", ctx) if "interface" in prof_raw else DDNS_AUTO_INTERFACE
        if not IFACE_NAME_RE.match(iface):
            raise ConfigError(f"{ctx}.interface 网卡名非法: {iface!r}")

        provider = _require_str(prof_raw, "provider", ctx).lower()
        if provider not in VALID_DDNS_PROVIDERS:
            raise ConfigError(
                f"{ctx}.provider 无效: {provider!r}（支持: {', '.join(VALID_DDNS_PROVIDERS)}）"
            )

        record_type_raw = prof_raw.get("record_type", "AAAA")
        if not isinstance(record_type_raw, str) or not record_type_raw.strip():
            raise ConfigError(f"{ctx}.record_type 必须是非空字符串")
        record_type = record_type_raw.strip().upper()
        if record_type == "A":
            raise ConfigError(
                f"{ctx}.record_type = \"A\" 当前暂未实现：第一版 DDNS 仅支持 IPv6 AAAA 记录（配置模型已预留扩展）"
            )
        if record_type not in KNOWN_DDNS_RECORD_TYPES:
            raise ConfigError(
                f"{ctx}.record_type 无效: {record_type!r}（当前仅支持: {', '.join(SUPPORTED_DDNS_RECORD_TYPES)}）"
            )

        zone_val = _require_str(prof_raw, "zone", ctx, allow_empty=True).rstrip(".").lower()
        domain_val = _require_str(prof_raw, "domain", ctx, allow_empty=True).rstrip(".").lower()
        if zone_val and domain_val and zone_val != domain_val:
            raise ConfigError(f"{ctx}.zone ({zone_val!r}) 与 {ctx}.domain ({domain_val!r}) 冲突，请只配置其中一个")
        zone = zone_val or domain_val
        if any(ch.isspace() or ch in "/\\" for ch in zone):
            raise ConfigError(f"{ctx}.zone 域名格式非法: {zone!r}")

        host = _require_str(prof_raw, "host", ctx, allow_empty=True).rstrip(".")
        if any(ch.isspace() or ch in "/\\" for ch in host):
            raise ConfigError(f"{ctx}.host 主机记录格式非法: {host!r}")

        if provider != "webhook":
            if not zone:
                raise ConfigError(f"{ctx}.zone 不能为空（不得复用 [ingress].default_domain）")
            if not host:
                host = "@"

        cred_raw = prof_raw.get("credential_file", "")
        if not isinstance(cred_raw, str):
            raise ConfigError(f"{ctx}.credential_file 必须是字符串")
        credential_file = cred_raw.strip()
        if p_enabled and not credential_file:
            raise ConfigError(f"启用的 DDNS 配置 {ctx} 必须指定 credential_file（0600 凭据文件路径）")

        proxied = validate_bool(prof_raw.get("proxied", False), f"{ctx}.proxied")
        ttl = validate_positive_int(prof_raw.get("ttl", DEFAULT_DDNS_TTL), f"{ctx}.ttl")
        selection_strategy = _require_str(prof_raw, "selection_strategy", ctx) if "selection_strategy" in prof_raw else "latest"
        if selection_strategy not in DDNS_SELECTION_LABELS:
            raise ConfigError(f"{ctx}.selection_strategy 必须为 latest 或 latency")
        record_line = _require_str(prof_raw, "record_line", ctx, allow_empty=True) or DEFAULT_DNSPOD_RECORD_LINE

        auth_mode_raw = prof_raw.get("auth_mode", "")
        if not isinstance(auth_mode_raw, str):
            raise ConfigError(f"{ctx}.auth_mode 必须是字符串")
        auth_mode = auth_mode_raw.strip().lower()
        if auth_mode not in VALID_CF_AUTH_MODES:
            raise ConfigError(f"{ctx}.auth_mode 无效: {auth_mode!r}（可选: token, global_key）")

        p_probe_target: Optional[str] = None
        if "probe_target" in prof_raw and str(prof_raw["probe_target"]).strip():
            p_probe_target = validate_ipv6(prof_raw["probe_target"], f"{ctx}.probe_target")

        p_probe_timeout: Optional[int] = None
        if "probe_timeout_seconds" in prof_raw:
            p_probe_timeout = validate_positive_int(
                prof_raw["probe_timeout_seconds"], f"{ctx}.probe_timeout_seconds"
            )

        p_verify_interval: Optional[int] = None
        if "verify_interval_seconds" in prof_raw:
            p_verify_interval = validate_non_negative_int(
                prof_raw["verify_interval_seconds"], f"{ctx}.verify_interval_seconds"
            )

        profile = DdnsProfileConfig(
            name=pname,
            enabled=p_enabled,
            isp=isp,
            interface=iface,
            provider=provider,
            record_type=record_type,
            zone=zone,
            host=host,
            credential_file=credential_file,
            proxied=proxied,
            ttl=ttl,
            record_line=record_line,
            auth_mode=auth_mode,
            probe_target=p_probe_target,
            probe_timeout_seconds=p_probe_timeout,
            verify_interval_seconds=p_verify_interval,
            selection_strategy=selection_strategy,
        )
        if profile.provider != "webhook":
            dedup_key = (profile.fqdn, profile.record_type)
            if dedup_key in seen_records:
                other = seen_records[dedup_key]
                raise ConfigError(
                    f"DDNS 配置冲突: ddns.{other} 与 {ctx} 重复指向同一记录 "
                    f"{profile.fqdn} ({profile.record_type})，请避免相互覆盖"
                )
            seen_records[dedup_key] = pname
        profiles[pname] = profile

    return DdnsSettings(
        enabled=ddns_enabled,
        interval_seconds=interval_seconds,
        verify_interval_seconds=verify_interval_seconds,
        probe_target=probe_target,
        probe_timeout_seconds=probe_timeout_seconds,
        profiles=profiles,
    )


def parse_global_config_dict(data: Dict[str, Any], config_path: str = "") -> GlobalConfig:
    """Validate and convert a parsed dictionary into GlobalConfig."""
    tool_raw = data.get("tool") or {}
    if not isinstance(tool_raw, dict):
        raise ConfigError("[tool] 必须是配置表")

    rules_dir = str(tool_raw.get("rules_dir", DEFAULT_RULES_DIR)).strip() or DEFAULT_RULES_DIR
    state_dir = str(tool_raw.get("state_dir", DEFAULT_STATE_DIR)).strip() or DEFAULT_STATE_DIR
    lock_file_raw = str(tool_raw.get("lock_file", DEFAULT_COORDINATED_LOCK_FILE)).strip()
    lock_file = lock_file_raw or DEFAULT_COORDINATED_LOCK_FILE
    unit_tpl = str(tool_raw.get("systemd_unit_template", FIXED_SYSTEMD_UNIT_TEMPLATE)).strip()
    if unit_tpl != FIXED_SYSTEMD_UNIT_TEMPLATE:
        raise ConfigError(
            f"禁止修改受管 systemd 模板名: tool.systemd_unit_template 必须固定为 "
            f"{FIXED_SYSTEMD_UNIT_TEMPLATE!r}，当前为 {unit_tpl!r}"
        )
    startup_wait = validate_non_negative_int(
        tool_raw.get("startup_route_wait_seconds", DEFAULT_STARTUP_ROUTE_WAIT_SECONDS),
        "tool.startup_route_wait_seconds",
    )

    tool = ToolSettings(
        realm_bin=str(tool_raw.get("realm_bin", "")).strip(),
        rules_dir=rules_dir,
        state_dir=state_dir,
        systemd_unit_template=unit_tpl,
        lock_file=lock_file,
        startup_route_wait_seconds=startup_wait,
    )

    ingress_raw = data.get("ingress") or {}
    if not isinstance(ingress_raw, dict):
        raise ConfigError("[ingress] 必须是配置表")
    default_domain = (
        str(ingress_raw.get("default_domain", DEFAULT_INGRESS_DOMAIN)).strip() or DEFAULT_INGRESS_DOMAIN
    )
    dns_server = validate_ipv4(ingress_raw.get("dns_server", ""), "ingress.dns_server", allow_empty=True)
    listen_interface = _require_str(ingress_raw, "listen_interface", "ingress", allow_empty=True)
    if listen_interface and not IFACE_NAME_RE.fullmatch(listen_interface):
        raise ConfigError(f"ingress.listen_interface 网卡名非法: {listen_interface!r}")
    ingress = IngressSettings(default_domain=default_domain, dns_server=dns_server, listen_interface=listen_interface)

    lines_raw = data.get("lines")
    if not isinstance(lines_raw, dict) or not lines_raw:
        raise ConfigError("配置必须包含至少一个 [lines.<名称>] 出口线路定义")

    lines: Dict[str, LineConfig] = {}
    for line_name, line_data in lines_raw.items():
        if not LINE_NAME_RE.match(line_name):
            raise ConfigError(f"线路名称非法: {line_name!r} (仅支持字母数字和 ._-)")
        if not isinstance(line_data, dict):
            raise ConfigError(f"[lines.{line_name}] 必须是配置表")
        ctx = f"lines.{line_name}"
        iface = _require_str(line_data, "interface", ctx)
        if not IFACE_NAME_RE.match(iface):
            raise ConfigError(f"{ctx}.interface 网卡名非法: {iface!r}")
        family_raw = _require_str(line_data, "family", ctx, allow_empty=True).lower()
        if family_raw and family_raw not in ("ipv4", "ipv6"):
            raise ConfigError(f"{ctx}.family 无效: {family_raw!r}（仅支持 ipv4 或 ipv6）")
        raw_source = _require_str(line_data, "source_ip", ctx)
        is_v6 = ":" in raw_source
        inferred_family = "ipv6" if is_v6 else "ipv4"
        if family_raw and family_raw != inferred_family:
            raise ConfigError(
                f"{ctx}.family ({family_raw}) 与 {ctx}.source_ip ({raw_source}) 地址族不匹配"
            )
        if is_v6:
            source_ip = validate_ipv6(raw_source, f"{ctx}.source_ip")
            gateway = validate_ipv6_gateway(line_data.get("gateway", ""), f"{ctx}.gateway", allow_empty=True)
            raw_table = line_data.get("table", None)
            if raw_table is None or (isinstance(raw_table, str) and not raw_table.strip()):
                table: Optional[int] = None
            else:
                table = validate_table_id(raw_table, f"{ctx}.table")
                if 252 <= table <= 255:
                    raise ConfigError(f"{ctx}.table 必须使用独立 IPv6 路由表，当前为 {table}")
        else:
            source_ip = validate_ipv4(raw_source, f"{ctx}.source_ip")
            gateway = validate_ipv4(line_data.get("gateway"), f"{ctx}.gateway")
            table = validate_table_id(line_data.get("table"), f"{ctx}.table")
        desc = _require_str(line_data, "description", ctx, allow_empty=True)
        lines[line_name] = LineConfig(
            name=line_name,
            interface=iface,
            source_ip=source_ip,
            gateway=gateway,
            table=table,
            description=desc,
            family=inferred_family,
        )

    ddns = _parse_ddns_settings(data.get("ddns"))
    return GlobalConfig(tool=tool, ingress=ingress, lines=lines, config_path=config_path, ddns=ddns)


def load_global_config(path: str) -> GlobalConfig:
    """Load and validate global config file."""
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise ConfigError(f"主配置文件不存在: {path}")
    try:
        text = cfg_path.read_text(encoding="utf-8")
        data = loads_toml(text)
    except TomlParseError as exc:
        raise ConfigError(f"主配置文件 TOML 解析失败 ({path}): {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"无法读取主配置文件 ({path}): {exc}") from exc
    return parse_global_config_dict(data, config_path=str(cfg_path))


def parse_rule_config_dict(
    data: Dict[str, Any],
    default_domain: str = DEFAULT_INGRESS_DOMAIN,
    source_path: str = "",
) -> RuleConfig:
    """Validate and convert a parsed dictionary into RuleConfig."""
    rule_sec = data.get("rule")
    if not isinstance(rule_sec, dict):
        raise ConfigError("规则文件必须包含 [rule] 配置节")
    name = _require_str(rule_sec, "name", "rule")
    if not RULE_NAME_RE.match(name):
        raise ConfigError(f"rule.name 非法: {name!r} (仅支持字母数字开头及 ._-，长度 1-63)")
    line = _require_str(rule_sec, "line", "rule")
    description = _require_str(rule_sec, "description", "rule", allow_empty=True)

    ingress_sec = data.get("ingress") or {}
    if not isinstance(ingress_sec, dict):
        raise ConfigError("[ingress] 必须是配置表")
    ingress_domain = _require_str(ingress_sec, "domain", "ingress", allow_empty=True)
    ddns_profile = _require_str(ingress_sec, "ddns_profile", "ingress", allow_empty=True)
    if ddns_profile and not DDNS_PROFILE_NAME_RE.fullmatch(ddns_profile):
        raise ConfigError("ingress.ddns_profile 不是有效的 DDNS 配置名")
    ingress_fixed_ip = validate_ipv4(
        ingress_sec.get("fixed_ip", ""), "ingress.fixed_ip", allow_empty=True
    )
    public_port = validate_port(ingress_sec.get("public_port"), "ingress.public_port")

    forward_sec = data.get("forward")
    if not isinstance(forward_sec, dict):
        raise ConfigError("规则文件必须包含 [forward] 配置节")
    listen_ip = _require_str(forward_sec, "listen_ip", "forward")
    if ":" in listen_ip:
        try:
            listen_address = ipaddress.IPv6Address(listen_ip)
        except ipaddress.AddressValueError as exc:
            raise ConfigError(f"forward.listen_ip 不是合法的 IPv6 地址: {listen_ip!r}") from exc
        if (
            not listen_address.is_global or listen_address.is_multicast or listen_address.scope_id
            or listen_address.ipv4_mapped is not None
        ):
            raise ConfigError("IPv6 直连须填写本机公网 IPv6 地址")
        if ingress_domain or ingress_fixed_ip:
            raise ConfigError("IPv6 直连规则须留空 ingress.domain 和 ingress.fixed_ip")
        listen_ip = str(listen_address)
    else:
        listen_ip = validate_ipv4(listen_ip, "forward.listen_ip")
        if ddns_profile:
            raise ConfigError("只有 IPv6 直连入口可以跟随 DDNS")
        ingress_domain = ingress_domain or default_domain
    listen_port = validate_port(forward_sec.get("listen_port"), "forward.listen_port")
    if ":" in listen_ip and listen_port != public_port:
        raise ConfigError("IPv6 直连的公网端口须与本机监听端口相同")
    raw_remote = _require_str(forward_sec, "remote_ip", "forward")
    if ":" in raw_remote:
        remote_ip = validate_ipv6(raw_remote, "forward.remote_ip")
    else:
        remote_ip = validate_ipv4(raw_remote, "forward.remote_ip")
    remote_port = validate_port(forward_sec.get("remote_port"), "forward.remote_port")

    realm_sec = data.get("realm") or {}
    if not isinstance(realm_sec, dict):
        raise ConfigError("[realm] 必须是配置表")
    log_level = str(realm_sec.get("log_level", "warn")).strip() or "warn"
    if log_level not in VALID_LOG_LEVELS:
        raise ConfigError(f"realm.log_level 无效: {log_level!r} (可选: {', '.join(VALID_LOG_LEVELS)})")
    tcp_timeout = validate_non_negative_int(realm_sec.get("tcp_timeout", 5), "realm.tcp_timeout")
    tcp_keepalive = validate_non_negative_int(realm_sec.get("tcp_keepalive", 15), "realm.tcp_keepalive")
    tcp_keepalive_probe = validate_non_negative_int(
        realm_sec.get("tcp_keepalive_probe", 3), "realm.tcp_keepalive_probe"
    )

    return RuleConfig(
        name=name,
        line=line,
        public_port=public_port,
        listen_ip=listen_ip,
        listen_port=listen_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        description=description,
        ingress_domain=ingress_domain,
        ingress_fixed_ip=ingress_fixed_ip,
        ddns_profile=ddns_profile,
        log_level=log_level,
        tcp_timeout=tcp_timeout,
        tcp_keepalive=tcp_keepalive,
        tcp_keepalive_probe=tcp_keepalive_probe,
        source_path=source_path,
    )


def load_rule_config(path: str, default_domain: str = DEFAULT_INGRESS_DOMAIN) -> RuleConfig:
    """Load and validate a single forwarding rule TOML file."""
    rule_path = Path(path)
    if not rule_path.exists():
        raise ConfigError(f"规则文件不存在: {path}")
    try:
        text = rule_path.read_text(encoding="utf-8")
        data = loads_toml(text)
    except TomlParseError as exc:
        raise ConfigError(f"规则文件 TOML 解析失败 ({path}): {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"无法读取规则文件 ({path}): {exc}") from exc
    return parse_rule_config_dict(data, default_domain=default_domain, source_path=str(rule_path))


def render_rule_toml(rule: RuleConfig) -> str:
    """Render a canonical managed rule TOML file."""
    lines = [
        f"# Managed by leikwan_tools (rule: {rule.name})",
        "[rule]",
        f"name = {dump_toml_string(rule.name)}",
        f"description = {dump_toml_string(rule.description)}",
        f"line = {dump_toml_string(rule.line)}",
        "",
        "[ingress]",
        f"domain = {dump_toml_string(rule.ingress_domain)}",
        f"fixed_ip = {dump_toml_string(rule.ingress_fixed_ip)}",
        *([f"ddns_profile = {dump_toml_string(rule.ddns_profile)}"] if rule.ddns_profile else []),
        f"public_port = {rule.public_port}",
        "",
        "[forward]",
        f"listen_ip = {dump_toml_string(rule.listen_ip)}",
        f"listen_port = {rule.listen_port}",
        f"remote_ip = {dump_toml_string(rule.remote_ip)}",
        f"remote_port = {rule.remote_port}",
        "",
        "[realm]",
        f"log_level = {dump_toml_string(rule.log_level)}",
        f"tcp_timeout = {rule.tcp_timeout}",
        f"tcp_keepalive = {rule.tcp_keepalive}",
        f"tcp_keepalive_probe = {rule.tcp_keepalive_probe}",
        "",
    ]
    return "\n".join(lines)


def render_realm_toml(rule: RuleConfig, line: LineConfig, listen_interface: str = "") -> str:
    """Render per-rule Realm TOML binding listen, remote, outbound through IP, and outbound interface."""
    if rule.remote_is_ipv6 != line.is_ipv6:
        raise ConfigError(
            f"规则 {rule.name!r} 落地地址族 ({rule.remote_family}) 与出口线路 {line.name!r} ({line.family}) 不匹配"
        )
    dns_mode = "ipv6_only" if rule.remote_is_ipv6 else "ipv4_only"
    lines = [
        f"# Generated by leikwan_tools for rule: {rule.name}",
        "# Managed file - do not edit manually",
        "",
        "[log]",
        f"level = {dump_toml_string(rule.log_level)}",
        'output = "stdout"',
        "",
        "[dns]",
        f'mode = "{dns_mode}"',
        "",
        "[network]",
        "no_tcp = false",
        "use_udp = false",
        f"tcp_timeout = {rule.tcp_timeout}",
        f"tcp_keepalive = {rule.tcp_keepalive}",
        f"tcp_keepalive_probe = {rule.tcp_keepalive_probe}",
        "",
        "[[endpoints]]",
        f'listen = "{rule.listen_endpoint}"',
        f'remote = "{rule.remote_endpoint}"',
        f'through = "{format_realm_through(line.source_ip)}"',
        f'interface = "{line.interface}"',
    ]
    if listen_interface and not rule.direct_ipv6:
        lines.append(f'listen_interface = "{listen_interface}"')
    return "\n".join([*lines, ""])
