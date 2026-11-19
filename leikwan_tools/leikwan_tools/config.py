"""Configuration dataclasses, strict validation, and TOML rendering for leikwan_tools."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import re
from typing import Any, Dict

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


def validate_non_negative_int(value: Any, field_name: str) -> int:
    """Validate non-negative integer (rejecting bool)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(f"{field_name} 必须是非负整数，当前为 {value!r}")
    return value


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
    """Configured outbound line with source policy routing expectations."""

    name: str
    interface: str
    source_ip: str
    gateway: str
    table: int
    description: str = ""


@dataclass(frozen=True)
class GlobalConfig:
    """Top-level configuration loaded from config.toml."""

    tool: ToolSettings
    ingress: IngressSettings
    lines: Dict[str, LineConfig]
    config_path: str = ""


@dataclass(frozen=True)
class RuleConfig:
    """Single TCP forwarding rule with an IPv4 destination."""

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

    @property
    def direct_ipv6(self) -> bool:
        return ":" in self.listen_ip

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
        source_ip = validate_ipv4(line_data.get("source_ip"), f"{ctx}.source_ip")
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
        )

    return GlobalConfig(tool=tool, ingress=ingress, lines=lines, config_path=config_path)


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
        ingress_domain = ingress_domain or default_domain
    listen_port = validate_port(forward_sec.get("listen_port"), "forward.listen_port")
    if ":" in listen_ip and listen_port != public_port:
        raise ConfigError("IPv6 直连的公网端口须与本机监听端口相同")
    remote_ip = validate_ipv4(forward_sec.get("remote_ip"), "forward.remote_ip")
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
    lines = [
        f"# Generated by leikwan_tools for rule: {rule.name}",
        "# Managed file - do not edit manually",
        "",
        "[log]",
        f"level = {dump_toml_string(rule.log_level)}",
        'output = "stdout"',
        "",
        "[dns]",
        'mode = "ipv4_only"',
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
        f'remote = "{rule.remote_ip}:{rule.remote_port}"',
        f'through = "{line.source_ip}"',
        f'interface = "{line.interface}"',
    ]
    if listen_interface and not rule.direct_ipv6:
        lines.append(f'listen_interface = "{listen_interface}"')
    return "\n".join([*lines, ""])
