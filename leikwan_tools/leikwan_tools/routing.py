"""Plan and restore explicitly approved IPv4 source policy routing."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import IPv4Address, IPv4Network
import json
from pathlib import Path
import stat
from subprocess import TimeoutExpired
from typing import Any, Optional

from .config import GlobalConfig, LineConfig, load_global_config, parse_global_config_dict
from .ownership import ensure_safe_subpath, load_install_manifest, resolve_lock_file
from .system import (
    FileLock,
    PUBLIC_ROUTE_PROBE_IP,
    PreflightError,
    SystemErrorBase,
    atomic_write_text,
    get_local_network_state,
    run_cmd,
    systemd_daemon_reload,
    systemd_disable,
    systemd_stop,
    verify_egress_route,
    verify_line_interface_and_source,
)

UNIT_NAME = "leikwan_tools-routing.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME
STATE_FILE = "source-routing.json"
PROTOCOL = "242"
PRIORITIES = range(10000, 11000)


@dataclass(frozen=True)
class SourceRoute:
    interface: str
    source_ip: str
    gateway: str
    table: int
    network: str

    def command(self, kind: str, verb: str, priority: Optional[int] = None) -> list[str]:
        prefix = ["ip", "-4"]
        table = ["table", str(self.table)]
        if kind == "rule":
            return prefix + [
                "rule", verb, "from", self.source_ip + "/32", *table, "pref", str(priority),
                "protocol", PROTOCOL,
            ]
        fields = ["default", "via", self.gateway, "dev", self.interface]
        if kind == "connected":
            fields = [self.network, "dev", self.interface, "scope", "link", "src", self.source_ip]
        return prefix + ["route", verb, *fields, *table, "proto", PROTOCOL]

    def matches(self, kind: str, item: dict) -> bool:
        if kind == "rule":
            return (
                item.get("src") in (self.source_ip, self.source_ip + "/32")
                and item.get("table") == str(self.table)
                and item.get("srclen", 32) == 32
                and item.keys() <= {"src", "srclen", "table", "priority", "protocol"}
            )
        if item.get("dev") != self.interface or item.get("type", "1") != "1":
            return False
        if item.keys() - {
            "dst", "gateway", "dev", "protocol", "scope", "prefsrc", "flags", "metric", "type",
        } or set(item.get("flags", ())) - {"onlink", "linkdown"}:
            return False
        if item.get("prefsrc", self.source_ip) != self.source_ip:
            return False
        if kind == "connected":
            return (
                item.get("dst") in (self.network, self.network.removesuffix("/32"))
                and item.get("scope") == "253"
                and "gateway" not in item
            )
        return (
            item.get("dst") == "default"
            and item.get("gateway") == self.gateway
            and item.get("scope", "0") == "0"
        )


@dataclass(frozen=True)
class Entry:
    route: SourceRoute
    kind: str
    priority: Optional[int] = None

    def command(self, verb: str) -> list[str]:
        return self.route.command(self.kind, verb, self.priority)

    def existing(self) -> list[dict]:
        if self.kind == "rule":
            items = _ip_json("rule", "show")
            return [item for item in items if item.get("priority") == self.priority]
        return _ip_json("route", "show", "table", str(self.route.table), empty_table=True)

    def owned_live(self) -> bool:
        items = self.existing()
        matching = [item for item in items if self.route.matches(self.kind, item)]
        if self.kind == "rule" and len(items) > 1 and any(item.get("protocol") == PROTOCOL for item in matching):
            raise PreflightError(f"拒绝删除优先级 {self.priority} 存在歧义的源策略规则")
        return len(matching) == 1 and matching[0].get("protocol") == PROTOCOL and (
            self.kind == "rule" or (
                "metric" not in matching[0]
                and set(matching[0].get("flags", ())) <= {"linkdown"}
                and matching[0].get("prefsrc") == (self.route.source_ip if self.kind == "connected" else None)
            )
        )


def _ip_json(*args: str, empty_table: bool = False) -> list[dict]:
    command = ["ip", "-4", "-j", "-N", *args]
    try:
        result = run_cmd(command)
    except TimeoutExpired as exc:
        raise PreflightError(f"{' '.join(command)} 超时") from exc
    if result.returncode:
        if empty_table and "FIB table does not exist" in result.stderr:
            return []
        raise PreflightError(f"{' '.join(command)} 失败: {result.stderr.strip()}")
    try:
        items = json.loads(result.stdout)
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise ValueError
        return items
    except ValueError as exc:
        raise PreflightError(f"无法解析 {' '.join(command)} 的 JSON 输出") from exc


def _profile(cfg: GlobalConfig) -> dict[str, SourceRoute]:
    ipv4_lines = [line for line in cfg.lines.values() if not line.is_ipv6]
    if not ipv4_lines:
        raise PreflightError(
            "主配置中没有 IPv4 出口线路需要初始化源策略路由（IPv6 出口使用系统已有路由与 Realm socket 绑定，不自动修改系统 IPv6 路由）"
        )
    links, addresses = get_local_network_state()
    profile = {}
    sources = set()
    for line in ipv4_lines:
        if line.table is None or 252 <= line.table <= 255:
            raise PreflightError(f"线路 {line.name} 必须使用独立路由表，当前为 {line.table}")
        if line.table in {route.table for route in profile.values()} or line.source_ip in sources:
            raise PreflightError(f"线路 {line.name} 的路由表或源 IPv4 与其他线路重复")
        verify_line_interface_and_source(line, links, addresses)
        prefixes = {
            IPv4Network(f'{line.source_ip}/{item["prefixlen"]}', strict=False)
            for iface in _ip_json("addr", "show", "dev", line.interface)
            for item in iface.get("addr_info", [])
            if item.get("local") == line.source_ip
        }
        if len(prefixes) != 1 or line.gateway == line.source_ip:
            raise PreflightError(f"线路 {line.name} 的源 IPv4 前缀或网关配置异常")
        network = prefixes.pop()
        if IPv4Address(line.gateway) not in network:
            network = IPv4Network(line.gateway + "/32")
        profile[line.name] = SourceRoute(line.interface, line.source_ip, line.gateway, line.table, str(network))
        sources.add(line.source_ip)
    return profile


def _shares_source(route: SourceRoute, item: dict) -> bool:
    source = item.get("src", "all")
    if source == "all" or "not" in item:
        return True
    try:
        if "srclen" in item and "/" not in source:
            source = f'{source}/{item["srclen"]}'
        return IPv4Address(route.source_ip) in IPv4Network(source, strict=False)
    except ValueError:
        return True


def _scan(profile: dict[str, SourceRoute]) -> tuple[list[Entry], list[Entry]]:
    rules = _ip_json("rule", "show")
    used = {item["priority"] for item in rules}
    available = (priority for priority in PRIORITIES if priority not in used)
    add, keep = [], []
    builtin = {
        (0, "255"), (32766, "254"), (32767, "253"),
    }
    for name, route in sorted(profile.items()):
        found_rules = [item for item in rules if route.matches("rule", item)]
        if len(found_rules) > 1:
            raise PreflightError(f"线路 {name} 有重复的源策略规则: {found_rules}")
        priority = found_rules[0]["priority"] if found_rules else next(available, None)
        if priority is None:
            raise PreflightError("没有空闲的源策略规则优先级 (10000–10999)")
        for item in rules:
            pref, table = item["priority"], item.get("table")
            if item in found_rules:
                continue
            if (
                (pref, table) in builtin
                and item.get("src") == "all"
                and item.keys() <= {"src", "priority", "table", "protocol"}
            ):
                continue
            overlaps = _shares_source(route, item)
            if (
                table == str(route.table)
                or pref == priority
                or (overlaps and (pref < priority or item.get("src", "all") != "all"))
            ):
                raise PreflightError(f"线路 {name} 的源策略规则冲突: {item}")

        table_rows = _ip_json("route", "show", "table", str(route.table), empty_table=True)
        connected = [item for item in table_rows if route.matches("connected", item)]
        default = [item for item in table_rows if route.matches("default", item)]
        if len(connected) > 1 or len(default) > 1 or len(table_rows) != len(connected) + len(default):
            raise PreflightError(f"线路 {name} 的路由表 {route.table} 已包含不兼容路由: {table_rows}")
        if connected or not default:
            (keep if connected else add).append(Entry(route, "connected"))
        (keep if default else add).append(Entry(route, "default"))
        (keep if found_rules else add).append(Entry(route, "rule", priority))
    return add, keep


def _state_path(state_dir: str) -> Path:
    root = Path(state_dir)
    return ensure_safe_subpath(root, root / STATE_FILE)


def _read_state(path: Path) -> Optional[dict]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PreflightError(f"无法访问源策略路由记录 {path}") from exc
    try:
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.get("schema_version") != 1:
            raise ValueError
        return state
    except (ValueError, OSError) as exc:
        raise PreflightError(f"无法验证已批准的源策略路由记录 {path}") from exc


def _boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def _profile_data(profile: dict[str, SourceRoute]) -> dict:
    return {name: asdict(route) for name, route in profile.items()}


def _owned_entries(state: Optional[dict], profile: dict[str, SourceRoute], boot_id: str) -> list[Entry]:
    if state is None or state.get("boot_id") != boot_id:
        return []
    try:
        entries = []
        by_table = {route.table: route for route in profile.values()}
        for table, kind, priority in state["owned"]:
            if kind not in ("connected", "default", "rule"):
                raise ValueError
            if kind == "rule" and (type(priority) is not int or priority not in PRIORITIES):
                raise ValueError
            if kind != "rule" and priority is not None:
                raise ValueError
            entry = Entry(by_table[table], kind, priority)
            if entry not in entries:
                entries.append(entry)
        return entries
    except (KeyError, TypeError, ValueError) as exc:
        raise PreflightError("源策略路由归属记录无效") from exc


def _snapshot(cfg: GlobalConfig) -> tuple[Path, Optional[dict], dict[str, SourceRoute], list[Entry], list[Entry]]:
    path = _state_path(cfg.tool.state_dir)
    state = _read_state(path)
    profile = _profile(cfg)
    if state is not None and state.get("profile") != _profile_data(profile):
        raise PreflightError(f"线路或 IPv4 前缀与已批准的源策略路由记录不同: {path}")
    add, keep = _scan(profile)
    return path, state, profile, add, keep


def _preview(path: Path, state: Optional[dict], add: list[Entry], keep: list[Entry]) -> dict[str, Any]:
    return {
        "state_file": str(path),
        "boot_unit": UNIT_NAME,
        "persisted": state is not None,
        "add": [entry.command("add") for entry in add],
        "keep": [
            {"kind": entry.kind, **asdict(entry.route), "priority": entry.priority} for entry in keep
        ],
    }


def plan_routing(cfg: GlobalConfig) -> dict[str, Any]:
    path, state, _, add, keep = _snapshot(cfg)
    return _preview(path, state, add, keep)


def _mutate(command: list[str]) -> None:
    result = run_cmd(command)
    if result.returncode:
        raise PreflightError(f"{' '.join(command)} 失败: {result.stderr.strip()}")


def _remove_entries(entries: list[Entry]) -> list[str]:
    errors = []
    for entry in sorted(entries, key=lambda item: ("rule", "default", "connected").index(item.kind)):
        try:
            if entry.owned_live():
                _mutate(entry.command("del"))
        except (SystemErrorBase, TimeoutExpired, OSError) as exc:
            errors.append(str(exc))
    return errors


def _unit_is_owned() -> bool:
    return (
        not UNIT_PATH.is_symlink()
        and UNIT_PATH.is_file()
        and UNIT_PATH.read_bytes() == Path(__file__).with_name(UNIT_NAME).read_bytes()
    )


def _unit_matches_installation() -> bool:
    if not _unit_is_owned():
        return False
    unit = run_cmd(["systemctl", "show", "-p", "FragmentPath", "-p", "DropInPaths", UNIT_NAME])
    props = dict(line.split("=", 1) for line in unit.stdout.splitlines() if "=" in line)
    return unit.returncode == 0 and props.get("FragmentPath") == str(UNIT_PATH) and not props.get("DropInPaths")


def _assert_boot_install(cfg: GlobalConfig, manifest: Optional[dict]) -> None:
    result = run_cmd(["systemctl", "is-enabled", UNIT_NAME])
    if (
        not manifest
        or Path(manifest["config_file"]).resolve() != Path(cfg.config_path).resolve()
        or Path(manifest["state_dir"]).resolve() != Path(cfg.tool.state_dir).resolve()
        or not _unit_matches_installation()
        or result.returncode
        or result.stdout.strip() != "enabled"
    ):
        raise PreflightError("源策略路由初始化需要使用已安装的主配置和已启用的受管开机服务")


def apply_routing(
    cfg: GlobalConfig, expected: Optional[dict] = None, *, restore: bool = False, lock_timeout: float = 15.0,
) -> dict[str, Any]:
    if restore and not _read_state(_state_path(cfg.tool.state_dir)):
        return {"status": "unconfigured"}
    with FileLock(resolve_lock_file(), timeout=lock_timeout):
        if cfg.config_path:
            cfg = load_global_config(cfg.config_path)
        if restore and not _read_state(_state_path(cfg.tool.state_dir)):
            return {"status": "unconfigured"}
        _assert_boot_install(cfg, load_install_manifest())
        path, state, profile, add, keep = _snapshot(cfg)
        preview = _preview(path, state, add, keep)
        if expected is not None and preview != expected:
            raise PreflightError("路由状态已变更，请重新预览")
        boot_id = _boot_id()
        owned = [entry for entry in _owned_entries(state, profile, boot_id) if entry in keep and entry.owned_live()]
        added = []
        try:
            for entry in add:
                try:
                    _mutate(entry.command("add"))
                except (TimeoutExpired, KeyboardInterrupt):
                    added.append(entry)
                    raise
                added.append(entry)
            for line in cfg.lines.values():
                if not line.is_ipv6:
                    verify_egress_route(line, PUBLIC_ROUTE_PROBE_IP)
            new_state = {
                "schema_version": 1,
                "profile": _profile_data(profile),
                "boot_id": boot_id,
                "owned": [[entry.route.table, entry.kind, entry.priority] for entry in owned + added],
            }
            if state != new_state:
                atomic_write_text(path, json.dumps(new_state, indent=2) + "\n", mode=0o600)
        except (SystemErrorBase, TimeoutExpired, OSError, KeyboardInterrupt) as exc:
            errors = _remove_entries(added)
            detail = f"；回滚失败: {'；'.join(errors)}" if errors else "；已回滚本次新增项"
            raise PreflightError(f"源策略路由应用失败: {exc}{detail}") from exc
        return {**preview, "persisted": True, "status": "noop" if state == new_state and not added else "applied"}


def uninstall_routing(state_dir: str) -> list[str]:
    """Run under the uninstall lock after stopping managed relay instances."""
    path = _state_path(state_dir)
    state = _read_state(path)
    removed = []
    owned_unit = _unit_matches_installation()
    if state is not None:
        if not owned_unit:
            raise PreflightError(f"无法确认开机服务归属，已保留源策略路由记录 {path}")
        try:
            data = state["profile"]
            cfg = parse_global_config_dict({"lines": data})
            profile = {}
            for name, line in cfg.lines.items():
                if 252 <= line.table <= 255:
                    raise ValueError
                network = str(IPv4Network(data[name]["network"]))
                profile[name] = SourceRoute(line.interface, line.source_ip, line.gateway, line.table, network)
            if _profile_data(profile) != data:
                raise ValueError
        except (KeyError, TypeError, ValueError) as exc:
            raise PreflightError(f"无法验证源策略路由记录 {path}") from exc
        systemd_stop(UNIT_NAME)
        errors = _remove_entries(_owned_entries(state, profile, _boot_id()))
        if errors:
            raise PreflightError(f"卸载源策略路由失败: {'；'.join(errors)}")
        path.unlink()
        removed.append(str(path))
    if owned_unit:
        systemd_disable(UNIT_NAME, now=True)
        UNIT_PATH.unlink()
        systemd_daemon_reload()
        removed.append(str(UNIT_PATH))
    return removed
