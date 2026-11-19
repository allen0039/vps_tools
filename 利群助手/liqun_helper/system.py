"""Linux networking, policy routing, socket conflict inspection, file lock, and systemd helpers."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .config import LineConfig

SYS_ENV = {**os.environ, "LANG": "C", "LC_ALL": "C"}


class SystemErrorBase(RuntimeError):
    """Base runtime error for system inspection and control."""


class LockTimeoutError(SystemErrorBase):
    """Raised when exclusive write lock cannot be acquired within timeout."""


class PreflightError(SystemErrorBase):
    """Raised when system preconditions (address, policy route, port conflict) fail."""


class SystemdError(SystemErrorBase):
    """Raised when systemd operations fail."""


@dataclass(frozen=True)
class RouteGetResult:
    """Parsed output of `ip -4 route get <remote> from <src>`."""

    remote_ip: str
    source_ip: str
    dev: str
    via: str
    table: str
    src: str
    raw_output: str
    command: List[str]


@dataclass(frozen=True)
class PolicyRuleEntry:
    """Parsed entry from `ip -4 rule show`."""

    priority: int
    from_spec: str
    lookup_table: str
    raw_line: str


@dataclass(frozen=True)
class ListenerProc:
    """Process holding a listening socket."""

    name: str
    pid: int


@dataclass(frozen=True)
class ListenerSocket:
    """Parsed listening TCP socket from `ss`."""

    family: str  # "ipv4" | "ipv6"
    ip: str
    port: int
    raw_local: str
    procs: List[ListenerProc]


@dataclass(frozen=True)
class PortConflict:
    """Detected port collision."""

    conflict_type: str  # "精确地址冲突" | "通配端口冲突"
    listener: ListenerSocket


class FileLock:
    """Advisory non-blocking exclusive file lock with inode verification and timeout."""

    def __init__(self, lock_path: str, timeout: float = 15.0) -> None:
        self.lock_path = Path(lock_path)
        self.timeout = max(0.0, timeout)
        self._fd: Optional[int] = None

    def __enter__(self) -> "FileLock":
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o640)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fd_stat = os.fstat(fd)
                try:
                    path_stat = os.stat(self.lock_path)
                except FileNotFoundError:
                    path_stat = None
                if path_stat is not None and (fd_stat.st_ino, fd_stat.st_dev) == (
                    path_stat.st_ino,
                    path_stat.st_dev,
                ):
                    self._fd = fd
                    return self
                # Path was unlinked/replaced while waiting; retry on current inode.
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            except BlockingIOError:
                os.close(fd)
                if time.monotonic() >= deadline:
                    raise LockTimeoutError(
                        f"获取并发写锁超时 ({self.timeout:.1f}s): {self.lock_path}，可能有其他 liqun-helper 写操作正在执行"
                    )
                time.sleep(0.05)
            except Exception:
                os.close(fd)
                raise

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


def atomic_write_text(path: Path, content: str, mode: int = 0o644) -> None:
    """Atomically write UTF-8 text to disk using temp file + fsync + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def run_cmd(cmd: List[str], timeout: float = 15.0) -> subprocess.CompletedProcess:
    """Run external system utility safely without shell."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=SYS_ENV,
            check=False,
        )
    except OSError as exc:
        raise SystemErrorBase(f"无法执行系统命令 {' '.join(cmd)}: {exc}") from exc


def parse_ip_link_states(output: str) -> Dict[str, Tuple[str, List[str]]]:
    """Parse `ip -o link show` into {iface: (operstate, flags)}."""
    states: Dict[str, Tuple[str, List[str]]] = {}
    for line in output.splitlines():
        match = re.match(r"^\d+:\s+([^:@]+)(?:@[^:]+)?:\s+<([^>]*)>\s+(.*)$", line.strip())
        if not match:
            continue
        iface = match.group(1)
        flags = [f.strip() for f in match.group(2).split(",") if f.strip()]
        rest = match.group(3)
        state_match = re.search(r"\bstate\s+(\S+)", rest)
        operstate = state_match.group(1) if state_match else "UNKNOWN"
        states[iface] = (operstate, flags)
    return states


def parse_ip_addr_ipv4(output: str) -> Dict[str, List[str]]:
    """Parse `ip -4 -o addr show` into {iface: [ipv4, ...]}."""
    addrs: Dict[str, List[str]] = {}
    for line in output.splitlines():
        match = re.match(r"^\d+:\s+(\S+)\s+inet\s+([0-9.]+)(?:/\d+)?\b", line.strip())
        if not match:
            continue
        iface = match.group(1).split("@", 1)[0]
        ip_str = match.group(2)
        addrs.setdefault(iface, []).append(ip_str)
    return addrs


def get_local_network_state() -> Tuple[Dict[str, Tuple[str, List[str]]], Dict[str, List[str]]]:
    """Query local link states and IPv4 addresses via iproute2."""
    link_res = run_cmd(["ip", "-o", "link", "show"])
    if link_res.returncode != 0:
        raise PreflightError(f"查询本机网卡状态失败: {link_res.stderr.strip() or link_res.stdout.strip()}")
    addr_res = run_cmd(["ip", "-4", "-o", "addr", "show"])
    if addr_res.returncode != 0:
        raise PreflightError(f"查询本机 IPv4 地址失败: {addr_res.stderr.strip() or addr_res.stdout.strip()}")
    return parse_ip_link_states(link_res.stdout), parse_ip_addr_ipv4(addr_res.stdout)


def verify_local_listen_ip(listen_ip: str, addr_map: Dict[str, List[str]]) -> str:
    """Verify listen_ip is assigned on a local interface; returns owning interface name."""
    for iface, ips in addr_map.items():
        if listen_ip in ips:
            return iface
    raise PreflightError(
        f"本机未配置监听内网 IPv4 地址 {listen_ip}（当前本机 IPv4: {addr_map}）。"
        "请核对官方端口映射对应本机内网地址。"
    )


def verify_line_interface_and_source(
    line: LineConfig,
    link_states: Dict[str, Tuple[str, List[str]]],
    addr_map: Dict[str, List[str]],
) -> None:
    """Verify line interface exists, is UP, and carries expected source_ip."""
    if line.interface not in link_states:
        raise PreflightError(
            f"出口线路 {line.name!r} 配置的网卡 {line.interface!r} 不存在（现有网卡: {sorted(link_states)}）"
        )
    operstate, flags = link_states[line.interface]
    if "UP" not in flags or operstate == "DOWN":
        raise PreflightError(
            f"出口线路 {line.name!r} 的网卡 {line.interface} 状态异常: state={operstate}, flags={flags}"
        )
    iface_ips = addr_map.get(line.interface, [])
    if line.source_ip not in iface_ips:
        raise PreflightError(
            f"出口线路 {line.name!r} 的网卡 {line.interface} 缺少源 IPv4 {line.source_ip} "
            f"(当前该网卡 IPv4: {iface_ips})"
        )


def parse_rt_tables(text: str) -> Dict[str, str]:
    """Parse /etc/iproute2/rt_tables into {table_name: table_id_str}."""
    mapping: Dict[str, str] = {"local": "255", "main": "254", "default": "253"}
    for line in text.splitlines():
        cleaned = line.split("#", 1)[0].strip()
        if not cleaned:
            continue
        parts = cleaned.split()
        if len(parts) >= 2 and parts[0].isdigit():
            mapping[parts[1]] = parts[0]
    return mapping


def _load_rt_tables() -> Dict[str, str]:
    mapping: Dict[str, str] = {"local": "255", "main": "254", "default": "253"}
    candidates: List[Path] = [
        Path("/usr/share/iproute2/rt_tables"),
        Path("/etc/iproute2/rt_tables"),
    ]
    rt_dir = Path("/etc/iproute2/rt_tables.d")
    if rt_dir.is_dir():
        candidates.extend(sorted(rt_dir.glob("*.conf")))
    for path in candidates:
        if path.is_file():
            try:
                mapping.update(parse_rt_tables(path.read_text(encoding="utf-8", errors="ignore")))
            except OSError:
                pass
    return mapping


def _normalize_table_name(table_token: str, rt_tables: Optional[Dict[str, str]] = None) -> str:
    if not table_token:
        return ""
    if table_token.isdigit():
        return table_token
    tables = rt_tables if rt_tables is not None else _load_rt_tables()
    return tables.get(table_token, table_token)


def parse_route_get_output(
    remote_ip: str,
    source_ip: str,
    output: str,
    command: Optional[List[str]] = None,
    rt_tables: Optional[Dict[str, str]] = None,
) -> RouteGetResult:
    """Parse `ip -4 route get <remote> from <src>` first line."""
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    first = lines[0] if lines else ""
    tokens = first.split()

    def _find_after(key: str) -> str:
        for i, tok in enumerate(tokens[:-1]):
            if tok == key:
                return tokens[i + 1]
        return ""

    dev = _find_after("dev")
    via = _find_after("via")
    src = _find_after("src")
    raw_table = _find_after("table")
    table = _normalize_table_name(raw_table, rt_tables=rt_tables) if raw_table else ""

    return RouteGetResult(
        remote_ip=remote_ip,
        source_ip=source_ip,
        dev=dev,
        via=via,
        table=table,
        src=src,
        raw_output=first,
        command=command or ["ip", "-4", "route", "get", remote_ip, "from", source_ip],
    )


def parse_ip_rules(output: str, rt_tables: Optional[Dict[str, str]] = None) -> List[PolicyRuleEntry]:
    """Parse `ip -4 rule show` output."""
    entries: List[PolicyRuleEntry] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        prio_match = re.match(r"^(\d+):\s+(.*)$", stripped)
        if not prio_match:
            continue
        priority = int(prio_match.group(1))
        rest = prio_match.group(2)
        from_match = re.search(r"\bfrom\s+(\S+)", rest)
        lookup_match = re.search(r"\b(?:lookup|table)\s+(\S+)", rest)
        if not from_match or not lookup_match:
            continue
        entries.append(
            PolicyRuleEntry(
                priority=priority,
                from_spec=from_match.group(1),
                lookup_table=_normalize_table_name(lookup_match.group(1), rt_tables=rt_tables),
                raw_line=stripped,
            )
        )
    return entries


def check_policy_rule_matches(
    source_ip: str, expected_table: int, rules: List[PolicyRuleEntry]
) -> Optional[PolicyRuleEntry]:
    """Return matching ip rule if source_ip selects expected_table."""
    src_addr = ipaddress.IPv4Address(source_ip)
    expected_str = str(expected_table)
    for entry in rules:
        if entry.lookup_table != expected_str:
            continue
        if entry.from_spec == "all":
            continue
        try:
            net = ipaddress.IPv4Network(entry.from_spec, strict=False)
        except ValueError:
            continue
        if src_addr in net:
            return entry
    return None


def verify_egress_route(line: LineConfig, remote_ip: str) -> RouteGetResult:
    """Verify `ip -4 route get <remote_ip> from <source_ip>` (and oif <interface>) plus ip rule strictly match line."""
    cmd = ["ip", "-4", "route", "get", remote_ip, "from", line.source_ip]
    res = run_cmd(cmd)
    if res.returncode != 0:
        err = res.stderr.strip() or res.stdout.strip()
        raise PreflightError(
            f"路由探测失败 ({' '.join(cmd)}): exit={res.returncode}, {err}"
        )

    rt_tables = _load_rt_tables()
    parsed = parse_route_get_output(
        remote_ip=remote_ip,
        source_ip=line.source_ip,
        output=res.stdout,
        command=cmd,
        rt_tables=rt_tables,
    )

    mismatches: List[str] = []
    if parsed.dev != line.interface:
        mismatches.append(f"实际出口网卡 dev={parsed.dev or '(无)'}，预期={line.interface}")
    if parsed.via != line.gateway:
        mismatches.append(f"实际下一跳网关 via={parsed.via or '(直连/无)'}，预期={line.gateway}")

    expected_table_str = str(line.table)
    if line.table != 254:
        if parsed.table != expected_table_str:
            actual_table_desc = parsed.table if parsed.table else "main(默认主表)"
            mismatches.append(
                f"实际命中路由表 table={actual_table_desc}，预期={expected_table_str}（禁止退回主路由表或静默切线）"
            )
        rule_res = run_cmd(["ip", "-4", "rule", "show"])
        if rule_res.returncode != 0:
            raise PreflightError(f"查询源策略路由规则失败: {rule_res.stderr.strip()}")
        rules = parse_ip_rules(rule_res.stdout, rt_tables=rt_tables)
        if not check_policy_rule_matches(line.source_ip, line.table, rules):
            mismatches.append(
                f"`ip -4 rule show` 中未找到 from {line.source_ip} lookup {line.table} 的源策略路由"
            )

    # Also verify kernel oif-constrained lookup matching Realm SO_BINDTODEVICE behavior.
    oif_cmd = ["ip", "-4", "route", "get", remote_ip, "from", line.source_ip, "oif", line.interface]
    oif_res = run_cmd(oif_cmd)
    if oif_res.returncode != 0:
        err = oif_res.stderr.strip() or oif_res.stdout.strip()
        mismatches.append(f"指定出口网卡路由探测失败 ({' '.join(oif_cmd)}): {err}")
    else:
        oif_parsed = parse_route_get_output(
            remote_ip=remote_ip,
            source_ip=line.source_ip,
            output=oif_res.stdout,
            command=oif_cmd,
            rt_tables=rt_tables,
        )
        if oif_parsed.dev != line.interface or oif_parsed.via != line.gateway:
            mismatches.append(
                f"指定网卡 oif={line.interface} 路由结果不符: dev={oif_parsed.dev}, via={oif_parsed.via}"
            )

    if mismatches:
        raise PreflightError(
            f"出口线路 {line.name!r} 路由核对失败（严禁静默切到其他线路）:\n"
            f"  命令: {' '.join(cmd)}\n"
            f"  输出: {parsed.raw_output}\n"
            f"  差异: {'；'.join(mismatches)}"
        )
    return parsed


def _parse_local_addr_port(local_str: str) -> Tuple[str, int]:
    """Parse ss Local Address:Port such as 10.7.0.146:10001, 0.0.0.0:80, *:22, [::]:80, [::ffff:10.7.0.146]:80."""
    raw = local_str.strip()
    if raw.startswith("["):
        idx = raw.rfind("]:")
        if idx == -1:
            raise ValueError(f"Cannot parse IPv6 ss address: {local_str!r}")
        ip_part = raw[1:idx]
        port_part = raw[idx + 2 :]
    else:
        idx = raw.rfind(":")
        if idx == -1:
            raise ValueError(f"Cannot parse ss address: {local_str!r}")
        ip_part = raw[:idx]
        port_part = raw[idx + 1 :]
    ip_clean = ip_part.split("%", 1)[0]
    return ip_clean, int(port_part)


def _parse_ss_procs(proc_text: str) -> List[ListenerProc]:
    procs: List[ListenerProc] = []
    seen = set()
    for match in re.finditer(r'\("([^"]*)",pid=(\d+),fd=\d+\)', proc_text):
        key = (match.group(1), int(match.group(2)))
        if key not in seen:
            seen.add(key)
            procs.append(ListenerProc(name=key[0], pid=key[1]))
    return procs


def parse_ss_listeners(output: str, family: str) -> List[ListenerSocket]:
    """Parse `ss -H -l -t -n -p` output lines into ListenerSocket objects."""
    listeners: List[ListenerSocket] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 5)
        if len(parts) < 5:
            continue
        local_raw = parts[3]
        try:
            ip_clean, port = _parse_local_addr_port(local_raw)
        except ValueError:
            continue
        proc_col = parts[5] if len(parts) >= 6 else ""
        listeners.append(
            ListenerSocket(
                family=family,
                ip=ip_clean,
                port=port,
                raw_local=local_raw,
                procs=_parse_ss_procs(proc_col),
            )
        )
    return listeners


def list_tcp_listeners() -> List[ListenerSocket]:
    """List current IPv4 and IPv6 listening TCP sockets via `ss`."""
    listeners: List[ListenerSocket] = []
    for flag, fam in (("-4", "ipv4"), ("-6", "ipv6")):
        res = run_cmd(["ss", "-H", flag, "-l", "-t", "-n", "-p"])
        if res.returncode != 0:
            raise PreflightError(f"查询监听端口失败 (`ss -H {flag} -l -t -n -p`): {res.stderr.strip()}")
        listeners.extend(parse_ss_listeners(res.stdout, fam))
    return listeners


def read_bindv6only() -> int:
    """Read Linux net.ipv6.bindv6only sysctl (defaults to 0)."""
    sysctl_path = Path("/proc/sys/net/ipv6/bindv6only")
    try:
        return int(sysctl_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def find_port_conflicts(
    listen_ip: str,
    listen_port: int,
    listeners: Iterable[ListenerSocket],
    allowed_pids: Optional[Set[int]] = None,
    bindv6only: Optional[int] = None,
) -> List[PortConflict]:
    """Detect exact-address and wildcard TCP listening collisions."""
    allowed = allowed_pids or set()
    v6_only = read_bindv6only() if bindv6only is None else bindv6only
    conflicts: List[PortConflict] = []

    for item in listeners:
        if item.port != listen_port:
            continue

        conflict_type: Optional[str] = None
        if item.family == "ipv4":
            if item.ip == listen_ip:
                conflict_type = "精确地址冲突"
            elif item.ip in ("0.0.0.0", "*"):
                conflict_type = "通配端口冲突"
        elif item.family == "ipv6":
            if item.ip.lower() == f"::ffff:{listen_ip}".lower():
                conflict_type = "精确地址冲突(IPv4-mapped IPv6)"
            elif v6_only == 0 and item.ip in ("::", "*"):
                conflict_type = "通配端口冲突(IPv6 双栈 [::])"

        if conflict_type is None:
            continue

        if item.procs and all(proc.pid in allowed for proc in item.procs):
            continue

        conflicts.append(PortConflict(conflict_type=conflict_type, listener=item))

    return conflicts


def format_port_conflict_error(listen_ip: str, listen_port: int, conflicts: List[PortConflict]) -> str:
    """Build clear human-readable port conflict message without killing occupying processes."""
    lines = [f"监听端口 {listen_ip}:{listen_port} 已被占用，已停止应用（不会终止现有占用进程）:"]
    for c in conflicts:
        if c.listener.procs:
            proc_desc = ", ".join(f"{p.name}(pid={p.pid})" for p in c.listener.procs)
        else:
            proc_desc = "未知进程（如需查看 PID 请以 root 运行）"
        lines.append(f"  - [{c.conflict_type}] {c.listener.raw_local} -> {proc_desc}")
    return "\n".join(lines)


def unit_name_for_rule(template: str, rule_name: str) -> str:
    """Instantiate systemd template unit name for a rule."""
    if "%i" in template:
        return template.replace("%i", rule_name)
    if "@." in template:
        prefix, suffix = template.split("@.", 1)
        return f"{prefix}@{rule_name}.{suffix}"
    if template.endswith("@"):
        return f"{template}{rule_name}.service"
    return f"{template}@{rule_name}.service"


def systemd_show(unit_name: str) -> Dict[str, str]:
    """Query structured unit properties via `systemctl show`."""
    props = [
        "LoadState",
        "ActiveState",
        "SubState",
        "UnitFileState",
        "MainPID",
        "NRestarts",
        "ExecMainStatus",
        "Result",
    ]
    cmd = ["systemctl", "show", "--no-pager"]
    for prop in props:
        cmd.extend(["-p", prop])
    cmd.append(unit_name)
    res = run_cmd(cmd)
    if res.returncode != 0:
        raise SystemdError(f"systemctl show {unit_name} 失败: {res.stderr.strip()}")
    data: Dict[str, str] = {}
    for line in res.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


def systemd_is_enabled(unit_name: str) -> bool:
    """Check whether unit is enabled for boot persistence."""
    res = run_cmd(["systemctl", "is-enabled", unit_name])
    return res.returncode == 0 and res.stdout.strip() in ("enabled", "enabled-runtime", "static")


def systemd_is_active(unit_name: str) -> Optional[bool]:
    """Check whether unit is currently active, or return None when unknown."""
    res = run_cmd(["systemctl", "is-active", unit_name])
    state = res.stdout.strip()
    if state == "active":
        return True
    if state in {"inactive", "failed", "dead"}:
        return False
    return None


def systemd_daemon_reload() -> None:
    res = run_cmd(["systemctl", "daemon-reload"])
    if res.returncode != 0:
        raise SystemdError(f"systemctl daemon-reload 失败: {res.stderr.strip()}")


def systemd_enable(unit_name: str) -> None:
    res = run_cmd(["systemctl", "enable", unit_name])
    if res.returncode != 0:
        raise SystemdError(f"systemctl enable {unit_name} 失败: {res.stderr.strip()}")


def systemd_disable(unit_name: str, now: bool = False) -> None:
    cmd = ["systemctl", "disable"]
    if now:
        cmd.append("--now")
    cmd.append(unit_name)
    res = run_cmd(cmd)
    if res.returncode != 0:
        stderr = res.stderr.strip()
        if "No such file or directory" not in stderr and "not loaded" not in stderr:
            raise SystemdError(f"{' '.join(cmd)} 失败: {stderr}")


def systemd_restart(unit_name: str) -> None:
    res = run_cmd(["systemctl", "restart", unit_name], timeout=20.0)
    if res.returncode != 0:
        raise SystemdError(f"systemctl restart {unit_name} 失败: {res.stderr.strip()}")


def systemd_stop(unit_name: str) -> None:
    res = run_cmd(["systemctl", "stop", unit_name], timeout=20.0)
    if res.returncode != 0:
        stderr = res.stderr.strip()
        if "not loaded" not in stderr:
            raise SystemdError(f"systemctl stop {unit_name} 失败: {stderr}")


def systemd_reset_failed(unit_name: str) -> None:
    run_cmd(["systemctl", "reset-failed", unit_name])


def systemd_journal_tail(unit_name: str, lines: int = 20) -> str:
    res = run_cmd(["journalctl", "-u", unit_name, "-n", str(lines), "--no-pager", "-o", "short-iso"])
    if res.returncode != 0:
        return ""
    return res.stdout.strip()
