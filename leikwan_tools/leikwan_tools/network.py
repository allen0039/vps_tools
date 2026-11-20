"""Explicit, reversible system network settings for Debian and systemd."""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
from subprocess import TimeoutExpired

from . import DEFAULT_STATE_DIR, MANAGED_MARKER
from .ownership import resolve_lock_file
from .system import FileLock, SystemErrorBase, atomic_write_text, run_cmd


ETC = Path("/etc")
PROC_SYS = Path("/proc/sys")
STATE = Path(DEFAULT_STATE_DIR) / "system-network"
DEFAULT_DNS = "8.8.8.8,1.1.1.1"
RESOLVED = "systemd-resolved.service"
RESOLVED_CONF = "systemd/resolved.conf.d/90-leikwan_tools.conf"
NFT_TABLE = "leikwan_tools_ipv6_input"
NFT_CONF = "leikwan_tools-ipv6-input.nft"
NFT_UNIT = "leikwan_tools-ipv6-input.service"
NFT_UNIT_CONF = f"systemd/system/{NFT_UNIT}"
NFT_COMMENT = "Managed by leikwan_tools"
BBR_VALUES = {
    "net/core/default_qdisc": "fq",
    "net/ipv4/tcp_congestion_control": "bbr",
}
IPV6_SCOPES = Path("net/ipv6/conf")
IPV6_VALUES = {f"{IPV6_SCOPES}/{scope}/disable_ipv6": "1" for scope in ("all", "default")}
PATHS = {
    "ipv4-prefer": {"gai.conf"},
    "dns": {RESOLVED_CONF, "resolv.conf"},
    "ipv6": {"sysctl.d/99-leikwan_tools-ipv6.conf"},
    "bbr": {"sysctl.d/99-leikwan_tools-bbr.conf"},
    "ipv6-lockdown": {NFT_CONF, NFT_UNIT_CONF},
}


class NetworkError(SystemErrorBase):
    pass


def _cmd(*args: str) -> str:
    result = run_cmd(list(args))
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise NetworkError(f"{' '.join(args)}: {detail}")
    return result.stdout.strip()


def _snapshot(path: Path) -> dict | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or path.resolve() != path:
        raise NetworkError(f"拒绝修改符号链接或非普通文件: {path}")
    return {
        "text": path.read_bytes().decode("utf-8"),
        "mode": stat.S_IMODE(info.st_mode),
        "owner": [info.st_uid, info.st_gid],
    }


def _write(path: Path, data: dict | None) -> None:
    if _snapshot(path) == data:
        return
    if data is None:
        path.unlink(missing_ok=True)
    else:
        if path.parent.resolve() != path.parent:
            raise NetworkError(f"拒绝通过符号链接目录修改: {path}")
        atomic_write_text(path, data["text"], data["mode"], owner=tuple(data["owner"]))


def _backup_path(feature: str) -> Path:
    for directory in (STATE.parent, STATE):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise NetworkError(f"系统网络备份目录必须归 root 所有且不可由其他用户写入: {directory}")
    return STATE / f"{feature}.json"


def _load_backup(path: Path, feature: str) -> dict | None:
    data = _snapshot(path)
    if data is None:
        return None
    if data["owner"][0] != os.geteuid() or data["mode"] != 0o600:
        raise NetworkError(f"系统网络备份权限异常: {path}")
    record = json.loads(data["text"])
    if (
        not isinstance(record, dict)
        or record.get("version") != 1
        or not record["original"]
        or set(record["original"]) != set(record["managed"])
        or not set(record["original"]) <= PATHS[feature]
    ):
        raise NetworkError(f"系统网络备份格式无效: {path}")
    return record


def _save_backup(path: Path, record: dict) -> None:
    STATE.parent.mkdir(mode=0o755, exist_ok=True)
    STATE.mkdir(mode=0o700, exist_ok=True)
    atomic_write_text(path, json.dumps(record, ensure_ascii=False) + "\n", 0o600)


def pending_network_settings() -> list[str]:
    return [feature for feature in PATHS if os.path.lexists(STATE / f"{feature}.json")]


def _ipv4_prefer(text: str) -> str:
    lines = []
    values = []
    has_precedence = False
    for line in text.splitlines(keepends=True):
        fields = line.partition("#")[0].split()
        if len(fields) == 3 and fields[0] == "precedence":
            network = ipaddress.IPv6Network(fields[1], strict=False)
            has_precedence = True
            if network.subnet_of(ipaddress.IPv6Network("::ffff:0:0/96")):
                continue
            values.append(int(fields[2]))
        lines.append(line)
    defaults = "" if has_precedence else (
        "precedence ::1/128 50\nprecedence ::/0 40\nprecedence 2002::/16 30\nprecedence ::/96 20\n"
    )
    return "".join(lines).rstrip("\r\n") + f"\n\n{MANAGED_MARKER}\n{defaults}" + (
        f"precedence ::ffff:0:0/96 {max([99, *values]) + 1}\n"
    )


def _dns_servers(raw: str) -> list[str]:
    servers = []
    for item in raw.split(","):
        address = ipaddress.ip_address(item.strip())
        if address.is_unspecified or address.is_multicast or "%" in str(address):
            raise NetworkError(f"无效的 DNS 服务器地址: {address}")
        servers.append(str(address))
    return list(dict.fromkeys(servers))


def _dns_contents(raw: str) -> dict[str, str]:
    servers = _dns_servers(raw)
    resolv = ETC / "resolv.conf"
    if resolv.is_symlink():
        target = str(resolv.resolve())
        if target not in {
            "/run/systemd/resolve/stub-resolv.conf",
            "/run/systemd/resolve/resolv.conf",
            "/usr/lib/systemd/resolv.conf",
        } or not _resolved_active():
            raise NetworkError("resolv.conf 是非活动 systemd-resolved 或其他服务管理的符号链接，未修改。")
        return {RESOLVED_CONF: f"{MANAGED_MARKER}\n[Resolve]\nDNS=\nDNS={' '.join(servers)}\n"}
    if len(servers) > 3:
        raise NetworkError("普通 resolv.conf 最多支持 3 个 DNS 服务器。")
    current = _snapshot(resolv)
    lines = current["text"].splitlines(keepends=True) if current else []
    retained = "".join(
        line for line in lines if not re.match(r"^\s*nameserver\s", line) and line.rstrip() != MANAGED_MARKER
    )
    return {"resolv.conf": f"{MANAGED_MARKER}\n" + "".join(f"nameserver {server}\n" for server in servers) + retained}


def _resolved_active() -> bool:
    return run_cmd(["systemctl", "is-active", "--quiet", RESOLVED]).returncode == 0


def _read_sysctl(key: str) -> str:
    return (PROC_SYS / key).read_text(encoding="ascii").strip()


def _ipv6_keys() -> list[str]:
    scopes = sorted((PROC_SYS / IPV6_SCOPES).glob("*/disable_ipv6"))
    return list(dict.fromkeys([*IPV6_VALUES, *(str(path.relative_to(PROC_SYS)) for path in scopes)]))


def _set_sysctls(values: dict[str, str], *, allow_missing: bool = False) -> None:
    for key, value in values.items():
        try:
            if _read_sysctl(key) != value:
                (PROC_SYS / key).write_text(value + "\n", encoding="ascii")
            if _read_sysctl(key) != value:
                raise NetworkError(f"内核未采纳 {key}={value}")
        except FileNotFoundError:
            if not allow_missing or key in IPV6_VALUES or key in BBR_VALUES:
                raise


def _nft_ports(raw: str) -> list[int]:
    ports = set()
    for item in raw.split(","):
        port = item.strip()
        if not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
            raise NetworkError(f"无效的 TCP 端口: {port!r}")
        ports.add(int(port))
    ssh = os.environ.get("SSH_CONNECTION", "").split()
    if len(ssh) == 4 and ipaddress.ip_address(ssh[0]).version == 6 and int(ssh[3]) not in ports:
        raise NetworkError(f"放行列表必须包含当前 IPv6 SSH 端口 {ssh[3]}。")
    return sorted(ports)


def _nft_contents(raw: str) -> dict[str, str]:
    ports = ", ".join(map(str, _nft_ports(raw)))
    executable = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable:
        raise NetworkError("未找到 nft；请先安装 nftables。")
    return {
        NFT_CONF: f"""{MANAGED_MARKER}
add table ip6 {NFT_TABLE}
delete table ip6 {NFT_TABLE}
table ip6 {NFT_TABLE} {{
    comment "{NFT_COMMENT}"
    chain input {{
        type filter hook input priority filter + 5; policy accept;
        iifname "lo" accept
        ct state established,related accept
        meta l4proto ipv6-icmp accept
        udp sport 547 udp dport 546 accept
        tcp dport {{ {ports} }} accept
        counter drop
    }}
}}
""",
        NFT_UNIT_CONF: f"""{MANAGED_MARKER}
[Unit]
Description=leikwan_tools IPv6 inbound filter
After=nftables.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart={executable} -f {ETC / NFT_CONF}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""",
    }


def _nft_table() -> str | None:
    listed = _cmd("nft", "list", "tables").splitlines()
    if f"table ip6 {NFT_TABLE}" not in listed:
        return None
    return _cmd("nft", "list", "table", "ip6", NFT_TABLE)


def _verify_nft_owner(record: dict | None, table: str | None) -> None:
    marker = f'comment "{NFT_COMMENT}"'
    if table is not None and (record is None or marker not in [line.strip() for line in table.splitlines()[1:2]]):
        raise NetworkError(f"拒绝修改非本工具受管的 nftables 表 {NFT_TABLE}")
    show = _cmd("systemctl", "show", "-p", "FragmentPath", "-p", "DropInPaths", NFT_UNIT)
    properties = dict(line.split("=", 1) for line in show.splitlines() if "=" in line)
    if properties.get("DropInPaths") or properties.get("FragmentPath", "") not in ("", str(ETC / NFT_UNIT_CONF)):
        raise NetworkError(f"拒绝修改非本工具受管的 systemd 单元 {NFT_UNIT}")


def _read_runtime(feature: str, record: dict | None) -> dict:
    if feature == "ipv6":
        return {key: _read_sysctl(key) for key in _ipv6_keys()}
    if feature == "bbr":
        return {key: _read_sysctl(key) for key in BBR_VALUES}
    if feature == "ipv6-lockdown":
        table = _nft_table()
        _verify_nft_owner(record, table)
        return {
            "table": table,
            "enabled": run_cmd(["systemctl", "is-enabled", "--quiet", NFT_UNIT]).returncode == 0,
        }
    return {}


def _activate_files(feature: str, files: dict, runtime: dict | None) -> None:
    if feature == "ipv6":
        keys = _ipv6_keys()
        values = {key: "1" for key in keys} if runtime is None else {
            key: runtime.get(key, runtime[f"{IPV6_SCOPES}/default/disable_ipv6"]) for key in keys
        }
        _set_sysctls(values, allow_missing=True)
    if feature == "bbr":
        _set_sysctls(runtime if runtime is not None else BBR_VALUES)
    if feature == "ipv6-lockdown":
        _cmd("systemctl", "daemon-reload")
        if runtime is None:
            _cmd("nft", "-c", "-f", str(ETC / NFT_CONF))
            _cmd("nft", "-f", str(ETC / NFT_CONF))
            _cmd("systemctl", "enable", NFT_UNIT)
        else:
            if runtime["table"] is not None:
                backup = STATE / "nft-runtime.tmp"
                try:
                    rules = f"add table ip6 {NFT_TABLE}\ndelete table ip6 {NFT_TABLE}\n{runtime['table']}\n"
                    atomic_write_text(backup, rules, 0o600)
                    _cmd("nft", "-f", str(backup))
                finally:
                    backup.unlink(missing_ok=True)
            elif _nft_table() is not None:
                _cmd("nft", "delete", "table", "ip6", NFT_TABLE)
            if runtime["enabled"]:
                _cmd("systemctl", "enable", NFT_UNIT)
            elif files[NFT_UNIT_CONF] is not None:
                _cmd("systemctl", "disable", NFT_UNIT)


def _desired_files(feature: str, value: str) -> dict[str, str]:
    if feature == "ipv4-prefer":
        current = _snapshot(ETC / "gai.conf")
        return {"gai.conf": _ipv4_prefer(current["text"] if current else "")}
    if feature == "dns":
        return _dns_contents(value)
    if feature == "ipv6-lockdown":
        return _nft_contents(value)
    values = IPV6_VALUES if feature == "ipv6" else BBR_VALUES
    path = next(iter(PATHS[feature]))
    return {path: f"{MANAGED_MARKER}\n" + "".join(f"{key.replace('/', '.')} = {val}\n" for key, val in values.items())}


def _change(feature: str, *, restore: bool, value: str) -> str:
    path = _backup_path(feature)
    record = _load_backup(path, feature)
    if restore and record is None:
        return "没有本工具的备份，未修改系统。"
    if restore:
        desired = {}
    elif feature == "ipv4-prefer" and record is not None:
        desired = {name: data["text"] for name, data in record["managed"].items()}
    else:
        desired = _desired_files(feature, value)
    if record is not None and not restore and set(desired) != set(record["original"]):
        raise NetworkError("系统 DNS 管理方式已变化，请先恢复原配置。")
    current = {name: _snapshot(ETC / name) for name in (record["original"] if record else desired)}
    if record is not None:
        for name, data in current.items():
            if data not in (record["managed"][name], record["original"][name]):
                raise NetworkError(f"{ETC / name} 已被外部修改，未覆盖；原始备份: {path}")
    else:
        for name, data in current.items():
            if data is not None and name not in ("gai.conf", "resolv.conf"):
                raise NetworkError(f"拒绝覆盖已有文件 {ETC / name}")

    if not restore and feature == "ipv6":
        ssh = os.environ.get("SSH_CONNECTION", "").split()
        if len(ssh) == 4 and ipaddress.ip_address(ssh[0]).version == 6:
            raise NetworkError("当前连接使用 IPv6 SSH，请通过 IPv4 SSH 或控制台操作。")
    if not restore and feature == "bbr" and "bbr" not in _read_sysctl("net/ipv4/tcp_available_congestion_control").split():
        _cmd("modprobe", "tcp_bbr")
        if "bbr" not in _read_sysctl("net/ipv4/tcp_available_congestion_control").split():
            raise NetworkError("当前内核不支持 BBR。")

    runtime = _read_runtime(feature, record)
    restart_resolved = RESOLVED_CONF in current and _resolved_active()
    if RESOLVED_CONF in desired and not restart_resolved:
        raise NetworkError("systemd-resolved 未运行，未修改系统 DNS。")
    if restore:
        target = record["original"]
        original_runtime = record["runtime"]
    else:
        target = {
            name: {**(current[name] or {"mode": 0o644, "owner": [os.geteuid(), os.getegid()]}), "text": text}
            for name, text in desired.items()
        }
        original_runtime = None
        _save_backup(path, {
            "version": 1,
            "original": record["original"] if record else current,
            "runtime": record["runtime"] if record else runtime,
            "managed": target,
        })

    def apply(files: dict, values: dict | None) -> None:
        if feature == "ipv6-lockdown" and files[NFT_UNIT_CONF] is None and (ETC / NFT_UNIT_CONF).exists():
            _cmd("systemctl", "disable", "--now", NFT_UNIT)
        for name, data in files.items():
            _write(ETC / name, data)
        if restart_resolved:
            _cmd("systemctl", "restart", RESOLVED)
        _activate_files(feature, files, values)

    try:
        apply(target, original_runtime)
    except (Exception, KeyboardInterrupt) as exc:
        try:
            apply(current, runtime)
            if record is None:
                path.unlink()
            elif not restore:
                _save_backup(path, record)
        except Exception as rollback:
            raise NetworkError(f"操作失败: {exc}；回滚未完成: {rollback}；保留备份 {path}") from exc
        raise NetworkError(f"操作失败，已回滚: {exc}") from exc
    if restore:
        path.unlink()
        return "已恢复本工具修改前的配置。"
    return f"已应用；原始备份: {path}"


def _status() -> dict:
    def read(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def probe(action):
        try:
            return action()
        except (SystemErrorBase, TimeoutExpired, OSError):
            return None

    def backups():
        try:
            STATE.stat()
        except FileNotFoundError:
            return []
        if not os.access(STATE, os.X_OK):
            return None
        return pending_network_settings()

    resolv = ETC / "resolv.conf"
    table = probe(lambda: _nft_table() or "")
    return {
        "IPv4 地址优先级": re.findall(r"^\s*precedence[ \t]+::ffff:[^\s]+[ \t]+(\d+)", read(ETC / "gai.conf"), re.M),
        "系统 DNS（resolv.conf）": re.findall(r"^\s*nameserver[ \t]+([^\s#]+)", read(resolv), re.M),
        "systemd-resolved": probe(lambda: _cmd("resolvectl", "dns")),
        "IPv6 disable_ipv6": {str(Path(key).parent.name): read(PROC_SYS / key).strip() or None for key in _ipv6_keys()},
        "IPv6 入站收口": table,
        "BBR / fq": {key.rsplit("/", 1)[-1]: read(PROC_SYS / key).strip() or None for key in BBR_VALUES},
        "本工具备份": probe(backups),
    }


def network_command(feature: str, action: str = "", value: str = "") -> dict:
    if platform.system() != "Linux":
        raise NetworkError("系统网络优化只支持 Linux（目标环境：Debian + systemd）。")
    try:
        if feature == "status":
            return _status()
        if os.geteuid() != 0:
            raise NetworkError("修改系统网络设置需要 root，请使用 sudo。")
        with FileLock(resolve_lock_file()):
            restore = action == "restore" or (feature == "ipv4-prefer" and action == "disable")
            return {"结果": _change(feature, restore=restore, value=value)}
    except (OSError, TimeoutExpired, ValueError, TypeError, KeyError) as exc:
        raise NetworkError(f"系统网络操作失败: {exc}") from exc
