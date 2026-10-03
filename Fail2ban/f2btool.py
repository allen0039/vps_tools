#!/usr/bin/env python3
"""Fail2ban SSH configuration for the safe-ssh-port iptables firewall."""

import argparse
import ast
import contextlib
import copy
import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

VERSION = "0.1.0"
CONFIG_NAME = "99-vpstools-sshd.local"
MARKER = "# vpstools-fail2ban: "
CHAIN = "f2b-vpstools-sshd"
DEFAULTS = dict(enabled=True, ports=[22], bantime=360000, findtime=600,
                maxretry=5, scope="ssh", ignoreip=["127.0.0.1/8", "::1"])


class ToolError(Exception):
    pass


def run(args, check=True, timeout=45):
    try:
        result = subprocess.run([str(arg) for arg in args], text=True,
                                capture_output=True, timeout=timeout,
                                env=dict(os.environ, LC_ALL="C"))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"无法执行 {args[0]}：{exc}") from exc
    if check and result.returncode:
        raise ToolError(f"{shlex.join([str(arg) for arg in args])} 失败：\n"
                        f"{result.stdout.strip()}\n{result.stderr.strip()}")
    return result


def normalize_ip(value, network=True, allow_all=False):
    try:
        if "/" in value and network:
            result = ipaddress.ip_network(value, strict=False)
            if result.prefixlen == 0 and not allow_all:
                raise ToolError("白名单不能包含整个互联网：0.0.0.0/0 或 ::/0。")
        else:
            result = ipaddress.ip_address(value)
        return str(result)
    except ValueError as exc:
        raise ToolError(f"无效的 IP{'/CIDR' if network else ''}：{value}") from exc


def current_ip():
    value = (os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT", "")).split()
    if not value:
        return None
    try:
        return normalize_ip(value[0], network=False)
    except ToolError:
        return None


def validate(settings):
    if set(settings) != set(DEFAULTS) or type(settings["enabled"]) is not bool:
        raise ToolError("工具配置字段无效。")
    ports = settings["ports"]
    if (not isinstance(ports, list) or not ports or len(ports) > 15 or
            any(type(port) is not int or not 1 <= port <= 65535 for port in ports)):
        raise ToolError("SSH 端口必须为 1–65535，最多支持 15 个端口。")
    for key, minimum, maximum in (("bantime", 1, 31536000), ("findtime", 1, 604800),
                                  ("maxretry", 1, 1000)):
        if type(settings[key]) is not int or not minimum <= settings[key] <= maximum:
            raise ToolError(f"{key} 必须在 {minimum}–{maximum} 之间。")
    if settings["scope"] not in ("ssh", "all"):
        raise ToolError("封禁范围必须为 ssh 或 all。")
    entries = settings["ignoreip"]
    # 从已有配置继承的域名也保留；新增输入仅接受 IP/CIDR。
    if (not isinstance(entries, list) or len(entries) > 512 or
            any(not isinstance(ip, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]+", ip)
                for ip in entries)):
        raise ToolError("已有白名单含无法安全保留的格式，请检查原 Fail2ban 配置。")


def render(settings, include_ignore=True):
    validate(settings)
    ports = ",".join(str(port) for port in sorted(set(settings["ports"])))
    action = "iptables-multiport" if settings["scope"] == "ssh" else "iptables-allports"
    protocol = "tcp" if settings["scope"] == "ssh" else "all"
    lines = [MARKER + json.dumps(settings, ensure_ascii=True, sort_keys=True),
             "# Managed by f2btool; use the menu to change or restore this file.",
             "[sshd]", f"enabled = {str(settings['enabled']).lower()}",
             "filter = sshd[mode=normal]", "backend = systemd", f"port = {ports}",
             f"bantime = {settings['bantime']}", f"findtime = {settings['findtime']}",
             f"maxretry = {settings['maxretry']}", f"banaction = {action}",
             f'action = {action}[actname=vpstools-sshd, name=vpstools-sshd, port="%(port)s", protocol={protocol}, '
             'chain=INPUT, families="inet4 inet6", actionstart_on_demand=false]']
    if include_ignore:
        lines.append("ignoreip = " + " ".join(settings["ignoreip"]))
    return "\n".join(lines) + "\n"


def decode(text):
    try:
        first = text.splitlines()[0]
        if not first.startswith(MARKER):
            raise ValueError("missing marker")
        settings = json.loads(first[len(MARKER):])
        validate(settings)
        if render(settings) != text:
            raise ValueError("file edited")
        return settings
    except (ValueError, IndexError, TypeError, KeyError) as exc:
        raise ToolError("工具专属配置被手动修改或格式无效；请先保存改动再处理，拒绝覆盖。") from exc


def atomic_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ToolError(f"拒绝覆盖非普通文件：{path}")
    fd, temporary = tempfile.mkstemp(prefix=".f2btool-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class App:
    def __init__(self, config_dir=Path("/etc/fail2ban"), state_dir=Path("/var/lib/vpstools-fail2ban")):
        self.config_dir = config_dir
        self.state_dir = state_dir
        self.config = config_dir / "jail.d" / CONFIG_NAME

    def client(self, *args, check=True):
        return run(["fail2ban-client", "-c", self.config_dir, *args], check=check)

    @contextlib.contextmanager
    def lock(self):
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        path = self.state_dir / "lock"
        if path.is_symlink():
            raise ToolError(f"锁文件不能是符号链接：{path}")
        with path.open("a") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ToolError("另一个 Fail2ban 配置操作正在执行，请稍后重试。") from exc
            yield

    def load(self, required=False):
        if self.config.is_symlink():
            raise ToolError(f"工具配置不能是符号链接：{self.config}")
        if not self.config.exists():
            if required:
                raise ToolError("尚未由本工具配置 SSH 防护，请先选择安装与配置。")
            return None
        return decode(self.config.read_text())

    def preflight(self, packages=False):
        if not Path("/run/systemd/system").is_dir():
            raise ToolError("第一版需要 Debian/Ubuntu 的 systemd 环境。")
        release = Path("/etc/os-release").read_text()
        if not re.search(r'^ID=["\']?(debian|ubuntu)["\']?$', release, re.M):
            raise ToolError("第一版仅支持 Debian/Ubuntu。")
        if shutil.which("ufw") and run(["ufw", "status"], check=False).stdout.startswith("Status: active"):
            raise ToolError("UFW 已启用；本工具要求由 safe-ssh-port 管理 iptables，请先规划防火墙迁移。")
        if shutil.which("firewall-cmd") and run(["firewall-cmd", "--state"], check=False).returncode == 0:
            raise ToolError("firewalld 正在运行，本工具暂不支持混合管理。")
        if run(["systemctl", "is-active", "--quiet", "ssh.socket"], check=False).returncode == 0:
            raise ToolError("检测到 ssh.socket；第一版不能自动同步 socket 管理的 SSH 端口。")
        safe = shutil.which("safe-ssh-port") or "/usr/local/sbin/safe-ssh-port"
        if not Path(safe).is_file() or run([safe, "--fail2ban-integration-version"], check=False).stdout.strip() != "1":
            raise ToolError("请先安装/更新本仓库的 safe-ssh-port；旧版可能绕过封禁或持久化临时封禁。")
        if packages:
            missing = not shutil.which("fail2ban-client") or not shutil.which("iptables")
            journal = run(["/usr/bin/python3", "-c", "import systemd.journal"], check=False)
            if missing or journal.returncode:
                print("正在安装 fail2ban、python3-systemd 和 iptables……", flush=True)
                env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
                fresh = not shutil.which("fail2ban-client")
                masked = run(["systemctl", "is-enabled", "fail2ban.service"], check=False).stdout.strip()
                if masked in ("masked", "masked-runtime"):
                    raise ToolError("fail2ban.service 已被管理员 mask，请先检查服务设置。")
                # 新安装时先防止包管理器在白名单/日志后端配置前自动启动服务。
                if fresh:
                    run(["systemctl", "mask", "--runtime", "fail2ban.service"])
                try:
                    for args in (["apt-get", "update"], ["apt-get", "install", "-y", "fail2ban", "python3-systemd", "iptables"]):
                        if subprocess.run(args, env=env).returncode:
                            raise ToolError("软件包安装失败，请修复 apt 后重试。")
                finally:
                    if fresh:
                        run(["systemctl", "unmask", "--runtime", "fail2ban.service"])
                        run(["systemctl", "daemon-reload"])
                        if shutil.which("fail2ban-client"):
                            run(["systemctl", "disable", "fail2ban.service"])
        for command in ("fail2ban-client", "iptables", "ip6tables", "sshd", "journalctl"):
            if not shutil.which(command):
                raise ToolError(f"缺少 {command}；请先选择安装与配置。")
        run(["/usr/bin/python3", "-c", "import systemd.journal"])
        run(["iptables", "-w", "-S", "INPUT"])
        run(["ip6tables", "-w", "-S", "INPUT"])
        run(["sshd", "-t"])

    def ports(self):
        values = [int(line.split()[1]) for line in run(["sshd", "-T"]).stdout.splitlines()
                  if re.fullmatch(r"port [0-9]+", line)]
        if not values or any(not 1 <= port <= 65535 for port in values):
            raise ToolError("无法读取有效 SSH 端口。")
        return sorted(set(values))

    def inherited_ignoreip(self, settings):
        # 在副本里修正最小系统缺少 auth.log 的问题，再让 Fail2ban 自己解析继承关系。
        with tempfile.TemporaryDirectory(prefix="f2btool-config-") as directory:
            staged = Path(directory) / "config"
            shutil.copytree(self.config_dir, staged)
            atomic_write(staged / "jail.d" / CONFIG_NAME, render(settings, include_ignore=False))
            result = run(["fail2ban-client", "-c", staged, "-d"])
        entries = []
        for line in result.stdout.splitlines():
            try:
                command = ast.literal_eval(line)
            except (SyntaxError, ValueError):
                continue
            if isinstance(command, list) and command[:3] == ["set", "sshd", "addignoreip"]:
                entries.extend(command[3:])
        merged = list(dict.fromkeys([*entries, *settings["ignoreip"]]))
        check = dict(settings, ignoreip=merged)
        validate(check)
        return merged

    def snapshot(self, previous):
        root = self.state_dir / "backups"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        name = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
        backup = root / name
        backup.mkdir(mode=0o700)
        atomic_write(backup / "meta.json", json.dumps({"existed": previous is not None}) + "\n")
        if previous is not None:
            atomic_write(backup / "config.local", previous)
        return backup

    def verify_runtime(self, settings):
        result = self.client("status", "sshd", check=False)
        if not settings["enabled"]:
            if result.returncode == 0:
                raise ToolError("SSH jail 仍在运行，可能被后加载的配置覆盖。")
            return
        if result.returncode:
            raise ToolError("SSH jail 未成功启动：" + result.stdout + result.stderr)
        for key in ("bantime", "findtime", "maxretry"):
            if self.client("get", "sshd", key).stdout.strip() != str(settings[key]):
                raise ToolError(f"{key} 未按工具配置生效，可能被其他配置覆盖。")
        ignore = self.client("get", "sshd", "ignoreip").stdout
        effective_networks = []
        for token in re.findall(r"[0-9A-Fa-f:.]+(?:/[0-9]+)?", ignore):
            try:
                effective_networks.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                pass
        for entry in settings["ignoreip"]:
            try:
                expected_network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue  # 保留的域名可能由 Fail2ban 解析成地址。
            if expected_network not in effective_networks:
                raise ToolError(f"白名单 {entry} 未生效，可能被其他配置覆盖。")
        action = "vpstools-sshd"
        for key, expected in (("name", "vpstools-sshd"), ("chain", "INPUT"),
                              ("port", ",".join(map(str, settings["ports"]))),
                              ("protocol", "tcp" if settings["scope"] == "ssh" else "all")):
            if self.client("get", "sshd", "action", action, key).stdout.strip() != expected:
                raise ToolError(f"iptables 封禁动作的 {key} 未正确生效。")

    def verify_config(self, settings):
        self.client("-t")
        if settings is None:
            return
        commands = []
        for line in self.client("-d").stdout.splitlines():
            try:
                command = ast.literal_eval(line)
            except (SyntaxError, ValueError):
                continue
            if isinstance(command, list):
                commands.append(command)
        enabled = ["start", "sshd"] in commands
        if enabled != settings["enabled"]:
            raise ToolError("SSH jail 的启用状态被其他配置覆盖。")
        if enabled:
            actions = [cmd for cmd in commands if cmd[:3] == ["set", "sshd", "addaction"]]
            if ["add", "sshd", "systemd"] not in commands or actions != [["set", "sshd", "addaction", "vpstools-sshd"]]:
                raise ToolError("日志后端或封禁动作被其他配置覆盖。")

    def release_ignored(self, settings):
        networks = []
        for entry in settings["ignoreip"]:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass
        for token in re.findall(r"[0-9A-Fa-f:.]+", self.client("get", "sshd", "banip").stdout):
            try:
                ip = ipaddress.ip_address(token)
            except ValueError:
                continue
            if any(ip.version == network.version and ip in network for network in networks):
                self.client("set", "sshd", "unbanip", str(ip))

    def reload_sshd(self, enabled=True):
        if self.client("status", "sshd", check=False).returncode == 0:
            self.client("reload", "--restart", "sshd")
        elif enabled:
            # 单 jail restart 要求 jail 已存在。普通 reload 能新增 sshd，
            # 并保留其他未改变的 jail 的运行状态。
            self.client("reload")

    def wait_jail(self, settings):
        if not settings["enabled"]:
            return
        deadline = time.monotonic() + 12
        while self.client("status", "sshd", check=False).returncode:
            if time.monotonic() >= deadline:
                raise ToolError("服务已启动，但 SSH jail 在 12 秒内没有就绪。")
            time.sleep(0.25)

    def verify_firewall(self, settings):
        for command in ("iptables", "ip6tables"):
            lines = run([command, "-w", "-S", "INPUT"]).stdout.splitlines()
            found = False
            for line in lines:
                words = shlex.split(line)
                if "-j" not in words:
                    continue
                target = words[words.index("-j") + 1]
                if target == CHAIN:
                    found = True
                    if any(option in words for option in ("-s", "-d", "-i", "-o", "!")):
                        raise ToolError(f"{command} 的 Fail2ban 跳转含额外限制，无法保证封禁覆盖。")
                    protocol = words[words.index("-p") + 1] if "-p" in words else "all"
                    if settings["scope"] == "ssh":
                        if "--dports" not in words or protocol != "tcp":
                            raise ToolError(f"{command} 未正确限制 SSH TCP 端口。")
                        ports = set(words[words.index("--dports") + 1].split(","))
                        if ports != set(map(str, settings["ports"])):
                            raise ToolError(f"{command} 的 Fail2ban 端口与 SSH 不一致。")
                    elif protocol != "all":
                        raise ToolError(f"{command} 未应用全部协议封禁。")
                    break
                if target == "ACCEPT" or target.startswith("ALLENTOOL_"):
                    raise ToolError(f"{command} 中放行/管理链位于 Fail2ban 之前，封禁可能被绕过。")
            if not found:
                raise ToolError(f"{command} 没有建立 {CHAIN} 跳转，封禁动作尚未就绪。")
            chain = run([command, "-w", "-S", CHAIN]).stdout
            if "-j RETURN" not in chain:
                raise ToolError(f"{command} 的 Fail2ban 链缺少 RETURN，拒绝应用。")

    def wait_firewall(self, settings):
        deadline = time.monotonic() + 12
        while True:
            try:
                self.verify_firewall(settings)
                return
            except ToolError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)

    def refresh_persistence(self):
        if shutil.which("netfilter-persistent"):
            safe = shutil.which("safe-ssh-port") or "/usr/local/sbin/safe-ssh-port"
            run([safe, "firewall-save"])

    def apply(self, settings, activate=False):
        previous = self.config.read_text() if self.config.exists() else None
        if previous is not None:
            decode(previous)
        backup = self.snapshot(previous)
        was_active = run(["systemctl", "is-active", "--quiet", "fail2ban"], check=False).returncode == 0
        was_enabled = run(["systemctl", "is-enabled", "--quiet", "fail2ban"], check=False).returncode == 0
        service_touched = False
        try:
            if settings is None:
                self.config.unlink(missing_ok=True)
            else:
                atomic_write(self.config, render(settings))
            self.verify_config(settings)
            if was_active:
                service_touched = True
                self.reload_sshd(settings is None or settings["enabled"])
            elif activate and settings and settings["enabled"]:
                service_touched = True
                run(["systemctl", "start", "fail2ban"])
            if service_touched and settings:
                self.wait_jail(settings)
                self.verify_runtime(settings)
                if settings["enabled"]:
                    self.wait_firewall(settings)
                    self.release_ignored(settings)
            if activate and settings and settings["enabled"]:
                run(["systemctl", "enable", "fail2ban"])
            self.refresh_persistence()
        except (ToolError, OSError, KeyboardInterrupt) as exc:
            if previous is None:
                self.config.unlink(missing_ok=True)
            else:
                atomic_write(self.config, previous)
            rollback_errors = []
            if service_touched:
                try:
                    if was_active:
                        self.reload_sshd(previous is None or decode(previous)["enabled"])
                    else:
                        run(["systemctl", "stop", "fail2ban"])
                except ToolError as error:
                    rollback_errors.append(str(error))
            if not was_enabled:
                try:
                    run(["systemctl", "disable", "fail2ban"])
                except ToolError as error:
                    rollback_errors.append(str(error))
            message = f"应用失败，已恢复配置文件。备份：{backup}\n{exc}"
            if rollback_errors:
                message += "\n服务恢复未完成：\n" + "\n".join(rollback_errors)
            raise ToolError(message) from exc
        print(f"配置已保存{'并验证 SSH jail' if service_touched and settings else ''}。备份：{backup}")

    def configure(self, args=None):
        with self.lock():
            self.preflight(packages=True)
            existing = self.load()
            settings = copy.deepcopy(existing or DEFAULTS)
            settings["ports"] = self.ports()
            settings["enabled"] = True
            if existing is None:
                settings["ignoreip"] = self.inherited_ignoreip(settings)
            source = current_ip()
            if source and (not args or not args.no_current_ip):
                settings["ignoreip"] = list(dict.fromkeys([*settings["ignoreip"], source]))
            if args:
                for key in ("bantime", "findtime", "maxretry", "scope"):
                    if getattr(args, key) is not None:
                        settings[key] = getattr(args, key)
                for ip in args.ignore_ip:
                    settings["ignoreip"].append(normalize_ip(ip))
                validate(settings)
            else:
                print("读取当前 SSH 端口：" + ",".join(map(str, settings["ports"])))
                print("默认值来自文章：10 分钟内失败 5 次，封禁 100 小时。")
                settings["bantime"] = ask_number("封禁秒数（3600=1小时，86400=1天，360000=100小时）", settings["bantime"], 1, 31536000)
                settings["findtime"] = ask_number("检测窗口秒数", settings["findtime"], 1, 604800)
                settings["maxretry"] = ask_number("窗口内达到多少次失败触发封禁", settings["maxretry"], 1, 1000)
                scope = input(f"封禁范围：1. SSH端口  2. 全部端口 [{'1' if settings['scope'] == 'ssh' else '2'}]：").strip()
                if scope not in ("", "1", "2"):
                    raise ToolError("范围选项无效，已取消。")
                if scope:
                    settings["scope"] = "ssh" if scope == "1" else "all"
                extra = input("额外管理 IP/CIDR（多个用空格分隔，回车跳过）：").split()
                settings["ignoreip"] = list(dict.fromkeys([*settings["ignoreip"], *(normalize_ip(value) for value in extra)]))
            show_settings(settings)
            print("当前 SSH 来源 IP：" + (source or "未检测到，请在白名单菜单添加管理 IP"))
            if args and args.yes or confirm("应用以上配置并启用 SSH 防护？"):
                self.apply(settings, activate=True)
            else:
                print("已取消配置。")

    def update(self, transform, activate=False):
        with self.lock():
            self.preflight()
            settings = self.load(required=True)
            transform(settings)
            validate(settings)
            self.apply(settings, activate=activate)

    def sync_ports(self):
        with self.lock():
            settings = self.load()
            if settings is None:
                print("尚无本工具管理的配置，无需同步。")
                return
            self.preflight()
            ports = self.ports()
            if ports == settings["ports"]:
                print("Fail2ban SSH 端口已同步。")
                return
            settings["ports"] = ports
            self.apply(settings)

    def whitelist(self, action, value=None):
        if action == "list":
            print("\n".join(self.load(required=True)["ignoreip"]))
            return
        value = normalize_ip(value, allow_all=action == "remove")
        if action == "remove" and value in ("127.0.0.0/8", "::1", "::1/128"):
            raise ToolError("保留回环地址白名单。")
        source = current_ip()
        if action == "remove" and source:
            network = ipaddress.ip_network(value, strict=False)
            ip = ipaddress.ip_address(source)
            if ip.version == network.version and ip in network and not confirm("正在移除包含当前管理 IP 的白名单，继续？"):
                return
        def transform(settings):
            if action == "add":
                settings["ignoreip"] = list(dict.fromkeys([*settings["ignoreip"], value]))
            else:
                wanted = ipaddress.ip_network(value, strict=False)
                matches = []
                for entry in settings["ignoreip"]:
                    try:
                        if ipaddress.ip_network(entry, strict=False) == wanted:
                            matches.append(entry)
                    except ValueError:
                        pass
                if not matches:
                    raise ToolError("该 IP/CIDR 不在本工具白名单中。")
                settings["ignoreip"] = [entry for entry in settings["ignoreip"] if entry not in matches]
        self.update(transform)

    def unban(self, ip):
        ip = normalize_ip(ip, network=False)
        with self.lock():
            self.load(required=True)
            self.client("set", "sshd", "unbanip", ip)
        print(f"已请求从 SSH jail 解封 {ip}；防火墙自身的 IP/国家黑名单仍需单独管理。")

    def backups(self):
        root = self.state_dir / "backups"
        return sorted((path for path in root.iterdir() if path.is_dir() and not path.is_symlink()), reverse=True) if root.exists() else []

    def restore(self, name):
        if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", name):
            raise ToolError("备份名称无效。")
        with self.lock():
            self.preflight()
            self.load(required=True)
            backup = self.state_dir / "backups" / name
            if backup.is_symlink() or any(path.is_symlink() for path in (backup / "meta.json", backup / "config.local")):
                raise ToolError("备份不能是符号链接。")
            meta = json.loads((backup / "meta.json").read_text())
            if type(meta.get("existed")) is not bool:
                raise ToolError("备份元数据无效。")
            settings = decode((backup / "config.local").read_text()) if meta["existed"] else None
            if settings:
                settings["ports"] = self.ports()
            self.apply(settings)
            print("已恢复工具配置；SSH 端口使用当前 sshd 配置。")

    def status(self):
        settings = self.load()
        if settings:
            show_settings(settings)
            try:
                if self.ports() != settings["ports"]:
                    print("警告：SSH 端口与 Fail2ban 配置不同，请执行 sudo f2btool sync-ports。")
            except ToolError as exc:
                print(exc)
        else:
            print("尚未由本工具配置 SSH 防护。")
        if shutil.which("fail2ban-client"):
            print(self.client("status", "sshd", check=False).stdout.strip())
        else:
            print("Fail2ban 尚未安装。")
        for command in ("iptables", "ip6tables"):
            if not shutil.which(command):
                continue
            rules = run([command, "-w", "-S", "INPUT"], check=False)
            before = []
            found = False
            for line in rules.stdout.splitlines():
                words = shlex.split(line)
                if "-j" not in words:
                    continue
                target = words[words.index("-j") + 1]
                if target == CHAIN:
                    found = True
                    print(f"{command}：发现 Fail2ban 跳转" + ("，但前面有放行/管理链，请检查顺序" if before else "，位于放行规则之前"))
                    break
                if target == "ACCEPT" or target.startswith("ALLENTOOL_"):
                    before.append(line)
            if not found:
                print(f"{command}：尚无 {CHAIN} 跳转；请结合 jail 状态和日志检查，不能仅凭服务 active 判断封禁有效。")

    def diagnose(self):
        self.status()
        if shutil.which("fail2ban-client"):
            result = self.client("-t", check=False)
            print(result.stdout + result.stderr)
        for units in (("fail2ban",), ("ssh", "sshd")):
            args = ["journalctl", "--no-pager", "-n", "25"]
            for unit in units:
                args.extend(["-u", unit])
            print(run(args, check=False).stdout)

    def menu(self):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ToolError("菜单需要交互终端；可使用 f2btool --help 查看命令模式。")
        while True:
            print(f"\nFail2ban SSH 防护 v{VERSION}（iptables）")
            print("  1. 安装 / 配置 SSH 防护\n  2. 查看状态与封禁列表\n  3. 解封 IP\n"
                  "  4. 管理白名单\n  5. 启用 SSH 防护\n  6. 停用 SSH 防护\n"
                  "  7. 同步 SSH 端口\n  8. 恢复工具配置备份\n  9. 配置校验与日志诊断\n  0. 返回")
            choice = input("请选择：").strip()
            try:
                if choice == "0":
                    return
                if choice == "1":
                    self.configure()
                elif choice == "2":
                    self.status()
                elif choice == "3":
                    self.unban(input("待解封的 IPv4/IPv6：").strip())
                elif choice == "4":
                    self.whitelist("list")
                    action = input("1. 添加  2. 移除  0. 返回：").strip()
                    if action in ("1", "2"):
                        self.whitelist("add" if action == "1" else "remove", input("IP/CIDR：").strip())
                elif choice in ("5", "6"):
                    enabled = choice == "5"
                    if confirm("启用 SSH 防护？" if enabled else "停用 SSH jail（不会停止其他 jail）？"):
                        self.update(lambda settings: settings.update(enabled=enabled, ports=self.ports()), activate=enabled)
                elif choice == "7":
                    self.sync_ports()
                elif choice == "8":
                    backups = self.backups()
                    for index, backup in enumerate(backups, 1):
                        print(f"  {index}. {backup.name}")
                    value = input("选择备份序号（回车取消）：").strip()
                    if value.isdigit() and 1 <= int(value) <= len(backups) and confirm("恢复该备份？"):
                        self.restore(backups[int(value) - 1].name)
                elif choice == "9":
                    self.diagnose()
                else:
                    print("选项无效。")
            except (ToolError, OSError, ValueError) as exc:
                print(f"[f2btool] 错误：{exc}", file=sys.stderr)


def show_settings(settings):
    print(f"SSH 防护：{'启用' if settings['enabled'] else '停用'}；端口：{','.join(map(str, settings['ports']))}")
    print(f"{settings['findtime']} 秒内失败 {settings['maxretry']} 次，封禁 {settings['bantime']} 秒；"
          f"范围：{'SSH TCP端口' if settings['scope'] == 'ssh' else '来源IP全部端口'}")
    print("白名单：" + " ".join(settings["ignoreip"]))


def ask_number(label, default, minimum, maximum):
    while True:
        value = input(f"{label} [{default}]：").strip()
        if not value:
            return default
        if value.isdecimal() and minimum <= int(value) <= maximum:
            return int(value)
        print(f"请输入 {minimum}–{maximum} 之间的整数。")


def confirm(question):
    if not sys.stdin.isatty():
        raise ToolError("此操作需要交互确认；自动配置可显式使用 configure --yes。")
    return input(question + " [y/N] ").strip().lower() == "y"


def main(argv=None):
    parser = argparse.ArgumentParser(description="与 safe-ssh-port 配合的 Fail2ban iptables SSH 防护工具")
    parser.add_argument("--version", action="version", version=f"f2btool {VERSION}")
    sub = parser.add_subparsers(dest="command")
    for command in ("menu", "status", "diagnose", "sync-ports", "backups", "enable", "disable"):
        sub.add_parser(command)
    configure = sub.add_parser("configure", help="安装所需软件包、配置并启用 SSH jail")
    for key in ("bantime", "findtime", "maxretry"):
        configure.add_argument("--" + key, type=int)
    configure.add_argument("--scope", choices=("ssh", "all"))
    configure.add_argument("--ignore-ip", action="append", default=[])
    configure.add_argument("--no-current-ip", action="store_true", help="不自动加入当前 SSH 来源 IP")
    configure.add_argument("--yes", action="store_true", help="接受配置并安装缺失的软件包")
    sub.add_parser("unban").add_argument("ip")
    whitelist = sub.add_parser("whitelist")
    whitelist.add_argument("action", choices=("list", "add", "remove"))
    whitelist.add_argument("ip", nargs="?")
    sub.add_parser("restore").add_argument("backup")
    args = parser.parse_args(argv)
    command = args.command or "menu"
    if sys.platform != "linux":
        raise ToolError("请在 Linux VPS 上运行；帮助和版本查询可在其他系统使用。")
    if os.geteuid() != 0:
        if sys.stdin.isatty() and shutil.which("sudo"):
            os.execvp("sudo", ["sudo", "--preserve-env=SSH_CONNECTION,SSH_CLIENT", "--",
                               sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
        raise ToolError("请使用 sudo f2btool 或以 root 运行。")
    app = App()
    if command == "configure":
        if not args.yes and not sys.stdin.isatty():
            raise ToolError("非交互配置需要 --yes。")
        app.configure(args)
    elif command in ("enable", "disable"):
        enabled = command == "enable"
        app.update(lambda settings: settings.update(enabled=enabled, ports=app.ports()), activate=enabled)
    elif command == "whitelist":
        if args.action != "list" and args.ip is None:
            parser.error("添加或移除白名单需要 IP/CIDR")
        app.whitelist(args.action, args.ip)
    elif command == "unban":
        app.unban(args.ip)
    elif command == "restore":
        app.restore(args.backup)
    elif command == "backups":
        print("\n".join(path.name for path in app.backups()))
    else:
        getattr(app, command.replace("-", "_"))()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ToolError, OSError, ValueError) as error:
        print(f"[f2btool] 错误：{error}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\n已取消。", file=sys.stderr)
        sys.exit(130)
