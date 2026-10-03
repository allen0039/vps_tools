#!/usr/bin/env python3
"""Linux IPv6 管理：地址选择优先级、临时禁用、GRUB 内核禁用。"""

import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid

TOOL_ID = "vps-tools-ipv6tool"
VERSION = "0.1.0"
MARKER = "# Managed by ipv6tool; restore with ipv6tool enable"
BOOT_CONTENT = (MARKER + '\nGRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX:+$GRUB_CMDLINE_LINUX }ipv6.disable=1"\n').encode()
DEFAULT_PRECEDENCE = {"::1/128": 50, "::/0": 40, "2002::/16": 30,
                      "::/96": 20, "::ffff:0:0/96": 10}


class ToolError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pack(data):
    return base64.b64encode(data).decode("ascii")


def unpack(data):
    try:
        return base64.b64decode(data, validate=True)
    except (ValueError, TypeError) as exc:
        raise ToolError("备份编码无效。") from exc


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def atomic_write(path, data, mode=0o600, owner=None):
    """同一文件系统中替换，拒绝跟随符号链接；写入和目录均 fsync。"""
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ToolError("拒绝修改非普通文件：" + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".ipv6tool-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            if owner is not None and owner != (os.geteuid(), os.getegid()):
                os.fchown(stream.fileno(), *owner)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync_dir(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def file_snapshot(path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ToolError("拒绝修改非普通文件：" + str(path))
    if not path.exists():
        return {"exists": False}
    stat = path.stat()
    data = path.read_bytes()
    return {"exists": True, "data": pack(data), "sha256": digest(data),
            "mode": stat.st_mode & 0o777, "uid": stat.st_uid, "gid": stat.st_gid}


def restore_file(path, snapshot):
    # 先验证文件类型，即使恢复目标是“原来不存在”也不删除符号链接。
    file_snapshot(path)
    if snapshot["exists"]:
        data = unpack(snapshot["data"])
        if digest(data) != snapshot["sha256"]:
            raise ToolError("备份文件校验失败。")
        atomic_write(path, data, snapshot["mode"], (snapshot["uid"], snapshot["gid"]))
    elif path.exists():
        path.unlink()
        sync_dir(path.parent)


def run_command(args, data=None, binary=False):
    process = None
    try:
        process = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=not binary, start_new_session=True,
                                   env=dict(os.environ, LC_ALL="C"))
        try:
            stdout, stderr = process.communicate(input=data, timeout=60)
        except BaseException:
            # GRUB 子进程必须先停下，随后才能回滚，避免并发写入引导配置。
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError("命令执行失败：" + shlex.join(args) + "：" + str(exc)) from exc
    if process.returncode:
        error = stderr.decode(errors="replace") if binary else stderr
        raise ToolError("命令失败：" + shlex.join(args) + "\n" + error.strip())
    return stdout


def priority_config(original, mode):
    text = original.decode("utf-8")
    if "# BEGIN ipv6tool" in text or "# END ipv6tool" in text:
        raise ToolError("发现未登记的 ipv6tool 配置，请先找回对应备份。")
    table = dict(DEFAULT_PRECEDENCE)
    lines = []
    for line in text.splitlines(keepends=True):
        tokens = line.split("#", 1)[0].split()
        if tokens and tokens[0] == "precedence":
            if len(tokens) != 3:
                raise ToolError("已有 precedence 配置格式无效，请先检查 /etc/gai.conf。")
            try:
                network = ipaddress.IPv6Network(tokens[1], strict=False)
                value = int(tokens[2])
            except ValueError as exc:
                raise ToolError("已有 precedence 地址或数值无效。") from exc
            if not 0 <= value <= 2147483647:
                raise ToolError("已有 precedence 数值超出范围。")
            table[str(network)] = value
            line = "# ipv6tool saved: " + line
        lines.append(line)
    # 保留用户的其他前缀策略；回环默认值保持不变。
    table["::/0"] = 40
    table["::ffff:0:0/96"] = 100 if mode == "ipv4" else 10
    result = "".join(lines)
    if result and not result.endswith("\n"):
        result += "\n"
    result += "# BEGIN ipv6tool\n# glibc 地址选择策略：" + mode + " 优先\n"
    result += "".join("precedence %s %d\n" % item for item in table.items())
    result += "# END ipv6tool\n"
    return result.encode()


class Manager:
    def __init__(self, root=Path("/"), runner=run_command):
        self.root = Path(root)
        self.run = runner
        self.state_dir = self.path("var/lib/ipv6tool")
        self.state_file = self.state_dir / "state.json"
        self.gai = self.path("etc/gai.conf")
        self.boot_file = self.path("etc/default/grub.d/99-ipv6tool.cfg")
        self.grub_cfg = self.path("boot/grub/grub.cfg")
        self.ipv6_conf = self.path("proc/sys/net/ipv6/conf")

    def path(self, name):
        return self.root / name

    @contextlib.contextmanager
    def locked(self):
        if self.state_dir.is_symlink():
            raise ToolError("状态目录不能是符号链接。")
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_dir.chmod(0o700)
        lock = self.state_dir / "operation.lock"
        fd = os.open(str(lock), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ToolError("另一个 IPv6 配置操作正在运行。") from exc
            yield
        finally:
            os.close(fd)

    def state(self):
        if not self.state_file.exists():
            return {}
        if self.state_file.is_symlink():
            raise ToolError("状态文件不能是符号链接。")
        try:
            value = json.loads(self.state_file.read_text())
        except (ValueError, OSError) as exc:
            raise ToolError("状态文件无法读取；保留现场，未修改系统。") from exc
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise ToolError("状态文件格式不受支持。")
        for key in ("priority", "temporary", "complete"):
            if key in value and not isinstance(value[key], dict):
                raise ToolError("状态文件格式不受支持。")
        return value

    def save_state(self, state):
        atomic_write(self.state_file, canonical(dict(state, schema=1)))

    def backup(self, kind, payload):
        directory = self.state_dir / "backups"
        if directory.is_symlink():
            raise ToolError("备份目录不能是符号链接。")
        directory.mkdir(mode=0o700, exist_ok=True)
        name = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name += "-" + uuid.uuid4().hex + ".json"
        record = {"tool": TOOL_ID, "schema": 1, "kind": kind, "payload": payload}
        envelope = {"record": record, "sha256": digest(canonical(record))}
        atomic_write(directory / name, canonical(envelope))
        if self.read_backup(name, kind) != payload:
            raise ToolError("备份写入验证失败，停止配置。")
        return name

    def read_backup(self, name, kind):
        if not isinstance(name, str) or not re.fullmatch(r"[0-9TZ]+-[0-9a-f]{32}\.json", name):
            raise ToolError("备份名称无效。")
        path = self.state_dir / "backups" / name
        if path.is_symlink() or not path.is_file():
            raise ToolError("恢复所需备份缺失或不是普通文件。")
        try:
            envelope = json.loads(path.read_text())
            record = envelope["record"]
            if (digest(canonical(record)) != envelope["sha256"] or
                    record["tool"] != TOOL_ID or record["schema"] != 1 or record["kind"] != kind):
                raise ValueError("checksum/schema")
            return record["payload"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ToolError("备份完整性校验失败；未执行恢复。") from exc

    def check_gai_owned(self, state):
        entry = state.get("priority")
        if entry:
            saved = self.read_backup(entry["backup"], "priority")
            current = file_snapshot(self.gai)
            original = saved["gai"]
            is_original = current == original
            is_applied = current["exists"] and current["sha256"] == entry["applied"]
            is_previous = current == entry.get("previous")
            if not is_applied and not (entry.get("phase") in ("preparing", "restoring") and (is_original or is_previous)):
                raise ToolError("gai.conf 在应用后被其他程序修改；拒绝覆盖，请人工合并备份。")
            return original
        return file_snapshot(self.gai)

    def priority(self, mode):
        state = self.state()
        original = self.check_gai_owned(state)
        if mode == "restore":
            if "priority" not in state:
                return "没有本工具修改的优先级配置。"
            previous = file_snapshot(self.gai)
            before = dict(state["priority"])
            state["priority"]["phase"] = "restoring"
            self.save_state(state)
            try:
                restore_file(self.gai, original)
                del state["priority"]
                self.save_state(state)
            except BaseException:
                restore_file(self.gai, previous)
                state["priority"] = before
                self.save_state(state)
                raise
            return "已恢复设置优先级前的原始配置。长期运行的应用可能需要重启。"
        source = unpack(original["data"]) if original["exists"] else b""
        desired = priority_config(source, mode)
        previous = file_snapshot(self.gai)
        backup = self.backup("priority", {"gai": original})
        old_state = dict(state)
        # 第一次原始备份始终保留，切换不会覆盖为“已修改”状态。
        state["priority"] = {"backup": state.get("priority", {}).get("backup", backup),
                             "mode": mode, "applied": digest(desired), "phase": "preparing",
                             "previous": previous}
        self.save_state(state)
        try:
            atomic_write(self.gai, desired, previous.get("mode", 0o644),
                         (previous["uid"], previous["gid"]) if previous["exists"] else None)
            if self.gai.read_bytes() != desired:
                raise ToolError("优先级写入验证失败。")
            state["priority"]["phase"] = "applied"
            del state["priority"]["previous"]
            self.save_state(state)
        except BaseException:
            restore_file(self.gai, previous)
            self.save_state(old_state)
            raise
        return ("已设置 %s 优先；不改变协议启用状态。长期运行的应用可能需要重启。\n原始备份：%s" %
                ("IPv4" if mode == "ipv4" else "IPv6", self.state_dir / "backups" / state["priority"]["backup"]))

    def boot_id(self):
        return self.path("proc/sys/kernel/random/boot_id").read_text().strip()

    def kernel_disabled(self):
        return "ipv6.disable=1" in self.path("proc/cmdline").read_text().split()

    def flags(self):
        if not self.ipv6_conf.is_dir():
            raise ToolError("内核未提供 IPv6 接口开关；可能已从内核禁用 IPv6。")
        result = {}
        for path in sorted(self.ipv6_conf.glob("*/disable_ipv6")):
            value = path.read_text().strip()
            if value not in ("0", "1"):
                raise ToolError("IPv6 接口开关值无效：" + str(path))
            result[path.parent.name] = value
        if "all" not in result or "default" not in result:
            raise ToolError("IPv6 接口开关不完整。")
        return result

    def write_flag(self, name, value):
        if name not in self.flags() or value not in ("0", "1"):
            raise ToolError("接口已消失或开关值无效：" + name)
        (self.ipv6_conf / name / "disable_ipv6").write_text(value + "\n")

    def apply_flags(self, saved):
        current = self.flags()
        # all 写入会影响全部接口，所以必须先写，然后恢复每个接口的原值。
        self.write_flag("all", saved["all"])
        self.write_flag("default", saved["default"])
        for name in current:
            if name not in ("all", "default"):
                self.write_flag(name, saved.get(name, saved["default"]))

    def interface_indices(self):
        interfaces = json.loads(self.run(["ip", "-j", "link", "show"]))
        return {item["ifname"]: item["ifindex"] for item in interfaces}

    def runtime_snapshot(self):
        return {"flags": self.flags(), "boot_id": self.boot_id(),
                "indices": self.interface_indices(),
                "addresses": pack(self.run(["ip", "-6", "address", "save"], binary=True)),
                "routes": pack(self.run(["ip", "-6", "route", "save", "table", "all"], binary=True))}

    def restore_runtime(self, saved):
        if saved["boot_id"] != self.boot_id():
            raise ToolError("备份属于另一次启动；不能向当前系统重放旧地址和路由。")
        current = self.interface_indices()
        if any(current.get(name) != index for name, index in saved["indices"].items()):
            raise ToolError("接口已删除或重新创建；拒绝按旧索引恢复地址和路由，请人工恢复。")
        self.apply_flags(saved["flags"])
        self.run(["ip", "-6", "address", "restore"], data=unpack(saved["addresses"]), binary=True)
        self.run(["ip", "-6", "route", "restore"], data=unpack(saved["routes"]), binary=True)
        actual = self.flags()
        if any(actual.get(name) != value for name, value in saved["flags"].items()
               if name != "all"):
            raise ToolError("恢复后接口开关不匹配，保留备份供重试。")

    def temporary(self):
        state = self.state()
        if self.kernel_disabled() or "complete" in state:
            raise ToolError("已配置或已从内核关闭 IPv6；请先执行 enable 并按提示重启。")
        if "temporary" in state:
            saved = self.read_backup(state["temporary"]["backup"], "temporary")
            if saved["boot_id"] == self.boot_id():
                if any(value != "1" for name, value in self.flags().items() if name != "all"):
                    raise ToolError("临时禁用后有接口被其他程序重新启用；请先恢复，再重新禁用。")
                return "IPv6 已临时禁用；原始备份保留。"
            del state["temporary"]
            self.save_state(state)
        saved = self.runtime_snapshot()
        backup = self.backup("temporary", saved)
        # 在改变接口之前登记恢复点，异常退出后仍可 enable。
        state["temporary"] = {"backup": backup}
        self.save_state(state)
        try:
            self.apply_flags(dict.fromkeys(saved["flags"], "1"))
            if any(value != "1" for name, value in self.flags().items() if name != "all"):
                raise ToolError("接口 IPv6 未全部关闭。")
        except BaseException as exc:
            try:
                self.restore_runtime(saved)
                del state["temporary"]
                self.save_state(state)
            except BaseException as rollback:
                raise ToolError("临时禁用失败，自动恢复也失败；备份保留，请执行 enable。\n%s\n%s" % (exc, rollback)) from exc
            raise
        return "IPv6 已临时禁用，包括 ::1；没有写入启动配置。\n运行 ipv6tool enable 恢复；重启后临时禁用结束。"

    def check_boot_backend(self):
        release = self.path("etc/os-release").read_text()
        ids = re.findall(r'^ID=[\"\']?([a-z0-9_-]+)', release, re.M)
        if not ids or ids[0] not in ("debian", "ubuntu"):
            raise ToolError("彻底关闭目前仅支持 Debian/Ubuntu 的标准 GRUB 启动环境。")
        if not self.path("etc/default/grub").is_file() or not self.grub_cfg.is_file():
            raise ToolError("没有找到标准 GRUB 配置；拒绝修改未知启动方式。")
        if self.path("boot/loader/entries").exists():
            raise ToolError("检测到其他启动项配置；请先确认实际启动方式，未修改配置。")
        generator = shutil.which("grub-mkconfig")
        if not generator or not shutil.which("update-grub"):
            raise ToolError("需要 grub-mkconfig 和 update-grub；不会自动安装或切换引导器。")
        if "/etc/default/grub.d/" not in Path(generator).read_text(errors="replace"):
            raise ToolError("当前 GRUB 生成器不支持配置片段，拒绝修改。")
        if shutil.which("bootctl"):
            try:
                status = self.run(["bootctl", "status", "--no-pager"])
            except ToolError:
                status = ""
            section = status.split("Current Boot Loader:", 1)
            if len(section) == 2 and "systemd-boot" in section[1].split("Available Boot Loaders", 1)[0]:
                raise ToolError("当前使用 systemd-boot；不能通过 GRUB 配置彻底关闭。")

    def boot_sources(self):
        files = [self.path("etc/default/grub"), self.grub_cfg, self.boot_file]
        directory = self.boot_file.parent
        if directory.is_symlink():
            raise ToolError("GRUB 配置片段目录不能是符号链接。")
        if directory.exists():
            files.extend(sorted(directory.glob("*.cfg")))
        return {str(path.relative_to(self.root)): file_snapshot(path) for path in files}

    def generated_has(self, disabled):
        lines = []
        for line in self.grub_cfg.read_text().splitlines():
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            if tokens and tokens[0] in ("linux", "linuxefi", "linux16") and any("vmlinuz" in token for token in tokens[1:2]):
                lines.append(tokens)
        if not lines or any(("ipv6.disable=1" in line) != disabled for line in lines):
            raise ToolError("生成的 GRUB 内核启动项与目标不一致，未确认配置成功。")

    def regenerate(self, disabled):
        self.run(["update-grub"])
        self.generated_has(disabled)

    def complete(self):
        state = self.state()
        if "complete" in state:
            self.read_backup(state["complete"]["backup"], "complete")
            self.check_boot_owned()
            self.generated_has(True)
            if state["complete"].get("phase") != "disabled":
                raise ToolError("上次彻底关闭操作未完成；请先执行 enable 恢复。")
            return "彻底关闭已配置，关闭前的备份保留。" + ("当前内核已禁用 IPv6。" if self.kernel_disabled() else "重启后生效。")
        if "temporary" in state:
            raise ToolError("请先恢复临时禁用，再配置彻底关闭，以便保存启用状态的备份。")
        self.check_boot_backend()
        if self.kernel_disabled():
            raise ToolError("IPv6 已被其他配置从内核禁用；不能建立可重新开启的原始备份。")
        original = file_snapshot(self.boot_file)
        if original["exists"]:
            raise ToolError("发现未登记的 99-ipv6tool.cfg；拒绝覆盖，请找回其备份。")
        # 不替换其他人的 ipv6.disable 参数；恢复时不能替用户移除原有禁用。
        self.generated_has(False)
        sources = self.boot_sources()
        if any(re.search(rb"\bipv6\.disable\s*=", unpack(item["data"]))
               for item in sources.values() if item["exists"]):
            raise ToolError("原启动配置已有 ipv6.disable 参数；请先人工处理，未修改配置。")
        payload = {"boot_file": original, "sources": sources, "boot_id": self.boot_id()}
        backup = self.backup("complete", payload)
        state["complete"] = {"backup": backup, "phase": "preparing"}
        self.save_state(state)
        try:
            atomic_write(self.boot_file, BOOT_CONTENT, 0o644)
            self.regenerate(True)
            state["complete"]["phase"] = "disabled"
            self.save_state(state)
        except BaseException as exc:
            try:
                restore_file(self.boot_file, original)
                self.regenerate(False)
                del state["complete"]
                self.save_state(state)
            except BaseException as rollback:
                raise ToolError("配置失败且自动恢复失败，备份保留；请执行 enable 并检查 GRUB。\n%s\n%s" % (exc, rollback)) from exc
            raise
        return "IPv6 内核禁用已配置，重启后生效（包括 ::1 和 IPv6 socket）。不会自动重启。\n关闭前备份：" + str(self.state_dir / "backups" / backup)

    def check_boot_owned(self, allow_absent=False):
        current = file_snapshot(self.boot_file)
        if not current["exists"] and allow_absent:
            return
        if not current["exists"] or unpack(current["data"]) != BOOT_CONTENT:
            raise ToolError("GRUB 工具片段已被外部修改；拒绝覆盖，请人工合并备份。")

    def enable(self):
        state = self.state()
        if "complete" in state:
            entry = state["complete"]
            saved = self.read_backup(entry["backup"], "complete")
            self.check_boot_backend()
            self.check_boot_owned(allow_absent=entry.get("phase") in ("preparing", "restoring"))
            # 先记录恢复中的状态；update-grub 失败后仍能重试恢复。
            entry["phase"] = "restoring"
            self.save_state(state)
            restore_file(self.boot_file, saved["boot_file"])
            self.regenerate(False)
            del state["complete"]
            self.save_state(state)
            if self.kernel_disabled():
                return "关闭前的启动配置已恢复；重启后重新启用 IPv6。不会自动重启。"
            return "关闭前的启动配置已恢复；当前内核没有 ipv6.disable=1。"
        if "temporary" in state:
            saved = self.read_backup(state["temporary"]["backup"], "temporary")
            if saved["boot_id"] != self.boot_id():
                del state["temporary"]
                self.save_state(state)
                return "已跨重启，临时禁用已结束；没有向当前系统重放旧地址和路由。"
            self.restore_runtime(saved)
            del state["temporary"]
            self.save_state(state)
            return "已恢复临时禁用前的接口开关、地址和路由；动态地址可能需要重新获取。"
        if self.kernel_disabled():
            raise ToolError("内核禁用不是由本工具配置，缺少可恢复备份；请检查原引导配置。")
        return "没有本工具管理的禁用配置；未覆盖其他工具的 IPv6 设置。"

    def status(self):
        state = self.state()
        priority = state.get("priority")
        description = "原系统策略（未由本工具管理）"
        if priority:
            description = ("IPv4" if priority["mode"] == "ipv4" else "IPv6") + " 优先"
            if priority.get("phase") != "applied":
                description += "（操作未完成，可恢复原优先级）"
            if not self.gai.exists() or digest(self.gai.read_bytes()) != priority["applied"]:
                description += "（配置被外部修改）"
        lines = ["IPv6 管理工具 v" + VERSION, "系统地址选择策略：" + description]
        lines.append("当前内核：" + ("IPv6 已从内核禁用" if self.kernel_disabled() else "没有 ipv6.disable=1 参数"))
        if "complete" in state:
            phase = state["complete"].get("phase")
            lines.append("彻底关闭配置：" + ("已配置" if phase == "disabled" else "操作未完成，请恢复并检查") + "；恢复备份：" + state["complete"]["backup"])
        else:
            lines.append("彻底关闭配置：未由本工具配置")
        if self.ipv6_conf.is_dir():
            flags = self.flags()
            lines.append("接口 IPv6：" + "，".join("%s=%s" % (name, "禁用" if value == "1" else "启用")
                                                   for name, value in flags.items() if name not in ("all", "default")))
            lines.append("新接口默认：" + ("禁用" if flags["default"] == "1" else "启用"))
        if "temporary" in state:
            saved = self.read_backup(state["temporary"]["backup"], "temporary")
            lines.append("临时禁用备份：" + ("可恢复" if saved["boot_id"] == self.boot_id() else "属于上次启动，临时禁用已结束"))
        for args, title in ((["ip", "-6", "address", "show"], "IPv6 地址"),
                            (["ip", "-6", "route", "show", "default"], "IPv6 默认路由")):
            try:
                output = self.run(args).strip()
            except ToolError as exc:
                output = "无法读取：" + str(exc)
            lines.append(title + "：\n" + (output or "无"))
        lines.append("地址和路由不代表公网可达；本工具不会主动向第三方发起联网检测。")
        return "\n".join(lines)


def guard_ssh():
    """--yes 也不能绕过 IPv6 SSH 保护；无法识别 sshd 会话时保守拒绝。"""
    connection = os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT")
    if connection:
        fields = connection.split()
        try:
            if len(fields) not in (3, 4):
                raise ValueError()
            client = ipaddress.ip_address(fields[0].split("%", 1)[0])
            server = ipaddress.ip_address(fields[2].split("%", 1)[0]) if len(fields) == 4 else client
        except ValueError as exc:
            raise ToolError("无法识别 SSH 使用的协议，拒绝禁用 IPv6。") from exc
        if any(address.version == 6 and address.ipv4_mapped is None for address in (client, server)):
            raise ToolError("当前 SSH 使用 IPv6，禁止禁用。请先通过 IPv4 SSH 或云控制台登录。")
        return
    if os.environ.get("SSH_TTY"):
        raise ToolError("检测到 SSH 终端但没有连接地址，拒绝禁用 IPv6。")
    pid = os.getppid()
    for _ in range(40):
        if pid <= 1:
            break
        try:
            proc = Path("/proc") / str(pid)
            if proc.joinpath("comm").read_text().strip().startswith("sshd"):
                raise ToolError("检测到 SSH 会话但地址环境变量已丢失；请保留 SSH_CONNECTION 后重试。")
            status = proc.joinpath("status").read_text()
            match = re.search(r"^PPid:\s*(\d+)", status, re.M)
            if not match:
                break
            pid = int(match[1])
        except OSError:
            break


def require_glibc():
    try:
        version = os.confstr("CS_GNU_LIBC_VERSION")
    except (ValueError, OSError):
        version = None
    if not version or not version.startswith("glibc "):
        raise ToolError("优先级设置需要 glibc；musl/Alpine 不支持 gai.conf。")


def confirm(message, yes=False):
    if yes:
        return
    if not sys.stdin.isatty():
        raise ToolError("修改需要交互确认；命令行自动化请显式添加 --yes。")
    if input(message + " [y/N] ").strip().lower() not in ("y", "yes"):
        raise ToolError("已取消，未修改配置。")


def operate(manager, command, mode=None, yes=False):
    with manager.locked():
        if command == "priority":
            if mode != "restore":
                require_glibc()
            confirm("恢复原优先级配置？" if mode == "restore" else "设置 %s 优先（保留并备份原配置）？" % mode, yes)
            return manager.priority(mode)
        if command == "disable":
            guard_ssh()
            confirm("临时禁用所有接口 IPv6（包括 ::1）？" if mode == "temporary" else
                    "备份后配置内核彻底关闭 IPv6？重启后生效，包括 ::1 和 IPv6 socket", yes)
            return manager.temporary() if mode == "temporary" else manager.complete()
        confirm("恢复本工具禁用前的 IPv6 配置？内核关闭的恢复需要重启", yes)
        return manager.enable()


def menu(manager):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ToolError("菜单需要交互终端；请使用 --help 查看命令模式。")
    while True:
        print("\nIPv6 管理工具 v" + VERSION)
        print("1. 查看 IPv6 状态\n2. IPv4 优先\n3. IPv6 优先\n4. 恢复原优先级")
        print("5. 临时禁用 IPv6\n6. 彻底关闭 IPv6（备份后配置，重启生效）\n7. 恢复禁用前的 IPv6 配置\n0. 退出")
        try:
            choice = input("请选择：").strip()
            if choice == "0":
                return
            if choice == "1":
                print(manager.status())
            elif choice in ("2", "3", "4"):
                print(operate(manager, "priority", {"2": "ipv4", "3": "ipv6", "4": "restore"}[choice]))
            elif choice in ("5", "6"):
                print(operate(manager, "disable", "temporary" if choice == "5" else "complete"))
            elif choice == "7":
                print(operate(manager, "enable"))
            else:
                print("无效选项。")
        except (ToolError, OSError, ValueError) as exc:
            print("错误：" + str(exc), file=sys.stderr)
        except EOFError:
            return


def main(argv=None):
    parser = argparse.ArgumentParser(description="IPv6 管理；不会禁用 IPv4，不会自动重启。")
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("menu", help="中文交互菜单（默认）")
    commands.add_parser("status", help="查看接口、地址、路由和备份状态")
    priority = commands.add_parser("priority", help="设置地址选择优先级或恢复")
    priority.add_argument("mode", choices=("ipv4", "ipv6", "restore"))
    priority.add_argument("--yes", action="store_true")
    disable = commands.add_parser("disable", help="临时禁用或内核彻底关闭 IPv6")
    disable.add_argument("mode", choices=("temporary", "complete"))
    disable.add_argument("--yes", action="store_true")
    enable = commands.add_parser("enable", help="从备份恢复禁用前配置")
    enable.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    if platform.system() != "Linux":
        parser.error("请在 Linux VPS 上运行；此工具不会修改当前非 Linux 主机。")
    command = args.command or "menu"
    if os.geteuid() != 0:
        if sys.stdin.isatty() and shutil.which("sudo"):
            os.execvp("sudo", ["sudo", "--preserve-env=SSH_CONNECTION,SSH_CLIENT,SSH_TTY", "--",
                               sys.executable, str(Path(__file__).resolve())] + list(sys.argv[1:] if argv is None else argv))
        parser.error("读取备份状态或修改配置需要 root；请使用 sudo ipv6tool ...。")
    manager = Manager()
    try:
        if command == "menu":
            menu(manager)
        elif command == "status":
            print(manager.status())
        else:
            print(operate(manager, command, getattr(args, "mode", None), args.yes))
        return 0
    except (ToolError, OSError, ValueError, KeyError) as exc:
        print("[ipv6tool] 错误：" + str(exc), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\n已退出；未完成的操作可用 enable 恢复。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
