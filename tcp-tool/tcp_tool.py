#!/usr/bin/env python3
"""Import sysctl data without executing pasted shell commands (Python 3.8+)."""
import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import termios
import tty
import uuid

VERSION = "0.1.1"
TOOL_ID = "vps-tools-tcptool"
HEADER = "# Managed by vps-tools-tcptool\n"
CONFIG = Path("/etc/sysctl.d/99-z-tcptool.conf")
STATE = Path("/var/lib/tcptool")
KEYS = set("""
kernel.pid_max kernel.panic kernel.sysrq kernel.core_pattern kernel.printk
kernel.numa_balancing kernel.sched_autogroup_enabled
vm.swappiness vm.dirty_ratio vm.dirty_background_ratio vm.panic_on_oom
vm.overcommit_memory vm.min_free_kbytes
net.core.default_qdisc net.core.netdev_max_backlog net.core.rmem_max
net.core.wmem_max net.core.rmem_default net.core.wmem_default net.core.somaxconn
net.core.optmem_max net.ipv4.tcp_fastopen net.ipv4.tcp_timestamps
net.ipv4.tcp_tw_reuse net.ipv4.tcp_fin_timeout net.ipv4.tcp_slow_start_after_idle
net.ipv4.tcp_max_tw_buckets net.ipv4.tcp_sack net.ipv4.tcp_fack
net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.ipv4.tcp_mtu_probing
net.ipv4.tcp_congestion_control net.ipv4.tcp_notsent_lowat
net.ipv4.tcp_window_scaling net.ipv4.tcp_adv_win_scale
net.ipv4.tcp_moderate_rcvbuf net.ipv4.tcp_no_metrics_save
net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_max_orphans
net.ipv4.tcp_synack_retries net.ipv4.tcp_syn_retries
net.ipv4.tcp_abort_on_overflow net.ipv4.tcp_stdurg net.ipv4.tcp_rfc1337
net.ipv4.tcp_syncookies net.ipv4.ip_local_port_range net.ipv4.ip_no_pmtu_disc
net.ipv4.route.gc_timeout net.ipv4.neigh.default.gc_stale_time
net.ipv4.neigh.default.gc_thresh3 net.ipv4.neigh.default.gc_thresh2
net.ipv4.neigh.default.gc_thresh1 net.ipv4.icmp_echo_ignore_broadcasts
net.ipv4.icmp_ignore_bogus_error_responses net.ipv4.conf.all.rp_filter
net.ipv4.conf.default.rp_filter net.ipv4.conf.all.arp_announce
net.ipv4.conf.default.arp_announce net.ipv4.conf.all.arp_ignore
net.ipv4.conf.default.arp_ignore
""".split())
STRINGS = {"kernel.core_pattern", "net.core.default_qdisc",
           "net.ipv4.tcp_congestion_control"}
COUNTS = {"kernel.printk": 4, "net.ipv4.tcp_rmem": 3,
          "net.ipv4.tcp_wmem": 3, "net.ipv4.ip_local_port_range": 2}


def normalized(value):
    return " ".join(value.split())


def parse_config(text):
    """Strict data parser: allow comments and common Markdown copy artifacts."""
    if len(text.encode("utf-8")) > 128 * 1024:
        raise ValueError("参数文本超过 128 KiB。")
    result = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().replace("\\_", "_")
        if line.endswith("\\"):
            line = line[:-1].rstrip()
        if not line or line.startswith("#") or line in ("```", "```ini", "```conf", "```text"):
            continue
        line = line.split("#", 1)[0].strip()
        match = re.fullmatch(r"([a-z][a-z0-9_.]*)\s*=\s*(.+)", line)
        if not match:
            raise ValueError("第 %d 行不是 key = value；请复制参数配置，而非一键命令。" % number)
        key, value = match.groups()
        if key not in KEYS:
            raise ValueError("第 %d 行：不在本工具支持的参数列表中：%s" % (number, key))
        if key in result:
            raise ValueError("第 %d 行重复参数：%s" % (number, key))
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("第 %d 行含控制字符。" % number)
        value = normalized(value)
        if key in STRINGS:
            if not re.fullmatch(r"[A-Za-z0-9_%./:+-]{1,128}", value):
                raise ValueError("第 %d 行字符串值格式错误。" % number)
            if key == "kernel.core_pattern" and value.startswith("|"):
                raise ValueError("不支持执行 core dump 管道命令。")
        elif not re.fullmatch(r"-?\d+(?: -?\d+)*", value):
            raise ValueError("第 %d 行需要整数或整数列表。" % number)
        elif len(value.split()) != COUNTS.get(key, 1):
            raise ValueError("第 %d 行整数数量错误：%s" % (number, key))
        elif any(abs(int(v)) > 2**63 - 1 for v in value.split()):
            raise ValueError("第 %d 行整数过大。" % number)
        else:
            value = " ".join(str(int(v)) for v in value.split())
        result[key] = value
    if not result:
        raise ValueError("没有可导入的参数。")
    return result


def value_issue(key, value):
    if key in STRINGS:
        return None
    nums = [int(v) for v in value.split()]
    if key == "net.ipv4.tcp_adv_win_scale":
        if not -31 <= nums[0] <= 31:
            return "旧内核允许范围为 -31..31；新内核可能已弃用此参数"
    elif any(v < 0 for v in nums):
        return "此参数不接受负数"
    if key in ("net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem") and nums != sorted(nums):
        return "缓冲区必须满足 min <= default <= max"
    if key == "net.ipv4.ip_local_port_range" and not 1 <= nums[0] < nums[1] <= 65535:
        return "端口范围必须满足 1 <= 起始 < 结束 <= 65535"
    if key in ("vm.swappiness",) and not 0 <= nums[0] <= 200:
        return "swappiness 范围为 0..200（老内核可能只支持 0..100）"
    if key in ("vm.dirty_ratio", "vm.dirty_background_ratio") and nums[0] > 100:
        return "百分比范围为 0..100"
    return None


class System:
    def __init__(self):
        self.sysctl = shutil.which("sysctl")
        if platform.system() != "Linux" or not self.sysctl:
            raise RuntimeError("检查和应用需要 Linux VPS 及 sysctl（通常由 procps 提供）。")

    def path(self, key):
        return Path("/proc/sys") / key.replace(".", "/")

    def read(self, key):
        return normalized(self.path(key).read_text().strip())

    def write(self, key, value):
        # Argument arrays only. Pasted values never reach a shell.
        result = subprocess.run([self.sysctl, "-w", key + "=" + value],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, env=dict(os.environ, LC_ALL="C"))
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        actual = self.read(key)
        if actual != normalized(value):
            raise RuntimeError("写入后读回不一致：请求 %s，实际 %s" % (value, actual))

    def boot_id(self):
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def make_plan(values, system, include_system=False):
    rows = []
    for key, value in values.items():
        old, reason = None, value_issue(key, value)
        if not include_system and not key.startswith("net."):
            reason = "仅网络模式；kernel/vm 仅在完整模式应用"
        try:
            old = system.read(key)
        except (OSError, RuntimeError) as exc:
            reason = "内核不支持或无法读取：%s" % exc
        if not reason and key == "net.ipv4.tcp_congestion_control":
            try:
                available = system.read("net.ipv4.tcp_available_congestion_control").split()
                if value not in available:
                    reason = "算法未就绪，可用：%s；请先安装/加载对应内核模块" % " ".join(available)
            except OSError as exc:
                reason = "无法检查拥塞控制算法：%s" % exc
        rows.append({"key": key, "value": value, "old": old, "reason": reason})
    return rows


def serialize(values):
    return HEADER + "".join("%s = %s\n" % item for item in values.items())


def file_image(path):
    if path.is_symlink():
        raise RuntimeError("拒绝操作符号链接：%s" % path)
    if not path.exists():
        return None
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError("拒绝操作非普通文件：%s" % path)
    return {"data": base64.b64encode(path.read_bytes()).decode("ascii"),
            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}


def image_hash(snapshot):
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()


def record_hash(data):
    return image_hash({key: value for key, value in data.items() if key != "checksum"})


def atomic_write(path, data, mode=0o600, owner=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix="." + path.name + "-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            if owner is not None:
                os.fchown(handle.fileno(), *owner)
            os.fsync(handle.fileno())
        os.replace(temp, path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def restore_file(path, snapshot):
    if snapshot is None:
        if path.exists():
            path.unlink()
            fsync_dir(path.parent)
    else:
        atomic_write(path, base64.b64decode(snapshot["data"]), snapshot["mode"],
                     (snapshot["uid"], snapshot["gid"]))


class Engine:
    def __init__(self, system, config=CONFIG, state=STATE):
        self.system, self.config, self.state = system, config, state

    @contextlib.contextmanager
    def lock(self):
        if self.state.is_symlink():
            raise RuntimeError("状态目录不能是符号链接。")
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state, 0o700)
        fd = os.open(str(self.state / "operation.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("另一项 tcptool 操作正在进行。")
            yield

    def records(self):
        result = []
        if self.state.exists():
            for path in sorted(self.state.glob("*.json")):
                data = json.loads(path.read_text())
                if data.get("checksum") != record_hash(data):
                    raise RuntimeError("备份数据校验失败：%s" % path)
                if data.get("tool") != TOOL_ID or data.get("config") != str(self.config):
                    raise RuntimeError("备份身份或配置路径不匹配：%s" % path)
                if data.get("original_hash") != image_hash(data["file_before"]):
                    raise RuntimeError("备份配置校验失败：%s" % path)
                result.append((path, data))
        return result

    def latest(self):
        records = [(p, d) for p, d in self.records() if d["status"] not in ("rolled_back", "cancelled")]
        return records[-1] if records else None

    def save(self, path, data):
        data["checksum"] = record_hash(data)
        atomic_write(path, (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode())
        if json.loads(path.read_text()) != data:
            raise RuntimeError("备份写入后校验失败。")

    def managed(self):
        snapshot = file_image(self.config)
        if snapshot is None:
            return {}, snapshot
        text = base64.b64decode(snapshot["data"]).decode("utf-8")
        if not text.startswith(HEADER):
            raise RuntimeError("已有同名配置不属于 tcptool，拒绝覆盖：%s" % self.config)
        return parse_config(text), snapshot

    def backup_inventory(self):
        return [(path, data, data["status"] not in ("rolled_back", "cancelled"))
                for path, data in self.records()]

    def cleanup_candidates(self, keep=0):
        if keep < 0:
            raise ValueError("保留数量不能为负数。")
        removable = [path for path, _, protected in self.backup_inventory() if not protected]
        return removable[:-keep] if keep else removable

    def delete_backups(self, names):
        # Resolve exact record names under a lock; never accept arbitrary paths.
        with self.lock():
            inventory = {p.name: (p, protected) for p, _, protected in self.backup_inventory()}
            names = set(names)
            for name in names:
                if name not in inventory:
                    raise ValueError("备份不存在：%s" % name)
                if inventory[name][1]:
                    raise RuntimeError("备份仍用于逐次回滚，不能删除：%s" % name)
            for name in sorted(names):
                inventory[name][0].unlink()
            if names:
                fsync_dir(self.state)
            return len(names)

    def profile_path(self, name):
        if not re.fullmatch(r"[\w\-]{1,60}", name, re.UNICODE):
            raise ValueError("方案名限 1..60 个字母、数字、中文、下划线或短横线。")
        return self.state / "profiles" / (name + ".json")

    def save_profile(self, name, values, overwrite=False):
        values = parse_config(serialize(values))
        with self.lock():
            path = self.profile_path(name)
            if path.is_symlink() or path.parent.is_symlink():
                raise RuntimeError("参数方案不能是符号链接。")
            if path.exists() and not overwrite:
                raise RuntimeError("方案已存在：%s" % name)
            path.parent.mkdir(mode=0o700, exist_ok=True)
            os.chmod(path.parent, 0o700)
            data = {"tool": TOOL_ID, "name": name, "values": values,
                    "time": datetime.datetime.now(datetime.timezone.utc).isoformat()}
            self.save(path, data)
            return path

    def load_profile(self, name):
        path = self.profile_path(name)
        if path.is_symlink() or path.parent.is_symlink():
            raise RuntimeError("参数方案不能是符号链接。")
        data = json.loads(path.read_text())
        if (data.get("tool") != TOOL_ID or data.get("name") != name or
                data.get("checksum") != record_hash(data)):
            raise RuntimeError("参数方案校验失败：%s" % name)
        return parse_config(serialize(data["values"]))

    def profile_names(self):
        directory = self.state / "profiles"
        if directory.is_symlink():
            raise RuntimeError("参数方案目录不能是符号链接。")
        return sorted(p.stem for p in directory.glob("*.json"))

    def delete_profile(self, name):
        with self.lock():
            self.load_profile(name)
            self.profile_path(name).unlink()
            fsync_dir(self.state / "profiles")

    def apply(self, values, include_system=False):
        values = parse_config(serialize(values))
        with self.lock():
            active = self.latest()
            if active and active[1]["status"] != "applied":
                raise RuntimeError("发现未完成操作，请先执行 rollback：%s" % active[0])
            previous, snapshot = self.managed()
            if active and image_hash(snapshot) != active[1]["file_after_hash"]:
                raise RuntimeError("工具配置已被外部修改，请人工合并后再操作。")
            rows = make_plan(values, self.system, include_system)
            chosen = [row for row in rows if not row["reason"]]
            if not chosen:
                raise RuntimeError("没有可应用的参数。")
            # Updating imports retains earlier managed keys not included this time.
            merged = dict(previous)
            merged.update((row["key"], row["value"]) for row in chosen)
            if (snapshot is not None and
                    base64.b64decode(snapshot["data"]) == serialize(merged).encode() and
                    all(row["old"] == row["value"] for row in chosen)):
                return None, rows
            timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            path = self.state / (timestamp + "-" + uuid.uuid4().hex[:8] + ".json")
            data = {"tool": TOOL_ID, "config": str(self.config), "status": "pending",
                    "time": timestamp, "boot_id": self.system.boot_id(),
                    "file_before": snapshot, "original_hash": image_hash(snapshot),
                    "before": {row["key"]: row["old"] for row in chosen},
                    "wanted": {row["key"]: row["value"] for row in chosen},
                    "attempted": [], "skipped": [row for row in rows if row["reason"]]}
            # Expected file image is saved before any mutation, including publication.
            after = {"data": base64.b64encode(serialize(merged).encode()).decode(),
                     "mode": 0o644, "uid": os.geteuid(), "gid": os.getegid()}
            data["file_after_hash"] = image_hash(after)
            self.save(path, data)
            try:
                for row in chosen:
                    key = row["key"]
                    # Recheck live values to avoid using a stale preflight snapshot.
                    if self.system.read(key) != row["old"]:
                        raise RuntimeError("参数在应用期间被其他程序修改：%s" % key)
                    data["attempted"].append(key)
                    self.save(path, data)
                    if row["old"] != row["value"]:
                        self.system.write(key, row["value"])
                if image_hash(file_image(self.config)) != image_hash(snapshot):
                    raise RuntimeError("配置在应用期间被其他程序修改。")
                atomic_write(self.config, serialize(merged).encode(), 0o644)
                if image_hash(file_image(self.config)) != data["file_after_hash"]:
                    raise RuntimeError("持久配置写入后校验失败。")
                data["status"] = "applied"
                self.save(path, data)
            except BaseException as exc:
                data["error"] = str(exc)
                errors = self.restore_runtime(data, check_conflicts=False)
                # Never overwrite an externally changed file on failure.
                try:
                    current_hash = image_hash(file_image(self.config))
                    if current_hash == data["file_after_hash"]:
                        restore_file(self.config, snapshot)
                    elif current_hash != image_hash(snapshot):
                        errors.append("持久配置被外部修改，请人工合并")
                except Exception as restore_error:
                    errors.append(str(restore_error))
                data["status"] = "rollback_failed" if errors else "cancelled"
                data["restore_errors"] = errors
                self.save(path, data)
                raise RuntimeError("应用失败：%s；%s。备份：%s" % (
                    exc, "恢复不完整：" + "; ".join(errors) if errors else "已撤销本次修改", path)) from exc
            return path, rows

    def restore_runtime(self, data, check_conflicts=True):
        errors = []
        keys = list(reversed(data["attempted"]))
        same_boot = data["boot_id"] == self.system.boot_id()
        if check_conflicts and same_boot:
            for key in keys:
                try:
                    actual = self.system.read(key)
                    if actual not in (data["before"][key], data["wanted"][key]):
                        errors.append("%s 已被外部修改（当前 %s），拒绝覆盖" % (key, actual))
                except Exception as exc:
                    errors.append("%s: %s" % (key, exc))
            if errors:
                return errors
        for key in keys:
            try:
                if self.system.read(key) != data["before"][key]:
                    self.system.write(key, data["before"][key])
            except Exception as exc:
                errors.append("%s: %s" % (key, exc))
        return errors

    def rollback(self):
        with self.lock():
            latest = self.latest()
            if latest is None:
                raise RuntimeError("没有可回滚的操作。")
            path, data = latest
            snapshot = file_image(self.config)
            if image_hash(snapshot) not in (data["file_after_hash"], data["original_hash"]):
                raise RuntimeError("持久配置被外部修改，拒绝覆盖。备份：%s" % path)
            errors = self.restore_runtime(data)
            if not errors:
                try:
                    if image_hash(file_image(self.config)) != image_hash(snapshot):
                        raise RuntimeError("持久配置在回滚期间被外部修改，拒绝覆盖")
                    restore_file(self.config, data["file_before"])
                except Exception as exc:
                    errors.append(str(exc))
            if errors:
                data["status"] = "rollback_failed"
                data["restore_errors"] = errors
                self.save(path, data)
                raise RuntimeError("回滚不完整：%s；保留备份，可再次 rollback。" % "; ".join(errors))
            data["status"] = "rolled_back"
            self.save(path, data)
            return path


def conflicts(values):
    """Report overlapping assignments; loaders have different ordering rules."""
    found = []
    paths = {Path("/etc/sysctl.conf")}
    for directory in ("/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"):
        paths.update(Path(directory).glob("*.conf"))
    for path in sorted(paths):
        if path == CONFIG:
            continue
        try:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                match = re.match(r"\s*([a-z][a-z0-9_./]*)\s*=\s*([^#;]+)", line)
                if match and match[1].replace("/", ".") in values:
                    key = match[1].replace("/", ".")
                    found.append("%s:%d  %s = %s" % (path, number, key, match[2].strip()))
        except (OSError, UnicodeError):
            continue
    return found


def show_plan(rows, overlaps=()):
    for row in rows:
        if row["reason"]:
            print("[跳过] %s = %s — %s" % (row["key"], row["value"], row["reason"]))
        else:
            print("[应用] %s: %s -> %s" % (row["key"], row["old"], row["value"]))
    accepted = sum(not row["reason"] for row in rows)
    print("可应用 %d 项，跳过 %d 项。" % (accepted, len(rows) - accepted))
    if overlaps:
        print("其他配置也设置了这些参数；启动/重载顺序可能覆盖本工具的值：")
        for item in overlaps:
            print("  " + item)
    if any(row["key"].startswith(("kernel.", "vm.")) and not row["reason"] for row in rows):
        print("完整模式包含系统参数：panic_on_oom=1 可能在 OOM 时触发内核 panic；")
        print("kernel.panic 控制 panic 后重启，sysrq/内存预留/overcommit 也会改变系统行为。")
    print("default_qdisc 只设置默认队列，不会重建现有网卡队列；性能需用实际流量验证。")


def require_root():
    if os.geteuid() != 0:
        raise RuntimeError("修改或读取备份需要 root；请用 sudo tcptool 或 sudo python3 tcp_tool.py。")


def read_paste():
    print("直接粘贴网站的参数配置，支持的终端会自动进入预览。")
    print("若粘贴后仍在等待，独立输入 END 或按 Ctrl+D；CANCEL 取消，Ctrl+C 返回。")
    try:
        fd = sys.stdin.fileno()
        terminal = os.isatty(fd) and os.environ.get("TERM") != "dumb"
    except (AttributeError, OSError, ValueError):
        terminal = False
    if terminal:
        text = read_terminal_paste(fd)
        return parse_config(text) if text is not None else None
    return read_manual_paste()


def read_terminal_paste(fd):
    """Use terminal paste boundaries, never timing or a guessed final sysctl key."""
    original = termios.tcgetattr(fd)
    data, line, escape = bytearray(), bytearray(), bytearray()
    bracketed = False
    start, end = b"\x1b[200~", b"\x1b[201~"

    def echo(value):
        sys.stdout.buffer.write(value)
        sys.stdout.buffer.flush()

    try:
        tty.setcbreak(fd, termios.TCSANOW)
        sys.stdout.write("\x1b[?2004h")
        sys.stdout.flush()
        while True:
            char = os.read(fd, 1)
            if not char:
                return data.decode("utf-8") if data else None
            if escape or char == b"\x1b":
                escape.extend(char)
                marker = end if bracketed else start
                if bytes(escape) == marker:
                    escape.clear()
                    if bracketed:
                        print("\n粘贴完成，正在检查参数。")
                        return data.decode("utf-8")
                    bracketed = True
                elif not marker.startswith(escape):
                    raise ValueError("粘贴中含不支持的终端控制序列，请只复制参数文本。")
                continue
            if bracketed:
                data.extend(char)
            elif char == b"\x04":
                data.extend(line)
                return data.decode("utf-8") if data else None
            elif char in (b"\x7f", b"\x08"):
                if line:
                    index = len(line) - 1
                    while index > 0 and line[index] & 0xC0 == 0x80:
                        index -= 1
                    del line[index:]
                    echo(b"\b \b")
            elif char in (b"\n", b"\r"):
                echo(b"\n")
                command = line.strip()
                if command == b"CANCEL":
                    return None
                if command == b"END":
                    return data.decode("utf-8")
                data.extend(line + b"\n")
                line.clear()
            else:
                if char[0] < 32 and char != b"\t":
                    raise ValueError("输入含控制字符，请只复制参数文本。")
                line.extend(char)
                echo(char)
            if len(data) + len(line) > 128 * 1024:
                raise ValueError("粘贴内容过长。")
    finally:
        # Discard remaining pasted input so it cannot answer subsequent prompts.
        try:
            termios.tcflush(fd, termios.TCIFLUSH)
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, original)
            sys.stdout.write("\x1b[?2004l")
            sys.stdout.flush()


def read_manual_paste():
    lines = []
    size = 0
    while True:
        try:
            line = input()
        except EOFError:
            return parse_config("\n".join(lines)) if lines else None
        if line.strip() == "CANCEL":
            return None
        if line.strip() == "END":
            return parse_config("\n".join(lines))
        lines.append(line)
        size += len(line.encode("utf-8")) + 1
        if size > 128 * 1024:
            raise ValueError("粘贴内容过长。")


def confirm(prompt):
    return input(prompt + " [y/N] ").strip().lower() == "y"


def preview(values, system, include_system):
    rows = make_plan(values, system, include_system)
    show_plan(rows, conflicts({r["key"]: r["value"] for r in rows if not r["reason"]}))
    return rows


def compact_preview(values, system, include_system=False):
    rows = make_plan(values, system, include_system)
    usable = [r for r in rows if not r["reason"]]
    changes = [r for r in usable if r["old"] != r["value"]]
    print("\n%s：导入 %d 项，需修改 %d 项，当前值相同 %d 项，跳过 %d 项。" % (
        "完整模式" if include_system else "仅网络模式", len(rows), len(changes),
        len(usable) - len(changes), len(rows) - len(usable)))
    for row in changes:
        print("  %s: %s -> %s" % (row["key"], row["old"], row["value"]))
    for row in rows:
        if row["reason"] and (include_system or row["key"].startswith("net.")):
            print("  [跳过] %s：%s" % (row["key"], row["reason"]))
    overlaps = conflicts({r["key"]: r["value"] for r in usable})
    if overlaps:
        print("其他配置有重复设置，重启/重载可能覆盖：")
        for item in overlaps:
            print("  " + item)
    if any(not r["reason"] and r["key"].startswith(("kernel.", "vm.")) for r in rows):
        print("含系统参数：panic_on_oom 可能触发内核 panic；panic/sysrq/内存项会改变系统行为。")
    return rows


def report_apply(path, rows):
    if path is None:
        print("运行值与持久配置均已一致，无需修改，未创建新备份。")
    else:
        print("已应用并验证 %d 项；备份：%s" % (sum(not r["reason"] for r in rows), path))


def edit_values(values, key, value):
    if key not in values:
        raise ValueError("该参数不在此方案中：%s" % key)
    parsed = parse_config("%s = %s" % (key, value))
    if len(parsed) != 1 or key not in parsed:
        raise ValueError("每次只能编辑一个参数。")
    issue = value_issue(key, parsed[key])
    if issue:
        raise ValueError(issue)
    updated = dict(values)
    updated[key] = parsed[key]
    return updated


def parameter_actions(values, system, engine):
    include_system = False
    while True:
        rows = compact_preview(values, system, include_system)
        print("2. 切换仅网络/完整模式  3. 查看全部参数\n"
              "4. 修改单个参数  5. 保存为命名方案  0. 返回")
        action = input("备份并应用以上参数？[y/N]（或输入操作编号）：").strip().lower()
        if action in ("", "n", "no", "0"):
            return
        if action in ("y", "yes", "1"):
            if not any(not r["reason"] for r in rows):
                print("没有可应用的参数。")
                continue
            require_root()
            report_apply(*engine.apply(values, include_system))
            return
        elif action == "2":
            include_system = not include_system
        elif action == "3":
            preview(values, system, include_system)
        elif action == "4":
            keys = list(values)
            for index, key in enumerate(keys, 1):
                print("%d. %s = %s" % (index, key, values[key]))
            key = input("参数编号或参数名（0 返回）：").strip()
            if key == "0":
                continue
            if key.isdigit() and 1 <= int(key) <= len(keys):
                key = keys[int(key) - 1]
            if key not in values:
                print("参数不在方案中。选择“查看全部参数”可查名称。")
                continue
            print("方案当前值：" + values[key])
            try:
                updated = edit_values(values, key, input("新值：").strip())
                require_root()
                engine.save_profile("last-import", updated, overwrite=True)
                values = updated
            except (ValueError, RuntimeError) as exc:
                print("错误：%s" % exc)
        elif action == "5":
            require_root()
            name = input("方案名称（例如 上海-千兆）：").strip()
            path = engine.profile_path(name)
            if path.exists() and not confirm("同名方案已存在，覆盖？"):
                continue
            engine.save_profile(name, values, overwrite=True)
            print("已保存方案：" + name)
        else:
            print("无效选项。")


BACKUP_STATUS = {"applied": "已应用", "pending": "未完成", "rollback_failed": "回滚未完成",
                 "rolled_back": "已回滚", "cancelled": "已撤销"}


def show_backups(engine):
    inventory = engine.backup_inventory()
    if not inventory:
        print("暂无备份记录。")
    for index, (path, data, protected) in enumerate(inventory, 1):
        print("%d. %s  %s  %d 项  %s" % (index, path.name,
              BACKUP_STATUS.get(data["status"], data["status"]), len(data["wanted"]),
              "保护：用于回滚" if protected else "可删除"))
    print("共 %d 条，保护 %d 条，可清理 %d 条。" % (
        len(inventory), sum(p for _, _, p in inventory), sum(not p for _, _, p in inventory)))
    return inventory


def choose_index(items, prompt):
    choice = input(prompt + "（0 返回）：").strip()
    if choice == "0":
        return None
    if not choice.isdigit() or not 1 <= int(choice) <= len(items):
        raise ValueError("编号无效。")
    return items[int(choice) - 1]


def backup_menu(system, engine):
    require_root()
    while True:
        inventory = show_backups(engine)
        print("1. 查看详情  2. 删除指定可清理备份  3. 批量清理\n"
              "4. 复用备份中的目标参数  0. 返回")
        choice = input("请选择：").strip()
        if choice == "0":
            return
        if choice in ("1", "2", "4"):
            item = choose_index(inventory, "备份编号")
            if item is None:
                continue
            path, data, protected = item
            if choice == "1":
                print("备份：%s\n状态：%s\n%s" % (path, BACKUP_STATUS.get(data["status"], data["status"]),
                      "仍用于回滚，受保护。" if protected else "已失效，可清理。"))
                for key, value in data["wanted"].items():
                    print("  %s: %s -> %s" % (key, data["before"][key], value))
                for row in data.get("skipped", []):
                    print("  [跳过] %s = %s：%s" % (row["key"], row["value"], row["reason"]))
                if data.get("error") or data.get("restore_errors"):
                    print("操作错误：%s\n恢复错误：%s" % (data.get("error", ""), data.get("restore_errors", [])))
            elif choice == "2":
                if protected:
                    print("此备份仍用于逐次回滚，不能删除。")
                elif confirm("删除 %s？" % path.name):
                    print("已删除 %d 条备份。" % engine.delete_backups([path.name]))
            else:
                parameter_actions(dict(data["wanted"]), system, engine)
        elif choice == "3":
            raw = input("保留最近几条可清理记录？回车清理全部可清理记录：").strip()
            keep = int(raw or "0")
            candidates = engine.cleanup_candidates(keep)
            if not candidates:
                print("没有可清理的记录。")
                continue
            size = sum(p.stat().st_size for p in candidates)
            for path in candidates:
                print("  " + path.name)
            if confirm("删除上述 %d 条（%.1f KiB）？保留全部有效恢复点" % (len(candidates), size / 1024)):
                print("已清理 %d 条备份。" % engine.delete_backups([p.name for p in candidates]))
        else:
            print("无效选项。")


def profile_menu(system, engine):
    require_root()
    while True:
        names = engine.profile_names()
        if not names:
            print("暂无保存方案；导入后会保存 last-import，也可在参数预览中命名保存。")
            return
        for index, name in enumerate(names, 1):
            print("%d. %s%s" % (index, name, "（最近导入）" if name == "last-import" else ""))
        name = choose_index(names, "方案编号")
        if name is None:
            return
        print("1. 预览 / 修改 / 应用（回车）  2. 删除此方案  0. 返回列表")
        choice = input("请选择：").strip()
        if choice in ("", "1"):
            parameter_actions(engine.load_profile(name), system, engine)
        elif choice == "2" and confirm("删除方案 %s？不会修改当前系统参数" % name):
            engine.delete_profile(name)
            print("已删除方案。")


def status(system, engine):
    print("TCP 参数导入工具 v%s | 内核 %s" % (VERSION, platform.release()))
    for key in ("net.ipv4.tcp_congestion_control", "net.ipv4.tcp_available_congestion_control",
                "net.core.default_qdisc"):
        try:
            print("%s = %s" % (key, system.read(key)))
        except OSError as exc:
            print("%s: %s" % (key, exc))
    if engine.config.exists():
        values, _ = engine.managed()
        print("持久配置：%s（%d 项）" % (engine.config, len(values)))
        for key, desired in values.items():
            try:
                actual = system.read(key)
                print("[%s] %s = %s%s" % ("一致" if actual == desired else "差异", key, actual,
                      "（配置 %s）" % desired if actual != desired else ""))
            except OSError:
                print("[不支持] " + key)
    else:
        print("尚未写入本工具的持久配置。")


def menu(system, engine):
    if not sys.stdin.isatty():
        raise RuntimeError("菜单需要交互终端；可使用 check/apply 命令导入文件。")
    while True:
        print("\nTCP 参数导入工具 v%s\n1. 粘贴网站参数\n2. 从文件导入\n3. 查看当前状态\n4. 备份管理（详情 / 删除 / 清理 / 复用）\n5. 回滚最近一次应用\n6. 已保存的参数方案\n7. 重新应用当前持久配置\n0. 退出" % VERSION)
        try:
            choice = input("请选择：").strip()
            if choice == "0":
                return 0
            if choice in ("1", "2"):
                try:
                    values = read_paste() if choice == "1" else parse_config(
                        Path(input("参数文件路径：").strip()).expanduser().read_text())
                except KeyboardInterrupt:
                    print("\n已取消导入。")
                    continue
                if values is None:
                    continue
                require_root()
                engine.save_profile("last-import", values, overwrite=True)
                print("已保存最近导入；下次可从“参数方案”直接复用。")
                parameter_actions(values, system, engine)
            elif choice == "3":
                status(system, engine)
            elif choice == "4":
                backup_menu(system, engine)
            elif choice == "5":
                require_root()
                latest = engine.latest()
                if latest is None:
                    print("没有可回滚的操作。")
                    continue
                print("恢复点：%s（%s）" % (latest[0], latest[1]["status"]))
                if latest[1]["boot_id"] != system.boot_id():
                    print("该备份来自上一次启动；将恢复备份中的运行值和工具配置。")
                if confirm("恢复最近一次应用前的运行值和持久配置？"):
                    print("已回滚：%s" % engine.rollback())
            elif choice == "6":
                profile_menu(system, engine)
            elif choice == "7":
                values, _ = engine.managed()
                if not values:
                    print("暂无本工具的持久配置。")
                else:
                    parameter_actions(values, system, engine)
            else:
                print("无效选项。")
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            print("错误：%s" % exc, file=sys.stderr)
        except EOFError:
            return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="导入 omnitt.com 的 sysctl 参数配置，不执行网站的一键命令。")
    parser.add_argument("--version", action="version", version="tcptool " + VERSION)
    sub = parser.add_subparsers(dest="command")
    for name in ("check", "apply"):
        p = sub.add_parser(name, help="检查参数" if name == "check" else "备份并应用")
        source = p.add_mutually_exclusive_group(required=True)
        source.add_argument("file", nargs="?", help="参数文件；- 表示标准输入")
        source.add_argument("--profile", help="使用已保存的参数方案")
        p.add_argument("--include-system", action="store_true", help="同时导入 kernel/vm 参数")
        if name == "apply":
            p.add_argument("--yes", action="store_true", help="确认应用预览中未跳过的参数")
    sub.add_parser("status", help="当前参数及持久配置差异")
    sub.add_parser("backups", help="查看备份记录")
    p = sub.add_parser("backup-cleanup", help="清理已回滚/已撤销记录；有效恢复点受保护")
    p.add_argument("--keep", type=int, default=0, help="保留最近 N 条可清理记录")
    p.add_argument("--yes", action="store_true", help="执行删除；未指定时仅预览")
    p = sub.add_parser("backup-delete", help="删除指定已失效备份")
    p.add_argument("name", help="备份文件名，不接受路径")
    p.add_argument("--yes", action="store_true", help="执行删除；未指定时仅预览")
    sub.add_parser("profiles", help="列出保存的参数方案")
    p = sub.add_parser("profile-save", help="将参数文件保存为方案，不应用")
    p.add_argument("name")
    p.add_argument("file")
    p.add_argument("--overwrite", action="store_true")
    p = sub.add_parser("profile-delete", help="删除参数方案")
    p.add_argument("name")
    p.add_argument("--yes", action="store_true", help="执行删除；未指定时仅预览")
    p = sub.add_parser("rollback", help="逐次回滚最近一次操作")
    p.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    system = System()
    engine = Engine(system)
    if args.command is None:
        return menu(system, engine)
    if args.command in ("check", "apply"):
        if args.profile:
            require_root()
            values = engine.load_profile(args.profile)
        else:
            text = sys.stdin.read(128 * 1024 + 1) if args.file == "-" else Path(args.file).read_text()
            values = parse_config(text)
        rows = preview(values, system, args.include_system)
        if args.command == "check":
            return 0 if any(not r["reason"] for r in rows) else 1
        require_root()
        if not args.yes:
            if not sys.stdin.isatty():
                raise RuntimeError("非交互应用需要 --yes；建议先 check。")
            if not confirm("备份后应用可用参数并写入持久配置？"):
                return 0
        report_apply(*engine.apply(values, args.include_system))
    elif args.command == "status":
        status(system, engine)
    elif args.command == "backups":
        require_root()
        show_backups(engine)
    elif args.command in ("backup-cleanup", "backup-delete"):
        require_root()
        if args.command == "backup-cleanup":
            candidates = engine.cleanup_candidates(args.keep)
        else:
            inventory = {p.name: (p, protected) for p, _, protected in engine.backup_inventory()}
            if args.name not in inventory:
                raise ValueError("备份不存在：%s" % args.name)
            path, protected = inventory[args.name]
            if protected:
                raise RuntimeError("备份仍用于回滚，不能删除：%s" % args.name)
            candidates = [path]
        for path in candidates:
            print("待清理：%s" % path.name)
        if args.yes:
            print("已清理 %d 条备份。" % engine.delete_backups([p.name for p in candidates]))
        else:
            print("仅预览 %d 条，追加 --yes 执行清理；有效恢复点始终保留。" % len(candidates))
    elif args.command == "profiles":
        require_root()
        for name in engine.profile_names():
            print(name)
    elif args.command == "profile-save":
        require_root()
        values = parse_config(Path(args.file).expanduser().read_text())
        print("已保存：%s" % engine.save_profile(args.name, values, args.overwrite))
    elif args.command == "profile-delete":
        require_root()
        engine.load_profile(args.name)
        if args.yes:
            engine.delete_profile(args.name)
            print("已删除方案：%s" % args.name)
        else:
            print("待删除方案：%s；追加 --yes 执行删除。" % args.name)
    elif args.command == "rollback":
        require_root()
        if not args.yes:
            if not sys.stdin.isatty():
                raise RuntimeError("非交互回滚需要 --yes。")
            if not confirm("恢复最近一次应用前的运行值和工具配置？"):
                return 0
        print("已回滚：%s" % engine.rollback())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        sys.exit(130)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print("错误：%s" % error, file=sys.stderr)
        sys.exit(1)
