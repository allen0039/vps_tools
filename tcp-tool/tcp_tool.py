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
import uuid

VERSION = "0.1.0"
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

    def apply(self, values, include_system=False):
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
    print("粘贴网站的参数配置（不要粘贴一键命令）；独立一行输入 END 结束，CANCEL 取消：")
    lines = []
    while True:
        line = input()
        if line.strip() == "CANCEL":
            return None
        if line.strip() == "END":
            return parse_config("\n".join(lines))
        lines.append(line)
        if sum(len(v) + 1 for v in lines) > 128 * 1024:
            raise ValueError("粘贴内容过长。")


def confirm(prompt):
    return input(prompt + " [y/N] ").strip().lower() == "y"


def preview(values, system, include_system):
    rows = make_plan(values, system, include_system)
    show_plan(rows, conflicts({r["key"]: r["value"] for r in rows if not r["reason"]}))
    return rows


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
        print("\nTCP 参数导入工具 v%s\n1. 粘贴网站参数并应用\n2. 从文件导入\n3. 查看当前状态\n4. 查看备份记录\n5. 回滚最近一次应用\n0. 退出" % VERSION)
        try:
            choice = input("请选择：").strip()
            if choice == "0":
                return 0
            if choice in ("1", "2"):
                values = read_paste() if choice == "1" else parse_config(
                    Path(input("参数文件路径：").strip()).expanduser().read_text())
                if values is None:
                    continue
                mode = input("1. 仅网络（默认）  2. 完整参数（含 kernel/vm）：").strip()
                if mode not in ("", "1", "2"):
                    raise ValueError("无效模式。")
                rows = preview(values, system, mode == "2")
                if not any(not r["reason"] for r in rows):
                    continue
                if confirm("备份后应用上述可用参数，并写入独立持久配置？"):
                    require_root()
                    path, final_rows = engine.apply(values, mode == "2")
                    print("已应用 %d 项并读回验证；备份：%s" % (sum(not r["reason"] for r in final_rows), path))
            elif choice == "3":
                status(system, engine)
            elif choice == "4":
                require_root()
                for path, data in engine.records():
                    print("%s  %s  %d 项" % (path.name, data["status"], len(data["wanted"])))
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
        p.add_argument("file", help="参数文件；- 表示标准输入")
        p.add_argument("--include-system", action="store_true", help="同时导入 kernel/vm 参数")
        if name == "apply":
            p.add_argument("--yes", action="store_true", help="确认应用预览中未跳过的参数")
    sub.add_parser("status", help="当前参数及持久配置差异")
    sub.add_parser("backups", help="查看备份记录")
    p = sub.add_parser("rollback", help="逐次回滚最近一次操作")
    p.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    system = System()
    engine = Engine(system)
    if args.command is None:
        return menu(system, engine)
    if args.command in ("check", "apply"):
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
        path, rows = engine.apply(values, args.include_system)
        print("已应用 %d 项并读回验证；配置：%s；备份：%s" % (
            sum(not r["reason"] for r in rows), CONFIG, path))
    elif args.command == "status":
        status(system, engine)
    elif args.command == "backups":
        require_root()
        for path, data in engine.records():
            print("%s  %s  %d 项" % (path, data["status"], len(data["wanted"])))
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
