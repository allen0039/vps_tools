#!/usr/bin/env python3
"""VPS 端逐轮 iperf3 测速；只使用 Python 标准库。

每次监听由独立 guardian 持有。控制管道 EOF（包括主进程 SIGKILL）和
固定截止时间都会关闭本次子进程组；不根据端口向其他进程发送信号。
"""
import argparse
import csv
import datetime
import ipaddress
import json
import math
import os
from pathlib import Path
import random
import re
import select
import shlex
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

if sys.version_info < (3, 8):
    print("需要 Python 3.8 或更新版本", file=sys.stderr)
    sys.exit(1)

from dataclasses import asdict, dataclass

VERSION = "0.1.2"
SCRIPT = Path(__file__).resolve()
DIRECTION_NAMES = {"download": "下载：VPS → 本地", "upload": "上传：本地 → VPS"}


class ProbeError(Exception):
    pass


class Cancelled(Exception):
    pass


def say(message):
    print(message, flush=True)


def system_package_manager():
    release = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            key, separator, value = line.partition("=")
            if separator and key in ("ID", "ID_LIKE", "PRETTY_NAME"):
                release[key] = value.strip().strip("\"'")
    except OSError:
        pass
    managers = {"debian": ("apt-get",), "ubuntu": ("apt-get",),
                "rhel": ("dnf", "yum"), "fedora": ("dnf", "yum"),
                "centos": ("dnf", "yum"), "rocky": ("dnf", "yum"),
                "almalinux": ("dnf", "yum"), "amzn": ("dnf", "yum"),
                "suse": ("zypper",), "opensuse": ("zypper",),
                "opensuse-leap": ("zypper",), "opensuse-tumbleweed": ("zypper",),
                "alpine": ("apk",), "arch": ("pacman",), "manjaro": ("pacman",)}
    candidates = ("apt-get", "dnf", "yum", "zypper", "apk", "pacman")
    for identity in (release.get("ID", "") + " " + release.get("ID_LIKE", "")).split():
        if identity in managers:
            candidates = managers[identity]
            break
    for manager in candidates:
        if shutil.which(manager):
            return release.get("PRETTY_NAME", "Linux"), manager
    raise ProbeError("无法识别可用的系统包管理器，请手动安装 iperf3 后重试")


def ensure_iperf3():
    if shutil.which("iperf3"):
        return
    system, manager = system_package_manager()
    prefix = []
    if os.geteuid() != 0:
        if not shutil.which("sudo"):
            raise ProbeError("自动安装 iperf3 需要 root 或 sudo 权限，请以 root 重新运行")
        prefix = ["sudo", "--"]
    say("检测到 {}，缺少 iperf3，正在使用 {} 自动安装……".format(system, manager))

    def run(command, **kwargs):
        result = subprocess.run(prefix + command, **kwargs)
        if result.returncode:
            raise ProbeError("依赖安装失败（{}，退出码 {}）；请检查权限、网络及软件源后重试"
                             .format(command[0], result.returncode))

    if manager == "apt-get":
        run(["apt-get", "update"])
        # Debian 的 iperf3 安装脚本依据此选项决定是否启用常驻服务。
        run(["debconf-set-selections"], input="iperf3 iperf3/start_daemon boolean false\n", text=True)
        run(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "iperf3"])
    elif manager in ("dnf", "yum"):
        run([manager, "install", "-y", "iperf3"])
    elif manager == "zypper":
        run([manager, "--non-interactive", "install", "iperf3"])
    elif manager == "apk":
        run([manager, "add", "--no-cache", "iperf3"])
    else:
        run([manager, "-S", "--needed", "--noconfirm", "iperf3"])
    if not shutil.which("iperf3"):
        raise ProbeError("安装完成后仍未找到 iperf3，请检查软件包及 PATH 后重试")
    say("iperf3 已安装，继续测速。")


def integer(value, low, high, name):
    value = str(value)
    if not re.fullmatch(r"[0-9]{1,9}", value) or not low <= int(value) <= high:
        raise ProbeError("{}必须为 {}～{} 的整数".format(name, low, high))
    return int(value)


def validate_host(host):
    host = host.strip()
    if not host or len(host) > 253 or host.startswith("-"):
        raise ProbeError("请输入 VPS 的 IP 或域名，不要包含协议、端口或空格")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            raise ProbeError("请输入有效的 IP 或域名")
        if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-")
               for part in host.rstrip(".").split(".")):
            raise ProbeError("请输入有效的域名")
    return host


def default_host():
    # SSH_CONNECTION 中第三项是服务器侧地址；NAT 场景仍需用户核实。
    parts = os.environ.get("SSH_CONNECTION", "").split()
    return parts[2] if len(parts) == 4 else ""


def port_free(port):
    """实际尝试 bind，同时排除 IPv4/IPv6 的已有 TCP 绑定。"""
    # BSD 上 SO_REUSEADDR 可能允许 wildcard bind 覆盖具体地址，先排除监听。
    if sys.platform.startswith("linux"):
        try:
            for name in ("tcp", "tcp6"):
                table = Path("/proc/net") / name
                if not table.exists():
                    continue
                for line in table.read_text().splitlines()[1:]:
                    fields = line.split()
                    if fields[3] == "0A" and int(fields[1].split(":")[1], 16) == port:
                        return False
        except (OSError, ValueError, IndexError):
            return False
    elif shutil.which("lsof"):
        if subprocess.run([shutil.which("lsof"), "-nP", "-iTCP:{}".format(port), "-sTCP:LISTEN"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2).returncode == 0:
            return False
    for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        if family == socket.AF_INET6 and not socket.has_ipv6:
            continue
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            if family == socket.AF_INET6 and exc.errno in (49, 99, 97):
                continue
            return False
        with sock:
            # 与 iperf3 一致，允许复用上一轮 TIME_WAIT；仍拒绝已有监听。
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                sock.bind((address, port))
            except OSError as exc:
                # 没有 IPv6 内核支持的机器仍允许 IPv4 测试。
                if family == socket.AF_INET6 and exc.errno in (49, 99, 97):
                    continue
                return False
    return True


def random_port():
    for _ in range(300):
        port = random.SystemRandom().randrange(20000, 60000)
        if port_free(port):
            return port
    raise ProbeError("未找到空闲 TCP 端口，请手动选择")


def owned_tcp_socket(pid, port, tcp_state):
    """被动确认本次进程的 TCP socket；不连接单次服务端。"""
    if sys.platform.startswith("linux"):
        inodes = set()
        try:
            for entry in Path("/proc/{}/fd".format(pid)).iterdir():
                try:
                    target = os.readlink(str(entry))
                except OSError:
                    continue
                if target.startswith("socket:["):
                    inodes.add(target[8:-1])
            for name in ("tcp", "tcp6"):
                table = Path("/proc/{}/net/{}".format(pid, name))
                if not table.exists():
                    continue
                for line in table.read_text().splitlines()[1:]:
                    fields = line.split()
                    if (len(fields) > 9 and fields[3] == tcp_state
                            and int(fields[1].split(":")[1], 16) == port
                            and fields[9] in inodes):
                        return True
        except (OSError, ValueError):
            return False
        return False
    # 开发用回环测试支持 macOS；正式 CLI 仅面向 Linux VPS。
    lsof = shutil.which("lsof")
    if not lsof:
        return False
    result = subprocess.run([lsof, "-nP", "-a", "-p", str(pid),
                             "-iTCP:{}".format(port), "-sTCP:" + ("LISTEN" if tcp_state == "0A" else "ESTABLISHED")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    return result.returncode == 0


def listener_ready(pid, port):
    return owned_tcp_socket(pid, port, "0A")


def write_json(path, value):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def stop_child(process):
    # 未 wait 的自有子进程 PID 不会被回收复用；进程组在启动时独立创建。
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def guardian(control_fd, prefix, port, family, bind, lifetime, executable):
    """内部子进程入口。主进程消失时控制管道 EOF，不依赖主进程的 trap。"""
    interrupted = [False]

    def on_signal(_number, _frame):
        interrupted[0] = True

    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, on_signal)
    prefix = Path(prefix)
    state_path = prefix.with_suffix(".state.json")
    state = {"state": "starting"}
    process = None
    started = time.monotonic()
    next_socket_check = started
    command = [executable, "-" + family, "-s", "-1", "-J", "-p", str(port)]
    if bind:
        command += ["-B", bind]
    try:
        with prefix.with_suffix(".json").open("w") as out, prefix.with_suffix(".err").open("w") as err:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       start_new_session=True, close_fds=True)
            state["pid"] = process.pid
            write_json(state_path, state)
            while True:
                if interrupted[0]:
                    state.update(state="stopped", reason="收到退出信号")
                    break
                readable, _, _ = select.select([control_fd], [], [], 0.1)
                if readable and os.read(control_fd, 1) == b"":
                    state.update(state="stopped", reason="主进程已退出")
                    break
                if time.monotonic() - started >= lifetime:
                    state.update(state="timeout", reason="达到本轮最大生存时间")
                    break
                rc = process.poll()
                if rc is not None:
                    state.update(state="finished", returncode=rc)
                    break
                if state["state"] == "starting":
                    if listener_ready(process.pid, port):
                        state.update(state="ready")
                        write_json(state_path, state)
                    elif time.monotonic() - started >= 10:
                        state.update(state="failed", reason="未能确认本次进程的监听")
                        break
                elif state["state"] == "ready" and time.monotonic() >= next_socket_check:
                    next_socket_check = time.monotonic() + 1
                    if owned_tcp_socket(process.pid, port, "01"):
                        state.update(state="connected")
                        write_json(state_path, state)
    except Exception as exc:
        state.update(state="failed", reason=str(exc))
    finally:
        if process is not None:
            stop_child(process)
        os.close(control_fd)
        write_json(state_path, state)
    return 0


def number(value, field, positive=False):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0 or (positive and value <= 0)):
        raise ProbeError("{}={}，需要有效{}数值".format(field, repr(value), "正" if positive else "非负"))
    return value


def parse_result(path, streams, direction, duration, omit):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ProbeError("结果不是 JSON 对象")
        if data.get("error"):
            raise ProbeError("iperf3：" + str(data["error"]))
        test = data["start"]["test_start"]
        if (test.get("protocol") != "TCP" or test.get("reverse", 0) != (direction == "download")
                or test.get("bidir", 0)):
            raise ProbeError("测试方向或协议不符，本轮要求 TCP " + DIRECTION_NAMES[direction])
        if test.get("num_streams") != streams or len(data["end"]["streams"]) != streams:
            raise ProbeError("连接数不符，本轮要求 {} 个连接".format(streams))
        if test.get("duration") != duration or test.get("omit", 0) != omit:
            raise ProbeError("请求时长或预热时间不符，本轮要求 -t {} -O {}".format(duration, omit))
        end = data["end"]
        sent = end.get("sum_sent", {})
        received = end.get("sum_received", {})
        # 下载时部分版本的服务端无法得到接收端汇总，会返回零占位记录。
        receiver_placeholder = (direction == "download" and received.get("bytes", 0) == 0
                                and received.get("bits_per_second", 0) == 0
                                and received.get("sender") is not False)
        if received and not receiver_placeholder:
            total, source = received, "receiver"
        elif direction == "download":
            total, source = sent, "sender"
        else:
            raise ProbeError("缺少服务端接收汇总")
        rate = number(total.get("bits_per_second"), "吞吐", True)
        byte_count = number(total.get("bytes"), "传输字节数", True)
        seconds = number(total.get("seconds"), "实际测试时长", True)
        tolerance = min(2, max(0.25, duration * 0.1))
        if not duration - tolerance <= seconds <= duration + omit + 3:
            raise ProbeError("实际测试时长 {:.2f} 秒，与请求 {} 秒不符".format(seconds, duration))
        # 双向都检查已提供的数值；零占位允许，但不当作实测吞吐。
        for name, summary in (("sum_sent", sent), ("sum_received", received)):
            for key in ("bytes", "bits_per_second", "seconds"):
                if key in summary:
                    number(summary[key], name + "." + key)
        retransmits = sent.get("retransmits")
        if retransmits is not None:
            integer_number = number(retransmits, "重传次数")
            if int(integer_number) != integer_number:
                raise ProbeError("重传次数不是整数")
        rtts = []
        for entry in end["streams"]:
            sender = entry.get("sender", {})
            if "mean_rtt" in sender:
                rtt = number(sender["mean_rtt"], "mean_rtt")
                if rtt > 0:
                    rtts.append(rtt / 1000)
        intervals = []
        for interval in data.get("intervals", []):
            total_interval = interval.get("sum")
            if not total_interval:
                continue
            interval_rate = number(total_interval.get("bits_per_second"), "区间吞吐")
            if not total_interval.get("omitted") and total_interval.get("seconds", 0) >= 0.5:
                intervals.append(interval_rate / 1e6)
        cv = None
        if len(intervals) >= 3 and statistics.mean(intervals) > 0:
            cv = statistics.pstdev(intervals) / statistics.mean(intervals) * 100
        peers = data["start"].get("connected", [])
        return {"mbps": rate / 1e6, "bytes": byte_count, "seconds": seconds,
                "rate_source": source, "retransmits": retransmits,
                "rtt_ms": statistics.mean(rtts) if rtts else None, "cv_percent": cv,
                "interval_mbps": intervals,
                "client": peers[0].get("remote_host") if peers else None}
    except ProbeError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError) as exc:
        raise ProbeError("无法解析完整测速结果：{}".format(exc)) from exc


def complete_summary(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        end = data.get("end", {})
        return isinstance(end, dict) and any(isinstance(end.get(key), dict)
                                            for key in ("sum_sent", "sum_received"))
    except (OSError, ValueError, AttributeError):
        return False


@dataclass
class Config:
    host: str
    port: int = 0
    streams: tuple = (1, 4, 8)
    direction: str = "download"
    duration: int = 15
    omit: int = 2
    repeat: int = 1
    wait: int = 300
    family: str = "4"
    bind: str = ""
    output_dir: str = ""


def local_command(config, port, streams, direction):
    args = ["iperf3", "-" + config.family, "-c", config.host, "-p", str(port),
            "-P", str(streams), "-t", str(config.duration), "-O", str(config.omit), "-i", "1"]
    if direction == "download":
        args.append("-R")
    return " ".join(shlex.quote(item) for item in args)


def result_base(output_dir=""):
    return (Path(output_dir).expanduser() if output_dir else
            Path.home() / ".local/state/iperf3-tool").resolve()


def finished_result(directory, base):
    """只认可本工具在父目录内创建、且已写入最终报告的普通会话目录。"""
    if (directory.is_symlink() or not directory.is_dir() or directory.parent != base
            or not re.fullmatch(r"\d{8}T\d{6}Z-[A-Za-z0-9_-]+", directory.name)):
        return False
    try:
        session_path, report_path = directory / "session.json", directory / "report.json"
        if session_path.is_symlink() or report_path.is_symlink():
            return False
        session = json.loads(session_path.read_text(encoding="utf-8"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return (isinstance(session, dict) and isinstance(report, dict)
                and session.get("started_utc") == directory.name.split("-", 1)[0]
                and isinstance(session.get("config"), dict)
                and isinstance(session.get("plan"), list)
                and report.get("status") in ("complete", "partial", "failed", "interrupted"))
    except (OSError, ValueError):
        return False


def result_size(directory):
    total = 0

    def unreadable(error):
        raise error

    for root, _directories, files in os.walk(directory, followlinks=False, onerror=unreadable):
        for name in files:
            total += (Path(root) / name).lstat().st_size
    return total


def human_size(size):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return "{:.2f} {}".format(size, unit)
        size /= 1024


def delete_results(directories, base):
    deleted = 0
    for directory in directories:
        if not finished_result(directory, base):
            say("跳过：目录已变化、测试尚未结束或不是有效结果：" + str(directory))
            continue
        try:
            # rmtree 不跟随目录内的符号链接；不递归删除结果父目录。
            shutil.rmtree(directory)
            deleted += 1
            say("已删除：" + str(directory))
        except OSError as exc:
            say("清理失败：{}：{}".format(directory, exc))
    say("已清理 {} 个测试结果目录。".format(deleted))


def cleanup_history(output_dir=""):
    base = result_base(output_dir)
    say("\n历史测试结果目录：" + str(base))
    if not base.exists():
        say("没有可清理的历史测试数据。")
        return
    directories = sorted((path for path in base.iterdir() if finished_result(path, base)), reverse=True)
    if not directories:
        say("没有可清理的历史测试数据（仅列出已结束且报告有效的测试）。")
        return
    total = 0
    for index, directory in enumerate(directories, 1):
        size = result_size(directory)
        total += size
        say("{}）{}  {}".format(index, directory.name, human_size(size)))
    say("共 {} 次测试，文件大小合计 {}。".format(len(directories), human_size(total)))
    while True:
        selection = ask("选择要删除的编号（逗号分隔，如 1,3）/ all 全部 / 0 返回", "0").lower()
        if selection == "0":
            return
        if selection == "all":
            selected = directories
            break
        try:
            indices = sorted({integer(value.strip(), 1, len(directories), "编号")
                              for value in selection.split(",")})
            selected = [directories[index - 1] for index in indices]
            break
        except ProbeError as exc:
            say(str(exc))
    say("将永久删除以下测试的全部结果、原始数据和日志：")
    for directory in selected:
        say("  " + str(directory))
    if choose("确认删除 {} 个目录？y 是 / n 否".format(len(selected)), {"y", "n"}, "n") == "y":
        delete_results(selected, base)
    else:
        say("已取消清理，结果数据保留。")


def cleanup_current(directory):
    try:
        if choose("是否清理本次结果数据（包括原始数据和日志）？y 是 / n 否", {"y", "n"}, "n") == "y":
            delete_results([directory], directory.parent)
        else:
            say("本次结果数据已保留。")
    except (Cancelled, KeyboardInterrupt):
        say("\n已退出清理。")


class Session:
    def __init__(self, config, interactive=False):
        self.config = config
        self.interactive = interactive
        self.port = config.port or random_port()
        base = result_base(config.output_dir)
        base.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
        self.directory = Path(tempfile.mkdtemp(prefix=stamp, dir=str(base)))
        self.process = None
        self.control_fd = None
        self.results = []
        directions = ("download", "upload") if config.direction == "both" else (config.direction,)
        self.plan = [(streams, direction, repeat)
                     for streams in config.streams for direction in directions
                     for repeat in range(1, config.repeat + 1)]
        write_json(self.directory / "session.json", {"version": VERSION, "config": asdict(config),
                   "port": self.port, "started_utc": stamp.rstrip("-"), "plan": self.plan})

    def stop(self):
        if self.control_fd is not None:
            os.close(self.control_fd)
            self.control_fd = None
        if self.process is not None:
            # guardian 需要最多两秒等待 iperf3 优雅退出。
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=5)
            self.process = None

    def start(self, prefix, lifetime):
        if not port_free(self.port):
            raise ProbeError("TCP {} 已被占用，请重新选择；不会终止已有进程".format(self.port))
        reader, writer = os.pipe()
        self.control_fd = writer
        try:
            with prefix.with_suffix(".guardian.err").open("w") as errors:
                self.process = subprocess.Popen(
                    [sys.executable, str(SCRIPT), "_serve", str(reader), str(prefix), str(self.port),
                     self.config.family, self.config.bind, str(lifetime), shutil.which("iperf3")],
                    pass_fds=(reader,), start_new_session=True, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=errors)
        finally:
            os.close(reader)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            state = self.state(prefix)
            if state.get("state") in ("ready", "connected"):
                return
            if self.process.poll() is not None:
                raise ProbeError("服务端启动失败：" + self.diagnostic(prefix, state))
            time.sleep(0.1)
        raise ProbeError("未能确认本次 iperf3 进程的监听")

    @staticmethod
    def state(prefix):
        try:
            return json.loads(prefix.with_suffix(".state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    @staticmethod
    def diagnostic(prefix, state):
        texts = [str(state.get("reason", ""))]
        for suffix in (".err", ".guardian.err"):
            path = prefix.with_suffix(suffix)
            if path.exists():
                texts.append(path.read_text(encoding="utf-8", errors="replace")[:2000].strip())
        return "；".join(text for text in texts if text) or "请查看本轮原始 JSON 和日志"

    def attempt(self, index, streams, direction, attempt_number):
        config = self.config
        prefix = self.directory / "test-{:02d}-attempt-{:02d}".format(index, attempt_number)
        # 无效连接可以有限次数重启，但不会刷新本轮总时间预算。
        deadline = time.monotonic() + config.wait + config.duration + config.omit + 15
        wait_deadline = time.monotonic() + config.wait
        connection_ever_seen = False
        for connection in range(1, 6):
            actual = prefix.with_name(prefix.name + "-connection-{:02d}".format(connection))
            try:
                self.start(actual, max(1, deadline - time.monotonic()))
                say("\n[监听就绪] TCP {}｜{} 个连接｜{}".format(self.port, streams, DIRECTION_NAMES[direction]))
                say("本地执行（请等待这一轮完成再执行下一条）：\n\n  " + local_command(config, self.port, streams, direction) + "\n")
                say("最多等待 {} 秒，测量 {} 秒，预热 {} 秒。Ctrl+C 退出并释放监听。".format(
                    config.wait, config.duration, config.omit))
                say("请确保主机防火墙与云安全组允许本机访问 TCP {}。".format(self.port))
                next_notice = time.monotonic() + 5
                connected_seen = False
                while self.process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise ProbeError("本轮超时，未取得有效完成结果；请检查本地命令、网络及防火墙")
                    if time.monotonic() >= next_notice:
                        say("[{}] 剩余最多 {:.0f} 秒".format(
                            "测试中，等待汇总" if connected_seen else "等待本地连接", deadline - time.monotonic()))
                        next_notice = time.monotonic() + 5
                    if not connected_seen and self.state(actual).get("state") == "connected":
                        connected_seen = True
                        connection_ever_seen = True
                        say("[已连接] 正在传输，等待本轮结果……")
                    if not connection_ever_seen and time.monotonic() >= wait_deadline:
                        raise ProbeError("等待本地连接超时（{} 秒），已关闭本轮监听".format(config.wait))
                    time.sleep(0.1)
                state = self.state(actual)
                raw = actual.with_suffix(".json")
                if state.get("state") != "finished":
                    raise ProbeError(self.diagnostic(actual, state))
                try:
                    result = parse_result(raw, streams, direction, config.duration, config.omit)
                    if state.get("returncode") != 0:
                        raise ProbeError("iperf3 退出码 {}".format(state.get("returncode")))
                except ProbeError as exc:
                    actual.with_suffix(".validation.log").write_text(str(exc) + "\n", encoding="utf-8")
                    if complete_summary(raw):
                        raise
                    # 仅恢复无完整汇总的握手失败/端口扫描；监听错误不盲目重启。
                    if not port_free(self.port) or connection == 5 or deadline - time.monotonic() < 1:
                        raise
                    say("[连接未完成] {}。恢复监听（{}/5）；日志：{}".format(exc, connection, raw))
                    continue
                result["raw_json"] = str(raw)
                return result
            finally:
                self.stop()
        raise ProbeError("无有效结果")

    def save(self, status):
        write_json(self.directory / "report.json", {"version": VERSION, "status": status,
                   "port": self.port, "config": asdict(self.config), "results": self.results})
        fields = ["test", "streams", "direction", "repeat", "status", "mbps", "rate_source",
                  "retransmits", "rtt_ms", "cv_percent", "bytes", "seconds", "client", "raw_json", "error"]
        with (self.directory / "report.csv").open("w", encoding="utf-8-sig", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.results)

    def summary(self):
        say("\n测试汇总（Mbps；NA 表示未取得）：")
        say("连接数  方向  次数  状态      吞吐       重传     RTT(ms)  吞吐来源")
        for row in self.results:
            say("{:<6} {:<3} {:<4} {:<8} {:<10} {:<8} {:<8} {}".format(
                row["streams"], "下载" if row["direction"] == "download" else "上传", row["repeat"],
                {"ok": "完成", "failed": "失败", "skipped": "跳过", "interrupted": "中断", "running": "进行中"}.get(row["status"], row["status"]),
                metric(row.get("mbps")), metric(row.get("retransmits")),
                metric(row.get("rtt_ms")), "接收端" if row.get("rate_source") == "receiver"
                else "发送端" if row.get("rate_source") == "sender" else "NA"))
        for direction in ("download", "upload"):
            groups = {}
            for row in self.results:
                if row["status"] == "ok" and row["direction"] == direction:
                    groups.setdefault(row["streams"], []).append(row["mbps"])
            if groups:
                say(DIRECTION_NAMES[direction] + " 中位数：" + "；".join(
                    "{} 连接 {:.2f} Mbps".format(streams, statistics.median(rates))
                    for streams, rates in sorted(groups.items())))
                if 1 in groups:
                    baseline = statistics.median(groups[1])
                    for streams, rates in sorted(groups.items()):
                        if streams != 1:
                            say("  {} 连接 / 单连接：{:.2f} 倍".format(streams, statistics.median(rates) / baseline))
        say("结果目录：" + str(self.directory))

    def run(self):
        status = "failed"
        try:
            say("iperf3 VPS 测速 v{}｜TCP {}｜共 {} 轮".format(VERSION, self.port, len(self.plan)))
            say("测试将尽量跑满带宽；预计测量 {} 秒，另含预热和等待时间。".format(
                len(self.plan) * self.config.duration))
            for index, (streams, direction, repeat) in enumerate(self.plan, 1):
                say("\n[{}/{}] {}｜{} 连接｜第 {} 次".format(index, len(self.plan), DIRECTION_NAMES[direction], streams, repeat))
                row = {"test": index, "streams": streams, "direction": direction, "repeat": repeat,
                       "status": "running"}
                self.results.append(row)
                for attempt_number in range(1, 4):
                    try:
                        row.update(self.attempt(index, streams, direction, attempt_number), status="ok")
                        row.pop("error", None)
                        say("[完成] {:.2f} Mbps｜重传 {}｜RTT {} ms｜波动 CV {}%".format(
                            row["mbps"], metric(row["retransmits"]), metric(row["rtt_ms"]), metric(row["cv_percent"])))
                        say("本轮客户端：" + str(row.get("client") or "NA"))
                        if row["rate_source"] == "sender":
                            say("吞吐来源：发送端统计；服务端未取得接收端实测汇总。")
                        break
                    except ProbeError as exc:
                        row.update(status="failed", error=str(exc))
                        say("[失败] " + str(exc))
                        self.save("running")
                        if not self.interactive or attempt_number == 3:
                            raise
                        action = choose("r 重试本轮 / s 跳过 / q 结束", {"r", "s", "q"}, "r")
                        if action == "q":
                            raise Cancelled()
                        if action == "s":
                            row["status"] = "skipped"
                            break
                self.save("running")
            status = "partial" if any(row["status"] != "ok" for row in self.results) else "complete"
            return 0 if status == "complete" else 1
        except (Cancelled, KeyboardInterrupt):
            status = "interrupted"
            if self.results and self.results[-1]["status"] == "running":
                self.results[-1].update(status="interrupted", error="用户中断")
            say("\n测试已中断。")
            return 130
        except ProbeError as exc:
            say("测试停止：" + str(exc))
            return 1
        finally:
            self.stop()
            self.save(status)
            self.summary()
            say("本次测速进程已退出，未保留常驻测速服务。")
            if status != "interrupted" and (self.interactive or
                                           (sys.stdin.isatty() and sys.stdout.isatty())):
                cleanup_current(self.directory)


def metric(value):
    return "NA" if value is None else "{:.2f}".format(value)


def ask(label, default=""):
    try:
        value = input("{}{}：".format(label, " [{}]".format(default) if default != "" else "")).strip()
    except EOFError:
        raise Cancelled()
    return value or str(default)


def choose(label, options, default):
    while True:
        value = ask(label, default).lower()
        if value in options:
            return value
        say("无效选项，请重新输入。")


def ask_integer(label, default, low, high):
    while True:
        try:
            return integer(ask(label, default), low, high, label)
        except ProbeError as exc:
            say(str(exc))


def menu():
    say("\niperf3 VPS 测速工具 v" + VERSION)
    say("在 VPS 上配置，在本地运行屏幕给出的 iperf3 命令。")
    while True:
        action = choose("操作：1 开始测速 / 2 清理历史测试数据 / 0 退出", {"0", "1", "2"}, "1")
        if action == "0":
            raise Cancelled()
        if action == "1":
            break
        cleanup_history()
    while True:
        try:
            host = validate_host(ask("本地能访问的 VPS IP/域名（核实 NAT 公网地址）", default_host()))
            break
        except ProbeError as exc:
            say(str(exc))
    family = "6" if ":" in host else "4"
    if ":" not in host and not re.fullmatch(r"[0-9.]+", host):
        family = choose("IP 版本：4 IPv4 / 6 IPv6", {"4", "6"}, "4")
    selection = choose("端口：1 随机未占用 / 2 自定义 / 0 退出", {"0", "1", "2"}, "1")
    if selection == "0":
        raise Cancelled()
    port = 0
    if selection == "2":
        while True:
            port = ask_integer("TCP 端口", 5201, 1024, 65535)
            if port_free(port):
                break
            say("该端口已有 TCP 绑定，请重新选择；不会关闭原有进程。")
    mode = choose("模式：1 单连接 / 2 自定义连接数 / 3 依次 1、4、8 / 0 退出", {"0", "1", "2", "3"}, "3")
    if mode == "0":
        raise Cancelled()
    streams = (1,) if mode == "1" else (ask_integer("并行连接数", 4, 1, 128),) if mode == "2" else (1, 4, 8)
    direction = {"1": "download", "2": "upload", "3": "both"}[
        choose("方向：1 下载 VPS→本地 / 2 上传 本地→VPS / 3 双向", {"1", "2", "3"}, "1")]
    duration = ask_integer("每次测量秒数", 15, 1, 3600)
    omit = ask_integer("预热秒数（不计入测量）", 2, 0, 60)
    repeat = ask_integer("每项重复次数", 1, 1, 20)
    wait = ask_integer("本轮等待连接预算（秒）", 300, 1, 3600)
    say("\n计划：{} 连接｜{}｜测量 {} 秒 + 预热 {} 秒｜每项 {} 次".format(
        "/".join(map(str, streams)), "双向" if direction == "both" else DIRECTION_NAMES[direction], duration, omit, repeat))
    if choose("开始测试？y 开始 / n 退出", {"y", "n"}, "y") != "y":
        raise Cancelled()
    return Config(host, port, streams, direction, duration, omit, repeat, wait, family)


def parser():
    result = argparse.ArgumentParser(description="VPS 端 iperf3 测速：无参数打开中文交互，配置后逐轮显示本地命令。")
    result.add_argument("--version", action="version", version="iperf3-tool " + VERSION)
    result.add_argument("--host", help="本地客户端连接的 VPS IP 或域名")
    result.add_argument("--port", default="auto", help="auto（默认）或 1024～65535 的自定义 TCP 端口")
    result.add_argument("--streams", default="1,4,8", help="连接数，用逗号分隔，例如 1 或 4 或 1,4,8")
    result.add_argument("--direction", choices=("download", "upload", "both"), default="download")
    result.add_argument("--duration", default="15", help="每次测量秒数，默认 15")
    result.add_argument("--omit", default="2", help="预热秒数，默认 2")
    result.add_argument("--repeat", default="1", help="每项重复次数，默认 1")
    result.add_argument("--wait", default="300", help="本轮连接等待预算，默认 300 秒")
    result.add_argument("--family", choices=("4", "6"), help="IP 版本，默认根据地址选择")
    result.add_argument("--bind", default="", help="仅在 VPS 指定本地监听 IP")
    result.add_argument("--output-dir", default="", help="结果父目录，默认 ~/.local/state/iperf3-tool")
    result.add_argument("--cleanup", action="store_true", help="交互清理历史测试数据，不启动测速；可配合 --output-dir")
    return result


def cli_config(args):
    host = validate_host(args.host or default_host())
    port = 0 if args.port == "auto" else integer(args.port, 1024, 65535, "端口")
    streams = tuple(integer(value.strip(), 1, 128, "连接数") for value in args.streams.split(","))
    if len(streams) > 16 or len(set(streams)) != len(streams):
        raise ProbeError("连接数列表最多 16 项，且不能重复")
    family = args.family or ("6" if ":" in host else "4")
    if args.bind:
        try:
            bind_ip = ipaddress.ip_address(args.bind)
        except ValueError:
            raise ProbeError("--bind 必须是 VPS 本地 IP 地址")
        if str(bind_ip.version) != family:
            raise ProbeError("--bind 与 IP 版本不一致")
    return Config(host, port, streams, args.direction,
                  integer(args.duration, 1, 3600, "时长"), integer(args.omit, 0, 60, "预热"),
                  integer(args.repeat, 1, 20, "重复次数"), integer(args.wait, 1, 3600, "等待时间"),
                  family, args.bind, args.output_dir)


def install_signal_handlers():
    already_interrupted = [False]

    def interrupted(_number, _frame):
        if not already_interrupted[0]:
            already_interrupted[0] = True
            raise Cancelled()

    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "_serve":
        return guardian(int(argv[1]), argv[2], int(argv[3]), argv[4], argv[5], float(argv[6]), argv[7])
    args = parser().parse_args(argv)
    if not sys.platform.startswith("linux"):
        print("请在 Linux VPS 的 SSH 终端运行；本地设备仅运行 iperf3 客户端。", file=sys.stderr)
        return 1
    try:
        interactive = not argv
        if interactive and (not sys.stdin.isatty() or not sys.stdout.isatty()):
            raise ProbeError("菜单需要交互终端；脚本模式请使用 --host VPS地址")
        install_signal_handlers()
        if args.cleanup:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise ProbeError("清理历史测试数据需要交互终端")
            cleanup_history(args.output_dir)
            return 0
        config = menu() if interactive else cli_config(args)
        ensure_iperf3()
        return Session(config, interactive).run()
    except (Cancelled, KeyboardInterrupt):
        say("已退出。")
        return 130
    except (ProbeError, OSError) as exc:
        print("错误：" + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
