#!/usr/bin/env python3
"""指定用户启用 SSH 密码认证；支持定时、直到重启和永久开启。"""

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
import pwd
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

TOOL_ID = "vps-tools-sshpasswdtool"
VERSION = "0.1.0"
BEGIN = "# BEGIN sshpasswdtool runtime include"
END = "# END sshpasswdtool runtime include"
ACTIVE_PHASES = {"preparing", "active", "restore_failed"}


def operation_mode(state):
    # 兼容 0.1.0 保存的临时操作状态。
    return state.get("mode", "until_reboot" if state["expires_at"] is None else "timed")


class ToolError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"


def regular_file(path):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ToolError("拒绝访问非普通文件：" + str(path))


def private_dir(path):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ToolError("拒绝使用非普通目录：" + str(path))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.geteuid():
        raise ToolError("目录属主不正确：" + str(path))
    path.chmod(0o700)


def sync_dir(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, data, mode=0o600, owner=None):
    path = Path(path)
    regular_file(path)
    fd, temporary = tempfile.mkstemp(prefix=".sshpasswdtool-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            if owner and owner != (os.geteuid(), os.getegid()):
                os.fchown(stream.fileno(), *owner)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run_command(args, check=True):
    process = None
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True,
                                   env=dict(os.environ, LC_ALL="C"))
        try:
            stdout, stderr = process.communicate(timeout=15)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError("命令执行失败：" + shlex.join(args) + "：" + str(exc)) from exc
    if check and process.returncode:
        raise ToolError("命令失败：" + shlex.join(args) + "\n" + stderr.strip())
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def validate_user(user):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\$?", user):
        raise ToolError("用户名格式不支持。")
    try:
        return pwd.getpwnam(user)
    except KeyError as exc:
        raise ToolError("用户不存在：" + user) from exc


def password_available(options, user):
    """判断有无密码路径，不把 PasswordAuthentication 单独当作登录结果。"""
    if user == "root" and options.get("permitrootlogin") != "yes":
        return False
    methods = options.get("authenticationmethods", "any").split()
    if "any" in methods:
        return (options.get("passwordauthentication") == "yes" or
                options.get("kbdinteractiveauthentication") == "yes")
    return any((method == "password" and options.get("passwordauthentication") == "yes") or
               (method.startswith("keyboard-interactive") and
                options.get("kbdinteractiveauthentication") == "yes") for method in methods)


def check_baseline(options, user):
    if options.get("pubkeyauthentication") != "yes":
        raise ToolError("目标用户未允许公钥认证；请先配置并验证密钥登录。")
    if user == "root" and options.get("permitrootlogin") not in {"yes", "prohibit-password", "without-password"}:
        raise ToolError("root 当前被禁止登录或限制为强制命令；不自动解除该限制。")
    if options.get("authenticationmethods", "any") not in {"any", "publickey"}:
        raise ToolError("发现多因素或其他 AuthenticationMethods 策略，不能自动切换。")
    if password_available(options, user):
        raise ToolError("该用户当前仍有密码/键盘交互登录路径；请先设置并验证日常仅密钥策略，再开启密码。")


def connection_context():
    value = os.environ.get("SSH_CONNECTION", "")
    if not value:
        return {"addr": "127.0.0.1", "host": "127.0.0.1", "laddr": "127.0.0.1", "lport": "22"}
    fields = value.split()
    try:
        if len(fields) != 4:
            raise ValueError()
        client = str(ipaddress.ip_address(fields[0]))
        local = str(ipaddress.ip_address(fields[2]))
        if not all(1 <= int(fields[index]) <= 65535 for index in (1, 3)):
            raise ValueError()
    except ValueError as exc:
        raise ToolError("SSH_CONNECTION 格式无效，无法判断适用的 Match 规则。") from exc
    return {"addr": client, "host": client, "laddr": local, "lport": fields[3]}


def unit_quote(value):
    # systemd 的参数分隔、specifier 和环境变量展开与 shell 不同。
    value = str(value).replace("%", "%%").replace("$", "$$")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Backend:
    def __init__(self, config=Path("/etc/ssh/sshd_config")):
        self.config = Path(config)
        self.sshd = shutil.which("sshd") or "/usr/sbin/sshd"

    def effective(self, user, context, config=None):
        match = ",".join(["user=" + user] + [key + "=" + context[key]
                                            for key in ("addr", "host", "laddr", "lport")])
        output = run_command([self.sshd, "-T", "-f", str(config or self.config), "-C", match]).stdout
        return dict(line.split(None, 1) for line in output.splitlines() if " " in line)

    def validate(self, config=None):
        run_command([self.sshd, "-t", "-f", str(config or self.config)])

    def ctl(self, *args, check=True):
        return run_command(["systemctl", *args], check=check)

    def service(self):
        if not shutil.which("systemctl") or not Path("/run/systemd/system").is_dir():
            raise ToolError("密码登录管理需要正在运行的 systemd；当前环境不支持。")
        for unit in ("ssh.service", "sshd.service"):
            if self.ctl("is-active", "--quiet", unit, check=False).returncode == 0:
                self.check_service(unit)
                return unit
        raise ToolError("未找到正在运行的 ssh.service 或 sshd.service。")

    def check_service(self, unit):
        output = self.ctl("show", unit, "--property=MainPID", "--property=CanReload").stdout
        properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        pid = properties.get("MainPID", "0")
        if not pid.isdigit() or int(pid) <= 0 or properties.get("CanReload") != "yes":
            raise ToolError("SSH 服务不支持重载或无法找到实际 sshd 进程。")
        try:
            executable = os.readlink("/proc/" + pid + "/exe")
            cmdline = Path("/proc/" + pid + "/cmdline").read_bytes().replace(b"\0", b" ").decode()
            environment = Path("/proc/" + pid + "/environ").read_bytes().split(b"\0")
            extra = " ".join(item.decode() for item in environment if item.startswith(b"SSHD_OPTS="))
        except (OSError, UnicodeError) as exc:
            raise ToolError("无法检查正在运行的 SSH 启动参数。") from exc
        if os.path.realpath(executable) != os.path.realpath(self.sshd):
            raise ToolError("SSH 主进程与系统 sshd 不一致，停止自动修改。")
        if re.search(r"(?:^|[\s=])-[fop]", cmdline + " " + extra):
            raise ToolError("SSH 使用自定义 -f/-o/-p 启动参数；当前版本仅管理标准 /etc/ssh/sshd_config。")

    def check_account(self, user):
        account = validate_user(user)
        if Path(account.pw_shell).name in {"false", "nologin"}:
            raise ToolError("该用户没有可登录的 shell。")
        fields = run_command(["passwd", "-S", user]).stdout.split()
        if len(fields) < 2 or fields[0] != user or fields[1] not in {"P", "PS"}:
            raise ToolError("该账户没有可用密码或已锁定。请先运行 sudo passwd " + user + " 设置密码。")

    def reload(self, unit):
        if self.ctl("is-active", "--quiet", unit, check=False).returncode != 0:
            raise ToolError("SSH 服务已停止，无法重载；请检查磁盘配置并启动 SSH 服务后重试。")
        self.check_service(unit)
        self.ctl("reload", unit)


class PasswordTool:
    def __init__(self, config=Path("/etc/ssh/sshd_config"), state_dir=Path("/var/lib/sshpasswdtool"),
                 runtime_dir=Path("/run/sshpasswdtool"), unit_dir=Path("/run/systemd/system"),
                 boot_file=Path("/proc/sys/kernel/random/boot_id"), backend=None,
                 lock_path=Path("/run/lock/vpstools-ssh.lock"), key_active=Path("/var/lib/sshkeytool/active.json")):
        self.config = Path(config)
        self.state_dir = Path(state_dir)
        self.runtime_dir = Path(runtime_dir)
        self.unit_dir = Path(unit_dir)
        self.boot_file = Path(boot_file)
        self.backend = backend or Backend(self.config)
        self.state_file = self.state_dir / "state.json"
        self.auth_file = self.runtime_dir / "auth.conf"
        self.persistent_auth_file = self.state_dir / "persistent-auth.conf"
        self.lock_path = Path(lock_path)
        self.key_active = Path(key_active)

    def boot_id(self):
        return self.boot_file.read_text().strip()

    @contextlib.contextmanager
    def lock(self, wait=False):
        private_dir(self.state_dir)
        path = self.lock_path
        path.parent.mkdir(parents=True, exist_ok=True)
        regular_file(path)
        fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_uid != os.geteuid():
                raise ToolError("SSH 操作锁属主不正确。")
            deadline = time.monotonic() + 30
            try:
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if not wait or time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
            except BlockingIOError as exc:
                raise ToolError("另一个密码登录操作正在执行，请稍后重试。") from exc
            yield
        finally:
            os.close(fd)

    def load_state(self):
        regular_file(self.state_file)
        if not self.state_file.exists():
            return None
        try:
            state = json.loads(self.state_file.read_text())
            if (state["tool"] != TOOL_ID or state["version"] != 1 or
                    not re.fullmatch(r"[a-f0-9]{32}", state["token"]) or
                    not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\$?", state["user"]) or
                    state["service"] not in {"ssh.service", "sshd.service"} or
                    state["phase"] not in ACTIVE_PHASES | {"closed"}):
                raise ValueError()
            for key in ("boot_id", "context", "baseline", "auth_sha256", "expires_at", "expires_monotonic"):
                state[key]
            if operation_mode(state) not in {"timed", "until_reboot", "permanent"}:
                raise ValueError()
            return state
        except (KeyError, TypeError, ValueError) as exc:
            raise ToolError("操作状态无效，请保留 /var/lib/sshpasswdtool 供恢复。") from exc

    def save_state(self, state):
        atomic_write(self.state_file, canonical(state))

    def legacy_hook(self):
        path = str(self.auth_file).replace("\\", "\\\\").replace('"', '\\"')
        return (BEGIN + '\nMatch all\nInclude "' + path + '"\n' + END + "\n").encode()

    def hook(self):
        paths = [str(path).replace("\\", "\\\\").replace('"', '\\"')
                 for path in (self.auth_file, self.persistent_auth_file)]
        return (BEGIN + "\nMatch all\n" + "".join('Include "' + path + '"\n' for path in paths) +
                END + "\n").encode()

    def auth_path(self, state):
        return self.persistent_auth_file if operation_mode(state) == "permanent" else self.auth_file

    def has_auth(self):
        return any(path.exists() or path.is_symlink() for path in (self.auth_file, self.persistent_auth_file))

    def key_blocks(self, data):
        """仅识别本仓库 sshkeytool 的简单管理块，不移动其他条件认证规则。"""
        pattern = re.compile(rb"(?m)^# BEGIN sshkeytool ([A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\$?)\n"
                             rb".*?^# END sshkeytool \1\n?", re.S)
        blocks = list(pattern.finditer(data))
        allowed = {b"pubkeyauthentication": b"yes", b"exposeauthinfo": b"yes",
                   b"authenticationmethods": b"publickey", b"passwordauthentication": b"no",
                   b"kbdinteractiveauthentication": b"no", b"permitrootlogin": b"prohibit-password"}
        for block in blocks:
            lines = block.group().splitlines()[1:-1]
            if not lines or lines[0] != b"Match User " + block.group(1):
                raise ToolError("sshkeytool 标记块格式不支持。")
            for line in lines[1:]:
                fields = line.split(None, 1)
                if len(fields) != 2 or allowed.get(fields[0].lower()) != fields[1]:
                    raise ToolError("sshkeytool 标记块含有未知策略，停止自动修改。")
        return blocks

    def candidate_config(self, original):
        if self.legacy_hook() in original:
            return original.replace(self.legacy_hook(), self.hook(), 1)
        blocks = self.key_blocks(original)
        if blocks:
            position = blocks[0].start()
            return original[:position] + self.hook() + original[position:]
        return original + (b"\n" if original and not original.endswith(b"\n") else b"") + self.hook()

    def check_hook(self, data):
        if BEGIN.encode() not in data and END.encode() not in data:
            return False
        hook = self.hook() if self.hook() in data else self.legacy_hook()
        if data.count(hook) != 1 or data.count(BEGIN.encode()) != 1 or data.count(END.encode()) != 1:
            raise ToolError("主配置中的 sshpasswdtool Include 被修改，请先检查该标记块。")
        tail = data.split(hook, 1)[1]
        # Include 可以位于已识别的 sshkeytool 块前；到期后空入口继续继承它们。
        for block in reversed(self.key_blocks(tail)):
            tail = tail[:block.start()] + tail[block.end():]
        if any(line.strip() and not line.lstrip().startswith(b"#") for line in tail.splitlines()):
            raise ToolError("认证 Include 后面出现了未知配置，请检查完整标记块的位置。")
        return True

    def auth_content(self, state):
        text = ("# sshpasswdtool operation " + state["token"] + "\nMatch User " + state["user"] +
                "\n    PasswordAuthentication yes\n    KbdInteractiveAuthentication no\n")
        # OpenSSH 9.2 在读取已有 any 后，再遇到任何块中的 any 会拒绝完整配置。
        # any 基线直接继承；显式 publickey 才在开启期间增加独立 password 选项。
        if state["baseline"].get("authenticationmethods", "any") == "publickey":
            text += "    AuthenticationMethods publickey password\n"
        if state["user"] == "root":
            text += "    PermitRootLogin yes\n"
        return (text + "Match all\n").encode()

    def backup(self, token, data, metadata):
        directory = self.state_dir / "backups"
        private_dir(directory)
        value = {"tool": TOOL_ID, "path": str(self.config), "data": base64.b64encode(data).decode(),
                 "sha256": digest(data), "mode": stat.S_IMODE(metadata.st_mode),
                 "uid": metadata.st_uid, "gid": metadata.st_gid}
        path = directory / (token + ".json")
        atomic_write(path, canonical(value))
        saved = json.loads(path.read_text())
        if digest(base64.b64decode(saved["data"], validate=True)) != saved["sha256"]:
            raise ToolError("配置备份重新读取校验失败，尚未开启密码登录。")

    def units(self, token):
        stem = "sshpasswdtool-" + token
        return self.unit_dir / (stem + ".service"), self.unit_dir / (stem + ".timer")

    def prepare_job(self, state, seconds):
        # 保存独立执行器，直接运行仓库文件或升级命令也不会丢失当前回退程序。
        runner = self.state_dir / "expire_runner.py"
        atomic_write(runner, Path(__file__).read_bytes(), 0o700)
        service, timer = self.units(state["token"])
        regular_file(service)
        regular_file(timer)
        if service.exists() or timer.exists():
            raise ToolError("定时任务文件已存在，停止修改。")
        command = " ".join(unit_quote(value) for value in
                           (os.path.realpath(sys.executable), runner, "expire", "--token", state["token"]))
        content = ("# Managed by sshpasswdtool\n[Unit]\nDescription=Restore temporary SSH password policy\n"
                   "StartLimitIntervalSec=0\n[Service]\nType=oneshot\nExecStart=" + command +
                   "\nTimeoutStartSec=120s\nRestart=on-failure\nRestartSec=30s\n")
        atomic_write(service, content.encode(), 0o644)
        if seconds is not None:
            content = ("# Managed by sshpasswdtool\n[Unit]\nDescription=Expire temporary SSH password login\n"
                       "[Timer]\nOnActiveSec=" + str(seconds) + "s\nAccuracySec=1s\nUnit=" + service.name + "\n")
            atomic_write(timer, content.encode(), 0o644)
        self.backend.ctl("daemon-reload")
        if seconds is not None:
            self.backend.ctl("start", timer.name)
            self.backend.ctl("is-active", "--quiet", timer.name)

    def clean_job(self, state):
        if operation_mode(state) == "permanent":
            return []
        service, timer = self.units(state["token"])
        warnings = []
        try:
            self.backend.ctl("stop", timer.name, check=False)
            for path in (timer, service):
                regular_file(path)
                if path.exists():
                    if not path.read_bytes().startswith(b"# Managed by sshpasswdtool\n"):
                        raise ToolError("任务文件被外部修改：" + str(path))
                    path.unlink()
            self.backend.ctl("daemon-reload")
        except (ToolError, OSError) as exc:
            warnings.append("临时认证已撤销，但任务清理未完成：" + str(exc))
        # 不能 stop 正在执行此代码的 service，也不能等待一个正等操作锁的旧 worker。
        return warnings

    def remove_auth(self, state):
        path = self.auth_path(state)
        if path.parent.is_symlink():
            raise ToolError("认证配置目录被替换为符号链接，停止删除。")
        regular_file(path)
        if path.exists():
            prefix = ("# sshpasswdtool operation " + state["token"] + "\n").encode()
            if not path.read_bytes().startswith(prefix):
                raise ToolError("认证文件无法关联到当前操作，拒绝删除：" + str(path))
            path.unlink()
            sync_dir(path.parent)

    def finish(self, state):
        try:
            self.remove_auth(state)
            self.backend.validate()
            self.backend.reload(state["service"])
            actual = self.backend.effective(state["user"], state["context"])
            if password_available(actual, state["user"]):
                raise ToolError("本工具的认证配置已撤销，但其他 SSH 配置仍允许密码/键盘交互登录。")
        except (ToolError, OSError) as exc:
            state["phase"] = "restore_failed"
            state["last_error"] = str(exc)
            self.save_state(state)
            raise ToolError("恢复尚未完成：" + str(exc) + "\n请保留现有会话，修复后运行 sshpasswdtool close。") from exc
        state["phase"] = "closed"
        state["closed_at"] = time.time()
        state.pop("last_error", None)
        self.save_state(state)
        return self.clean_job(state)

    def enable(self, user="root", minutes=30, until_reboot=False, permanent=False):
        validate_user(user)
        if until_reboot and permanent:
            raise ToolError("永久模式不能同时选择直到重启。")
        mode = "permanent" if permanent else "until_reboot" if until_reboot else "timed"
        if mode == "timed" and (not isinstance(minutes, int) or not 1 <= minutes <= 10080):
            raise ToolError("时间应为 1～10080 分钟。")
        with self.lock():
            regular_file(self.key_active)
            if self.key_active.exists():
                raise ToolError("SSH 密钥工具有待确认或待恢复的操作；请先完成该操作再开启密码。")
            old = self.load_state()
            if old and old["phase"] in ACTIVE_PHASES:
                if (operation_mode(old) != "permanent" and old["boot_id"] != self.boot_id()
                        and not self.has_auth()):
                    self.finish(old)
                else:
                    raise ToolError("已有密码登录操作（用户 " + old["user"] + "）；请先运行 sshpasswdtool close。")
            private_dir(self.runtime_dir)
            for path in (self.auth_file, self.persistent_auth_file):
                regular_file(path)
            if self.has_auth():
                raise ToolError("发现未登记的认证文件，停止修改。")
            regular_file(self.config)
            original = self.config.read_bytes()
            metadata = self.config.stat()
            has_hook = self.check_hook(original)
            service = self.backend.service()
            self.backend.check_account(user)
            self.backend.validate()
            context = connection_context()
            baseline = self.backend.effective(user, context)
            check_baseline(baseline, user)
            state = {"tool": TOOL_ID, "version": 1, "token": uuid.uuid4().hex, "user": user,
                     "service": service, "boot_id": self.boot_id(), "context": context,
                     "baseline": baseline, "mode": mode, "phase": "preparing", "created_at": time.time(),
                     "expires_at": None, "expires_monotonic": None, "auth_sha256": ""}
            content = self.auth_content(state)
            state["auth_sha256"] = digest(content)
            self.backup(state["token"], original, metadata)
            self.save_state(state)
            candidate = None
            try:
                if self.hook() not in original:
                    candidate = self.candidate_config(original)
                    fd, preview = tempfile.mkstemp(prefix=".sshpasswdtool-check-", dir=str(self.config.parent))
                    try:
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(candidate)
                        self.backend.validate(Path(preview))
                        if self.backend.effective(user, context, Path(preview)) != baseline:
                            raise ToolError("空 Include 改变了原有配置，停止开启。")
                    finally:
                        os.unlink(preview)
                    if self.config.read_bytes() != original:
                        raise ToolError("SSH 主配置在准备期间改变，停止写入。")
                    atomic_write(self.config, candidate, stat.S_IMODE(metadata.st_mode),
                                 (metadata.st_uid, metadata.st_gid))
                self.backend.validate()
                if self.backend.effective(user, context) != baseline:
                    raise ToolError("空 Include 改变了原有配置，停止开启。")
                seconds = minutes * 60 if mode == "timed" else None
                if seconds is not None:
                    state["expires_at"] = time.time() + seconds
                    state["expires_monotonic"] = time.monotonic() + seconds
                    self.save_state(state)
                # 定时任务先验证为 active，随后才创建密码认证配置。
                if mode != "permanent":
                    self.prepare_job(state, seconds)
                atomic_write(self.auth_path(state), content)
                self.backend.validate()
                effective = self.backend.effective(user, context)
                if (effective.get("passwordauthentication") != "yes" or
                        effective.get("pubkeyauthentication") != "yes" or
                        effective.get("kbdinteractiveauthentication") != "no" or
                        not password_available(effective, user)):
                    raise ToolError("密码规则未实际生效，可能被更早的 Match 策略限制。")
                if state["expires_monotonic"] is not None and time.monotonic() >= state["expires_monotonic"]:
                    raise ToolError("准备时间已超过临时窗口，停止开启。")
                self.backend.reload(service)
                state["phase"] = "active"
                self.save_state(state)
            except BaseException as exc:
                # 撤销只移除本次认证文件，保留其他工具的改动；兼容旧入口升级。
                try:
                    if candidate is not None:
                        current = self.config.read_bytes()
                        if current == candidate:
                            atomic_write(self.config, original, stat.S_IMODE(metadata.st_mode),
                                         (metadata.st_uid, metadata.st_gid))
                        elif current.count(self.hook()) == 1:
                            current_metadata = self.config.stat()
                            replacement = self.legacy_hook() if has_hook else b""
                            atomic_write(self.config, current.replace(self.hook(), replacement, 1),
                                         stat.S_IMODE(current_metadata.st_mode),
                                         (current_metadata.st_uid, current_metadata.st_gid))
                    self.finish(state)
                except (ToolError, OSError) as restore_error:
                    raise ToolError("开启失败：" + str(exc) + "\n" + str(restore_error)) from exc
                raise
            return state

    def close(self, token=None):
        with self.lock(wait=token is not None):
            state = self.load_state()
            if token and (not state or state["token"] != token):
                return []
            # 永久模式只接受手动 close，即使有旧 worker 也不能撤销它。
            if token and operation_mode(state) == "permanent":
                return []
            if not state or state["phase"] == "closed":
                if self.has_auth():
                    raise ToolError("发现未登记的认证文件，不能报告已关闭；请检查 /run/sshpasswdtool 和 /var/lib/sshpasswdtool。")
                return []
            try:
                return self.finish(state)
            except ToolError:
                service = self.units(state["token"])[0]
                if token is None and operation_mode(state) != "permanent" and service.exists():
                    # 手动 close 失败也交给独立 service 重试；不持锁等待 worker。
                    with contextlib.suppress(ToolError):
                        self.backend.ctl("start", "--no-block", service.name, check=False)
                raise

    def status(self, user="root"):
        validate_user(user)
        options = self.backend.effective(user, connection_context())
        print("目标用户：" + user)
        print("当前磁盘配置（按当前来源或本地 127.0.0.1 解析）：")
        for key in ("pubkeyauthentication", "passwordauthentication", "kbdinteractiveauthentication",
                    "permitrootlogin", "authenticationmethods"):
            print("  " + key + ": " + options.get(key, "未知"))
        print("密码登录路径：" + ("配置允许（仍受账户、PAM、Allow/Deny 等规则限制）" if password_available(options, user)
                                  else "配置禁止"))
        state = self.load_state()
        if not state or state["phase"] == "closed":
            print("密码登录管理：未开启")
            if self.has_auth():
                print("警告：存在未登记的认证文件，请检查 /run/sshpasswdtool 和 /var/lib/sshpasswdtool。")
            return
        print("操作用户：" + state["user"])
        mode = operation_mode(state)
        path = self.auth_path(state)
        if state["phase"] == "restore_failed":
            print("密码登录管理：恢复失败，需运行 close 重试。\n" + state.get("last_error", ""))
        elif mode == "permanent":
            print("永久模式：" + state["phase"] + "，重启后继续生效，直到手动 close。")
        elif state["boot_id"] != self.boot_id() and not path.exists():
            print("临时窗口：重启后已失效；/run 临时文件不存在。")
        elif mode == "until_reboot":
            print("临时窗口：本次开机有效，重启或 close 后关闭。")
        else:
            remaining = max(0, int(state["expires_monotonic"] - time.monotonic()))
            deadline = datetime.datetime.fromtimestamp(state["expires_at"]).astimezone().isoformat(timespec="seconds")
            print("临时窗口：" + state["phase"] + "，剩余约 " + str(remaining) + " 秒；预计截止 " + deadline)
            timer = self.units(state["token"])[1]
            if self.backend.ctl("is-active", "--quiet", timer.name, check=False).returncode != 0:
                print("警告：定时器当前未运行，请检查恢复任务或立即 close。")
        regular_file(path)
        if path.exists() and digest(path.read_bytes()) != state["auth_sha256"]:
            print("警告：认证文件已被修改。")
        elif not path.exists() and (mode == "permanent" or state["boot_id"] == self.boot_id()):
            print("认证文件不存在；需 close 核验并重载运行中的 SSH。")


def confirm(message, yes=False):
    if yes:
        return True
    if not sys.stdin.isatty():
        raise ToolError("非交互修改需要 --yes；可先运行 status 查看配置。")
    return input(message + " [y/N] ").strip().lower() in {"y", "yes", "是"}


def set_password(user):
    validate_user(user)
    if not sys.stdin.isatty():
        raise ToolError("设置密码需要交互终端。")
    result = subprocess.run(["passwd", user])
    if result.returncode:
        raise ToolError("密码未设置成功。")
    print("系统用户密码已修改；关闭密码登录不会还原或删除该密码。")


def enabled_message(state):
    if operation_mode(state) == "permanent":
        deadline = "永久有效，重启后继续生效，直到手动关闭"
    elif state["expires_at"] is None:
        deadline = "本次开机期间有效，重启后自动恢复"
    else:
        deadline = "约 " + str(max(0, int((state["expires_monotonic"] - time.monotonic() + 59) / 60))) + " 分钟后或重启时恢复"
    print("已为 " + state["user"] + " 允许密码认证；" + deadline + "。密钥认证继续允许。")
    print("请另开一个新连接测试密码登录；立即结束：sudo sshpasswdtool close")


def menu(tool, user):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ToolError("菜单需要交互终端；使用 sshpasswdtool --help 查看命令。")
    while True:
        print("\nSSH 密码登录管理 v" + VERSION + "  目标用户：" + user)
        print("1. 查看状态\n2. 临时开启（定时，默认 30 分钟）\n3. 临时开启（直到重启）\n"
              "4. 关闭密码登录（临时 / 永久）\n5. 设置/修改用户密码\n6. 切换目标用户\n"
              "7. 永久开启（直到手动关闭）\n0. 返回")
        try:
            choice = input("请选择：").strip()
            if choice == "0":
                return
            if choice == "1":
                tool.status(user)
            elif choice in {"2", "3"}:
                minutes = 30
                if choice == "2":
                    value = input("开放多少分钟 [30]：").strip() or "30"
                    if not value.isdigit():
                        raise ToolError("请输入整数分钟。")
                    minutes = int(value)
                if confirm("为 " + user + " 临时开启密码登录？"):
                    enabled_message(tool.enable(user, minutes, choice == "3"))
            elif choice == "4":
                if confirm("关闭本工具开启的密码登录并恢复原认证策略？"):
                    for warning in tool.close():
                        print(warning, file=sys.stderr)
                    print("本工具的密码许可已关闭；已登录会话仍保持连接。")
            elif choice == "5":
                set_password(user)
            elif choice == "6":
                candidate = input("用户名 [root]：").strip() or "root"
                validate_user(candidate)
                user = candidate
            elif choice == "7":
                if confirm("为 " + user + " 永久开启密码登录，重启后保留，直到手动关闭？"):
                    enabled_message(tool.enable(user, permanent=True))
            else:
                print("无效选项。")
        except (ToolError, OSError) as exc:
            print("错误：" + str(exc), file=sys.stderr)
        except (EOFError, KeyboardInterrupt):
            return


def build_parser():
    parser = argparse.ArgumentParser(description="指定用户开启 SSH 密码登录；支持定时、直到重启或永久模式。")
    parser.add_argument("--version", action="version", version="sshpasswdtool " + VERSION)
    sub = parser.add_subparsers(dest="command")
    for command in ("status", "menu", "passwd"):
        child = sub.add_parser(command)
        child.add_argument("--user", default="root")
    child = sub.add_parser("enable", help="开启密码登录，默认 30 分钟；可选择永久模式")
    child.add_argument("--user", default="root")
    mode = child.add_mutually_exclusive_group()
    mode.add_argument("--minutes", type=int, default=30)
    mode.add_argument("--until-reboot", action="store_true")
    mode.add_argument("--permanent", action="store_true", help="重启后保留，直到手动 close")
    child.add_argument("--yes", action="store_true")
    child = sub.add_parser("close", help="关闭本工具开启的密码登录（临时 / 永久）")
    child.add_argument("--yes", action="store_true")
    child = sub.add_parser("expire", help="内部恢复任务")
    child.add_argument("--token", required=True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if platform.system() != "Linux":
        print("请在 Linux VPS 上使用。", file=sys.stderr)
        return 1
    if os.geteuid() != 0:
        if sys.stdin.isatty() and shutil.which("sudo"):
            os.execvp("sudo", ["sudo", "--preserve-env=SSH_CONNECTION,SSH_CLIENT,SSH_TTY", "--",
                               sys.executable, str(Path(__file__).resolve()), *(sys.argv[1:] if argv is None else argv)])
        print("需要 root；请运行 sudo sshpasswdtool ...。", file=sys.stderr)
        return 1
    tool = PasswordTool()
    try:
        if args.command in (None, "menu"):
            menu(tool, getattr(args, "user", "root"))
        elif args.command == "status":
            tool.status(args.user)
        elif args.command == "passwd":
            set_password(args.user)
        elif args.command == "enable":
            message = "永久开启密码登录，重启后保留，直到手动关闭？" if args.permanent else "临时开启密码登录？"
            if confirm("为 " + args.user + " " + message, args.yes):
                enabled_message(tool.enable(args.user, args.minutes, args.until_reboot, args.permanent))
        elif args.command == "close":
            if confirm("关闭本工具开启的密码登录（临时 / 永久）？", args.yes):
                for warning in tool.close():
                    print(warning, file=sys.stderr)
                print("本工具的密码许可已关闭；已登录会话仍保持连接。")
        elif args.command == "expire":
            for warning in tool.close(args.token):
                print(warning, file=sys.stderr)
    except (ToolError, OSError) as exc:
        print("错误：" + str(exc), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
