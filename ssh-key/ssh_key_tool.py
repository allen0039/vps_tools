#!/usr/bin/env python3
"""指定用户的 SSH 公钥管理；独立回退、两阶段新连接验证。"""
import argparse
import base64
import contextlib
import datetime
import fcntl
import glob
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

TOOL_ID = "vps-tools-sshkeytool"
VERSION = "0.1.0"
PENDING = {"generating", "preparing", "await_key", "await_before", "await_after", "rollback_failed"}
FINISHED = {"committed", "rolled_back"}
MAX_INPUT = 1024 * 1024
MAX_KEYS = 128
AUTH_FIELDS = ("pubkeyauthentication", "passwordauthentication", "kbdinteractiveauthentication",
               "permitrootlogin", "authenticationmethods", "authorizedkeysfile",
               "authorizedkeyscommand", "trustedusercakeys", "forcecommand", "chrootdirectory",
               "gssapiauthentication", "hostbasedauthentication", "exposeauthinfo")


class ToolError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def run(args):
    try:
        p = subprocess.run([str(a) for a in args], stdin=subprocess.DEVNULL, text=True,
                           capture_output=True, timeout=30, env=dict(os.environ, LC_ALL="C"))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError("命令无法执行：" + str(args[0]) + "：" + str(exc)) from exc
    if p.returncode:
        raise ToolError("命令失败：" + shlex.join([str(a) for a in args]) + "\n" + p.stderr.strip())
    return p.stdout


def regular(path):
    path = Path(path)
    # 拒绝父目录符号链接，不能只检查最终路径。
    for part in (path,) + tuple(path.parents):
        if part.is_symlink():
            raise ToolError("拒绝符号链接路径：" + str(part))
    if path.exists() and not path.is_file():
        raise ToolError("不是普通文件：" + str(path))


def sync_dir(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600, owner=None):
    path = Path(path)
    regular(path)
    fd, temporary = tempfile.mkstemp(prefix=".sshkeytool-", dir=str(path.parent))
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


def snapshot(path):
    regular(path)
    if not path.exists():
        return {"exists": False}
    s = path.stat()
    data = path.read_bytes()
    return {"exists": True, "data": base64.b64encode(data).decode(), "sha256": digest(data),
            "mode": stat.S_IMODE(s.st_mode), "uid": s.st_uid, "gid": s.st_gid}


def unpacksnap(value):
    try:
        data = base64.b64decode(value["data"], validate=True)
        if digest(data) != value["sha256"]:
            raise ValueError("checksum")
        return data
    except (ValueError, KeyError, TypeError) as exc:
        raise ToolError("备份内容或校验值无效。") from exc


def same_snapshot(a, b):
    keys = ("exists", "sha256", "mode", "uid", "gid")
    return all(a.get(k) == b.get(k) for k in keys)


def restore(path, value):
    regular(path)
    if value["exists"]:
        atomic(path, unpacksnap(value), value["mode"], (value["uid"], value["gid"]))
    elif path.exists():
        path.unlink()
        sync_dir(path.parent)


def safe_name(user):
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?", user):
        raise ToolError("用户名格式不支持。")
    return user


def connection(value=None):
    items = (os.environ.get("SSH_CONNECTION", "") if value is None else value).split()
    if len(items) != 4:
        raise ToolError("需要可识别的 SSH 新连接；请在 SSH 会话中运行，并保留 SSH_CONNECTION。")
    try:
        ipaddress.ip_address(items[0])
        ipaddress.ip_address(items[2])
        if not all(1 <= int(p) <= 65535 for p in (items[1], items[3])):
            raise ValueError("port")
    except ValueError as exc:
        raise ToolError("SSH_CONNECTION 的地址或端口无效。") from exc
    return items


def parse_effective(text):
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition(" ")
        if sep:
            result[key.lower()] = value.strip()
    return result


def password_allowed(user, settings):
    if user == "root" and settings.get("permitrootlogin") in (
            "no", "prohibit-password", "without-password", "forced-commands-only"):
        return False
    methods = settings.get("authenticationmethods", "any")
    return settings.get("passwordauthentication") == "yes" and (
        methods == "any" or any("password" in x.split(",") for x in methods.split()))


def keyboard_allowed(user, settings):
    if user == "root" and settings.get("permitrootlogin") in (
            "no", "prohibit-password", "without-password", "forced-commands-only"):
        return False
    methods = settings.get("authenticationmethods", "any")
    return settings.get("kbdinteractiveauthentication") == "yes" and (
        methods == "any" or any(any(m.startswith("keyboard-interactive") for m in x.split(","))
                               for x in methods.split()))


def key_only(user, settings):
    if settings.get("pubkeyauthentication") != "yes":
        return False
    if user == "root" and settings.get("permitrootlogin") in ("no", "forced-commands-only"):
        return False
    methods = settings.get("authenticationmethods", "any")
    if methods != "any":
        return all(all(m == "publickey" for m in alternative.split(","))
                   for alternative in methods.split())
    return not (password_allowed(user, settings) or keyboard_allowed(user, settings) or
                settings.get("gssapiauthentication") == "yes" or
                settings.get("hostbasedauthentication") == "yes")


def managed_pattern(user):
    return re.compile(rb"(?m)^# BEGIN sshkeytool " + user.encode() +
                      rb"\n.*?^# END sshkeytool " + user.encode() + rb"\n?", re.S)


def policy_config(original, user, strict=False):
    safe_name(user)
    pattern = managed_pattern(user)
    matches = list(pattern.finditer(original))
    if len(matches) > 1:
        raise ToolError("重复的 sshkeytool 配置块，请先检查。")
    # 不把临时准备阶段降级为比已有工具策略更宽松。
    previous = matches[0].group() if matches else b""
    if previous and b"AuthenticationMethods publickey\n" in previous:
        strict = True
    rest = pattern.sub(b"", original)
    if rest and not rest.endswith(b"\n"):
        rest += b"\n"
    lines = ["# BEGIN sshkeytool " + user, "Match User " + user,
             "    PubkeyAuthentication yes", "    ExposeAuthInfo yes"]
    if strict:
        lines.extend(["    AuthenticationMethods publickey", "    PasswordAuthentication no",
                      "    KbdInteractiveAuthentication no"])
        if user == "root":
            lines.append("    PermitRootLogin prohibit-password")
    lines.append("# END sshkeytool " + user)
    return rest + ("\n".join(lines) + "\n").encode()


def key_fields(line):
    """只解析授权文件结构；密钥材料交给 ssh-keygen 校验。"""
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    try:
        tokens = shlex.split(line, comments=False)
    except ValueError as exc:
        raise ToolError("授权公钥存在引号不完整的记录。") from exc
    for index in (0, 1):
        if index + 1 < len(tokens) and re.fullmatch(
                r"(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+", tokens[index]):
            return {"type": tokens[index], "blob": tokens[index + 1],
                    "options": tokens[0] if index else "",
                    "comment": " ".join(tokens[index + 2:]), "line": line.strip()}
    raise ToolError("授权公钥记录格式无法识别。")


class Manager:
    def __init__(self, root=Path("/"), runner=run, users=pwd.getpwnam, clock=time.time):
        self.root = Path(root).resolve()
        self.runner, self.users, self.clock = runner, users, clock
        self.config = self.path("/etc/ssh/sshd_config")
        self.state_dir = self.path("/var/lib/sshkeytool")
        self.operations = self.state_dir / "operations"
        self.pending_keys = self.state_dir / "pending-keys"
        self.active_path = self.state_dir / "active.json"
        self.lock_path = self.path("/run/lock/vpstools-ssh.lock")
        self.systemd = self.path("/etc/systemd/system")
        self.sshd = "/usr/sbin/sshd"
        self.service = None

    def path(self, value):
        absolute = Path(value)
        if absolute == self.root or self.root in absolute.parents:
            return absolute
        return self.root / value.lstrip("/")

    def private_dir(self, path):
        for parent in (path,) + tuple(path.parents):
            if parent.is_symlink():
                raise ToolError("状态目录不能是符号链接。")
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        s = path.stat()
        if s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) & 0o077:
            raise ToolError("状态目录属主或权限不安全：" + str(path))

    @contextlib.contextmanager
    def locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        regular(self.lock_path)
        fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_uid != os.geteuid():
                raise ToolError("SSH 操作锁属主不正确。")
            # 定时回退可短暂等待；交互程序不持锁等待用户输入。
            limit = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= limit:
                        raise ToolError("另一个 SSH 配置操作正在运行。")
                    time.sleep(0.1)
            self.private_dir(self.state_dir)
            self.private_dir(self.operations)
            self.private_dir(self.pending_keys)
            yield
        finally:
            os.close(fd)

    def write_json(self, path, payload):
        atomic(path, canonical({"payload": payload, "sha256": digest(canonical(payload))}))
        self.read_json(path)

    def read_json(self, path):
        regular(path)
        try:
            wrapper = json.loads(path.read_bytes())
            value = wrapper["payload"]
            if wrapper["sha256"] != digest(canonical(value)):
                raise ValueError("checksum")
            return value
        except (ValueError, KeyError, TypeError) as exc:
            raise ToolError("状态/备份校验失败：" + str(path)) from exc

    def state_path(self, ident):
        if not re.fullmatch(r"[0-9a-f]{32}", ident):
            raise ToolError("操作编号必须是 32 位十六进制字符。")
        return self.operations / ident / "state.json"

    def load(self, ident):
        path = self.state_path(ident)
        if not path.exists():
            raise ToolError("操作记录不存在。")
        value = self.read_json(path)
        if value.get("id") != ident or value.get("version") != 1:
            raise ToolError("操作记录版本或编号不一致。")
        return value

    def save(self, state):
        self.write_json(self.state_path(state["id"]), state)

    def active(self):
        if not self.active_path.exists():
            return None
        return self.load(self.read_json(self.active_path)["id"])

    def user(self, name):
        safe_name(name)
        try:
            return self.users(name)
        except KeyError as exc:
            raise ToolError("用户不存在：" + name) from exc

    def effective(self, name, conn=None, config=None):
        args = [self.sshd, "-T", "-f", str(config or self.config)]
        if conn is None:
            try:
                conn = connection()
            except ToolError:
                conn = ["127.0.0.1", "1", "127.0.0.1", "22"]
        args += ["-C", "user=%s,addr=%s,host=%s,laddr=%s,lport=%s" %
                 (name, conn[0], conn[0], conn[2], conn[3])]
        return parse_effective(self.runner(args))

    def fingerprint(self, material):
        with tempfile.TemporaryDirectory(prefix="sshkeytool-key-") as d:
            key = Path(d) / "public.pub"
            key.write_text(material + "\n")
            key.chmod(0o600)
            output = self.runner(["ssh-keygen", "-l", "-E", "sha256", "-f", str(key)])
        match = re.search(r"\bSHA256:[A-Za-z0-9+/]+", output)
        if not match:
            raise ToolError("OpenSSH 未返回合法公钥指纹。")
        return match.group()

    def parse_keys(self, data):
        if len(data) > MAX_INPUT:
            raise ToolError("公钥文件超过 1 MiB。")
        try:
            lines = data.decode("utf-8").splitlines()
        except UnicodeError as exc:
            raise ToolError("公钥文件必须是 UTF-8 文本。") from exc
        result = []
        for number, line in enumerate(lines, 1):
            fields = key_fields(line)
            if fields:
                if "-cert-" in fields["type"] or "cert-authority" in fields["options"]:
                    raise ToolError("第一版只管理普通公钥；证书/CA 记录保留并停止自动修改。")
                fields["fingerprint"] = self.fingerprint(fields["type"] + " " + fields["blob"])
                fields["number"] = number
                result.append(fields)
                if len(result) > MAX_KEYS:
                    raise ToolError("第一版最多管理 128 条公钥记录。")
        return result

    def key_paths(self, name, settings):
        info = self.user(name)
        result = []
        for token in settings.get("authorizedkeysfile", "").split():
            if token == "none":
                continue
            token = token.replace("%%", "\x00").replace("%h", info.pw_dir)
            token = token.replace("%u", name).replace("%U", str(info.pw_uid)).replace("\x00", "%")
            if "%" in token or any(c in token for c in "*?["):
                raise ToolError("第一版不修改带未知 token 或通配符的公钥路径。")
            absolute = Path(token) if token.startswith("/") else Path(info.pw_dir) / token
            path = self.path(str(absolute))
            if path not in result:
                result.append(path)
        return result

    def status(self, name):
        settings = self.effective(name)
        paths = self.key_paths(name, settings)
        keys, issues = [], []
        for path in paths:
            try:
                regular(path)
                if path.exists():
                    for key in self.parse_keys(path.read_bytes()):
                        key["file"] = str(path)
                        keys.append(key)
                    s = path.stat()
                    if s.st_uid not in (0, self.user(name).pw_uid) or s.st_mode & 0o022:
                        issues.append("授权文件属主/权限需要检查：" + str(path))
            except ToolError as exc:
                issues.append(str(exc))
        active = self.active() if self.active_path.exists() else None
        verification = None
        if self.operations.exists():
            states = [self.load(p.parent.name) for p in self.operations.glob("*/state.json")]
            states = sorted((s for s in states if s["user"] == name), key=lambda s: s["created"], reverse=True)
            for state in states:
                if state["phase"] == "committed" and state["verified"]:
                    proof = state["verified"][-1]
                    try:
                        valid = state["baseline"] == self.configuration_stamp()
                        valid = valid and state.get("key_baseline") == self.authorization_stamp(name, settings)
                    except (ToolError, OSError) as exc:
                        valid = False
                        issues.append(str(exc))
                    verification = {"id": state["id"], "valid": valid, **proof}
                    break
        return {"user": name, "effective": {k: settings.get(k, "未知") for k in AUTH_FIELDS},
                "pubkey_allowed": settings.get("pubkeyauthentication") == "yes" and
                 not (name == "root" and settings.get("permitrootlogin") == "no"),
                "password_allowed": password_allowed(name, settings),
                "keyboard_allowed": keyboard_allowed(name, settings), "key_only": key_only(name, settings),
                "keys": keys, "issues": issues, "scope": os.environ.get("SSH_CONNECTION", "本机回环模拟；非公网连接验证"),
                "verification": verification,
                "active": {k: active[k] for k in ("id", "user", "phase", "deadline")} if active else None}

    def configuration_files(self):
        files, seen = [], set()

        def walk(path, depth=0):
            if depth > 16:
                raise ToolError("SSH Include 嵌套过深。")
            regular(path)
            if path in seen:
                raise ToolError("重复或循环的 SSH Include，请先整理配置。")
            seen.add(path)
            files.append(path)
            for line in path.read_text().splitlines():
                try:
                    parts = shlex.split(line, comments=True)
                except ValueError as exc:
                    raise ToolError("SSH 配置引号不完整。") from exc
                if parts and parts[0].lower() == "include":
                    for token in parts[1:]:
                        absolute = token if token.startswith("/") else "/etc/ssh/" + token
                        for child in sorted(glob.glob(str(self.path(absolute)))):
                            walk(Path(child), depth + 1)
        walk(self.config)
        return files

    def configuration_stamp(self):
        return {str(p): digest(p.read_bytes()) for p in self.configuration_files()}

    def authorization_stamp(self, name, settings=None):
        result = {}
        for path in self.key_paths(name, settings or self.effective(name)):
            value = snapshot(path)
            value.pop("data", None)
            result[str(path)] = value
        return result

    def preflight(self, name):
        if platform.system() != "Linux" or os.geteuid() != 0:
            raise ToolError("修改操作需要在 Linux VPS 上以 root/sudo 运行。")
        os_release = self.path("/etc/os-release").read_text()
        if not re.search(r"(?m)^ID=(?:\"?)(debian|ubuntu)(?:\"?)$", os_release):
            raise ToolError("第一版自动修改支持 Debian/Ubuntu。")
        if self.active():
            raise ToolError("已有待确认/待恢复操作，请先 confirm、rollback 或查看 history。")
        if self.path("/var/lib/safe-ssh-port/state").exists():
            raise ToolError("SSH 端口工具存在未结束操作，请先处理。")
        self.runner([self.sshd, "-t", "-f", str(self.config)])
        self.service = self.detect_service()
        settings = self.effective(name)
        for key in ("authorizedkeyscommand", "trustedusercakeys", "forcecommand", "chrootdirectory"):
            if settings.get(key, "none") != "none":
                raise ToolError("第一版不自动修改 %s 的自定义认证环境。" % key)
        if settings.get("authenticationmethods", "any") not in ("any", "publickey"):
            raise ToolError("已有多因素/多密钥认证，第一版仅显示，不重写。")
        if name == "root" and settings.get("permitrootlogin") in ("no", "forced-commands-only"):
            raise ToolError("root 被禁止或限为强制命令，不自动扩大登录权限。")
        paths = self.key_paths(name, settings)
        if not paths:
            raise ToolError("未配置文件公钥路径。")
        home = self.path(self.user(name).pw_dir)
        for p in paths:
            regular(p)
            if home not in p.parents:
                raise ToolError("第一版仅修改该用户家目录内的授权文件。")
            if p.parent not in (home, home / ".ssh"):
                raise ToolError("第一版仅修改家目录或 .ssh 目录内的授权文件。")
            if p.exists():
                self.parse_keys(p.read_bytes())
        for directory in (home, home / ".ssh"):
            if directory.is_symlink():
                raise ToolError("用户 SSH 目录不能是符号链接。")
            if directory.exists() and (directory.stat().st_uid not in (0, self.user(name).pw_uid)
                                       or directory.stat().st_mode & 0o022):
                raise ToolError("请先修复目录属主和组/其他用户写权限：" + str(directory))
        # 不修改外部包含的 Match；发现 Host 条件时缺少 DNS 上下文，停止自动修改。
        for p in self.configuration_files():
            for line in p.read_text().splitlines():
                if re.search(r"(?i)^\s*Match\s+.*\bHost\b", line):
                    raise ToolError("发现按 Host 匹配的规则，第一版不自动修改。")
        return settings, paths

    def detect_service(self):
        if self.runner(["systemctl", "show", "-p", "SystemState", "--value"]).strip() not in ("running", "degraded"):
            raise ToolError("需要运行中的 systemd。")
        for service in ("ssh.service", "sshd.service"):
            try:
                self.runner(["systemctl", "is-active", "--quiet", service])
            except ToolError:
                continue
            pid = int(self.runner(["systemctl", "show", "-p", "MainPID", "--value", service]).strip())
            try:
                args = self.path("/proc/%d/cmdline" % pid).read_bytes().replace(b"\x00", b" ").decode()
            except (OSError, UnicodeError) as exc:
                raise ToolError("无法识别 SSH 服务进程。") from exc
            if not re.fullmatch(r"(?:sshd: )?/usr/sbin/sshd -D(?: \[listener\].*)?\s*", args):
                raise ToolError("发现自定义 SSH 启动参数，第一版只读检测，不自动修改。")
            return service
        raise ToolError("未找到运行中的 ssh.service/sshd.service。")

    def reload(self, state):
        self.runner([self.sshd, "-t", "-f", str(self.config)])
        self.runner(["systemctl", "reload", state["service"]])
        self.runner(["systemctl", "is-active", "--quiet", state["service"]])

    def arm(self, state):
        ident = state["id"]
        script = self.operations / ident / "runner.py"
        if not script.exists():
            atomic(script, Path(__file__).read_bytes())
        # OnCalendar 的格式精度为秒，向上取整避免提前触发后被超时检查忽略。
        deadline = datetime.datetime.fromtimestamp(math.ceil(state["deadline"]), datetime.timezone.utc)
        name = "sshkeytool-" + ident
        service = ("[Unit]\nDescription=SSH key operation rollback\nAfter=local-fs.target\n"
                   "[Service]\nType=oneshot\nExecStart=/usr/bin/python3 %s _timeout %s\n" % (script, ident))
        timer = ("[Unit]\nDescription=SSH key confirmation deadline\n[Timer]\n"
                 "OnCalendar=%s UTC\nPersistent=true\nAccuracySec=1s\nRandomizedDelaySec=0\n"
                 "[Install]\nWantedBy=timers.target\n" % deadline.strftime("%Y-%m-%d %H:%M:%S"))
        atomic(self.systemd / (name + ".service"), service.encode(), 0o644)
        atomic(self.systemd / (name + ".timer"), timer.encode(), 0o644)
        self.runner(["systemctl", "daemon-reload"])
        self.runner(["systemctl", "enable", name + ".timer"])
        self.runner(["systemctl", "restart", name + ".timer"])
        self.runner(["systemctl", "is-active", "--quiet", name + ".timer"])

    def disarm(self, state):
        name = "sshkeytool-" + state["id"]
        if (self.systemd / (name + ".timer")).exists():
            self.runner(["systemctl", "disable", "--now", name + ".timer"])
        for suffix in (".timer", ".service"):
            p = self.systemd / (name + suffix)
            regular(p)
            if p.exists():
                p.unlink()
        self.runner(["systemctl", "daemon-reload"])

    def begin(self, user, action, timeout):
        if not 60 <= timeout <= 1800:
            raise ToolError("确认时限必须为 60–1800 秒。")
        settings, paths = self.preflight(user)
        ident = uuid.uuid4().hex
        self.private_dir(self.operations / ident)
        state = {"version": 1, "id": ident, "user": user, "action": action,
                 "phase": "generating" if action == "generate" else "preparing",
                 "created": self.clock(), "deadline": self.clock() + timeout, "timeout": timeout,
                 "service": self.service, "origin": " ".join(connection()), "last_connection": "",
                 "changes": [], "settings_before": settings, "key_path": str(paths[0]),
                 "baseline": self.configuration_stamp(), "verified": [], "expected_fingerprints": []}
        self.save(state)
        self.write_json(self.active_path, {"id": ident})
        try:
            self.arm(state)
        except BaseException:
            self.rollback_locked(state)
            raise
        return state

    def change(self, state, path, data, mode=None, owner=None):
        before = snapshot(path)
        mode = mode if mode is not None else before.get("mode", 0o600)
        owner = owner or (before.get("uid", os.geteuid()), before.get("gid", os.getegid()))
        after = {"exists": True, "sha256": digest(data), "mode": mode, "uid": owner[0], "gid": owner[1]}
        record = next((x for x in state["changes"] if x["path"] == str(path)), None)
        if record:
            if not same_snapshot(before, record["after"]):
                raise ToolError("修改对象被外部程序改变：" + str(path))
            record["previous"] = before
            record["after"] = after
        else:
            state["changes"].append({"path": str(path), "before": before, "after": after})
        # 修改意图先落盘；进程在替换前/后退出均可恢复。
        self.save(state)
        atomic(path, data, mode, owner)

    def add_material(self, state, data):
        incoming = self.parse_keys(data)
        if not incoming:
            raise ToolError("没有有效公钥。")
        # 第一版导入普通公钥，现有授权限制则原样保留。
        if any(k["options"] for k in incoming):
            raise ToolError("新导入请提供普通公钥；已有授权限制不会修改。")
        settings = self.effective(state["user"])
        all_keys = []
        for p in self.key_paths(state["user"], settings):
            if p.exists():
                all_keys += self.parse_keys(p.read_bytes())
        seen = {k["fingerprint"] for k in all_keys}
        selected = []
        for key in incoming:
            if key["fingerprint"] not in seen:
                selected.append(key)
                seen.add(key["fingerprint"])
        if not selected:
            raise ToolError("公钥已存在；未添加重复记录，也未解除原有限制。")
        path = Path(state["key_path"])
        if not path.parent.exists():
            path.parent.mkdir(mode=0o700)
            info = self.user(state["user"])
            if (info.pw_uid, info.pw_gid) != (os.geteuid(), os.getegid()):
                os.chown(path.parent, info.pw_uid, info.pw_gid)
            state["created_directory"] = str(path.parent)
            self.save(state)
        before = path.read_bytes() if path.exists() else b""
        if before and not before.endswith(b"\n"):
            before += b"\n"
        data = before + ("\n".join(k["line"] for k in selected) + "\n").encode()
        info = self.user(state["user"])
        self.change(state, path, data, 0o600, (info.pw_uid, info.pw_gid))
        state["expected_fingerprints"] = [k["fingerprint"] for k in selected]
        self.save(state)

    def prepare(self, state, data=None):
        if self.clock() >= state["deadline"]:
            raise ToolError("操作已超过确认时限。")
        if self.configuration_stamp() != state["baseline"]:
            raise ToolError("准备期间 SSH 配置被外部修改。")
        if data is not None:
            self.add_material(state, data)
        current = self.config.read_bytes()
        candidate = policy_config(current, state["user"])
        actual = self.validate_candidate(state, candidate, connection(state["origin"]))
        if actual.get("pubkeyauthentication") != "yes" or actual.get("exposeauthinfo") != "yes":
            raise ToolError("已有更早的 Match 规则阻止准备配置生效。")
        # 准备只允许公钥和公开认证信息，不改变其他原有认证项。
        for key in AUTH_FIELDS:
            if key not in ("pubkeyauthentication", "exposeauthinfo") and actual.get(key) != state["settings_before"].get(key):
                raise ToolError("准备阶段改变了原认证方式：" + key)
        self.change(state, self.config, candidate)
        self.reload(state)
        state["baseline"] = self.configuration_stamp()
        state["key_baseline"] = self.authorization_stamp(state["user"])
        state["phase"] = "await_before" if state["action"] == "switch" else "await_key"
        state["phase_started"] = self.clock()
        self.save(state)

    def validate_candidate(self, state, data, conn):
        fd, name = tempfile.mkstemp(prefix=".sshkeytool-check-", dir=str(self.config.parent))
        candidate = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
            self.runner([self.sshd, "-t", "-f", str(candidate)])
            return self.effective(state["user"], conn, candidate)
        finally:
            candidate.unlink()

    def start(self, user, action="switch", data=None, timeout=300):
        with self.locked():
            state = self.begin(user, action, timeout)
            try:
                self.prepare(state, data)
            except BaseException:
                self.rollback_locked(state)
                raise
            return state

    def generate(self, user, kind="ed25519", no_passphrase=False, pem=False, timeout=300):
        if kind not in ("ed25519", "rsa") or (pem and kind != "rsa"):
            raise ToolError("PEM 导出仅用于 RSA。")
        if not no_passphrase and not sys.stdin.isatty():
            raise ToolError("加密私钥需交互终端；请用 ssh -t，或明确选择 --no-passphrase。")
        with self.locked():
            state = self.begin(user, "generate", timeout)
            folder = self.pending_keys / state["id"]
            self.private_dir(folder)
        key = folder / "identity"
        args = ["ssh-keygen", "-q", "-t", kind, "-f", str(key), "-C",
                "sshkeytool-%s-%s" % (user, state["id"][:8])]
        if kind == "rsa":
            args += ["-b", "4096"]
        if pem:
            args += ["-m", "PEM"]
        if no_passphrase:
            args += ["-N", ""]
        try:
            # 口令交互在操作锁之外；独立回退不会被输入等待阻塞。
            if subprocess.call(args) != 0:
                raise ToolError("密钥生成失败。")
            key.chmod(0o600)
            with self.locked():
                state = self.load(state["id"])
                if state["phase"] != "generating":
                    raise ToolError("生成操作已被取消或回退。")
                self.prepare(state, key.with_suffix(".pub").read_bytes())
            return state
        except BaseException:
            with self.locked():
                state = self.load(state["id"])
                if state["phase"] not in FINISHED:
                    self.rollback_locked(state)
                self.cleanup_private(state)
            raise

    def auth_proof(self, state):
        conn = connection()
        joined = " ".join(conn)
        if joined in (state["origin"], state.get("last_connection")):
            raise ToolError("必须另建 SSH 连接确认，不能复用原连接。")
        login = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
        if login != state["user"]:
            raise ToolError("请从目标用户的新连接确认。")
        info_path = os.environ.get("SSH_USER_AUTH", "")
        if not info_path:
            raise ToolError("新连接缺少 SSH_USER_AUTH；使用公钥新建连接，sudo 时保留 SSH_* 环境。")
        p = Path(info_path)
        regular(p)
        s = p.stat()
        if s.st_size > 32768 or s.st_uid not in (0, self.user(state["user"]).pw_uid):
            raise ToolError("认证凭据文件属主或大小无效。")
        if s.st_mtime < state["phase_started"] - 1:
            raise ToolError("认证信息来自本阶段开始之前的连接。")
        fingerprints = []
        for line in p.read_text().splitlines():
            method, _, material = line.partition(" ")
            if method == "publickey":
                fields = key_fields(material)
                if fields:
                    fingerprints.append(self.fingerprint(fields["type"] + " " + fields["blob"]))
        if not fingerprints:
            raise ToolError("这次连接未提供公钥认证凭据。")
        expected = state["expected_fingerprints"]
        if expected and not any(f in expected for f in fingerprints):
            raise ToolError("新连接使用了旧公钥，请用刚导入/生成的私钥确认。")
        return {"connection": joined, "fingerprints": fingerprints, "time": self.clock(),
                "evidence": "sshd ExposeAuthInfo"}

    def confirm(self, ident):
        with self.locked():
            state = self.load(ident)
            if state["phase"] not in ("await_key", "await_before", "await_after"):
                raise ToolError("这个操作当前不能确认：" + state["phase"])
            if self.clock() >= state["deadline"]:
                self.rollback_locked(state)
                raise ToolError("确认已超时，已执行回退。")
            if self.configuration_stamp() != state["baseline"]:
                raise ToolError("SSH 配置已经变化，请先回退或检查。")
            if self.authorization_stamp(state["user"]) != state.get("key_baseline"):
                raise ToolError("授权公钥文件已经变化，请先回退或检查。")
            for record in state["changes"]:
                if not same_snapshot(snapshot(Path(record["path"])), record["after"]):
                    raise ToolError("修改对象已被外部改变，不能确认。")
            proof = self.auth_proof(state)
            state["verified"].append(proof)
            state["last_connection"] = proof["connection"]
            if state["phase"] == "await_before":
                state["deadline"] = self.clock() + state["timeout"]
                self.save(state)
                try:
                    self.arm(state)
                    candidate = policy_config(self.config.read_bytes(), state["user"], True)
                    actual = self.validate_candidate(state, candidate, connection(proof["connection"]))
                    if not key_only(state["user"], actual) or actual.get("authenticationmethods") != "publickey":
                        raise ToolError("目标策略未生效，可能存在更早的 Match 规则。")
                    self.change(state, self.config, candidate)
                    self.reload(state)
                    state["phase"] = "await_after"
                    state["phase_started"] = self.clock()
                    state["baseline"] = self.configuration_stamp()
                    self.save(state)
                except BaseException:
                    self.rollback_locked(state)
                    raise
            else:
                if state["phase"] == "await_after" and not key_only(
                        state["user"], self.effective(state["user"], connection(proof["connection"]))):
                    raise ToolError("当前策略已不再是仅公钥认证。")
                state["phase"] = "committed"
                state["finished"] = self.clock()
                self.save(state)  # 先提交，再取消 timer，迟到回调只会看到终态。
                self.terminal_cleanup(state)
            return state

    def terminal_cleanup(self, state):
        # 提交后若清理中断，保留 active 和 timer；迟到回调只重试清理，不撤销提交。
        try:
            self.cleanup_private(state)
            self.disarm(state)
            self.clear_active(state)
            if state.pop("cleanup_error", None) is not None:
                self.save(state)
        except (ToolError, OSError) as exc:
            state["cleanup_error"] = str(exc)
            self.save(state)
            raise ToolError("认证操作已结束，但临时文件/定时器清理未完成；请执行 sshkeytool _timeout " +
                            state["id"] + " 重试清理：" + str(exc)) from exc

    def clear_active(self, state):
        if self.active_path.exists() and self.read_json(self.active_path).get("id") == state["id"]:
            self.active_path.unlink()
            sync_dir(self.state_dir)

    def cleanup_private(self, state):
        folder = self.pending_keys / state["id"]
        if folder.is_symlink():
            raise ToolError("私钥临时目录被改为符号链接。")
        if folder.exists():
            for name in ("identity", "identity.pub"):
                p = folder / name
                regular(p)
                if p.exists():
                    p.unlink()
            folder.rmdir()

    def rollback_locked(self, state):
        if state["phase"] == "rolled_back":
            self.terminal_cleanup(state)
            return state
        # 手动恢复已提交配置也受当前文件校验保护。
        try:
            for record in state["changes"]:
                current = snapshot(Path(record["path"]))
                if not (same_snapshot(current, record["after"]) or same_snapshot(current, record["before"]) or
                        (record.get("previous") and same_snapshot(current, record["previous"]))):
                    raise ToolError("外部修改冲突，保留当前内容和备份：" + record["path"])
                if record["before"]["exists"]:
                    unpacksnap(record["before"])
            for record in reversed(state["changes"]):
                restore(Path(record["path"]), record["before"])
            if state["changes"]:
                self.reload(state)
            self.cleanup_private(state)
            directory = state.get("created_directory")
            if directory:
                p = Path(directory)
                if p.exists() and not any(p.iterdir()):
                    p.rmdir()
            state["phase"] = "rolled_back"
            state["finished"] = self.clock()
            state.pop("error", None)
            self.save(state)
            self.clear_active(state)
            self.disarm(state)
        except (ToolError, OSError) as exc:
            state["phase"] = "rollback_failed"
            state["error"] = str(exc)
            self.save(state)
            self.write_json(self.active_path, {"id": state["id"]})
            # 私钥不留在出错的配置备份中；清理失败本身不能掩盖回退错误。
            try:
                self.cleanup_private(state)
            except (ToolError, OSError):
                pass
            raise ToolError("回退未完成，备份保留于 %s：%s" % (self.state_path(state["id"]).parent, exc)) from exc
        return state

    def rollback(self, ident, expired_only=False):
        with self.locked():
            state = self.load(ident)
            if expired_only and state["phase"] in FINISHED:
                self.terminal_cleanup(state)
                return state
            if expired_only and self.clock() < state["deadline"]:
                self.arm(state)
                return state
            return self.rollback_locked(state)

    def extend(self, ident, seconds):
        if not 60 <= seconds <= 1800:
            raise ToolError("延期必须为 60–1800 秒。")
        with self.locked():
            state = self.load(ident)
            if state["phase"] not in PENDING or state["phase"] == "rollback_failed":
                raise ToolError("此操作不能延期。")
            if self.clock() >= state["deadline"]:
                self.rollback_locked(state)
                raise ToolError("已经超时，不能延期。")
            state["deadline"] = self.clock() + seconds
            self.save(state)
            self.arm(state)
            return state

    def remove(self, user, fingerprint, timeout=300):
        with self.locked():
            state = self.begin(user, "remove", timeout)
            try:
                settings = self.effective(user)
                records = []
                for p in self.key_paths(user, settings):
                    if p.exists():
                        records.extend((p, k) for k in self.parse_keys(p.read_bytes()))
                selected = [(p, k) for p, k in records if k["fingerprint"] == fingerprint]
                remaining = {k["fingerprint"] for p, k in records if k["fingerprint"] != fingerprint}
                if not selected:
                    raise ToolError("没有找到这个公钥指纹。")
                if not remaining:
                    raise ToolError("不能删除最后一把文件授权公钥；请先添加并验证替代密钥。")
                for p in {p for p, k in selected}:
                    numbers = {k["number"] for path, k in selected if path == p}
                    data = b"".join(line for n, line in enumerate(p.read_bytes().splitlines(keepends=True), 1)
                                    if n not in numbers)
                    self.change(state, p, data)
                state["expected_fingerprints"] = sorted(remaining)
                self.save(state)
                self.prepare(state)
                return state
            except BaseException:
                self.rollback_locked(state)
                raise

    def history(self):
        if not self.operations.exists():
            return []
        values = []
        for p in sorted(self.operations.glob("*/state.json")):
            state = self.load(p.parent.name)
            values.append({k: state.get(k) for k in ("id", "user", "action", "phase", "created",
                                                    "deadline", "finished", "verified", "error", "cleanup_error")})
        return sorted(values, key=lambda x: x["created"], reverse=True)


def fetch_keys(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ToolError("公钥来源必须是无用户名密码的 HTTPS URL。")
    class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if urllib.parse.urlsplit(newurl).scheme != "https":
                raise ToolError("拒绝重定向到非 HTTPS 地址。")
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    try:
        opener = urllib.request.build_opener(HTTPSRedirect())
        with opener.open(url, timeout=15) as response:
            data = response.read(MAX_INPUT + 1)
    except (OSError, ValueError) as exc:
        raise ToolError("公钥下载失败：" + str(exc)) from exc
    if len(data) > MAX_INPUT:
        raise ToolError("下载的公钥文件过大。")
    return data


def show_status(info):
    print("SSH 密钥登录管理 v" + VERSION)
    print("目标用户：" + info["user"])
    print("公钥认证：" + ("已允许" if info["pubkey_allowed"] else "未允许"))
    print("授权公钥：%d 把" % len(info["keys"]))
    print("密码认证：" + ("允许" if info["password_allowed"] else "已禁止") +
          ("（root 登录策略）" if info["user"] == "root" and info["effective"]["permitrootlogin"] in
           ("prohibit-password", "without-password") else ""))
    print("键盘交互认证：" + ("允许" if info["keyboard_allowed"] else "已禁止"))
    print("当前磁盘策略：" + ("仅密钥" if info["key_only"] else "混合或自定义认证"))
    verified = info.get("verification")
    print("新连接验证：" + ("尚未由本工具登记" if verified is None else
          "已通过公钥验证（仅代表登记的来源和当时配置）" if verified["valid"] else
          "配置或公钥已变化，需要重新验证"))
    print("适用连接：" + info["scope"])
    if info["active"]:
        a = info["active"]
        print("待处理：%s %s，剩余 %d 秒" % (a["id"], a["phase"], max(0, int(a["deadline"] - time.time()))))
    for issue in info["issues"]:
        print("需要检查：" + issue)


def show_operation(state):
    print("操作编号：" + state["id"])
    print("当前阶段：" + state["phase"])
    if state["phase"] in PENDING:
        print("剩余确认时间：%d 秒；超时恢复修改前配置。" % max(0, int(state["deadline"] - time.time())))
        if state["action"] == "generate":
            print("下载私钥：/var/lib/sshkeytool/pending-keys/%s/identity" % state["id"])
            print("通过现有 SSH/SFTP 连接下载到电脑；私钥不会显示在终端或进入备份。")
        conn = connection(state["origin"])
        target = state["user"] + "@" + conn[2]
        remote = ("sshkeytool confirm " + state["id"] if state["user"] == "root" else
                  "sudo --preserve-env=SSH_CONNECTION,SSH_USER_AUTH sshkeytool confirm " + state["id"])
        args = ["ssh", "-S", "none", "-o", "PreferredAuthentications=publickey", "-o",
                "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "IdentitiesOnly=yes",
                "-i", "<电脑上的私钥路径>", "-p", conn[3], target, remote]
        print("在电脑新建连接确认（替换私钥路径，必要时按你的配置增加跳板）：")
        print(shlex.join(args))
        print("取消并恢复：sudo sshkeytool rollback " + state["id"])
    elif state["phase"] == "committed":
        print("已通过新连接公钥验证并提交；临时私钥已清理，备份已保留。")
    elif state["phase"] == "rolled_back":
        print("已恢复修改前配置。")


def ask(prompt):
    return input(prompt + " [y/N] ").strip().lower() == "y"


def menu(manager, user="root"):
    if not sys.stdin.isatty():
        raise ToolError("菜单需要交互终端；可使用 status --json 或命令模式。")
    while True:
        try:
            print()
            show_status(manager.status(user))
            print("1. 查看状态与判断依据\n2. 添加公钥\n3. 切换为仅密钥登录\n4. 查看 / 删除公钥\n"
                  "5. 恢复修改前配置\n6. 备份与操作记录\n7. 切换目标用户\n8. 自动生成新密钥对\n"
                  "9. 确认新连接 / 延期\n0. 返回")
            choice = input("请选择：").strip()
            if choice == "0":
                return
            if choice == "1":
                print(json.dumps(manager.status(user), ensure_ascii=False, indent=2))
            elif choice == "2":
                source = input("来源：1. 粘贴公钥  2. 文件  3. GitHub  4. HTTPS URL：").strip()
                if source == "1":
                    data = input("请粘贴完整公钥：").encode()
                elif source == "2":
                    data = Path(input("公钥文件：").strip()).read_bytes()
                elif source == "3":
                    github = input("GitHub 用户名：").strip()
                    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", github):
                        raise ToolError("GitHub 用户名格式无效。")
                    data = fetch_keys("https://github.com/" + github + ".keys")
                elif source == "4":
                    data = fetch_keys(input("HTTPS URL：").strip())
                else:
                    raise ToolError("无效来源。")
                for k in manager.parse_keys(data):
                    print(k["type"], k["fingerprint"], k["comment"])
                if ask("追加这些公钥并开始新连接验证？"):
                    show_operation(manager.start(user, "add", data))
            elif choice == "3":
                if manager.status(user)["key_only"]:
                    print("当前已符合仅密钥策略；可以继续登记新连接验证。")
                if ask("开始切换？保留当前会话，完成两次新连接验证后提交"):
                    show_operation(manager.start(user))
            elif choice == "4":
                for key in manager.status(user)["keys"]:
                    print(key["fingerprint"], key["type"], key["comment"], key["options"], key["file"])
                fingerprint = input("删除请输入完整指纹，直接回车仅查看：").strip()
                if fingerprint and ask("删除该指纹并验证另一把保留密钥？"):
                    show_operation(manager.remove(user, fingerprint))
            elif choice == "5":
                ident = input("需要恢复的操作编号：").strip()
                if ask("恢复这个操作修改前的文件与认证策略？"):
                    show_operation(manager.rollback(ident))
            elif choice == "6":
                print(json.dumps(manager.history(), ensure_ascii=False, indent=2))
            elif choice == "7":
                user = input("已有用户：").strip()
                manager.user(user)
            elif choice == "8":
                if input("1. 在 VPS 生成  2. 查看电脑生成方法 [1]：").strip() == "2":
                    print('在电脑执行：ssh-keygen -t ed25519 -f ~/.ssh/vps_login；随后导入 vps_login.pub。')
                    continue
                kind = "rsa" if input("类型：1. Ed25519（默认）  2. RSA：").strip() == "2" else "ed25519"
                encrypted = not ask("使用不带私钥口令的密钥？")
                pem = kind == "rsa" and ask("使用传统 PEM 私钥格式？")
                if ask("生成新密钥并开始下载验证？原密钥保留"):
                    show_operation(manager.generate(user, kind, not encrypted, pem))
            elif choice == "9":
                ident = input("操作编号：").strip()
                if input("1. 从新连接确认  2. 延期 5 分钟：").strip() == "2":
                    show_operation(manager.extend(ident, 300))
                else:
                    show_operation(manager.confirm(ident))
            else:
                print("无效选项。")
        except (ToolError, OSError, ValueError) as exc:
            print("操作未完成：" + str(exc), file=sys.stderr)


def parser():
    p = argparse.ArgumentParser(description="SSH 密钥登录管理（Debian/Ubuntu；默认仅管理指定用户）")
    p.add_argument("--version", action="version", version="sshkeytool " + VERSION)
    sub = p.add_subparsers(dest="command")
    for command in ("status", "switch", "menu"):
        c = sub.add_parser(command)
        c.add_argument("--user", default="root")
        if command == "status":
            c.add_argument("--json", action="store_true")
        if command == "switch":
            c.add_argument("--timeout", type=int, default=300)
    keys = sub.add_parser("keys").add_subparsers(dest="key_command", required=True)
    for command in ("list", "add", "generate", "remove"):
        c = keys.add_parser(command)
        c.add_argument("--user", default="root")
        if command == "list":
            c.add_argument("--json", action="store_true")
        else:
            c.add_argument("--timeout", type=int, default=300)
        if command == "add":
            sources = c.add_mutually_exclusive_group(required=True)
            sources.add_argument("--file")
            sources.add_argument("--key")
            sources.add_argument("--github")
            sources.add_argument("--url")
        if command == "generate":
            c.add_argument("--type", choices=("ed25519", "rsa"), default="ed25519")
            c.add_argument("--no-passphrase", action="store_true")
            c.add_argument("--pem", action="store_true")
        if command == "remove":
            c.add_argument("fingerprint")
    for command in ("confirm", "rollback", "extend", "_timeout"):
        c = sub.add_parser(command)
        c.add_argument("id")
        if command == "extend":
            c.add_argument("--seconds", type=int, default=300)
    sub.add_parser("history")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    manager = Manager()
    try:
        if args.command is None or args.command == "menu":
            menu(manager, getattr(args, "user", "root"))
        elif args.command == "status":
            result = manager.status(args.user)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                show_status(result)
        elif args.command == "history":
            print(json.dumps(manager.history(), ensure_ascii=False, indent=2))
        else:
            if os.geteuid() != 0:
                raise ToolError("此操作需要 root/sudo 权限。")
            if args.command == "switch":
                result = manager.start(args.user, timeout=args.timeout)
            elif args.command == "keys":
                if args.key_command == "list":
                    print(json.dumps(manager.status(args.user)["keys"], ensure_ascii=False, indent=2))
                    return 0
                if args.key_command == "generate":
                    result = manager.generate(args.user, args.type, args.no_passphrase, args.pem, args.timeout)
                elif args.key_command == "remove":
                    result = manager.remove(args.user, args.fingerprint, args.timeout)
                else:
                    if args.file:
                        data = Path(args.file).read_bytes()
                    elif args.key:
                        data = args.key.encode()
                    elif args.github:
                        if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", args.github):
                            raise ToolError("GitHub 用户名格式无效。")
                        data = fetch_keys("https://github.com/" + args.github + ".keys")
                    else:
                        data = fetch_keys(args.url)
                    print("准备添加：")
                    for k in manager.parse_keys(data):
                        print(k["type"], k["fingerprint"], k["comment"])
                    if not sys.stdin.isatty():
                        raise ToolError("导入需交互确认；请用 ssh -t 或菜单审阅公钥。")
                    if not ask("确认追加并开始新连接验证？"):
                        return 0
                    result = manager.start(args.user, "add", data, args.timeout)
            elif args.command == "confirm":
                result = manager.confirm(args.id)
            elif args.command == "extend":
                result = manager.extend(args.id, args.seconds)
            else:
                result = manager.rollback(args.id, args.command == "_timeout")
            if args.command != "_timeout":
                show_operation(result)
        return 0
    except (ToolError, OSError, ValueError) as exc:
        print("[sshkeytool] 操作未完成：" + str(exc), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\n已退出；待确认操作仍由独立回退任务保护。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
