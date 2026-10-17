#!/usr/bin/env bash
# VPS SOCKS5 manager. One file; Python is embedded to serialize credentials safely.
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || "${1:-}" == "help" ]]; then
    printf '%s\n' 'VPS SOCKS5 工具：请安装 Python 3 后运行 bash socks5.sh --help。'
    exit 0
  fi
  if [[ "$(uname -s)" != Linux || "$EUID" != 0 ]] || ! command -v apt-get >/dev/null 2>&1; then
    printf '%s\n' '需要 Python 3；自动安装仅支持 Debian/Ubuntu 的 root 用户。' >&2
    exit 1
  fi
  apt-get update
  apt-get install -y --no-install-recommends python3 ca-certificates
fi
exec python3 - "$0" "$@" 3<&0 <<'PY_SOCKS5'
import argparse
import contextlib
import copy
import fcntl
import grp
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile

VERSION = "0.1.0"
GOST_VERSION = "3.3.0"
TOOL = "vps-socks5"
ACCOUNT = "vps-socks5"
SERVICE = "vps-socks5.service"
CONFIG_DIR = Path("/etc/vps-socks5")
CONFIG = CONFIG_DIR / "config.json"
STATE = CONFIG_DIR / "state.json"
CERT = CONFIG_DIR / "server.crt"
KEY = CONFIG_DIR / "server.key"
CA = CONFIG_DIR / "ca.crt"
BUNDLE = CONFIG_DIR / "client.zip"
PREFIX = Path("/usr/local/lib/vps-socks5")
BINARY = PREFIX / "gost"
MANAGER = Path("/usr/local/bin/socks5")
UNIT = Path("/etc/systemd/system") / SERVICE
LOCK = Path("/run/lock/vps-socks5.lock")
ASSETS = {
    "amd64": "676fb7f78d267b6ae73df719c0c7f2b565dde7147da935cfafbc1e1da558b6d5",
    "arm64": "d03699e3f385d4ff5dad68046712adfcc7515325a064d2ab046e0bece30f8f8f",
}


class ToolError(Exception):
    pass


def say(message):
    print(message, flush=True)


def run(args, check=True, timeout=45, capture=True):
    try:
        result = subprocess.run(
            [str(x) for x in args], check=False, timeout=timeout,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True, env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError("执行失败：{} ({})".format(args[0], exc)) from exc
    if check and result.returncode:
        detail = (result.stderr or result.stdout or "").strip()[-1200:]
        raise ToolError("{} 执行失败：{}".format(args[0], detail))
    return result


def atomic_write(path, data, mode=0o600, gid=None):
    path = Path(path)
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd, name = tempfile.mkstemp(prefix=".new-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            if gid is not None:
                os.fchown(stream.fileno(), 0, gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, data, mode=0o600, gid=None):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n", mode, gid)


def valid_port(value):
    try:
        port = int(value)
    except (ValueError, TypeError) as exc:
        raise ToolError("端口必须是整数。") from exc
    if str(port) != str(value).strip() or not 1024 <= port <= 65535:
        raise ToolError("端口范围为 1024–65535。")
    return port


def valid_credential(value, label):
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 255:
        raise ToolError(label + "必须为 1–255 字节。")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ToolError(label + "不能包含控制字符或换行。")
    return value


def valid_host(value):
    value = value.strip()
    if not value or "%" in value:
        raise ToolError("请填写 VPS 的 IP 或域名，不要带协议和端口。")
    try:
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_multicast:
            raise ToolError("服务器地址不能是通配地址或组播地址。")
        return str(address)
    except ValueError:
        if len(value) > 253 or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in value.split(".")
        ):
            raise ToolError("服务器域名格式不正确；中文域名请先转换为 Punycode。")
        return value.lower()


def endpoint(host, port):
    return "[{}]:{}".format(host, port) if ":" in host else "{}:{}".format(host, port)


def local_host(listen):
    return {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(listen, listen)


def port_available(port, listen):
    family = socket.AF_INET6 if ":" in listen else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((listen, port))
            sock.listen(1)
        return True
    except OSError:
        return False


def choose_port(listen):
    low, high = 32768, 60999
    try:
        low, high = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
    except (OSError, ValueError):
        pass
    candidates = [port for port in range(20000, 60001) if not low <= port <= high]
    secrets.SystemRandom().shuffle(candidates)
    for port in candidates[:512]:
        if port_available(port, listen):
            return port
    raise ToolError("没有找到空闲高位端口，请手动指定 --port。")


def detect_host(listen="0.0.0.0"):
    if shutil.which("ip"):
        result = run(["ip", "-j", "address"], check=False)
        try:
            addresses = [item["local"] for interface in json.loads(result.stdout)
                         for item in interface.get("addr_info", [])
                         if ipaddress.ip_address(item["local"]).is_global
                         and ipaddress.ip_address(item["local"]).version == ipaddress.ip_address(listen).version]
            addresses.sort(key=lambda value: ":" in value)
            return addresses[0] if addresses else ""
        except (ValueError, KeyError, TypeError):
            pass
    return ""


def check_environment():
    if platform.system() != "Linux":
        raise ToolError("部署和管理需要在 Linux VPS 上运行；本机可查看 --help。")
    if os.geteuid() != 0:
        raise ToolError("请使用 sudo bash socks5.sh，或以 root 身份运行。")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    supported = {"debian": {"12", "13"}, "ubuntu": {"22.04", "24.04"}}
    if release.get("VERSION_ID") not in supported.get(release.get("ID"), set()):
        raise ToolError("第一版支持 Debian 12/13、Ubuntu 22.04/24.04。")
    if not Path("/run/systemd/system").is_dir() or not shutil.which("systemctl"):
        raise ToolError("需要由 systemd 管理服务的 VPS 环境。")
    for path in (CONFIG_DIR, PREFIX, MANAGER, UNIT):
        if path.is_symlink():
            raise ToolError("检测到保留路径是符号链接，已停止：" + str(path))


@contextlib.contextmanager
def locked():
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ToolError("另一个 socks5 管理操作正在运行，请稍后重试。") from exc
        yield


def ensure_dependencies():
    if shutil.which("openssl") and Path("/etc/ssl/certs/ca-certificates.crt").is_file():
        return
    say("正在安装 openssl 和 CA 证书……")
    run(["apt-get", "update"], timeout=600, capture=False)
    run(["apt-get", "install", "-y", "--no-install-recommends", "openssl", "ca-certificates"],
        timeout=600, capture=False)


def download_gost(destination, arch=None, expected=None):
    arch = arch or {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    if arch not in ASSETS and expected is None:
        raise ToolError("第一版仅支持 amd64 和 arm64。")
    digest = expected or ASSETS[arch]
    filename = "gost_{}_linux_{}.tar.gz".format(GOST_VERSION, arch)
    url = "https://github.com/go-gost/gost/releases/download/v{}/{}".format(GOST_VERSION, filename)
    say("正在下载 GOST {}（{}），并校验 SHA-256……".format(GOST_VERSION, arch))
    payload = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": TOOL + "/" + VERSION})
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read(100 * 1024 * 1024 + 1)
            break
        except (OSError, urllib.error.URLError) as exc:
            if attempt == 2:
                raise ToolError("下载失败，请检查 VPS 到 GitHub 的网络连接。") from exc
            time.sleep(attempt + 1)
    if len(payload) > 100 * 1024 * 1024 or hashlib.sha256(payload).hexdigest() != digest:
        raise ToolError("GOST 下载校验失败，未安装该文件。")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        entries = [entry for entry in archive.getmembers() if entry.name == "gost" and entry.isfile()]
        if len(entries) != 1 or entries[0].size > 150 * 1024 * 1024:
            raise ToolError("GOST 压缩包结构不符合预期。")
        source = archive.extractfile(entries[0])
        atomic_write(destination, source.read(), 0o755)
    if GOST_VERSION not in run([destination, "-V"]).stdout:
        raise ToolError("GOST 二进制版本不符合预期。")


def create_account():
    try:
        pwd.getpwnam(ACCOUNT)
    except KeyError:
        try:
            grp.getgrnam(ACCOUNT)
            raise ToolError("同名系统组已存在，请先检查：" + ACCOUNT)
        except KeyError:
            pass
        run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
             "--shell", "/usr/sbin/nologin", ACCOUNT])
        return True
    raise ToolError("同名系统账户已存在，为避免影响其他服务，已停止：" + ACCOUNT)


def service_gid():
    return grp.getgrnam(ACCOUNT).gr_gid


def delete_account():
    try:
        pwd.getpwnam(ACCOUNT)
    except KeyError:
        pass
    else:
        run(["userdel", ACCOUNT])
    try:
        grp.getgrnam(ACCOUNT)
    except KeyError:
        pass
    else:
        run(["groupdel", ACCOUNT])


def server_config(state):
    handler = {"type": "socks5" if state["mode"] == "socks5" else "relay",
               "auth": {"username": state["username"], "password": state["password"]},
               "metadata": {"bind": False}}
    listener = {"type": "tcp"}
    if state["mode"] == "tls":
        listener = {"type": "tls", "tls": {"certFile": str(CERT), "keyFile": str(KEY),
                    "options": {"minVersion": "VersionTLS12"}}}
    else:
        handler["metadata"].update({"notls": True, "udp": False})
    return {"services": [{"name": TOOL, "addr": endpoint(state["listen"], state["port"]),
                          "handler": handler, "listener": listener}],
            "log": {"level": "warn"}}


def client_config(state, local_port=1080, remote_host=None, ca_file="server.crt"):
    host = remote_host or state["host"]
    if not host:
        raise ToolError("无法确定 VPS 公网地址，请在导出时指定 --host 公网IP或域名。")
    dialer = {"type": "tcp"}
    if state["mode"] == "tls":
        tls = {"secure": True, "serverName": state["host"]}
        if state["trust"] != "system":
            tls["caFile"] = ca_file
        dialer = {"type": "tls", "tls": tls}
    node = {"name": "vps", "addr": endpoint(host, state["port"]),
            "connector": {"type": "relay" if state["mode"] == "tls" else "socks5",
                          "auth": {"username": state["username"], "password": state["password"]}},
            "dialer": dialer}
    return {"services": [{"name": "local-socks5", "addr": endpoint("127.0.0.1", local_port),
                          "handler": {"type": "socks5", "chain": "vps",
                                      "metadata": {"udp": False, "bind": False, "notls": True}},
                          "listener": {"type": "tcp"}}],
            "chains": [{"name": "vps", "hops": [{"name": "hop-0", "nodes": [node]}]}],
            "log": {"level": "warn"}}


def install_certificate(state, cert=None, key=None, ca=None):
    gid = service_gid()
    if cert:
        for source in (cert, key):
            if not Path(source).is_file():
                raise ToolError("证书或私钥不存在：" + str(source))
        atomic_write(CERT, Path(cert).read_bytes(), 0o640, gid)
        atomic_write(KEY, Path(key).read_bytes(), 0o640, gid)
        state["trust"] = "custom" if ca else "system"
        if ca:
            atomic_write(CA, Path(ca).read_bytes(), 0o640, gid)
    else:
        try:
            ipaddress.ip_address(state["host"])
            san = "IP:" + state["host"]
        except ValueError:
            san = "DNS:" + state["host"]
        run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
             "-keyout", KEY, "-out", CERT, "-days", "365", "-subj", "/CN=" + state["host"],
             "-addext", "subjectAltName=" + san])
        for path in (CERT, KEY):
            os.chmod(path, 0o640)
            os.chown(path, 0, gid)
        state["trust"] = "self-signed"
    run(["openssl", "x509", "-in", CERT, "-checkend", "60", "-noout"])
    try:
        ipaddress.ip_address(state["host"])
        match_flag = "-checkip"
    except ValueError:
        match_flag = "-checkhost"
    run(["openssl", "x509", "-in", CERT, match_flag, state["host"], "-noout"])
    cert_pub = run(["openssl", "x509", "-in", CERT, "-pubkey", "-noout"]).stdout
    key_pub = run(["openssl", "pkey", "-in", KEY, "-pubout"]).stdout
    if cert_pub != key_pub:
        raise ToolError("证书和私钥不匹配。")


def unit_content():
    return """[Unit]
Description=VPS SOCKS5 / TLS proxy (GOST)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={account}
Group={account}
ExecStart={binary} -C {config}
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
""".format(account=ACCOUNT, binary=BINARY, config=CONFIG)


def receive(sock, length):
    result = b""
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise ToolError("代理连接提前关闭。")
        result += part
    return result


def socks_auth(sock, username=None, password=None):
    sock.sendall(b"\x05\x01" + (b"\x02" if username is not None else b"\x00"))
    expected = b"\x05\x02" if username is not None else b"\x05\x00"
    if receive(sock, 2) != expected:
        raise ToolError("SOCKS5 认证方式不符合预期。")
    if username is not None:
        user, secret = username.encode("utf-8"), password.encode("utf-8")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
        if receive(sock, 2) != b"\x01\x00":
            raise ToolError("SOCKS5 用户名或密码认证失败。")


def socks_connect(sock, port):
    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", port))
    header = receive(sock, 4)
    if header[:2] != b"\x05\x00":
        raise ToolError("代理转发自检失败。")
    size = {1: 4, 4: 16}.get(header[3])
    if header[3] == 3:
        size = receive(sock, 1)[0]
    if size is None:
        raise ToolError("SOCKS5 返回了无效地址。")
    receive(sock, size + 2)


def wait_listener(host, port, process=None):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise ToolError("GOST 自检客户端启动失败。")
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    raise ToolError("端口未开始监听。")


def probe(state):
    host = local_host(state["listen"])
    wait_listener(host, state["port"])
    if state["mode"] == "socks5":
        # An anonymous client must be rejected, even when it offers no password method.
        with socket.create_connection((host, state["port"]), timeout=5) as sock:
            sock.sendall(b"\x05\x01\x00")
            if receive(sock, 2) != b"\x05\xff":
                raise ToolError("匿名代理自检失败：服务未强制认证。")
    else:
        ca_file = str(CERT if state["trust"] == "self-signed" else CA) if state["trust"] != "system" else None
        context = ssl.create_default_context(cafile=ca_file)
        with socket.create_connection((host, state["port"]), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=state["host"]):
                pass
    # A local echo target verifies real TCP forwarding without calling an external website.
    with socket.socket() as target, tempfile.TemporaryDirectory(prefix="socks5-probe-") as temp:
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(8)
        token = secrets.token_bytes(32)

        def echo():
            try:
                with target.accept()[0] as connection:
                    connection.settimeout(5)
                    connection.sendall(receive(connection, len(token)))
            except (OSError, ToolError):
                pass

        threading.Thread(target=echo, daemon=True).start()
        process = None
        port = state["port"]
        try:
            if state["mode"] == "tls":
                port = choose_port("127.0.0.1")
                config = client_config(state, local_port=port, remote_host=host, ca_file=ca_file)
                path = Path(temp) / "client.json"
                write_json(path, config)
                process = subprocess.Popen([str(BINARY), "-C", str(path)],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                wait_listener("127.0.0.1", port, process)
                host = "127.0.0.1"
            with socket.create_connection((host, port), timeout=6) as sock:
                if state["mode"] == "socks5":
                    socks_auth(sock, state["username"], state["password"])
                else:
                    socks_auth(sock)
                socks_connect(sock, target.getsockname()[1])
                sock.sendall(token)
                if receive(sock, len(token)) != token:
                    raise ToolError("TCP 转发数据校验失败。")
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def health_check(state):
    if run(["systemctl", "is-active", "--quiet", SERVICE], check=False).returncode:
        raise ToolError("服务未运行；请使用 socks5 logs 查看日志。")
    probe(state)


def firewall_status():
    if shutil.which("ufw"):
        result = run(["ufw", "status"], check=False)
        if result.returncode == 0 and "Status: active" in result.stdout:
            return "ufw", result.stdout
    if shutil.which("firewall-cmd"):
        if run(["firewall-cmd", "--state"], check=False).returncode == 0:
            return "firewalld", ""
    return None, ""


def open_firewall(port):
    backend, status = firewall_status()
    if backend is None:
        raise ToolError("--open-firewall 需要已启用的 UFW 或 firewalld；请手动放行 TCP {}。".format(port))
    rule = {"backend": backend, "port": port}
    if backend == "ufw":
        if re.search(r"^\s*{}(?:/tcp)?(?:\s|$)".format(port), status, re.M):
            say("UFW 已有该端口规则，保留原规则，请确认允许来源。")
            return None
        run(["ufw", "allow", str(port) + "/tcp", "comment", TOOL + ":" + str(port)])
        return rule
    # Record the zone and each newly added rule; never reload or clear other rules.
    active = run(["firewall-cmd", "--get-active-zones"]).stdout
    zones = [line.strip() for line in active.splitlines() if line and not line[0].isspace()]
    if len(zones) > 1:
        raise ToolError("firewalld 存在多个活动 zone，请手动放行端口，避免修改错误的 zone。")
    rule["zone"] = zones[0] if zones else run(["firewall-cmd", "--get-default-zone"]).stdout.strip()
    rule["scopes"] = []
    try:
        for scope in ("runtime", "permanent"):
            prefix = ["firewall-cmd", "--zone=" + rule["zone"]]
            if scope == "permanent":
                prefix.append("--permanent")
            if run(prefix + ["--query-port={}/tcp".format(port)], check=False).returncode:
                run(prefix + ["--add-port={}/tcp".format(port)])
                rule["scopes"].append(scope)
    except BaseException:
        remove_firewall(rule)
        raise
    return rule if rule["scopes"] else None


def remove_firewall(rule):
    port = valid_port(rule["port"])
    if rule["backend"] == "ufw":
        result = run(["ufw", "status"], check=False)
        text = result.stdout
        if "Status: inactive" in text:
            text = run(["ufw", "show", "added"]).stdout
        marker = re.escape(TOOL + ":" + str(port)) + r"(?:['\"\s]|$)"
        if re.search(marker, text):
            run(["ufw", "--force", "delete", "allow", str(port) + "/tcp", "comment", TOOL + ":" + str(port)])
    elif rule["backend"] == "firewalld":
        for scope in rule["scopes"]:
            args = ["firewall-cmd", "--zone=" + rule["zone"]]
            if scope == "permanent":
                args.append("--permanent")
            result = run(args + ["--query-port={}/tcp".format(port)], check=False)
            if result.returncode not in (0, 1):
                raise ToolError("无法查询 firewalld 规则，已保留管理状态，请检查防火墙服务。")
            if result.returncode == 0:
                run(args + ["--remove-port={}/tcp".format(port)])
    else:
        raise ToolError("无法识别保存的防火墙规则。")


def load_state():
    if not STATE.is_file():
        raise ToolError("尚未安装，请运行 socks5.sh install。")
    state = json.loads(STATE.read_text())
    if state.get("tool") != TOOL or state.get("schema") != 1 or state.get("mode") not in ("socks5", "tls"):
        raise ToolError("状态文件格式不符合本工具，请检查 " + str(STATE))
    valid_port(state["port"])
    valid_credential(state["username"], "用户名")
    valid_credential(state["password"], "密码")
    ipaddress.ip_address(state["listen"])
    if state["host"]:
        valid_host(state["host"])
    if state["mode"] == "tls" and (not state["host"] or state.get("trust") not in ("system", "custom", "self-signed")):
        raise ToolError("TLS 状态文件不完整。")
    return state


def bundle_bytes(state, local_port=1080, host=None):
    config = client_config(state, local_port=local_port, remote_host=host)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("client.json", json.dumps(config, ensure_ascii=False, indent=2) + "\n")
        if state["mode"] == "tls" and state["trust"] != "system":
            archive.writestr("server.crt", (CERT if state["trust"] == "self-signed" else CA).read_bytes())
        archive.writestr("README.txt", "安装 GOST v3，将文件解压到专用目录。在该目录运行：\n"
                         "gost -C client.json\n\n"
                         "应用代理：SOCKS5 127.0.0.1:{}，应用中用户名密码留空。\n"
                         "本机 GOST 持有远端认证信息，请限制该目录和 client.json 的读取权限。\n"
                         "保持 GOST 运行；证书文件只包含公钥，不包含 VPS 私钥。\n"
                         "TLS 模式必须保留 secure=true；普通 SOCKS5 模式没有隧道加密。\n".format(local_port))
    return buffer.getvalue()


def refresh_bundle(state):
    if state["host"]:
        atomic_write(BUNDLE, bundle_bytes(state))


def show_info(state, password=True):
    say("模式：{}\n监听：{}\n服务器地址：{}\n用户名：{}".format(
        "SOCKS5" if state["mode"] == "socks5" else "TLS 加密隧道",
        endpoint(state["listen"], state["port"]), state["host"] or "请填写 VPS 公网 IP", state["username"]))
    if password:
        say("密码：" + state["password"])
    if state["mode"] == "tls":
        say("TLS 模式需要本机 GOST 客户端；证书校验已开启。")
    if BUNDLE.exists():
        say("客户端配置包：" + str(BUNDLE))
    say("请确认云安全组和主机防火墙允许 TCP {}。".format(state["port"]))


def prompt(text, default="", secret=False):
    if not sys.stdin.isatty():
        raise ToolError("非交互运行请添加 --auto，密码可用 --password-stdin 提供。")
    if secret:
        import getpass
        return getpass.getpass(text) or default
    return input(text) or default


def credentials(args, previous=None):
    username = args.username
    if username is None:
        username = (previous or {}).get("username", "")
        if not args.auto:
            username = prompt("用户名（回车{}）：".format("保留原用户名" if previous else "自动生成"), username)
        username = username or "s5_" + secrets.token_hex(4)
    if args.password_stdin:
        password = sys.stdin.read(4097)
        if password.endswith("\n"):
            password = password[:-1]
            if password.endswith("\r"):
                password = password[:-1]
    elif args.auto:
        password = secrets.token_urlsafe(18)
    else:
        password = prompt("密码（回车自动生成）：", secret=True) or secrets.token_urlsafe(18)
    return valid_credential(username, "用户名"), valid_credential(password, "密码")


def install(args, source):
    if any(path.exists() for path in (CONFIG_DIR, PREFIX, UNIT, MANAGER)):
        raise ToolError("保留路径已有文件，未覆盖。已安装时请使用 set-auth / set-port；可用 info 查看。")
    if args.ca and not args.cert or bool(args.cert) != bool(args.key):
        raise ToolError("自定义证书需要同时提供 --cert 和 --key；--ca 需与它们一起使用。")
    if args.mode != "tls" and (args.cert or args.key or args.ca):
        raise ToolError("证书参数仅适用于 --mode tls。")
    listen = str(ipaddress.ip_address(args.listen))
    username, password = credentials(args)
    host = args.host or detect_host(listen)
    if args.mode == "tls" and not host:
        if args.auto:
            raise ToolError("TLS 自动安装需要 --host VPS公网IP或域名，用于生成并校验证书。")
        host = prompt("VPS 公网 IP 或域名（用于证书和客户端连接）：")
    host = valid_host(host) if host else ""
    port = args.port
    if port is None and not args.auto:
        value = prompt("端口（回车随机高位端口）：")
        port = valid_port(value) if value else None
    port = valid_port(port) if port is not None else choose_port(listen)
    if not port_available(port, listen):
        raise ToolError("端口已占用，或监听地址不属于本机：" + endpoint(listen, port))
    state = {"tool": TOOL, "schema": 1, "mode": args.mode, "listen": listen, "host": host,
             "port": port, "username": username, "password": password,
             "gost_version": GOST_VERSION, "trust": "system", "firewalls": [], "created_user": False}
    ensure_dependencies()
    if args.open_firewall and firewall_status()[0] is None:
        raise ToolError("未发现已启用的 UFW/firewalld；请取消 --open-firewall 并手动放行端口。")
    with tempfile.TemporaryDirectory(prefix="socks5-install-") as temp:
        staged_binary = Path(temp) / "gost"
        download_gost(staged_binary)
        created = False
        try:
            state["created_user"] = create_account()
            created = True
            CONFIG_DIR.mkdir(mode=0o750)
            os.chmod(CONFIG_DIR, 0o750)
            os.chown(CONFIG_DIR, 0, service_gid())
            PREFIX.mkdir(mode=0o755)
            os.chmod(PREFIX, 0o755)
            atomic_write(BINARY, staged_binary.read_bytes(), 0o755)
            if args.mode == "tls":
                install_certificate(state, args.cert, args.key, args.ca)
            write_json(CONFIG, server_config(state), 0o640, service_gid())
            atomic_write(UNIT, unit_content(), 0o644)
            atomic_write(MANAGER, source.read_bytes(), 0o755)
            if args.open_firewall:
                rule = open_firewall(port)
                if rule:
                    state["firewalls"].append(rule)
            # Keep an ownership record before starting the service, also useful after a power loss.
            write_json(STATE, state)
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", "--now", SERVICE])
            health_check(state)
            refresh_bundle(state)
            write_json(STATE, state)
        except BaseException:
            if created:
                say("安装失败，正在清理本次创建的资源……")
                stopped = run(["systemctl", "disable", "--now", SERVICE], check=False).returncode == 0
                # If stopping fails, retain files for recovery instead of deleting a running service.
                if not stopped and UNIT.exists():
                    write_json(STATE, state)
                    say("服务停止失败，已保留资源。请检查 systemctl status " + SERVICE)
                    raise
                cleanup_failed = False
                for rule in state["firewalls"]:
                    try:
                        remove_firewall(rule)
                    except ToolError as exc:
                        say("防火墙清理失败：" + str(exc))
                        cleanup_failed = True
                if cleanup_failed:
                    write_json(STATE, state)
                    say("已保留状态及文件，可在修复防火墙后运行 socks5 uninstall 清理。")
                    raise
                delete_account()
                for path in (UNIT, MANAGER):
                    if path.exists():
                        path.unlink()
                for path in (CONFIG_DIR, PREFIX):
                    if path.exists():
                        shutil.rmtree(path)
                run(["systemctl", "daemon-reload"], check=False)
            raise
    say("安装成功，认证和 TCP 转发自检通过；已设置开机启动。")
    show_info(state)


def apply_change(previous, updated, open_port=False):
    old_config = CONFIG.read_bytes()
    old_bundle = BUNDLE.read_bytes() if BUNDLE.exists() else None
    new_rule = None
    try:
        if updated["port"] != previous["port"] and (open_port or previous["firewalls"]):
            new_rule = open_firewall(updated["port"])
            if new_rule:
                updated["firewalls"].append(new_rule)
        write_json(CONFIG, server_config(updated), 0o640, service_gid())
        run(["systemctl", "restart", SERVICE])
        health_check(updated)
        refresh_bundle(updated)
        write_json(STATE, updated)
    except BaseException:
        say("变更失败，正在恢复旧配置……")
        atomic_write(CONFIG, old_config, 0o640, service_gid())
        rollback_state = copy.deepcopy(previous)
        if old_bundle is not None:
            atomic_write(BUNDLE, old_bundle)
        elif BUNDLE.exists():
            BUNDLE.unlink()
        if new_rule:
            try:
                remove_firewall(new_rule)
            except ToolError as exc:
                say("新端口规则清理失败：" + str(exc))
                rollback_state["firewalls"].append(new_rule)
        write_json(STATE, rollback_state)
        result = run(["systemctl", "restart", SERVICE], check=False)
        if result.returncode:
            say("旧服务重启失败，请运行 socks5 logs 检查。")
        raise
    if updated["port"] != previous["port"]:
        kept = []
        for rule in updated["firewalls"]:
            if rule["port"] == updated["port"]:
                kept.append(rule)
                continue
            try:
                remove_firewall(rule)
            except ToolError as exc:
                say("旧防火墙规则保留待清理：" + str(exc))
                kept.append(rule)
        updated["firewalls"] = kept
        write_json(STATE, updated)
    say("变更成功，自检通过。旧客户端配置包已更新，请重新复制到本机。")


def uninstall(args):
    state = load_state()
    if not args.yes and prompt("确认卸载并删除本工具的账号配置和证书？[y/N]：").lower() != "y":
        say("已取消。")
        return
    run(["systemctl", "disable", "--now", SERVICE])
    for rule in state["firewalls"]:
        remove_firewall(rule)
    if state["created_user"]:
        delete_account()
    for path in (UNIT, MANAGER):
        if path.exists():
            path.unlink()
    for path in (CONFIG_DIR, PREFIX):
        if path.exists():
            shutil.rmtree(path)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "reset-failed", SERVICE], check=False)
    say("已卸载本工具的服务、配置和二进制。你自行复制的客户端配置包需自行删除。")


def parser():
    root = argparse.ArgumentParser(prog="socks5", description="VPS SOCKS5 / TLS 一键部署与管理（GOST v3）")
    root.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    commands = root.add_subparsers(dest="command")
    setup = commands.add_parser("install", help="安装；回车生成账号、密码和高位端口")
    setup.add_argument("--mode", choices=("socks5", "tls"), default="socks5", help="默认 socks5；tls 需要本机 GOST")
    setup.add_argument("--port", type=int, help="指定 1024–65535 端口")
    setup.add_argument("--listen", default="0.0.0.0", help="监听 IP；默认 IPv4 全接口，可指定 ::")
    setup.add_argument("--host", help="VPS 公网 IP/域名，用于客户端连接及 TLS 证书")
    setup.add_argument("--cert", help="自定义完整证书链 PEM 文件")
    setup.add_argument("--key", help="自定义未加密私钥 PEM 文件")
    setup.add_argument("--ca", help="自定义私有 CA PEM 文件；默认使用系统信任库")
    setup.add_argument("--open-firewall", action="store_true", help="在已启用的 UFW/firewalld 中添加 TCP 规则")
    auth = commands.add_parser("set-auth", help="修改认证；回车保留用户名、生成新密码")
    for command in (setup, auth):
        command.add_argument("--username", help="自定义用户名")
        command.add_argument("--password-stdin", action="store_true", help="从标准输入读取密码，避免出现在进程参数中")
        command.add_argument("--auto", action="store_true", help="非交互运行，未指定的凭据自动生成")
    port = commands.add_parser("set-port", help="修改端口；不指定则随机生成")
    port.add_argument("port", type=int, nargs="?")
    port.add_argument("--open-firewall", action="store_true", help="添加新端口的工具所属防火墙规则")
    for name, help_text in (("info", "显示连接信息和密码"), ("status", "显示服务状态，不显示密码"),
                            ("start", "启动并自检"), ("stop", "停止服务"), ("restart", "重启并自检"),
                            ("check", "验证认证、TLS 证书及 TCP 转发"), ("logs", "显示最近 50 行服务日志")):
        commands.add_parser(name, help=help_text)
    export = commands.add_parser("export-client", help="导出本机 GOST 配置包，不含 VPS 私钥")
    export.add_argument("--output", help="新 ZIP 文件路径；已有文件不会被覆盖")
    export.add_argument("--host", help="覆盖连接地址；TLS 仍校验原证书名称")
    export.add_argument("--local-port", type=int, default=1080, help="本机 SOCKS5 端口，默认 1080")
    remove = commands.add_parser("uninstall", help="卸载本工具")
    remove.add_argument("--yes", action="store_true", help="确认卸载，用于非交互运行")
    return root


def dispatch(args, source):
    if args.command == "install":
        install(args, source)
        return
    if args.command == "uninstall":
        uninstall(args)
        return
    state = load_state()
    if args.command == "info":
        show_info(state)
    elif args.command == "status":
        show_info(state, password=False)
        result = run(["systemctl", "is-active", SERVICE], check=False)
        say("服务状态：" + result.stdout.strip())
    elif args.command in ("start", "restart", "check"):
        if args.command != "check":
            run(["systemctl", args.command, SERVICE])
        health_check(state)
        say("服务运行正常，认证和 TCP 转发自检通过。")
    elif args.command == "stop":
        run(["systemctl", "stop", SERVICE])
        say("服务已停止。")
    elif args.command == "logs":
        result = run(["journalctl", "-u", SERVICE, "-n", "50", "--no-pager"])
        say(result.stdout.replace(state["password"], "[密码已隐藏]"))
    elif args.command == "set-auth":
        updated = copy.deepcopy(state)
        updated["username"], updated["password"] = credentials(args, state)
        apply_change(state, updated)
        show_info(updated)
    elif args.command == "set-port":
        updated = copy.deepcopy(state)
        updated["port"] = valid_port(args.port) if args.port is not None else choose_port(state["listen"])
        if updated["port"] == state["port"]:
            say("端口未改变。")
            return
        if not port_available(updated["port"], state["listen"]):
            raise ToolError("新端口已占用，未修改配置。")
        apply_change(state, updated, args.open_firewall)
        show_info(updated)
    elif args.command == "export-client":
        local_port = valid_port(args.local_port)
        host = valid_host(args.host) if args.host else None
        destination = Path(args.output).expanduser().resolve() if args.output else BUNDLE
        data = bundle_bytes(state, local_port, host)
        if destination != BUNDLE:
            fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        else:
            atomic_write(BUNDLE, data)
        say("已导出：{}\n解压后在该目录运行 gost -C client.json。".format(destination))


def menu():
    say("\nVPS SOCKS5 工具 v{}\n"
        "1. 安装普通 SOCKS5\n2. 安装 TLS 加密隧道\n3. 查看连接信息\n4. 查看状态\n"
        "5. 修改用户名和密码\n6. 修改端口\n7. 重启服务\n8. 导出客户端配置\n"
        "9. 查看日志\n10. 卸载\n0. 退出".format(VERSION))
    choice = prompt("请选择：")
    choices = {"1": ["install"], "2": ["install", "--mode", "tls"], "3": ["info"],
               "4": ["status"], "5": ["set-auth"], "7": ["restart"], "8": ["export-client"],
               "9": ["logs"], "10": ["uninstall"], "0": []}
    if choice == "6":
        port = prompt("新端口（回车随机生成）：")
        return ["set-port", port] if port else ["set-port"]
    if choice not in choices:
        raise ToolError("请输入有效的菜单编号。")
    return choices[choice]


def main(argv, source):
    os.umask(0o077)
    def terminate(signum, frame):
        raise ToolError("收到终止信号，正在退出。")
    signal.signal(signal.SIGTERM, terminate)
    root = parser()
    if not argv:
        if not sys.stdin.isatty():
            root.print_help()
            return 0
        # Python source is read from stdin; interactive prompts use the controlling terminal.
        argv = menu()
        if not argv:
            return 0
    if argv == ["help"]:
        argv = ["--help"]
    args = root.parse_args(argv)
    if not args.command:
        root.print_help()
        return 0
    check_environment()
    with locked():
        dispatch(args, source)
    return 0


if __name__ == "__main__":
    try:
        # The here-document carries the program. Reopen stdin so prompts and --password-stdin
        # read the caller's original input, saved by Bash as fd 3 below.
        sys.stdin = os.fdopen(os.dup(3), "r", encoding="utf-8")
        sys.exit(main(sys.argv[2:], Path(sys.argv[1]).resolve()))
    except (ToolError, OSError, ValueError, KeyError) as exc:
        print("错误：" + str(exc), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n操作已取消。", file=sys.stderr)
        sys.exit(130)
PY_SOCKS5
