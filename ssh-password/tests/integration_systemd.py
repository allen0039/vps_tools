#!/usr/bin/env python3
"""仅在带测试标记、无外部网络的专用 root/systemd 容器中运行。"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path("/var/lib/sshpasswdtool-integration")
CONFIG = Path("/etc/ssh/sshd_config")
ACCOUNT = "sshpasswd_fixture"
SPEC = importlib.util.spec_from_file_location("ssh_password_tool", ROOT / "ssh_password_tool.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def run(args, data=None, check=True, env=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=20, env=env)
    if check and result.returncode:
        raise AssertionError("command failed: " + repr(args) + "\n" + result.stderr)
    return result


def check_guard():
    if os.geteuid() != 0 or not Path("/etc/sshpasswdtool-integration-container").is_file():
        sys.exit("Use a disposable test container with /etc/sshpasswdtool-integration-container; never run on a VPS.")
    os.environ.pop("SSH_CONNECTION", None)
    run(["systemctl", "is-active", "--quiet", "ssh.service"])


def configure(password="no", permit="prohibit-password", methods="any", match=""):
    CONFIG.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nListenAddress 127.0.0.1\n"
                      "HostKey /etc/ssh/ssh_host_ed25519_key\nPubkeyAuthentication yes\n"
                      "PasswordAuthentication " + password + "\nKbdInteractiveAuthentication no\n"
                      "PermitRootLogin " + permit + "\nAuthenticationMethods " + methods + "\n"
                      "UsePAM yes\nAuthorizedKeysFile .ssh/authorized_keys\nSubsystem sftp internal-sftp\n" + match)
    run(["/usr/sbin/sshd", "-t"])
    run(["systemctl", "reload", "ssh.service"])


def setup():
    FIXTURE.mkdir(mode=0o700, exist_ok=True)
    password = secrets.token_urlsafe(32)
    run(["useradd", "-m", "-s", "/bin/bash", ACCOUNT], check=False)
    run(["chpasswd"], data="root:" + password + "\n" + ACCOUNT + ":" + password + "\n")
    key = FIXTURE / "id_ed25519"
    if not key.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    for user, home in (("root", Path("/root")), (ACCOUNT, Path("/home") / ACCOUNT)):
        directory = home / ".ssh"
        directory.mkdir(mode=0o700, exist_ok=True)
        authorized = directory / "authorized_keys"
        authorized.write_bytes(key.with_suffix(".pub").read_bytes())
        authorized.chmod(0o600)
        run(["chown", "-R", user + ":" + user, str(directory)])
    value = FIXTURE / "credentials.json"
    value.write_text(json.dumps({"password": password}))
    value.chmod(0o600)
    configure()
    host_key = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text()
    (FIXTURE / "known_hosts").write_text("127.0.0.1 " + host_key)
    return password


def login(password=None, user="root", port=22):
    args = ["ssh", "-F", "/dev/null", "-p", str(port), "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + str(FIXTURE / "known_hosts"), "-o", "ControlPath=none",
            "-o", "ControlMaster=no", "-o", "ConnectTimeout=3", "-o", "KbdInteractiveAuthentication=no"]
    env = dict(os.environ)
    if password is not None:
        args = ["sshpass", "-e", *args, "-o", "PreferredAuthentications=password", "-o",
                "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1"]
        env["SSHPASS"] = password
    else:
        args += ["-i", str(FIXTURE / "id_ed25519"), "-o", "IdentitiesOnly=yes", "-o",
                 "PasswordAuthentication=no", "-o", "BatchMode=yes"]
    return run([*args, user + "@127.0.0.1", "true"], check=False, env=env).returncode == 0


def assert_login(expected, password=None, user="root", port=22):
    deadline = time.monotonic() + 5
    while True:
        if login(password, user, port) == expected:
            return
        if time.monotonic() >= deadline:
            raise AssertionError("unexpected login result: " + repr((expected, user, port, password is not None)))
        time.sleep(0.1)


def cli(*args, success=True):
    result = run([sys.executable, str(ROOT / "ssh_password_tool.py"), *args], check=False)
    if (result.returncode == 0) != success:
        raise AssertionError("unexpected tool result: " + repr(args) + "\n" + result.stdout + result.stderr)
    return result


def timed_test(password):
    assert_login(True)
    assert_login(False, password)
    before_other = module.Backend().effective(ACCOUNT, module.connection_context())
    cli("enable", "--minutes", "1", "--yes")
    manager = module.PasswordTool()
    state = manager.load_state()
    service, timer = manager.units(state["token"])
    run(["systemd-analyze", "verify", str(service), str(timer)])
    assert_login(True, password)
    assert_login(True)
    assert module.Backend().effective(ACCOUNT, module.connection_context()) == before_other
    # 定时开启期间改成新端口，关闭不能恢复旧端口。
    CONFIG.write_bytes(CONFIG.read_bytes().replace(b"Port 22\n", b"Port 22222\n"))
    run(["systemctl", "reload", "ssh.service"])
    with (FIXTURE / "known_hosts").open("a") as stream:
        stream.write("[127.0.0.1]:22222 " + Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text())
    assert_login(True, port=22222)
    assert_login(True, password, port=22222)
    print("PASS: real key/password logins during 60-second window; timer survives CLI exit", flush=True)
    deadline = time.monotonic() + 75
    while manager.load_state()["phase"] != "closed":
        if time.monotonic() >= deadline:
            log = run(["journalctl", "-u", service.name, "--no-pager"], check=False).stdout
            raise AssertionError("timer did not restore: " + log)
        time.sleep(0.25)
    assert not manager.auth_file.exists()
    assert b"Port 22222\n" in CONFIG.read_bytes()
    assert_login(False, password, port=22222)
    assert_login(True, port=22222)
    print("PASS: real systemd expiry blocks new passwords, preserves keys and changed port", flush=True)


def remaining_tests(password):
    # 全局允许密码但 root 单独 prohibit-password 的常见基线。
    configure(password="yes")
    dropin = Path("/etc/ssh/sshd_config.d/50-fixture.conf")
    dropin.write_text("# provider fixture\nPasswordAuthentication yes\n")
    saved_dropin = dropin.read_bytes()
    cli("enable", "--until-reboot", "--yes")
    assert_login(True, password)
    assert_login(True)
    run(["systemctl", "restart", "ssh.service"])
    assert_login(True, password)  # SSH 服务重启不是服务器重启。
    cli("close", "--yes")
    assert_login(False, password)
    assert_login(True)
    assert dropin.read_bytes() == saved_dropin
    dropin.unlink()
    print("PASS: root prohibit-password restored; provider include preserved", flush=True)

    configure(password="yes", permit="yes", methods="publickey")
    assert_login(False, password)
    cli("enable", "--minutes", "5", "--yes")
    assert_login(True, password)
    assert_login(True)
    cli("close", "--yes")
    assert_login(False, password)
    assert_login(True)
    print("PASS: AuthenticationMethods publickey restored", flush=True)

    configure()
    cli("enable", "--user", ACCOUNT, "--minutes", "5", "--yes")
    assert_login(True, password, ACCOUNT)
    assert_login(True, user=ACCOUNT)
    assert_login(False, password)
    cli("close", "--yes")
    assert_login(False, password, ACCOUNT)
    assert_login(True, user=ACCOUNT)
    print("PASS: ordinary-user window does not enable root passwords", flush=True)

    configure(match="Match User root\n    PasswordAuthentication no\n    PermitRootLogin prohibit-password\n")
    original = CONFIG.read_bytes()
    cli("enable", "--minutes", "5", "--yes", success=False)
    assert CONFIG.read_bytes() == original
    assert not Path("/run/sshpasswdtool/auth.conf").exists()
    assert_login(True)
    assert_login(False, password)
    print("PASS: conflicting earlier Match fails and rolls back", flush=True)

    configure()
    run(["passwd", "-l", ACCOUNT])
    original = CONFIG.read_bytes()
    cli("enable", "--user", ACCOUNT, "--minutes", "5", "--yes", success=False)
    assert CONFIG.read_bytes() == original
    run(["chpasswd"], data=ACCOUNT + ":" + password + "\n")
    print("PASS: locked account rejected before configuration changes", flush=True)

    configure(password="yes")
    key_block = ("# BEGIN sshkeytool root\nMatch User root\n    PubkeyAuthentication yes\n"
                 "    ExposeAuthInfo yes\n    AuthenticationMethods publickey\n"
                 "    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n"
                 "    PermitRootLogin prohibit-password\n# END sshkeytool root\n")
    with CONFIG.open("a") as stream:
        stream.write(key_block)
    run(["systemctl", "reload", "ssh.service"])
    assert_login(False, password)
    cli("enable", "--until-reboot", "--yes")
    assert_login(True, password)
    assert_login(True)
    assert key_block in CONFIG.read_text()
    cli("close", "--yes")
    assert key_block in CONFIG.read_text()
    assert_login(False, password)
    assert_login(True)
    assert module.Backend().effective("root", module.connection_context())["authenticationmethods"] == "publickey"
    print("PASS: committed sshkeytool policy works with temporary passwords and is restored", flush=True)


def prepare_restart(password):
    configure(password="yes")
    cli("enable", "--until-reboot", "--yes")
    assert_login(True, password)
    assert_login(True)
    print("READY: restart the disposable container to clear its /run tmpfs", flush=True)


def check_restart():
    password = json.loads((FIXTURE / "credentials.json").read_text())["password"]
    assert not Path("/run/sshpasswdtool/auth.conf").exists()
    assert_login(False, password)
    assert_login(True)
    # Docker restart 共用宿主机 boot_id；这里验证 tmpfs 消失和实际认证，boot_id 分支由单元测试覆盖。
    cli("close", "--yes")
    print("PASS: /run reset restores password prohibition and usable keys", flush=True)


def prepare_permanent_restart():
    password = json.loads((FIXTURE / "credentials.json").read_text())["password"]
    manager = module.PasswordTool()
    previous = manager.load_state()
    assert previous is None or previous["phase"] == "closed"
    configure(password="yes", methods="publickey")
    # 模拟上一版本留下的空入口，验证实际 OpenSSH 配置升级。
    with CONFIG.open("ab") as stream:
        stream.write(manager.legacy_hook())
    run(["systemctl", "reload", "ssh.service"])
    assert_login(False, password)
    assert_login(True)
    cli("enable", "--permanent", "--yes")
    state = manager.load_state()
    assert state["mode"] == "permanent"
    assert manager.persistent_auth_file.stat().st_mode & 0o777 == 0o600
    assert manager.hook() in CONFIG.read_bytes()
    assert not manager.auth_file.exists()
    assert not any(path.exists() for path in manager.units(state["token"]))
    if previous:
        cli("expire", "--token", previous["token"])
    cli("expire", "--token", state["token"])
    run(["systemctl", "restart", "ssh.service"])
    assert_login(True, password)
    assert_login(True)
    assert manager.load_state()["phase"] == "active"
    print("READY: permanent password login and keys work; restart to verify persistence", flush=True)


def check_permanent_restart():
    password = json.loads((FIXTURE / "credentials.json").read_text())["password"]
    manager = module.PasswordTool()
    assert manager.persistent_auth_file.exists()
    assert not manager.auth_file.exists()
    assert "永久模式：active" in cli("status").stdout
    assert_login(True, password)
    assert_login(True)
    changed = CONFIG.read_bytes().replace(b"Port 22\n", b"Port 22223\n")
    CONFIG.write_bytes(changed)
    run(["systemctl", "reload", "ssh.service"])
    assert_login(True, password, port=22223)
    cli("close", "--yes")
    assert CONFIG.read_bytes() == changed
    assert not manager.persistent_auth_file.exists()
    assert manager.load_state()["phase"] == "closed"
    assert_login(False, password, port=22223)
    assert_login(True, port=22223)
    assert module.Backend().effective("root", module.connection_context())["authenticationmethods"] == "publickey"
    print("PASS: permanent mode survives restart; manual close restores key-only login and preserves the port", flush=True)


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check-restart", action="store_true")
    mode.add_argument("--prepare-permanent-restart", action="store_true")
    mode.add_argument("--check-permanent-restart", action="store_true")
    args = parser.parse_args()
    check_guard()
    if args.check_restart:
        check_restart()
        return
    if args.prepare_permanent_restart:
        prepare_permanent_restart()
        return
    if args.check_permanent_restart:
        check_permanent_restart()
        return
    original = CONFIG.read_bytes()
    run(["bash", str(ROOT / "install.sh")])
    assert CONFIG.read_bytes() == original
    password = setup()
    timed_test(password)
    remaining_tests(password)
    prepare_restart(password)


if __name__ == "__main__":
    main()
