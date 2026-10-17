"""Standard-library tests. Set GOST_TEST_BINARY to enable real protocol/lifecycle tests."""
import copy
import io
import json
import os
from pathlib import Path
import pty
import socket
import ssl
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "socks5.sh"


def load_manager():
    source = SCRIPT.read_text().split("<<'PY_SOCKS5'\n", 1)[1].rsplit("\nPY_SOCKS5", 1)[0]
    module = types.ModuleType("socks5_manager")
    exec(compile(source, str(SCRIPT), "exec"), module.__dict__)
    return module


class ManagerCase(unittest.TestCase):
    def enterContext(self, context):
        # unittest.TestCase.enterContext was introduced in Python 3.11.
        result = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return result

    def setUp(self):
        self.manager = load_manager()
        self.temporary = tempfile.TemporaryDirectory(prefix="socks5-tests-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        paths = {"CONFIG_DIR": root / "etc", "PREFIX": root / "lib",
                 "MANAGER": root / "bin" / "socks5", "UNIT": root / "systemd" / "vps-socks5.service"}
        for key, value in paths.items():
            setattr(self.manager, key, value)
        for key, filename in (("CONFIG", "config.json"), ("STATE", "state.json"),
                              ("CERT", "server.crt"), ("KEY", "server.key"),
                              ("CA", "ca.crt"), ("BUNDLE", "client.zip")):
            setattr(self.manager, key, paths["CONFIG_DIR"] / filename)
        self.manager.BINARY = paths["PREFIX"] / "gost"
        for path in (paths["MANAGER"].parent, paths["UNIT"].parent):
            path.mkdir()
        self.manager.service_gid = lambda: os.getgid()
        self.enterContext(mock.patch.object(self.manager.os, "chown"))
        self.enterContext(mock.patch.object(self.manager.os, "fchown"))
        self.enterContext(mock.patch.object(self.manager, "say"))

    def state(self, mode="socks5"):
        return {"tool": "vps-socks5", "schema": 1, "mode": mode, "listen": "127.0.0.1",
                "host": "127.0.0.1", "port": self.manager.choose_port("127.0.0.1"),
                "username": '用#户/"名', "password": 'p#as/s:@" \\word$密',
                "trust": "self-signed" if mode == "tls" else "system",
                "firewalls": [], "created_user": True, "gost_version": "3.3.0"}


class ValidationTests(ManagerCase):
    def test_cli_help_and_noninteractive_menu(self):
        for arguments in (["--help"], ["install", "--help"], []):
            result = subprocess.run(["bash", str(SCRIPT)] + arguments, input="", text=True,
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("socks5", result.stdout.lower())

    def test_password_stdin_keeps_special_characters(self):
        password = 'p#/:@" \\密$'
        args = self.manager.parser().parse_args(["install", "--auto", "--password-stdin"])
        with mock.patch.object(self.manager.sys, "stdin", io.StringIO(password + "\n")):
            user, result = self.manager.credentials(args)
        self.assertTrue(user.startswith("s5_"))
        self.assertEqual(result, password)
        for invalid in ("", "x\ny", "密" * 86):
            with self.assertRaises(self.manager.ToolError):
                self.manager.valid_credential(invalid, "密码")

    def test_interactive_menu_reads_saved_terminal_input(self):
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen(["bash", str(SCRIPT)], stdin=slave,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            os.close(slave)
            slave = None
            os.write(master, b"0\n")
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn("请选择", stdout)
        finally:
            os.close(master)
            if slave is not None:
                os.close(slave)

    def test_ports_and_host_validation(self):
        for port in (0, 108, 65536, "1;id", True):
            with self.assertRaises(self.manager.ToolError):
                self.manager.valid_port(port)
        for host in ("", "https://example.com", "example.com:443", "0.0.0.0", "a..com", "x;id"):
            with self.assertRaises(self.manager.ToolError):
                self.manager.valid_host(host)
        self.assertEqual(self.manager.valid_host("2001:db8::1"), "2001:db8::1")
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            self.assertFalse(self.manager.port_available(occupied.getsockname()[1], "127.0.0.1"))
            port = self.manager.choose_port("127.0.0.1")
            self.assertTrue(20000 <= port <= 60000)
            self.assertTrue(self.manager.port_available(port, "127.0.0.1"))

    def test_export_contains_credentials_but_never_private_key(self):
        m = self.manager
        m.CONFIG_DIR.mkdir()
        m.CERT.write_text("public certificate")
        m.KEY.write_text("PRIVATE KEY MUST NEVER LEAVE VPS")
        state = self.state("tls")
        data = m.bundle_bytes(state)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(set(archive.namelist()), {"client.json", "server.crt", "README.txt"})
            client = json.loads(archive.read("client.json"))
            node = client["chains"][0]["hops"][0]["nodes"][0]
            self.assertTrue(node["dialer"]["tls"]["secure"])
            self.assertEqual(node["connector"]["auth"]["password"], state["password"])
            self.assertEqual(client["services"][0]["addr"], "127.0.0.1:1080")
        self.assertNotIn(m.KEY.read_bytes(), data)

    def test_failed_download_hash_cannot_install_binary(self):
        self.manager.PREFIX.mkdir()
        with mock.patch.object(self.manager.urllib.request, "urlopen", return_value=io.BytesIO(b"tampered")):
            with self.assertRaisesRegex(self.manager.ToolError, "校验失败"):
                self.manager.download_gost(self.manager.BINARY, arch="amd64")
        self.assertFalse(self.manager.BINARY.exists())

    def test_ufw_does_not_claim_existing_rule(self):
        m = self.manager
        with mock.patch.object(m, "firewall_status", return_value=("ufw", "Status: active\n52381/tcp ALLOW Anywhere\n")):
            with mock.patch.object(m, "run") as run:
                self.assertIsNone(m.open_firewall(52381))
                run.assert_not_called()

    def test_ufw_will_not_delete_rule_without_ownership_marker(self):
        m = self.manager
        with mock.patch.object(m, "run", return_value=subprocess.CompletedProcess([], 0, "52381/tcp ALLOW Anywhere", "")) as run:
            m.remove_firewall({"backend": "ufw", "port": 52381})
        self.assertEqual(run.call_count, 1)

    def test_ufw_marker_port_must_match_exactly(self):
        m = self.manager
        with mock.patch.object(m, "run", return_value=subprocess.CompletedProcess([], 0, "52381/tcp ALLOW Anywhere # vps-socks5:52381", "")) as run:
            m.remove_firewall({"backend": "ufw", "port": 5238})
        self.assertEqual(run.call_count, 1)

    def test_firewalld_unavailable_keeps_rule_for_retry(self):
        m = self.manager
        with mock.patch.object(m, "run", return_value=subprocess.CompletedProcess([], 252, "", "not running")):
            with self.assertRaises(m.ToolError):
                m.remove_firewall({"backend": "firewalld", "port": 52381, "zone": "public", "scopes": ["permanent"]})

    def test_firewalld_only_removes_scopes_it_added(self):
        m = self.manager
        commands = []

        def run(args, **kwargs):
            commands.append(args)
            output = "public\n" if "--get-default-zone" in args else ""
            status = 1 if any(x.startswith("--query-port") for x in args) and "--permanent" in args else 0
            return subprocess.CompletedProcess(args, status, output, "")

        with mock.patch.object(m, "firewall_status", return_value=("firewalld", "")), mock.patch.object(m, "run", side_effect=run):
            rule = m.open_firewall(52381)
            self.assertEqual(rule["scopes"], ["permanent"])
        commands.clear()
        with mock.patch.object(m, "run", side_effect=lambda args, **kw: (commands.append(args) or subprocess.CompletedProcess(args, 0, "", ""))):
            m.remove_firewall(rule)
        removals = [args for args in commands if any(x.startswith("--remove-port") for x in args)]
        self.assertEqual(len(removals), 1)
        self.assertIn("--permanent", removals[0])
        self.assertFalse(any("--reload" in command for command in commands))


GOST = os.environ.get("GOST_TEST_BINARY")


@unittest.skipUnless(GOST, "set GOST_TEST_BINARY for real GOST tests")
class ProtocolAndLifecycleTests(ManagerCase):
    def setUp(self):
        super().setUp()
        self.process = None
        self.log = tempfile.TemporaryFile()
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop)
        self.real_run = self.manager.run
        self.enterContext(mock.patch.object(self.manager, "run", side_effect=self.system_run))

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None

    def start(self):
        self.stop()
        self.process = subprocess.Popen([str(self.manager.BINARY), "-C", str(self.manager.CONFIG)],
                                        stdout=self.log, stderr=self.log)
        time.sleep(0.15)

    def system_run(self, args, check=True, **kwargs):
        args = [str(arg) for arg in args]
        if args[0] == "systemctl":
            action = args[1]
            if action in ("restart", "start") or action == "enable":
                self.start()
            elif action in ("stop", "disable"):
                self.stop()
            status = 0
            if action == "is-active":
                status = int(self.process is None or self.process.poll() is not None)
            result = subprocess.CompletedProcess(args, status, "active\n" if status == 0 else "inactive\n", "")
            if status and check:
                raise self.manager.ToolError("test service inactive")
            return result
        if args[0] == "userdel":
            return subprocess.CompletedProcess(args, 0, "", "")
        return self.real_run(args, check=check, **kwargs)

    def install(self, mode="socks5"):
        m = self.manager
        args = m.parser().parse_args(["install", "--auto", "--mode", mode,
                                      "--host", "127.0.0.1", "--listen", "127.0.0.1"])

        def download(path):
            m.atomic_write(path, Path(GOST).read_bytes(), 0o755)

        with mock.patch.object(m, "download_gost", side_effect=download), \
             mock.patch.object(m, "ensure_dependencies"), mock.patch.object(m, "create_account", return_value=True):
            m.install(args, SCRIPT)
        return m.load_state()

    def start_special_credentials(self, mode="socks5"):
        m = self.manager
        m.CONFIG_DIR.mkdir()
        m.PREFIX.mkdir()
        m.atomic_write(m.BINARY, Path(GOST).read_bytes(), 0o755)
        state = self.state(mode)
        if mode == "tls":
            m.install_certificate(state)
        m.write_json(m.CONFIG, m.server_config(state), 0o640)
        self.start()
        m.wait_listener(state["listen"], state["port"], self.process)
        return state

    def test_special_character_password_real_authentication_and_forwarding(self):
        m = self.manager
        state = self.start_special_credentials()
        m.health_check(state)
        with socket.create_connection((state["listen"], state["port"]), timeout=5) as sock:
            with self.assertRaisesRegex(m.ToolError, "认证失败"):
                m.socks_auth(sock, state["username"], "wrong password")

    def test_tls_real_forwarding_and_wrong_credentials(self):
        m = self.manager
        state = self.start_special_credentials("tls")
        m.health_check(state)
        wrong = copy.deepcopy(state)
        wrong["password"] = "wrong password"
        with self.assertRaises(m.ToolError):
            m.probe(wrong)

    def test_tls_rejects_untrusted_certificate_and_wrong_server_name(self):
        m = self.manager
        state = self.start_special_credentials("tls")
        with socket.create_connection((state["listen"], state["port"]), timeout=5) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                ssl.create_default_context().wrap_socket(raw, server_hostname=state["host"])
        wrong = copy.deepcopy(state)
        wrong["host"] = "wrong.example.com"
        with self.assertRaises(ssl.SSLCertVerificationError):
            m.probe(wrong)

    def test_exported_tls_client_works_and_enforces_server_name(self):
        m = self.manager
        state = self.start_special_credentials("tls")
        for wrong_name in (False, True):
            with self.subTest(wrong_name=wrong_name), tempfile.TemporaryDirectory() as temp, socket.socket() as target:
                target.bind(("127.0.0.1", 0))
                target.listen(1)
                target.settimeout(5)
                port = m.choose_port("127.0.0.1")
                with zipfile.ZipFile(io.BytesIO(m.bundle_bytes(state, local_port=port))) as archive:
                    archive.extractall(temp)
                config_path = Path(temp) / "client.json"
                config = json.loads(config_path.read_text())
                if wrong_name:
                    config["chains"][0]["hops"][0]["nodes"][0]["dialer"]["tls"]["serverName"] = "wrong.example.com"
                    config_path.write_text(json.dumps(config))
                process = subprocess.Popen([str(m.BINARY), "-C", "client.json"], cwd=temp,
                                           stdout=self.log, stderr=self.log)
                try:
                    m.wait_listener("127.0.0.1", port, process)
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                        m.socks_auth(sock)
                        if wrong_name:
                            with self.assertRaises(m.ToolError):
                                m.socks_connect(sock, target.getsockname()[1])
                        else:
                            m.socks_connect(sock, target.getsockname()[1])
                            # Relay can defer dialing the target until the first payload arrives.
                            sock.sendall(b"export works")
                            with target.accept()[0] as remote:
                                remote.settimeout(5)
                                self.assertEqual(m.receive(remote, 12), b"export works")
                finally:
                    process.terminate()
                    process.wait(timeout=3)

    def test_custom_ca_certificate_supported_and_system_trust_rejects_it(self):
        m = self.manager
        state = self.start_special_credentials("tls")
        self.stop()
        m.install_certificate(state, cert=m.CERT, key=m.KEY, ca=m.CERT)
        self.start()
        m.health_check(state)
        self.assertEqual(state["trust"], "custom")
        wrong = copy.deepcopy(state)
        wrong["trust"] = "system"
        with self.assertRaises(ssl.SSLCertVerificationError):
            m.probe(wrong)

    def test_socks5_install_change_credentials_port_and_uninstall(self):
        self.lifecycle("socks5")

    def test_tls_install_change_credentials_port_and_uninstall(self):
        self.lifecycle("tls")

    def lifecycle(self, mode):
        m = self.manager
        state = self.install(mode)
        for path in (m.STATE, m.BUNDLE):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(m.CONFIG.stat().st_mode & 0o777, 0o640)
        self.assertEqual(m.CONFIG_DIR.stat().st_mode & 0o777, 0o750)
        self.assertEqual(m.PREFIX.stat().st_mode & 0o777, 0o755)
        with self.assertRaises(m.ToolError):
            self.install(mode)
        updated = copy.deepcopy(state)
        updated["password"] = 'updated#password/"密'
        m.apply_change(state, updated)
        m.health_check(m.load_state())
        old_port = updated["port"]
        new_state = copy.deepcopy(updated)
        new_state["port"] = m.choose_port("127.0.0.1")
        m.apply_change(updated, new_state)
        m.health_check(m.load_state())
        self.assertTrue(m.port_available(old_port, "127.0.0.1"))
        output = m.CONFIG_DIR.parent / "export.zip"
        args = m.parser().parse_args(["export-client", "--output", str(output)])
        m.dispatch(args, SCRIPT)
        with self.assertRaises(FileExistsError):
            m.dispatch(args, SCRIPT)
        m.uninstall(m.parser().parse_args(["uninstall", "--yes"]))
        for path in (m.CONFIG_DIR, m.PREFIX, m.UNIT, m.MANAGER):
            self.assertFalse(path.exists())
        self.assertTrue(output.exists())

    def test_failed_port_change_restores_working_configuration_and_bundle(self):
        m = self.manager
        state = self.install("tls")
        original_bundle = m.BUNDLE.read_bytes()
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            updated = copy.deepcopy(state)
            updated["port"] = occupied.getsockname()[1]
            with self.assertRaises(m.ToolError):
                m.apply_change(state, updated)
        self.assertEqual(m.load_state(), state)
        self.assertEqual(m.BUNDLE.read_bytes(), original_bundle)
        m.health_check(state)

    def test_failed_initial_health_check_cleans_new_install(self):
        m = self.manager
        with mock.patch.object(m, "health_check", side_effect=m.ToolError("injected failure")):
            with self.assertRaises(m.ToolError):
                self.install()
        for path in (m.CONFIG_DIR, m.PREFIX, m.UNIT, m.MANAGER):
            self.assertFalse(path.exists())
        self.assertIsNone(self.process)


if __name__ == "__main__":
    unittest.main()
