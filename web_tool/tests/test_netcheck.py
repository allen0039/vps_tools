import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("netcheck", ROOT / "netcheck.py")
netcheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netcheck)


class Handler(BaseHTTPRequestHandler):
    methods = []

    def do_HEAD(self):
        self.methods.append(self.command)
        if self.path == "/slow":
            time.sleep(0.6)
        status = {"/redirect": 302, "/loop": 302, "/missing": 404, "/no-head": 405}.get(self.path, 200)
        self.send_response(status)
        if self.path == "/redirect":
            self.send_header("Location", "/final?probe=1")
        elif self.path == "/loop":
            self.send_header("Location", "/loop")
        self.send_header("Content-Length", "999999999")
        self.end_headers()

    def do_GET(self):
        self.methods.append(self.command)
        self.send_error(500)

    def log_message(self, *args):
        pass


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:%d" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def cli(self, *args, script=None, cwd=None):
        return subprocess.run([sys.executable, str(script or ROOT / "netcheck.py"), *args],
                              capture_output=True, text=True, cwd=cwd, timeout=10)

    def test_head_and_relative_redirect_preserve_query_without_body(self):
        Handler.methods.clear()
        proc = self.cli("http", self.url + "/redirect", "--json")
        result = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(result["http"]["status"], 200)
        self.assertEqual(result["http"]["url"], self.url + "/final?probe=1")
        self.assertEqual([hop["status"] for hop in result["http"]["hops"]], [302, 200])
        self.assertEqual(Handler.methods, ["HEAD", "HEAD"])
        self.assertEqual(result["http"]["hops"][0]["ip"], "127.0.0.1")

    def test_redirect_loop_and_http_errors(self):
        for path, error in [("/loop", "重定向"), ("/missing", "404"), ("/no-head", "HEAD")]:
            with self.subTest(path=path):
                proc = self.cli("http", self.url + path, "--json", "--max-redirects", "1")
                self.assertEqual(proc.returncode, 1)
                self.assertIn(error, json.loads(proc.stdout)["http"]["error"])

    def test_http_hard_timeout(self):
        start = time.monotonic()
        proc = self.cli("http", self.url + "/slow", "--timeout", "0.2", "--json")
        self.assertEqual(proc.returncode, 1)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertIn("超时", json.loads(proc.stdout)["http"]["error"])

    def test_tcp_open_and_closed_ports(self):
        proc = self.cli("tcp", "127.0.0.1", "--port", str(self.server.server_port), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(result["tcp"][0]["ok"])
        self.assertTrue(result["dns"]["literal_ip"])
        with socket.socket() as bound:
            bound.bind(("127.0.0.1", 0))
            closed_port = bound.getsockname()[1]
            # 未 listen 的已占用端口无法连接。
            proc = self.cli("tcp", "127.0.0.1", "--port", str(closed_port), "--json")
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(json.loads(proc.stdout)["tcp"][0]["ok"])

    def test_literal_ipv6_and_system_resolver(self):
        proc = self.cli("dns", "::1", "--json")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["dns"]["addresses"], [{"ip": "::1", "family": "IPv6"}])
        result = netcheck.resolve("localhost", 2)
        self.assertTrue(result["ok"], result)
        self.assertIn("127.0.0.1", [item["ip"] for item in result["addresses"]])

    def test_invalid_inputs_and_options_are_structured(self):
        for command, target in [("dns", "$(touch nope)"), ("ping", "-c"),
                                ("http", "file:///etc/passwd"), ("http", "https://x:99999"),
                                ("http", "https://user:password@example.com")]:
            with self.subTest(target=target):
                # argparse 会把 -c 当作选项；使用 -- 将其作为目标传入。
                proc = self.cli(command, "--json", "--", target)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertFalse(json.loads(proc.stdout)["ok"])
        for value in ("0", "100", "nan"):
            self.assertEqual(self.cli("dns", "localhost", "--timeout", value).returncode, 2)

    def test_dns_hard_timeout_kills_worker(self):
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / "blocked.py"
            script.write_text("import time; time.sleep(30)\n")
            start = time.monotonic()
            with patch.object(netcheck, "SCRIPT", str(script)):
                result = netcheck.resolve("localhost", 0.2)
            self.assertFalse(result["ok"])
            self.assertIn("超时", result["error"])
            self.assertLess(time.monotonic() - start, 1.5)

    def test_ping_failure_does_not_skip_http_and_url_port(self):
        args = netcheck.parser().parse_args(["check", self.url, "--json"])
        with patch.object(netcheck, "ping_ip", return_value=netcheck.failure("ICMP disabled", ip="127.0.0.1")):
            result = netcheck.execute(args)
        self.assertFalse(result["ok"])
        self.assertTrue(result["http"]["ok"])
        self.assertTrue(result["tcp"][0]["ok"])
        self.assertEqual(result["tcp"][0]["port"], self.server.server_port)

    def test_address_cap_and_concurrency(self):
        lock = threading.Lock()
        state = {"active": 0, "maximum": 0, "calls": 0}

        def probe(ip, port, timeout):
            with lock:
                state["active"] += 1
                state["calls"] += 1
                state["maximum"] = max(state["maximum"], state["active"])
            time.sleep(0.02)
            with lock:
                state["active"] -= 1
            return dict(ok=True, ip=ip)

        dns = dict(addresses=[dict(ip="127.0.0.%d" % i) for i in range(1, 9)])
        args = netcheck.parser().parse_args(["tcp", "localhost", "--max-addresses", "5"])
        with patch.object(netcheck, "tcp_ip", side_effect=probe):
            result = netcheck.probe_addresses(dns, "tcp", args)
        self.assertEqual(len(result), 5)
        self.assertEqual(state["calls"], 5)
        self.assertLessEqual(state["maximum"], 3)

    def test_ping_linux_and_macos_output_and_command(self):
        samples = [
            "5 packets transmitted, 4 received, 20% packet loss, time 4005ms\nrtt min/avg/max/mdev = 1.001/2.002/3.003/0.4 ms",
            "5 packets transmitted, 4 packets received, 20.0% packet loss\nround-trip min/avg/max/stddev = 1.001/2.002/3.003/0.4 ms",
        ]
        for sample in samples:
            result = netcheck.parse_ping(sample)
            self.assertEqual(result["received"], 4)
            self.assertEqual(result["loss_pct"], 20)
            self.assertEqual(result["avg_ms"], 2.002)
        with patch.object(netcheck.platform, "system", return_value="Linux"), \
                patch.object(netcheck.shutil, "which", return_value="/usr/bin/ping"), \
                patch.object(netcheck, "run_process", return_value=subprocess.CompletedProcess([], 0, samples[0], "")) as run:
            self.assertTrue(netcheck.ping_ip("::1", 5, 5)["ok"])
            self.assertIn("-6", run.call_args[0][0])
            self.assertFalse(run.call_args[1].get("shell", False))

    def test_unicode_url_preserves_existing_escapes(self):
        url = netcheck.url_value("https://例子.测试/中文/%2F?q=延迟&literal=%20")
        self.assertIn("xn--", url)
        self.assertIn("/%E4%B8%AD%E6%96%87/%2F", url)
        self.assertIn("literal=%20", url)

    def test_interrupt_reaps_running_ping(self):
        with tempfile.TemporaryDirectory() as folder:
            mock_ping = Path(folder) / "ping"
            marker = Path(folder) / "ping.pid"
            mock_ping.write_text("#!%s\nimport os, time\nopen(%r, 'w').write(str(os.getpid()))\ntime.sleep(30)\n" % (sys.executable, str(marker)))
            mock_ping.chmod(0o755)
            env = dict(os.environ, PATH=folder + os.pathsep + os.environ["PATH"])
            proc = subprocess.Popen([sys.executable, str(ROOT / "netcheck.py"), "ping", "127.0.0.1"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            try:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not marker.exists():
                    time.sleep(0.02)
                self.assertTrue(marker.exists())
                child = int(marker.read_text())
                proc.send_signal(signal.SIGINT)
                stdout, stderr = proc.communicate(timeout=2)
                self.assertEqual(proc.returncode, 130, stdout + stderr)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()

    def test_installed_script_works_outside_repo_and_noninteractive_menu_exits(self):
        with tempfile.TemporaryDirectory() as folder:
            proc = subprocess.run(["bash", str(ROOT / "install.sh"), folder], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            installed = Path(folder) / "netcheck"
            proc = self.cli("http", self.url, "--json", script=installed, cwd=folder)
            self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = self.cli()
        self.assertEqual(proc.returncode, 2)
        self.assertIn("交互终端", proc.stderr)

    def test_menu_runs_dns_and_returns_then_exits(self):
        master, slave = pty.openpty()
        proc = subprocess.Popen([sys.executable, str(ROOT / "netcheck.py")], stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        output = b""
        try:
            os.write(master, b"1\n127.0.0.1\n0\n")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        output += os.read(master, 65536)
                    except OSError:
                        break
                elif proc.poll() is not None:
                    break
            proc.wait(timeout=2)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)
        text = output.decode()
        self.assertEqual(proc.returncode, 0, text)
        self.assertGreaterEqual(text.count("轻量网络检测"), 2)
        self.assertIn("IPv4 127.0.0.1", text)


if __name__ == "__main__":
    unittest.main()
