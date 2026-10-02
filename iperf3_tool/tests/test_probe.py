import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("iperf3_tool", ROOT / "iperf3_tool.py")
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


def fixture(direction="download", streams=1):
    sending = direction == "download"
    sent = {"bits_per_second": 8e6 if sending else 0, "bytes": 15e6 if sending else 0,
            "seconds": 15, "sender": sending}
    if sending:
        sent["retransmits"] = 12
    received = {"bits_per_second": 0 if sending else 7.8e6,
                "bytes": 0 if sending else 14.625e6, "seconds": 15, "sender": sending}
    return {"start": {"test_start": {"protocol": "TCP", "reverse": int(sending),
                                    "num_streams": streams, "duration": 15, "omit": 2},
                      "connected": [{"remote_host": "198.51.100.1"}]},
            "end": {"sum_sent": sent, "sum_received": received,
                    "streams": [{"sender": {"mean_rtt": 25000} if sending else {}}
                                for _ in range(streams)]},
            "intervals": [{"sum": {"bits_per_second": rate, "seconds": 1, "omitted": omitted}}
                          for rate, omitted in ((1e6, True), (8e6, False), (0, False), (8e6, False))]}


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "result.json"

    def parse(self, data, streams=1, direction="download"):
        self.path.write_text(json.dumps(data))
        return tool.parse_result(self.path, streams, direction, 15, 2)

    def test_reverse_placeholder_is_sender_not_zero_receiver(self):
        result = self.parse(fixture())
        self.assertEqual(result["mbps"], 8)
        self.assertEqual(result["rate_source"], "sender")
        self.assertEqual(result["retransmits"], 12)
        self.assertEqual(result["rtt_ms"], 25)
        self.assertEqual(result["interval_mbps"], [8, 0, 8])
        self.assertGreater(result["cv_percent"], 0)

    def test_upload_missing_sender_metrics_are_na(self):
        result = self.parse(fixture("upload", 4), 4, "upload")
        self.assertEqual(result["mbps"], 7.8)
        self.assertEqual(result["rate_source"], "receiver")
        self.assertIsNone(result["retransmits"])
        self.assertIsNone(result["rtt_ms"])

    def test_real_receiver_is_preferred(self):
        data = fixture()
        data["end"]["sum_received"].update(bytes=14e6, bits_per_second=7.5e6, sender=False)
        result = self.parse(data)
        self.assertEqual(result["mbps"], 7.5)
        self.assertEqual(result["rate_source"], "receiver")

    def test_wrong_parameters_and_invalid_metrics_rejected(self):
        variants = []
        for key, value in (("protocol", "UDP"), ("reverse", 0), ("bidir", 1), ("num_streams", 4),
                           ("duration", 60), ("omit", 0)):
            data = fixture()
            data["start"]["test_start"][key] = value
            variants.append(data)
        for key, value in (("seconds", 2), ("bits_per_second", float("nan")),
                           ("bits_per_second", -1), ("bytes", 0), ("retransmits", -1)):
            data = fixture()
            data["end"]["sum_sent"][key] = value
            variants.append(data)
        data = fixture(); data["end"]["streams"] = []; variants.append(data)
        data = fixture(); data["error"] = "connection lost"; variants.append(data)
        data = fixture(); data["end"]["sum_received"]["sender"] = False; variants.append(data)
        for data in variants:
            with self.subTest(data=data), self.assertRaises(tool.ProbeError):
                self.parse(data)

    def test_non_json_and_partial_json_rejected(self):
        for value in ("", "{", "[]", '{"start":{},"end":{}}'):
            self.path.write_text(value)
            with self.subTest(value=value), self.assertRaises(tool.ProbeError):
                tool.parse_result(self.path, 1, "download", 15, 2)

    def test_cli_validation_and_safe_command(self):
        for value in ("host;id", "$(id)", "https://host", "-option", "host:5201", "a b", "a..b"):
            with self.subTest(value=value), self.assertRaises(tool.ProbeError):
                tool.validate_host(value)
        self.assertEqual(tool.integer("08", 1, 128, "连接数"), 8)
        for value in ("1+1", "$(id)", "999999999999", "0"):
            with self.assertRaises(tool.ProbeError):
                tool.integer(value, 1, 128, "连接数")
        args = tool.parser().parse_args(["--host", "2001:db8::1", "--streams", "1,4,8"])
        config = tool.cli_config(args)
        self.assertEqual(config.family, "6")
        self.assertIn("-6 -c 2001:db8::1", tool.local_command(config, 5201, 4, "download"))
        self.assertIn("-R", tool.local_command(config, 5201, 4, "download"))
        self.assertNotIn("-R", tool.local_command(config, 5201, 4, "upload"))
        for extra in (["--port", "0"], ["--streams", "1,1"], ["--duration", "0"],
                      ["--family", "4", "--bind", "::1"]):
            with self.assertRaises(tool.ProbeError):
                tool.cli_config(tool.parser().parse_args(["--host", "127.0.0.1"] + extra))

    def test_port_detection_does_not_kill_occupied_socket(self):
        with socket.socket() as existing:
            existing.bind(("127.0.0.1", 0))
            existing.listen()
            self.assertFalse(tool.port_free(existing.getsockname()[1]))
            existing.getsockname()  # 原有 socket 仍然有效。
        self.assertTrue(tool.port_free(tool.random_port()))

    def test_report_persists_completed_round_on_interrupt(self):
        config = tool.Config("127.0.0.1", streams=(1, 4, 8), output_dir=self.temp.name)
        session = tool.Session(config)
        result = self.parse(fixture())
        with mock.patch.object(session, "attempt", side_effect=[result, tool.Cancelled()]), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = session.run()
        report = json.loads((session.directory / "report.json").read_text())
        self.assertEqual(rc, 130)
        self.assertEqual(report["status"], "interrupted")
        self.assertEqual([row["status"] for row in report["results"]], ["ok", "interrupted"])
        self.assertTrue((session.directory / "report.csv").exists())

    def test_failed_complete_summary_is_not_silently_accepted(self):
        config = tool.Config("127.0.0.1", streams=(1,), output_dir=self.temp.name)
        session = tool.Session(config)
        with mock.patch.object(session, "attempt", side_effect=tool.ProbeError("连接数不符")), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = session.run()
        report = json.loads((session.directory / "report.json").read_text())
        self.assertEqual(rc, 1)
        self.assertEqual(report["status"], "failed")
        self.assertIn("连接数不符", report["results"][0]["error"])

    def test_complete_result_with_nonzero_process_exit_is_not_retried(self):
        config = tool.Config("127.0.0.1", streams=(1,), output_dir=self.temp.name)
        session = tool.Session(config)

        def start(prefix, lifetime):
            prefix.with_suffix(".json").write_text(json.dumps(fixture()))
            tool.write_json(prefix.with_suffix(".state.json"), {"state": "finished", "returncode": 7})
            session.process = mock.Mock()
            session.process.poll.return_value = 0

        with mock.patch.object(session, "start", side_effect=start) as startup, \
                mock.patch.object(session, "stop"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(session.run(), 1)
        self.assertEqual(startup.call_count, 1)
        self.assertIn("退出码 7", session.results[0]["error"])

    def test_menu_accepts_custom_port_and_streams(self):
        answers = ["1", "203.0.113.10", "2", "5201", "2", "8", "3", "10", "0", "2", "60", "y"]
        with mock.patch("builtins.input", side_effect=answers), \
                mock.patch.object(tool, "port_free", return_value=True), \
                contextlib.redirect_stdout(io.StringIO()):
            config = tool.menu()
        self.assertEqual((config.port, config.streams, config.direction, config.repeat), (5201, (8,), "both", 2))

    def test_proc_listener_requires_matching_process_socket_inode(self):
        # Linux 的被动就绪检测必须同时匹配 fd inode，而不是只看全局端口。
        table = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" \
                "0: 0100007F:1451 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n"
        entry = Path("/proc/999/fd/3")
        with mock.patch.object(tool.sys, "platform", "linux"), \
                mock.patch.object(Path, "iterdir", return_value=iter([entry])), \
                mock.patch.object(Path, "exists", return_value=True), \
                mock.patch.object(Path, "read_text", return_value=table), \
                mock.patch.object(tool.os, "readlink", return_value="socket:[12345]"):
            self.assertTrue(tool.listener_ready(999, 5201))
        with mock.patch.object(tool.sys, "platform", "linux"), \
                mock.patch.object(Path, "iterdir", return_value=iter([entry])), \
                mock.patch.object(Path, "exists", return_value=True), \
                mock.patch.object(Path, "read_text", return_value=table), \
                mock.patch.object(tool.os, "readlink", return_value="socket:[99999]"):
            self.assertFalse(tool.listener_ready(999, 5201))


@unittest.skipUnless(shutil.which("iperf3") and (sys.platform.startswith("linux") or shutil.which("lsof")),
                     "真实回环测试需要 iperf3；macOS 另需 lsof，不自动安装")
class LoopbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = tool.Config("127.0.0.1", streams=(1,), duration=1, omit=0, wait=5,
                                  bind="127.0.0.1", output_dir=self.temp.name)

    def client(self, port, streams, direction="download", duration=1, omit=0):
        return subprocess.run([shutil.which("iperf3"), "-4", "-c", "127.0.0.1", "-p", str(port),
                               "-P", str(streams), "-t", str(duration), "-O", str(omit), "-b", "2M", "-J"]
                              + (["-R"] if direction == "download" else []),
                              capture_output=True, text=True, timeout=12)

    def drive(self, session, client_specs, hook=None):
        errors = []

        def worker():
            try:
                for index, specs in enumerate(client_specs, 1):
                    state_file = session.directory / "test-{:02d}-attempt-01-connection-01.state.json".format(index)
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        try:
                            state = json.loads(state_file.read_text())
                        except (OSError, ValueError):
                            state = {}
                        if state.get("state") == "ready":
                            break
                        time.sleep(0.05)
                    else:
                        raise AssertionError("服务端未监听")
                    if hook:
                        hook(index)
                    client = self.client(session.port, *specs)
                    if client.returncode:
                        raise AssertionError(client.stdout + client.stderr)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                rc = session.run()
        finally:
            thread.join(timeout=20)
        self.assertFalse(thread.is_alive())
        if errors:
            raise AssertionError(str(errors[0]) + "\n" + output.getvalue())
        return rc

    def test_real_six_rounds_upload_download_1_4_8_and_release(self):
        self.config.streams = (1, 4, 8)
        self.config.direction = "both"
        session = tool.Session(self.config)
        specs = [(streams, direction) for streams in (1, 4, 8) for direction in ("download", "upload")]
        self.assertEqual(self.drive(session, specs), 0)
        report = json.loads((session.directory / "report.json").read_text())
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["results"]), 6)
        self.assertTrue(all(row["mbps"] > 0 for row in report["results"]))
        for row in report["results"]:
            if row["direction"] == "upload":
                self.assertIsNone(row["retransmits"])
        self.assertFalse(tool.listener_ready(0, session.port))
        self.assertEqual(self.client(session.port, 1).returncode, 1)

    def test_wrong_streams_preserves_raw_and_stops(self):
        self.config.streams = (4,)
        session = tool.Session(self.config)
        self.assertEqual(self.drive(session, [(1, "download")]), 1)
        report = json.loads((session.directory / "report.json").read_text())
        self.assertIn("连接数不符", report["results"][0]["error"])
        self.assertEqual(len(list(session.directory.glob("*.validation.log"))), 1)
        self.assertEqual(len(list(session.directory.glob("*-connection-*.json"))) // 2, 1)

    def test_cleanup_on_control_pipe_eof_and_hard_deadline(self):
        for lifetime, close_pipe in ((30, True), (1.5, False)):
            with self.subTest(lifetime=lifetime):
                session = tool.Session(copy.copy(self.config))
                prefix = session.directory / "guardian"
                session.start(prefix, lifetime)
                pid = session.state(prefix)["pid"]
                self.assertTrue(tool.listener_ready(pid, session.port))
                if close_pipe:
                    os.close(session.control_fd)
                    session.control_fd = None
                session.process.wait(timeout=7)
                self.assertFalse(tool.listener_ready(pid, session.port))
                self.assertEqual(session.state(prefix)["state"], "stopped" if close_pipe else "timeout")
                session.stop()

    def test_incomplete_cookie_connection_recovers_once(self):
        session = tool.Session(self.config)

        def scan(_index):
            with socket.create_connection(("127.0.0.1", session.port), timeout=2) as scanner:
                scanner.sendall(b"short-cookie")
            prefix = session.directory / "test-01-attempt-01-connection-02"
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if tool.Session.state(prefix).get("state") == "ready":
                    return
                time.sleep(0.05)
            raise AssertionError("握手失败后未恢复监听")

        self.assertEqual(self.drive(session, [(1, "download")], hook=scan), 0)
        self.assertTrue((session.directory / "test-01-attempt-01-connection-01.validation.log").exists())
        self.assertEqual(len(session.results), 1)
        self.assertIn("connection-02.json", session.results[0]["raw_json"])

    def test_no_client_wait_timeout_releases_listener(self):
        self.config.wait = 1
        session = tool.Session(self.config)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(session.run(), 1)
        self.assertIn("等待本地连接超时", session.results[0]["error"])
        self.assertEqual(self.client(session.port, 1).returncode, 1)

    def test_interrupt_term_and_hup_release_listener_and_save_report(self):
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signum=signum):
                parent = subprocess.Popen([sys.executable, "-c", '''
import importlib.util, sys
spec=importlib.util.spec_from_file_location("iperf3_tool",sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
m.install_signal_handlers()
s=m.Session(m.Config("127.0.0.1",streams=(1,),bind="127.0.0.1",output_dir=sys.argv[2]))
sys.exit(s.run())
''', str(tool.SCRIPT), self.temp.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 10
                    output = ""
                    # 输出只有在被动确认监听成功后才包含这一行。
                    while "监听就绪" not in output and time.monotonic() < deadline:
                        readable, _, _ = select.select([parent.stdout], [], [], 0.1)
                        if readable:
                            chunk = os.read(parent.stdout.fileno(), 65536)
                            if not chunk:
                                break
                            output += chunk.decode("utf-8")
                    self.assertIn("监听就绪", output)
                    port = int(output.split("TCP ")[1].split("｜")[0])
                    parent.send_signal(signum)
                    out, err = parent.communicate(timeout=7)
                    self.assertEqual(parent.returncode, 130, output + out + err)
                    self.assertEqual(self.client(port, 1).returncode, 1)
                    reports = list(Path(self.temp.name).glob("*/report.json"))
                    self.assertTrue(any(json.loads(path.read_text())["status"] == "interrupted" for path in reports))
                finally:
                    if parent.poll() is None:
                        parent.kill()
                        parent.communicate()

    def test_killed_parent_leaves_no_listener(self):
        # 父进程 SIGKILL 后 guardian 通过管道 EOF 清理，不依赖 Python finally。
        prefix = Path(self.temp.name) / "orphan"
        port = tool.random_port()
        parent = subprocess.Popen([sys.executable, "-c", '''
import importlib.util, sys, time
spec=importlib.util.spec_from_file_location("iperf3_tool",sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
s=m.Session(m.Config("127.0.0.1",port=int(sys.argv[3]),bind="127.0.0.1",output_dir=sys.argv[4]))
s.start(m.Path(sys.argv[2]),30)
time.sleep(60)
''', str(tool.SCRIPT), str(prefix), str(port), self.temp.name],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                state = tool.Session.state(prefix)
                if state.get("state") == "ready":
                    break
                time.sleep(0.05)
            else:
                self.fail("父进程启动失败")
            parent.kill()
            parent.wait(timeout=3)
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline and tool.Session.state(prefix).get("state") != "stopped":
                time.sleep(0.05)
            self.assertEqual(tool.Session.state(prefix)["state"], "stopped")
            self.assertFalse(tool.listener_ready(state["pid"], port))
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait()
            parent.stderr.close()


if __name__ == "__main__":
    unittest.main()
