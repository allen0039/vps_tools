import importlib.util
import datetime
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "ssh_key_tool.py"
spec = importlib.util.spec_from_file_location("ssh_key_tool", SOURCE)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class Sandbox(tool.Manager):
    """真实 sshd/keygen；仅 systemd 和系统环境限制在沙箱替代。"""
    def preflight(self, user):
        if self.active():
            raise tool.ToolError("已有操作")
        self.runner([self.sshd, "-t", "-f", str(self.config)])
        self.service = "ssh.service"
        settings = self.effective(user)
        if settings.get("authenticationmethods") not in ("any", "publickey"):
            raise tool.ToolError("多因素认证")
        paths = self.key_paths(user, settings)
        for path in paths:
            tool.regular(path)
        return settings, paths


@unittest.skipUnless(Path("/usr/sbin/sshd").exists() and shutil.which("ssh-keygen"), "需要 OpenSSH")
class SSHKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_temp = tempfile.TemporaryDirectory()
        cls.key_folder = Path(cls.key_temp.name).resolve()
        cls.material = []
        for index in range(3):
            path = cls.key_folder / ("key%d" % index)
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(path), "-N", ""], check=True)
            cls.material.append(path.with_suffix(".pub").read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.key_temp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for path in ("etc/ssh/sshd_config.d", "etc/systemd/system", "root/.ssh", "home/alice/.ssh"):
            (self.root / path).mkdir(parents=True, mode=0o700)
        self.commands = []
        self.fail_reload = 0
        self.fail_timer = 0
        self.now = time.time()
        self.user_info = lambda user: pwd.struct_passwd((user, "x", os.geteuid(), os.getegid(), "",
                                                        "/root" if user == "root" else "/home/alice", "/bin/sh"))

        def runner(args):
            self.commands.append(list(args))
            if args[0] == "systemctl":
                if "reload" in args and self.fail_reload:
                    self.fail_reload -= 1
                    raise tool.ToolError("simulated reload failure")
                if "restart" in args and self.fail_timer:
                    self.fail_timer -= 1
                    raise tool.ToolError("simulated timer failure")
                return ""
            return tool.run(args)
        self.m = Sandbox(self.root, runner, self.user_info, lambda: self.now)
        self.original = ("Port 22222\nHostKey %s\nPidFile %s\nUsePAM no\n"
                         "PermitRootLogin prohibit-password\n#PubkeyAuthentication yes\n"
                         "PasswordAuthentication yes\nKbdInteractiveAuthentication no\n"
                         "GSSAPIAuthentication no\nHostbasedAuthentication no\n"
                         "AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n" %
                         (self.key_folder / "key0", self.root / "sshd.pid")).encode()
        self.m.config.write_bytes(self.original)
        self.key_path = self.root / "root/.ssh/authorized_keys"
        self.key_path.write_bytes(b"# keep comment\n" + self.material[0])
        self.key_path.chmod(0o600)
        self.key_original = self.key_path.read_bytes()
        self.environment = mock.patch.dict(os.environ, {"SSH_CONNECTION": "198.51.100.1 40000 192.0.2.1 22222",
                                                        "SUDO_USER": "root"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def new_proof(self, index=0, port=40001):
        p = self.root / ("proof-%d" % port)
        p.write_bytes(b"publickey " + self.material[index])
        p.chmod(0o600)
        os.utime(p, (self.now + 2, self.now + 2))
        os.environ["SSH_CONNECTION"] = "198.51.100.1 %d 192.0.2.1 22222" % port
        os.environ["SSH_USER_AUTH"] = str(p)

    def test_default_commented_key_enabled_root_password_disabled(self):
        result = self.m.status("root")
        self.assertTrue(result["pubkey_allowed"])
        self.assertFalse(result["password_allowed"])
        self.assertTrue(result["key_only"])
        self.assertEqual(len(result["keys"]), 1)
        self.assertEqual(result["effective"]["passwordauthentication"], "yes")
        self.assertFalse(self.m.state_dir.exists())

    def test_target_user_rules_do_not_disable_other_user_password(self):
        state = self.m.start("root")
        self.assertTrue(tool.password_allowed("alice", self.m.effective("alice")))
        self.new_proof()
        state = self.m.confirm(state["id"])
        self.assertEqual(state["phase"], "await_after")
        self.assertEqual(self.m.effective("root")["authenticationmethods"], "publickey")
        self.assertTrue(tool.password_allowed("alice", self.m.effective("alice")))
        self.new_proof(port=40002)
        done = self.m.confirm(state["id"])
        self.assertEqual(done["phase"], "committed")
        self.assertIsNone(self.m.active())
        self.assertEqual(len(done["verified"]), 2)
        self.m.rollback(done["id"])
        self.assertEqual(self.m.config.read_bytes(), self.original)

    def test_two_confirmations_cannot_reuse_old_or_same_new_connection(self):
        state = self.m.start("root")
        with self.assertRaisesRegex(tool.ToolError, "另建"):
            self.m.confirm(state["id"])
        self.new_proof()
        self.m.confirm(state["id"])
        with self.assertRaisesRegex(tool.ToolError, "另建"):
            self.m.confirm(state["id"])

    def test_import_preserves_existing_and_rejects_old_key_confirmation(self):
        state = self.m.start("root", "add", self.material[1])
        self.assertTrue(self.key_path.read_bytes().startswith(self.key_original))
        self.new_proof(0)
        with self.assertRaisesRegex(tool.ToolError, "旧公钥"):
            self.m.confirm(state["id"])
        self.new_proof(1, 40002)
        self.assertEqual(self.m.confirm(state["id"])["phase"], "committed")

    def test_duplicate_restricted_key_does_not_get_unrestricted_copy(self):
        self.key_path.write_bytes(b'from="198.51.100.0/24",command="echo two words" ' + self.material[0])
        before = self.key_path.read_bytes()
        with self.assertRaisesRegex(tool.ToolError, "已存在"):
            self.m.start("root", "add", self.material[0])
        self.assertEqual(self.key_path.read_bytes(), before)
        self.assertEqual(self.m.config.read_bytes(), self.original)
        self.assertIsNone(self.m.active())

    def test_generate_real_matching_pair_and_cleanup_after_correct_key(self):
        state = self.m.generate("root", no_passphrase=True)
        folder = self.m.pending_keys / state["id"]
        private = folder / "identity"
        public = private.with_suffix(".pub").read_bytes()
        extracted = tool.run(["ssh-keygen", "-y", "-f", str(private)])
        self.assertEqual(tool.key_fields(extracted)["blob"], tool.key_fields(public.decode())["blob"])
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.new_proof(0)
        with self.assertRaisesRegex(tool.ToolError, "旧公钥"):
            self.m.confirm(state["id"])
        proof = self.root / "generated-proof"
        proof.write_bytes(b"publickey " + public)
        os.utime(proof, (self.now + 2, self.now + 2))
        os.environ["SSH_USER_AUTH"] = str(proof)
        os.environ["SSH_CONNECTION"] = "198.51.100.1 40002 192.0.2.1 22222"
        self.assertEqual(self.m.confirm(state["id"])["phase"], "committed")
        self.assertFalse(folder.exists())
        record = self.m.state_path(state["id"]).read_bytes()
        self.assertNotIn(b"PRIVATE KEY", record)

    def test_timeout_cleans_generated_private_and_restores_exact_original(self):
        state = self.m.generate("root", no_passphrase=True)
        self.now += 301
        self.m.rollback(state["id"], expired_only=True)
        self.assertEqual(self.m.config.read_bytes(), self.original)
        self.assertEqual(self.key_path.read_bytes(), self.key_original)
        self.assertFalse((self.m.pending_keys / state["id"]).exists())

    def test_failed_reload_rolls_back_and_never_disables_password(self):
        self.fail_reload = 1
        with self.assertRaisesRegex(tool.ToolError, "reload"):
            self.m.start("root", "add", self.material[1])
        self.assertEqual(self.m.config.read_bytes(), self.original)
        self.assertEqual(self.key_path.read_bytes(), self.key_original)
        self.assertIsNone(self.m.active())

    def test_timer_failure_happens_before_auth_file_change(self):
        self.fail_timer = 1
        with self.assertRaisesRegex(tool.ToolError, "timer"):
            self.m.start("root", "add", self.material[1])
        self.assertEqual(self.m.config.read_bytes(), self.original)
        self.assertEqual(self.key_path.read_bytes(), self.key_original)

    def test_earlier_match_conflict_stops_before_config_replacement(self):
        original = self.original + b"Match User root\n    PubkeyAuthentication no\n"
        self.m.config.write_bytes(original)
        with self.assertRaisesRegex(tool.ToolError, "Match"):
            self.m.start("root")
        self.assertEqual(self.m.config.read_bytes(), original)

    def test_include_and_whitespace_are_parsed_by_real_openssh(self):
        include = self.root / "etc/ssh/sshd_config.d/cloud.conf"
        include.write_text("   PubkeyAuthentication no\n")
        self.m.config.write_bytes(("Include %s\n" % include).encode() + self.original)
        self.assertFalse(self.m.status("root")["pubkey_allowed"])
        self.assertIn(include, self.m.configuration_files())

    def test_external_modification_never_gets_overwritten_by_old_backup(self):
        state = self.m.start("root")
        altered = self.m.config.read_bytes() + b"# changed by another tool\n"
        self.m.config.write_bytes(altered)
        with self.assertRaisesRegex(tool.ToolError, "外部修改"):
            self.m.rollback(state["id"])
        self.assertEqual(self.m.config.read_bytes(), altered)
        self.assertEqual(self.m.load(state["id"])["phase"], "rollback_failed")
        self.assertEqual(self.m.active()["id"], state["id"])

    def test_backup_tamper_is_detected(self):
        state = self.m.start("root")
        path = self.m.state_path(state["id"])
        wrapper = json.loads(path.read_bytes())
        wrapper["payload"]["changes"][0]["before"]["data"] = "dGFtcGVy"
        path.write_text(json.dumps(wrapper))
        with self.assertRaisesRegex(tool.ToolError, "校验"):
            self.m.rollback(state["id"])

    def test_reboot_timer_uses_persistent_calendar_and_snapshot_runner(self):
        state = self.m.start("root")
        timer = self.m.systemd / ("sshkeytool-" + state["id"] + ".timer")
        self.assertIn("Persistent=true", timer.read_text())
        self.assertIn("OnCalendar=", timer.read_text())
        self.assertTrue((self.m.operations / state["id"] / "runner.py").exists())
        self.now += 301
        # 重新构造 Manager，相当于原菜单进程消失/机器启动后由保存的程序处理。
        fresh = Sandbox(self.root, self.m.runner, self.user_info, lambda: self.now)
        self.assertEqual(fresh.rollback(state["id"], expired_only=True)["phase"], "rolled_back")

    def test_committed_operation_ignores_late_timeout_callback(self):
        state = self.m.start("root", "add", self.material[1])
        self.new_proof(1)
        self.m.confirm(state["id"])
        before = self.m.config.read_bytes()
        self.now += 600
        self.assertEqual(self.m.rollback(state["id"], expired_only=True)["phase"], "committed")
        self.assertEqual(self.m.config.read_bytes(), before)

    def test_multi_factor_is_reported_but_not_rewritten(self):
        self.m.config.write_bytes(self.original + b"AuthenticationMethods publickey,password\n")
        self.assertFalse(self.m.status("root")["key_only"])
        with self.assertRaisesRegex(tool.ToolError, "多因素"):
            self.m.start("root")

    def test_remove_last_key_refused_and_other_key_removal_needs_new_proof(self):
        fp = self.m.parse_keys(self.material[0])[0]["fingerprint"]
        with self.assertRaisesRegex(tool.ToolError, "最后"):
            self.m.remove("root", fp)
        self.key_path.write_bytes(self.key_original + self.material[1])
        state = self.m.remove("root", fp)
        self.new_proof(0)
        with self.assertRaisesRegex(tool.ToolError, "旧公钥"):
            self.m.confirm(state["id"])
        self.new_proof(1, 40002)
        self.assertEqual(self.m.confirm(state["id"])["phase"], "committed")

    def test_second_stage_timeout_restores_previous_root_policy(self):
        state = self.m.start("root")
        self.new_proof()
        self.m.confirm(state["id"])
        self.now += 301
        self.m.rollback(state["id"], expired_only=True)
        self.assertEqual(self.m.config.read_bytes(), self.original)
        self.assertFalse(self.m.status("root")["password_allowed"])

    def test_sudo_user_and_stale_auth_info_cannot_confirm(self):
        state = self.m.start("root")
        self.new_proof()
        os.environ["SUDO_USER"] = "alice"
        with self.assertRaisesRegex(tool.ToolError, "目标用户"):
            self.m.confirm(state["id"])
        os.environ["SUDO_USER"] = "root"
        p = Path(os.environ["SSH_USER_AUTH"])
        os.utime(p, (self.now - 20, self.now - 20))
        with self.assertRaisesRegex(tool.ToolError, "之前"):
            self.m.confirm(state["id"])

    def test_second_pending_operation_is_refused(self):
        self.m.start("root")
        with self.assertRaisesRegex(tool.ToolError, "已有"):
            self.m.start("root", "add", self.material[1])

    def test_username_operation_id_and_symlink_validation(self):
        for name in ("root\nMatch all", "root,*", "../root"):
            with self.assertRaises(tool.ToolError):
                tool.safe_name(name)
        with self.assertRaises(tool.ToolError):
            self.m.state_path("../other")
        actual = self.root / "sensitive"
        actual.write_text("do not change")
        self.key_path.unlink()
        self.key_path.symlink_to(actual)
        with self.assertRaisesRegex(tool.ToolError, "符号链接"):
            self.m.start("root", "add", self.material[1])
        self.assertEqual(actual.read_text(), "do not change")

    def test_interrupted_second_write_recovers_preparatory_state(self):
        state = self.m.start("root")
        self.new_proof()
        original_atomic = tool.atomic
        failed = [False]
        def interrupted(path, data, *args, **kwargs):
            if Path(path) == self.m.config and b"AuthenticationMethods publickey\n" in data and not failed[0]:
                failed[0] = True
                raise tool.ToolError("simulated interruption before replacement")
            return original_atomic(path, data, *args, **kwargs)
        with mock.patch.object(tool, "atomic", interrupted):
            with self.assertRaisesRegex(tool.ToolError, "interruption"):
                self.m.confirm(state["id"])
        self.assertEqual(self.m.config.read_bytes(), self.original)
        self.assertEqual(self.m.load(state["id"])["phase"], "rolled_back")

    def test_invalid_public_key_fails_without_ssh_changes(self):
        with self.assertRaises(tool.ToolError):
            self.m.start("root", "add", b"ssh-ed25519 not-a-valid-key")
        self.assertEqual(self.m.config.read_bytes(), self.original)
        self.assertEqual(self.key_path.read_bytes(), self.key_original)

    def test_rsa_generation_is_4096_bit_and_optional_pem(self):
        state = self.m.generate("root", kind="rsa", no_passphrase=True, pem=True)
        path = self.m.pending_keys / state["id"] / "identity"
        self.assertTrue(path.read_bytes().startswith(b"-----BEGIN RSA PRIVATE KEY-----"))
        self.assertTrue(tool.run(["ssh-keygen", "-l", "-f", str(path)]).startswith("4096 "))
        self.m.rollback(state["id"])
        self.assertFalse(path.exists())

    def test_timer_rounds_fractional_deadline_up_and_rearms_early_callback(self):
        self.now = int(self.now) + 0.9
        state = self.m.start("root", timeout=60)
        timer = (self.m.systemd / ("sshkeytool-" + state["id"] + ".timer")).read_text()
        calendar = timer.split("OnCalendar=", 1)[1].splitlines()[0]
        trigger = datetime.datetime.strptime(calendar, "%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=datetime.timezone.utc).timestamp()
        self.assertGreaterEqual(trigger, state["deadline"])
        self.assertLess(trigger, state["deadline"] + 1)
        self.commands.clear()
        self.now = state["deadline"] - 0.1
        self.m.rollback(state["id"], expired_only=True)
        self.assertEqual(self.m.load(state["id"])["phase"], "await_before")
        self.assertTrue(any("restart" in c for c in self.commands))

    def test_external_key_change_blocks_confirmation_and_invalidates_status(self):
        state = self.m.start("root")
        self.new_proof()
        self.key_path.write_bytes(self.key_original + b"# external edit\n")
        with self.assertRaisesRegex(tool.ToolError, "授权公钥文件已经变化"):
            self.m.confirm(state["id"])
        self.m.rollback(state["id"])
        self.assertTrue(self.key_path.read_bytes().endswith(b"# external edit\n"))
        state = self.m.start("root")
        self.new_proof(port=40002)
        self.m.confirm(state["id"])
        self.new_proof(port=40003)
        self.m.confirm(state["id"])
        self.assertTrue(self.m.status("root")["verification"]["valid"])
        self.key_path.write_bytes(self.key_original)
        self.assertFalse(self.m.status("root")["verification"]["valid"])

    def test_committed_cleanup_failure_is_retried_without_rollback(self):
        state = self.m.generate("root", no_passphrase=True)
        key = self.m.pending_keys / state["id"] / "identity"
        auth = self.root / "generated-auth-proof"
        auth.write_bytes(b"publickey " + key.with_suffix(".pub").read_bytes())
        os.utime(auth, (self.now + 2, self.now + 2))
        os.environ["SSH_CONNECTION"] = "198.51.100.1 40001 192.0.2.1 22222"
        os.environ["SSH_USER_AUTH"] = str(auth)
        with mock.patch.object(self.m, "cleanup_private", side_effect=tool.ToolError("simulated cleanup failure")):
            with self.assertRaisesRegex(tool.ToolError, "清理未完成"):
                self.m.confirm(state["id"])
        committed_config = self.m.config.read_bytes()
        self.assertEqual(self.m.active()["phase"], "committed")
        self.assertTrue(key.exists())
        self.now += 301
        self.m.rollback(state["id"], expired_only=True)
        self.assertIsNone(self.m.active())
        self.assertFalse(key.exists())
        self.assertEqual(self.m.config.read_bytes(), committed_config)
        self.assertEqual(self.m.load(state["id"])["phase"], "committed")


class CLITests(unittest.TestCase):
    def test_noninteractive_menu_fails_without_modification(self):
        p = subprocess.run(["python3", str(SOURCE)], stdin=subprocess.DEVNULL, capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("交互终端", p.stderr)

    def test_help_and_version(self):
        for arg in ("--help", "--version"):
            p = subprocess.run(["python3", str(SOURCE), arg], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == "__main__":
    unittest.main()
