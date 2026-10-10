import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ssh_password_tool", ROOT / "ssh_password_tool.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class FakeBackend:
    def __init__(self, config, auth):
        self.config = config
        self.auth = auth
        self.auth_paths = [auth]
        self.options = {"pubkeyauthentication": "yes", "passwordauthentication": "yes",
                        "kbdinteractiveauthentication": "no", "permitrootlogin": "without-password",
                        "authenticationmethods": "any", "port": "21919"}
        self.calls = []
        self.timers = set()
        self.account_error = False
        self.timer_error = False
        self.candidate_error = False
        self.match_conflict = False
        self.open_reload_error = False
        self.restore_reload_error = False

    def effective(self, user, context, config=None):
        result = dict(self.options)
        if not self.match_conflict:
            for path in self.auth_paths:
                if not path.exists():
                    continue
                text = path.read_text()
                if "Match User " + user + "\n" in text:
                    for line in text.splitlines():
                        words = line.split(None, 1)
                        if len(words) == 2 and words[0].lower() not in {"match", "#"}:
                            result[words[0].lower()] = words[1]
        return result

    def auth_exists(self):
        return any(path.exists() for path in self.auth_paths)

    def validate(self, config=None):
        self.calls.append(("validate", self.auth_exists()))
        if config is not None and self.candidate_error:
            raise tool.ToolError("candidate invalid")

    def service(self):
        return "ssh.service"

    def check_account(self, user):
        if self.account_error:
            raise tool.ToolError("account locked")

    def reload(self, unit):
        self.calls.append(("reload", self.auth_exists()))
        if self.auth_exists() and self.open_reload_error:
            raise tool.ToolError("open reload failed")
        if not self.auth_exists() and self.restore_reload_error:
            raise tool.ToolError("restore reload failed")

    def ctl(self, *args, check=True):
        self.calls.append(("ctl", args, self.auth_exists()))
        if args[0] == "start" and args[1].endswith(".timer"):
            if self.timer_error:
                raise tool.ToolError("timer failed")
            self.timers.add(args[1])
        if args[0] == "stop":
            self.timers.discard(args[1])
        code = 0
        if args[0] == "is-active" and args[-1].endswith(".timer"):
            code = 0 if args[-1] in self.timers else 1
        if check and code:
            raise tool.ToolError("timer inactive")
        return subprocess.CompletedProcess(args, code, "", "")


class TemporaryPasswordTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.config = self.base / "sshd_config"
        self.original = b"Port 21919\nPasswordAuthentication yes\nPermitRootLogin prohibit-password\n"
        self.config.write_bytes(self.original)
        self.config.chmod(0o640)
        self.boot = self.base / "boot_id"
        self.boot.write_text("boot-one")
        self.unit_dir = self.base / "units"
        self.unit_dir.mkdir()
        self.backend = FakeBackend(self.config, self.base / "run" / "auth.conf")
        self.manager = tool.PasswordTool(config=self.config, state_dir=self.base / "state",
                                         runtime_dir=self.base / "run", unit_dir=self.unit_dir,
                                         boot_file=self.boot, backend=self.backend,
                                         lock_path=self.base / "ssh.lock", key_active=self.base / "key-active.json")
        self.backend.auth_paths.append(self.manager.persistent_auth_file)
        self.user_patch = patch.object(tool, "validate_user", return_value=SimpleNamespace(pw_shell="/bin/bash"))
        self.user_patch.start()
        self.addCleanup(self.user_patch.stop)
        self.env_patch = patch.dict(os.environ, {"SSH_CONNECTION": "198.51.100.10 51234 203.0.113.20 21919"})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def test_timer_armed_before_password_file_and_manual_close_restores_root_policy(self):
        state = self.manager.enable()
        self.assertEqual(state["phase"], "active")
        self.assertEqual(state["context"]["lport"], "21919")
        self.assertTrue(tool.password_available(self.backend.effective("root", state["context"]), "root"))
        self.assertNotIn("PubkeyAuthentication no", self.manager.auth_file.read_text())
        self.assertNotIn("AuthenticationMethods any", self.manager.auth_file.read_text())
        service, timer = self.manager.units(state["token"])
        self.assertIn("OnActiveSec=1800s", timer.read_text())
        self.assertIn("Restart=on-failure", service.read_text())
        self.assertIn("StartLimitIntervalSec=0", service.read_text())
        self.assertTrue((self.manager.state_dir / "expire_runner.py").is_file())
        timer_calls = [entry for entry in self.backend.calls if entry[0] == "ctl" and entry[1][0] == "start"]
        self.assertTrue(timer_calls)
        self.assertFalse(timer_calls[0][-1], "开启前必须有独立定时器")
        self.manager.close()
        self.assertFalse(self.manager.auth_file.exists())
        self.assertEqual(self.manager.load_state()["phase"], "closed")
        self.assertEqual(self.backend.effective("root", state["context"]), self.backend.options)
        self.assertEqual(list(self.unit_dir.iterdir()), [])
        self.assertTrue(self.config.read_bytes().startswith(self.original))

    def test_timer_failure_never_opens_password_and_removes_new_hook(self):
        self.backend.timer_error = True
        with self.assertRaisesRegex(tool.ToolError, "timer failed"):
            self.manager.enable()
        self.assertFalse(self.manager.auth_file.exists())
        self.assertFalse(any(entry == ("reload", True) for entry in self.backend.calls))
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.manager.load_state()["phase"], "closed")

    def test_candidate_syntax_failure_leaves_main_file_untouched(self):
        self.backend.candidate_error = True
        with self.assertRaisesRegex(tool.ToolError, "candidate invalid"):
            self.manager.enable()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.manager.auth_file.exists())

    def test_earlier_match_conflict_is_rolled_back(self):
        self.backend.match_conflict = True
        with self.assertRaisesRegex(tool.ToolError, "Match"):
            self.manager.enable()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.manager.auth_file.exists())

    def test_enable_reload_failure_restores_original_and_keeps_backup(self):
        self.backend.open_reload_error = True
        with self.assertRaisesRegex(tool.ToolError, "open reload failed"):
            self.manager.enable()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.manager.auth_file.exists())
        self.assertEqual(len(list((self.manager.state_dir / "backups").glob("*.json"))), 1)

    def test_restore_failure_is_recorded_and_can_be_retried(self):
        state = self.manager.enable()
        self.backend.restore_reload_error = True
        with self.assertRaisesRegex(tool.ToolError, "恢复尚未完成"):
            self.manager.close(state["token"])
        self.assertFalse(self.manager.auth_file.exists())
        self.assertEqual(self.manager.load_state()["phase"], "restore_failed")
        self.assertTrue(self.manager.units(state["token"])[0].exists())
        self.backend.restore_reload_error = False
        self.manager.close(state["token"])
        self.assertEqual(self.manager.load_state()["phase"], "closed")

    def test_until_reboot_has_no_timer_and_reboot_drops_password_rule(self):
        state = self.manager.enable(until_reboot=True)
        self.assertIsNone(state["expires_at"])
        self.assertFalse(self.manager.units(state["token"])[1].exists())
        self.manager.auth_file.unlink()  # 模拟内核清空 /run，而不是调用本工具恢复。
        self.boot.write_text("boot-two")
        self.assertFalse(tool.password_available(self.backend.effective("root", state["context"]), "root"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.manager.status()
        self.assertIn("重启后已失效", output.getvalue())
        next_state = self.manager.enable(minutes=1)
        self.assertNotEqual(next_state["token"], state["token"])
        self.assertEqual(self.config.read_text().count(tool.BEGIN), 1)

    def test_expire_removes_only_runtime_policy_and_preserves_changed_port(self):
        state = self.manager.enable(minutes=1)
        changed = self.config.read_bytes().replace(b"Port 21919", b"Port 22222")
        self.config.write_bytes(changed)
        self.manager.close(state["token"])
        self.assertEqual(self.config.read_bytes(), changed)
        self.assertFalse(self.manager.auth_file.exists())

    def test_old_expiry_token_cannot_close_new_window(self):
        first = self.manager.enable()
        self.manager.close()
        second = self.manager.enable()
        self.manager.close(first["token"])
        self.assertTrue(self.manager.auth_file.exists())
        self.assertEqual(self.manager.load_state()["token"], second["token"])
        self.assertIn(second["token"], self.manager.auth_file.read_text())

    def test_duplicate_enable_does_not_replace_recovery_point(self):
        state = self.manager.enable()
        original_auth = self.manager.auth_file.read_bytes()
        with self.assertRaisesRegex(tool.ToolError, "已有密码登录操作"):
            self.manager.enable(minutes=1)
        self.assertEqual(self.manager.load_state()["token"], state["token"])
        self.assertEqual(self.manager.auth_file.read_bytes(), original_auth)

    def test_locked_account_is_rejected_before_config_modification(self):
        self.backend.account_error = True
        with self.assertRaisesRegex(tool.ToolError, "account locked"):
            self.manager.enable()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.manager.state_file.exists())

    def test_existing_password_path_is_rejected(self):
        self.backend.options["permitrootlogin"] = "yes"
        with self.assertRaisesRegex(tool.ToolError, "当前仍有密码"):
            self.manager.enable()
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_keyboard_interactive_password_path_is_rejected(self):
        self.backend.options.update(permitrootlogin="yes", passwordauthentication="no", kbdinteractiveauthentication="yes")
        with self.assertRaisesRegex(tool.ToolError, "键盘交互"):
            self.manager.enable()

    def test_mfa_and_disabled_public_key_are_rejected(self):
        self.backend.options["authenticationmethods"] = "publickey,password"
        with self.assertRaisesRegex(tool.ToolError, "多因素"):
            self.manager.enable()
        self.backend.options["authenticationmethods"] = "any"
        self.backend.options["pubkeyauthentication"] = "no"
        with self.assertRaisesRegex(tool.ToolError, "公钥认证"):
            self.manager.enable()

    def test_explicit_publickey_methods_allow_password_only_during_window(self):
        self.backend.options.update(permitrootlogin="yes", authenticationmethods="publickey")
        state = self.manager.enable()
        self.assertIn("AuthenticationMethods publickey password", self.manager.auth_file.read_text())
        self.manager.close()
        self.assertEqual(self.backend.effective("root", state["context"])["authenticationmethods"], "publickey")

    def test_ordinary_user_policy_does_not_change_root_or_other_users(self):
        self.backend.options["passwordauthentication"] = "no"
        root_before = self.backend.effective("root", {})
        bob_before = self.backend.effective("bob", {})
        self.manager.enable(user="alice")
        self.assertNotIn("PermitRootLogin", self.manager.auth_file.read_text())
        self.assertEqual(self.backend.effective("root", {}), root_before)
        self.assertEqual(self.backend.effective("bob", {}), bob_before)
        self.assertEqual(self.backend.effective("alice", {})["passwordauthentication"], "yes")

    def test_private_state_backup_digest_and_main_metadata(self):
        state = self.manager.enable()
        backup = self.manager.state_dir / "backups" / (state["token"] + ".json")
        saved = json.loads(backup.read_text())
        self.assertEqual(saved["sha256"], tool.digest(self.original))
        self.assertEqual(self.manager.state_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.manager.runtime_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.manager.auth_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)

    def test_external_password_enable_is_reported_as_restore_failure(self):
        self.manager.enable()
        self.backend.options["permitrootlogin"] = "yes"
        with self.assertRaisesRegex(tool.ToolError, "其他 SSH 配置仍允许"):
            self.manager.close()
        self.assertFalse(self.manager.auth_file.exists())
        self.assertEqual(self.manager.load_state()["phase"], "restore_failed")

    def test_foreign_or_symlink_runtime_file_is_not_deleted(self):
        self.manager.enable()
        self.manager.auth_file.write_text("# unrelated\nPasswordAuthentication yes\n")
        with self.assertRaisesRegex(tool.ToolError, "拒绝删除"):
            self.manager.close()
        self.assertTrue(self.manager.auth_file.exists())
        self.manager.auth_file.unlink()
        target = self.base / "unrelated"
        target.write_text("keep")
        self.manager.auth_file.symlink_to(target)
        with self.assertRaisesRegex(tool.ToolError, "非普通文件"):
            self.manager.close()
        self.assertEqual(target.read_text(), "keep")

    def test_corrupt_state_never_claims_success(self):
        self.manager.enable()
        self.manager.state_file.write_text('{"tool":"bad"}')
        with self.assertRaisesRegex(tool.ToolError, "状态无效"):
            self.manager.close()
        self.assertTrue(self.manager.auth_file.exists())

    def test_operation_lock_rejects_concurrent_user_operation(self):
        with self.manager.lock():
            with self.assertRaisesRegex(tool.ToolError, "另一个密码登录操作"):
                self.manager.enable()

    def test_status_does_not_write_config_or_create_state(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.manager.status()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.manager.state_dir.exists())

    def test_orphan_runtime_file_is_not_reported_as_closed(self):
        self.manager.runtime_dir.mkdir()
        self.manager.auth_file.write_text("orphan")
        with self.assertRaisesRegex(tool.ToolError, "未登记"):
            self.manager.close()

    def test_modified_hook_refused_without_overwriting_configuration(self):
        self.config.write_bytes(self.original + self.manager.hook().replace(b"Match all", b"Match User alice"))
        changed = self.config.read_bytes()
        with self.assertRaisesRegex(tool.ToolError, "Include 被修改"):
            self.manager.enable()
        self.assertEqual(self.config.read_bytes(), changed)

    def test_invalid_duration_rejected_without_changing_config(self):
        for minutes in (0, -1, 10081):
            with self.assertRaisesRegex(tool.ToolError, "分钟"):
                self.manager.enable(minutes=minutes)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_known_sshkeytool_policy_is_preserved_after_runtime_include(self):
        block = (b"# BEGIN sshkeytool root\nMatch User root\n    PubkeyAuthentication yes\n"
                 b"    ExposeAuthInfo yes\n    AuthenticationMethods publickey\n"
                 b"    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n"
                 b"    PermitRootLogin prohibit-password\n# END sshkeytool root\n")
        self.config.write_bytes(self.original + block)
        self.backend.options["authenticationmethods"] = "publickey"
        self.manager.enable()
        current = self.config.read_bytes()
        self.assertLess(current.index(self.manager.hook()), current.index(block))
        self.manager.close()
        self.assertIn(block, self.config.read_bytes())
        self.manager.enable()
        self.assertEqual(self.config.read_text().count(tool.BEGIN), 1)

    def test_pending_key_management_operation_blocks_enable(self):
        self.manager.key_active.write_text("pending")
        with self.assertRaisesRegex(tool.ToolError, "待确认或待恢复"):
            self.manager.enable()
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_permanent_survives_reboot_and_manual_close_restores_key_policy(self):
        self.backend.options["authenticationmethods"] = "publickey"
        state = self.manager.enable(permanent=True)
        self.assertEqual(state["mode"], "permanent")
        self.assertIsNone(state["expires_at"])
        self.assertEqual(list(self.unit_dir.iterdir()), [])
        self.assertFalse(self.manager.auth_file.exists())
        persistent = self.manager.persistent_auth_file
        self.assertEqual(persistent.stat().st_mode & 0o777, 0o600)
        self.assertIn(str(persistent), self.config.read_text())
        self.manager.runtime_dir.rmdir()
        self.boot.write_text("boot-two")
        actual = self.backend.effective("root", state["context"])
        self.assertTrue(tool.password_available(actual, "root"))
        self.assertEqual(actual["pubkeyauthentication"], "yes")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.manager.status()
        self.assertIn("永久模式：active", output.getvalue())
        self.assertNotIn("重启后已失效", output.getvalue())
        changed = self.config.read_bytes().replace(b"Port 21919", b"Port 22222")
        self.config.write_bytes(changed)
        self.manager.close()
        self.assertFalse(persistent.exists())
        self.assertEqual(self.manager.load_state()["phase"], "closed")
        self.assertEqual(self.config.read_bytes(), changed)
        self.assertEqual(self.backend.effective("root", state["context"]), self.backend.options)

    def test_expiry_worker_never_closes_permanent_mode(self):
        old = self.manager.enable()
        self.manager.close()
        state = self.manager.enable(permanent=True)
        self.manager.close(old["token"])
        self.manager.close(state["token"])
        self.assertTrue(self.manager.persistent_auth_file.exists())
        self.assertEqual(self.manager.load_state()["phase"], "active")

    def test_permanent_cannot_be_replaced_by_temporary_mode_after_reboot(self):
        state = self.manager.enable(permanent=True)
        self.boot.write_text("boot-two")
        with self.assertRaisesRegex(tool.ToolError, "先运行 sshpasswdtool close"):
            self.manager.enable()
        self.assertEqual(self.manager.load_state()["token"], state["token"])
        self.assertFalse(self.manager.auth_file.exists())

    def test_permanent_reload_failure_removes_permission_and_restores_config(self):
        self.backend.open_reload_error = True
        with self.assertRaisesRegex(tool.ToolError, "open reload failed"):
            self.manager.enable(permanent=True)
        self.assertFalse(self.manager.persistent_auth_file.exists())
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.manager.load_state()["phase"], "closed")
        self.assertEqual(list(self.unit_dir.iterdir()), [])

    def test_permanent_close_failure_after_reboot_records_failure_and_allows_retry(self):
        self.manager.enable(permanent=True)
        self.boot.write_text("boot-two")
        self.backend.restore_reload_error = True
        with self.assertRaisesRegex(tool.ToolError, "恢复尚未完成"):
            self.manager.close()
        self.assertFalse(self.manager.persistent_auth_file.exists())
        self.assertEqual(self.manager.load_state()["phase"], "restore_failed")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.manager.status()
        self.assertIn("恢复失败", output.getvalue())
        self.backend.restore_reload_error = False
        self.manager.close()
        self.assertEqual(self.manager.load_state()["phase"], "closed")

    def test_permanent_ordinary_user_does_not_open_root_or_other_users(self):
        self.backend.options["passwordauthentication"] = "no"
        state = self.manager.enable(user="alice", permanent=True)
        self.assertTrue(tool.password_available(self.backend.effective("alice", state["context"]), "alice"))
        self.assertFalse(tool.password_available(self.backend.effective("root", state["context"]), "root"))
        self.assertFalse(tool.password_available(self.backend.effective("bob", state["context"]), "bob"))
        self.assertNotIn("PermitRootLogin yes", self.manager.persistent_auth_file.read_text())
        self.manager.close()
        self.assertFalse(tool.password_available(self.backend.effective("alice", state["context"]), "alice"))

    def test_orphan_or_foreign_persistent_file_is_not_overwritten_or_deleted(self):
        with self.manager.lock():
            self.manager.persistent_auth_file.write_text("unrelated")
        with self.assertRaisesRegex(tool.ToolError, "未登记"):
            self.manager.enable(permanent=True)
        with self.assertRaisesRegex(tool.ToolError, "未登记"):
            self.manager.close()
        self.assertEqual(self.manager.persistent_auth_file.read_text(), "unrelated")
        self.manager.persistent_auth_file.unlink()
        self.manager.enable(permanent=True)
        self.manager.persistent_auth_file.write_text("unrelated")
        with self.assertRaisesRegex(tool.ToolError, "拒绝删除"):
            self.manager.close()
        self.assertEqual(self.manager.persistent_auth_file.read_text(), "unrelated")

    def test_legacy_hook_and_state_support_close_and_upgrade_to_permanent(self):
        state = self.manager.enable(until_reboot=True)
        state.pop("mode")
        self.manager.save_state(state)
        self.config.write_bytes(self.config.read_bytes().replace(self.manager.hook(), self.manager.legacy_hook()))
        self.manager.close()
        self.manager.enable(permanent=True)
        self.assertIn(self.manager.hook(), self.config.read_bytes())
        self.assertEqual(self.config.read_text().count(tool.BEGIN), 1)
        self.manager.close()

    def test_legacy_hook_upgrade_failure_restores_original_hook(self):
        original = self.original + self.manager.legacy_hook()
        self.config.write_bytes(original)
        self.backend.open_reload_error = True
        with self.assertRaisesRegex(tool.ToolError, "open reload failed"):
            self.manager.enable(permanent=True)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse(self.manager.persistent_auth_file.exists())


class CommandTests(unittest.TestCase):
    def test_help_version_and_mutually_exclusive_modes(self):
        for flag in ("--help", "--version"):
            result = subprocess.run([os.sys.executable, str(ROOT / "ssh_password_tool.py"), flag],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        for flags in (("--minutes", "5", "--until-reboot"), ("--minutes", "5", "--permanent"),
                      ("--until-reboot", "--permanent")):
            result = subprocess.run([os.sys.executable, str(ROOT / "ssh_password_tool.py"), "enable", *flags],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
        args = tool.build_parser().parse_args(["enable", "--permanent", "--yes"])
        self.assertTrue(args.permanent)

    def test_connection_context_uses_ipv6_and_rejects_malformed_environment(self):
        with patch.dict(os.environ, SSH_CONNECTION="2001:db8::1 34567 2001:db8::2 21919"):
            self.assertEqual(tool.connection_context()["addr"], "2001:db8::1")
        with patch.dict(os.environ, SSH_CONNECTION="203.0.113.1 bad 203.0.113.2 22"):
            with self.assertRaises(tool.ToolError):
                tool.connection_context()

    def test_username_match_injection_rejected(self):
        for value in ("*", "root,alice", "root\nPasswordAuthentication yes", "-root", "root@host"):
            with self.assertRaises(tool.ToolError):
                tool.validate_user(value)


if __name__ == "__main__":
    unittest.main()
