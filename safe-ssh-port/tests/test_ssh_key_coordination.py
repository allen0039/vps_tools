import fcntl
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "safe-ssh-port.sh"


class SSHKeyCoordinationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.lock = self.base / "ssh.lock"
        self.active = self.base / "active.json"
        self.env = dict(os.environ, VPS_TOOLS_SSH_LOCK=str(self.lock), VPS_TOOLS_SSHKEY_ACTIVE=str(self.active))

    def bash(self, body):
        return subprocess.run(["bash", "-c", "source " + shlex.quote(str(SCRIPT)) + "\n" + body],
                              env=self.env, capture_output=True, text=True, timeout=5)

    def test_pending_key_operation_blocks_before_sshd_or_firewall(self):
        self.active.write_text("pending")
        p = self.bash('flock() { :; }; SSHD_BIN=mock_sshd; mock_sshd() { echo SHOULD_NOT_RUN; }; switch_port 22022 yes yes')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("密钥工具有待确认", p.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", p.stdout)

    def test_symbolic_link_lock_is_rejected(self):
        target = self.base / "unrelated"
        target.write_text("untouched")
        self.lock.symlink_to(target)
        p = self.bash('flock() { :; }; acquire_ssh_operation_lock')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("符号链接", p.stderr)
        self.assertEqual(target.read_text(), "untouched")

    @unittest.skipUnless(shutil.which("flock"), "跨进程锁测试需要 util-linux flock")
    def test_shell_lock_waits_for_python_flock(self):
        with self.lock.open("w") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            p = subprocess.Popen(["bash", "-c", "source " + shlex.quote(str(SCRIPT)) +
                                  '\nacquire_ssh_operation_lock; printf LOCK_ACQUIRED'],
                                 env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                time.sleep(0.2)
                self.assertIsNone(p.poll(), "Shell lock bypassed the Python lock")
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                stdout, stderr = p.communicate(timeout=5)
                self.assertEqual(p.returncode, 0, stderr)
                self.assertEqual(stdout, "LOCK_ACQUIRED")
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()


if __name__ == "__main__":
    unittest.main()
