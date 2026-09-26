import errno
import os
import pty
import select
import shlex
import subprocess
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "safe-ssh-port" / "safe-ssh-port.sh"


class VersionDisplayTest(unittest.TestCase):
    def run_menu_in_terminal(self, no_color=False):
        master, slave = pty.openpty()
        environment = os.environ.copy()
        if no_color:
            environment["NO_COLOR"] = "1"
        else:
            environment.pop("NO_COLOR", None)
        try:
            process = subprocess.Popen(
                ["bash", "-c", f"source {shlex.quote(str(SCRIPT))}; menu_mode"],
                stdin=subprocess.PIPE,
                stdout=slave,
                stderr=slave,
                cwd=PROJECT_ROOT,
                env=environment,
            )
            process.communicate(b"5\n", timeout=5)
            output = bytearray()
            while select.select([master], [], [], 0.2)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
            return process.returncode, bytes(output)
        finally:
            os.close(master)
            os.close(slave)

    def test_version_command(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "allentool v2026.09.26.1\n")

    def test_menu_version_is_plain_text_when_redirected(self):
        result = subprocess.run(
            ["bash", "-c", f"source {shlex.quote(str(SCRIPT))}; menu_mode"],
            input="5\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("allentool VPS 工具  v2026.09.26.1", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_menu_version_is_dim_yellow_in_terminal(self):
        returncode, output = self.run_menu_in_terminal()
        self.assertEqual(returncode, 0)
        self.assertIn(b"\x1b[2;33mv2026.09.26.1\x1b[0m", output)

    def test_no_color_disables_terminal_escape_codes(self):
        returncode, output = self.run_menu_in_terminal(no_color=True)
        self.assertEqual(returncode, 0)
        self.assertIn(b"v2026.09.26.1", output)
        self.assertNotIn(b"\x1b[", output)


if __name__ == "__main__":
    unittest.main()
