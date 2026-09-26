import errno
import os
import pty
import re
import select
import shlex
import subprocess
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "safe-ssh-port" / "safe-ssh-port.sh"
VERSION = re.search(r"(?m)^ALLENTOOL_VERSION=(\d+\.\d+\.\d+)$", SCRIPT.read_text()).group(1)


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
        self.assertEqual(result.stdout, f"allentool v{VERSION}\n")

    def test_menu_version_is_plain_text_when_redirected(self):
        result = subprocess.run(
            ["bash", "-c", f"source {shlex.quote(str(SCRIPT))}; menu_mode"],
            input="5\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"allentool VPS 工具  v{VERSION}\n", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_menu_version_is_dim_yellow_in_terminal(self):
        returncode, output = self.run_menu_in_terminal()
        self.assertEqual(returncode, 0)
        self.assertIn(f"allentool VPS 工具  \x1b[2;33mv{VERSION}\x1b[0m\r\n".encode(), output)

    def test_no_color_disables_terminal_escape_codes(self):
        returncode, output = self.run_menu_in_terminal(no_color=True)
        self.assertEqual(returncode, 0)
        self.assertIn(f"allentool VPS 工具  v{VERSION}\r\n".encode(), output)
        self.assertNotIn(b"\x1b[", output)

    def test_longer_version_stays_on_title_line(self):
        result = subprocess.run(
            ["bash", "-c", f"source {shlex.quote(str(SCRIPT))}; ALLENTOOL_VERSION=0.1.1234; menu_mode"],
            input="5\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("allentool VPS 工具  v0.1.1234\n", result.stdout)


if __name__ == "__main__":
    unittest.main()
