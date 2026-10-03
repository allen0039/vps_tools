import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "Fail2ban" / "install.sh"
SAFE = ROOT / "safe-ssh-port" / "safe-ssh-port.sh"


class OneClickInstallerTests(unittest.TestCase):
    def run_bash(self, script, *args):
        return subprocess.run(["bash", "-c", script, "test", *map(str, args)],
                              text=True, capture_output=True)

    def test_help_does_not_install(self):
        result = subprocess.run(["bash", str(INSTALLER), "--help"],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--ignore-ip", result.stdout)

    def test_local_bundle_checks_both_files(self):
        result = self.run_bash('source "$1/Fail2ban/install.sh"; prepare_sources; '
                               'cmp "$STAGE/Fail2ban/f2btool.py" "$1/Fail2ban/f2btool.py"; '
                               'cmp "$STAGE/safe-ssh-port/safe-ssh-port.sh" "$1/safe-ssh-port/safe-ssh-port.sh"', ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("本地", result.stdout)

    def test_remote_uses_same_commit_and_rejects_bad_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_bash('''
source "$1/Fail2ban/install.sh"
SOURCE_DIR="$2"
ROOT_DIR="$1"
download() {
    case "$1" in
        *commits/main*) printf '{"sha":"0123456789012345678901234567890123456789"}' > "$2" ;;
        *0123456789012345678901234567890123456789/safe-ssh-port/safe-ssh-port.sh)
            cp "$ROOT_DIR/safe-ssh-port/safe-ssh-port.sh" "$2" ;;
        *) printf '<html>unexpected download</html>' > "$2" ;;
    esac
}
prepare_sources
printf INSTALL_MUST_NOT_START
''', ROOT, tmp)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("INSTALL_MUST_NOT_START", result.stdout)
            self.assertIn("文件不是 Python 脚本", result.stderr)

    def test_unattended_safe_tool_upgrade_only_for_recognized_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            known = pathlib.Path(tmp) / "known"
            known.write_text(re.sub(r"^ALLENTOOL_VERSION=\d+\.\d+\.\d+$",
                                    "ALLENTOOL_VERSION=0.1.12", SAFE.read_text(),
                                    count=1, flags=re.M))
            accepted = self.run_bash('source "$1"; INSTALL_ASSUME_YES=yes; '
                                     'confirm_install_target "$1" "$2" tool', SAFE, known)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            unknown = pathlib.Path(tmp) / "unknown"
            unknown.write_text("#!/usr/bin/env bash\necho unrelated\n")
            rejected = self.run_bash('source "$1"; INSTALL_ASSUME_YES=yes; '
                                     'confirm_install_target "$1" "$2" tool', SAFE, unknown)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("拒绝自动覆盖", rejected.stderr)

    def test_safe_install_accepts_yes_only_for_install_command(self):
        result = self.run_bash('source "$1"; require_root() { :; }; '
                               'install_tool() { printf "ASSUME=%s\\n" "$INSTALL_ASSUME_YES"; }; '
                               'main install --yes', SAFE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ASSUME=yes\n")
        rejected = self.run_bash('source "$1"; require_root() { :; }; '
                                 'install_tool() { printf SHOULD_NOT_INSTALL; }; '
                                 'main install --force', SAFE)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertNotIn("SHOULD_NOT_INSTALL", rejected.stdout)


if __name__ == "__main__":
    unittest.main()
