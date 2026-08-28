import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DockerTests(unittest.TestCase):
    def test_entrypoint_executes_compose_command_instead_of_audit_loop(self):
        completed = subprocess.run(
            ["sh", str(ROOT / "docker" / "entrypoint.sh"), "/bin/echo", "web-service"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), "web-service")

    def test_compose_profiles_keep_explicit_service_commands(self):
        source = (ROOT / "compose.yml").read_text(encoding="utf-8")
        self.assertIn('command: ["/usr/local/bin/vps-audit-web"', source)
        self.assertIn('command: ["/usr/local/bin/vps-audit-bot"', source)
        self.assertIn('command: ["/usr/local/bin/vps-audit-nodes"', source)
        self.assertIn("healthcheck:", source)
        self.assertIn("vps-audit-maintenance", source)
        self.assertIn("vpspc-run:/run/vpspc", source)
        self.assertNotIn("/var/run/docker.sock", source)
        self.assertNotIn("build: .", source)
        self.assertIn("AUDIT_IMAGE:?set AUDIT_IMAGE in .env", source)

    def test_host_helper_setup_is_explicit_and_does_not_require_docker_socket_in_containers(self):
        setup = ROOT / "docker" / "setup-host-updater.sh"
        self.assertTrue(setup.is_file())
        source = setup.read_text(encoding="utf-8")
        self.assertIn("vps-audit-update-helper.socket", source)
        self.assertIn("docker-maintenance.json", source)
        self.assertIn("web_token is required", source)
        self.assertIn("telegram_token is required", source)
        self.assertNotIn("/var/run/docker.sock", (ROOT / "compose.yml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
