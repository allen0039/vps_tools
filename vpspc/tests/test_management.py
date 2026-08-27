import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vps_audit.management import (
    _active_ips_menu,
    _configure_ai_provider,
    _nodes_menu,
    _threshold_menu,
    _users_menu,
    _web_menu,
    interactive_menu,
)
from vps_audit.runtime import load_runtime_config
from vps_audit.settings import THRESHOLD_SPECS


class ManagementTests(unittest.TestCase):
    def _config(self, root: Path) -> Path:
        path = root / "config.json"
        path.write_text(
            json.dumps(
                {
                    "state_dir": str(root / "state"),
                    "report_dir": str(root / "reports"),
                    "telegram": {"enabled": False},
                    "openai_review": {"enabled": False},
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_users_menu_adds_multiple_users_and_selects_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            with patch("builtins.input", side_effect=["3", "alice", "3", "bob", "2", "0"]):
                _users_menu(str(path))
            config = load_runtime_config(str(path))
            self.assertEqual(config["subscription_monitoring"]["mode"], "allowlist")
            self.assertEqual(config["subscription_monitoring"]["users"], ["alice", "bob"])

    def test_threshold_menu_updates_selected_value(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            keys = list(THRESHOLD_SPECS)
            selection = str(keys.index("subscription_ip_count") + 1)
            with patch("builtins.input", side_effect=[selection, "14", "0"]):
                _threshold_menu(str(path))
            self.assertEqual(
                load_runtime_config(str(path))["rules"]["thresholds"]["subscription_ip_count"],
                14,
            )

    def test_main_menu_can_exit_without_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            with patch("vps_audit.management.os.geteuid", return_value=0), patch(
                "builtins.input", side_effect=["0"]
            ):
                interactive_menu(str(path), "/unused/install.sh")

    def test_web_menu_can_view_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            token = root / "web.token"
            token.write_text("web-test-token\n", encoding="utf-8")
            data = json.loads(path.read_text(encoding="utf-8"))
            data["web"] = {
                "enabled": True,
                "listen_host": "127.0.0.1",
                "listen_port": 18381,
                "token_file": str(token),
            }
            path.write_text(json.dumps(data), encoding="utf-8")
            with patch("builtins.input", side_effect=["1", "0"]):
                _web_menu(str(path))

    def test_local_manager_adds_provider_and_stores_key_privately(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root)
            with patch(
                "builtins.input",
                side_effect=[
                    "vendor",
                    "Vendor AI",
                    "https://vendor.example/v1",
                    "chat_completions",
                    "model-name",
                    "25",
                ],
            ), patch("vps_audit.management.getpass.getpass", return_value="api-secret"):
                provider_id = _configure_ai_provider(str(path))
            config = load_runtime_config(str(path))
            provider = config["openai_review"]["providers"][provider_id]
            key_path = Path(provider["api_key_file"])
            self.assertEqual(key_path.read_text(encoding="utf-8").strip(), "api-secret")
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)

    def test_local_active_ip_menu_selects_added_user(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            with patch("builtins.input", side_effect=["3", "alice", "0"]):
                _users_menu(str(path))
            result = {
                "user": "alice",
                "window_minutes": 15,
                "ip_count": 0,
                "ips": [],
            }
            with patch("builtins.input", side_effect=["1", "", "0"]), patch(
                "vps_audit.management.query_active_subscription_ips", return_value=result
            ) as query:
                _active_ips_menu(str(path))
            self.assertEqual(query.call_args.args[1], "alice")

    def test_nodes_menu_distinguishes_normal_and_replacement_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            with patch("vps_audit.management.list_registered_nodes", return_value=[]), patch(
                "vps_audit.management.create_install_command", return_value="install-command"
            ) as create, patch("builtins.input", side_effect=["1", "edge-normal", "0"]):
                _nodes_menu(str(path))
            create.assert_called_once_with(str(path), "edge-normal", replace=False)

            with patch("vps_audit.management.list_registered_nodes", return_value=[]), patch(
                "vps_audit.management.create_install_command", return_value="replace-command"
            ) as create, patch("builtins.input", side_effect=["2", "edge-replace", "0"]):
                _nodes_menu(str(path))
            create.assert_called_once_with(str(path), "edge-replace", replace=True)

    def test_nodes_menu_exposes_revoke_and_fixed_uninstall_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._config(Path(temporary))
            node = {
                "node_id": "node_1234567890abcdef12345678",
                "name": "edge",
                "revoked": False,
                "last_seen": None,
            }
            with patch(
                "vps_audit.management.list_registered_nodes", return_value=[node]
            ), patch("vps_audit.management.revoke_registered_node") as revoke, patch(
                "builtins.input",
                side_effect=["3", node["node_id"], "0"],
            ):
                _nodes_menu(str(path))
            revoke.assert_called_once_with(str(path), node["node_id"])

            with patch(
                "vps_audit.management.list_registered_nodes", return_value=[node]
            ), patch(
                "vps_audit.management.request_registered_node_uninstall",
                return_value={"id": "command-id"},
            ) as uninstall, patch(
                "builtins.input",
                side_effect=["4", node["node_id"], "0"],
            ):
                _nodes_menu(str(path))
            uninstall.assert_called_once_with(str(path), node["node_id"])


if __name__ == "__main__":
    unittest.main()
