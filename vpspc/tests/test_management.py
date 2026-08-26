import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vps_audit.management import _threshold_menu, _users_menu, interactive_menu
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


if __name__ == "__main__":
    unittest.main()
