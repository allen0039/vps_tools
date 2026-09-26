import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "bump_version.py"
SPEC = importlib.util.spec_from_file_location("bump_version", MODULE_PATH)
bump_version = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bump_version)


class AutoVersionTest(unittest.TestCase):
    def test_script_update_increments_patch(self):
        previous = "ALLENTOOL_VERSION=0.1.5\nold code\n"
        current = "ALLENTOOL_VERSION=0.1.5\nnew code\n"
        self.assertEqual(
            bump_version.bumped_source(previous, current),
            "ALLENTOOL_VERSION=0.1.6\nnew code\n",
        )

    def test_explicit_version_change_is_preserved(self):
        previous = "ALLENTOOL_VERSION=2026.09.26.1\nold code\n"
        current = "ALLENTOOL_VERSION=0.1.5\nnew code\n"
        self.assertIsNone(bump_version.bumped_source(previous, current))

    def test_unchanged_script_does_not_increment(self):
        source = "ALLENTOOL_VERSION=0.1.5\nold code\n"
        self.assertIsNone(bump_version.bumped_source(source, source))

    def test_ambiguous_version_fails(self):
        with self.assertRaises(ValueError):
            bump_version.bumped_source("no version\n", "ALLENTOOL_VERSION=0.1.5\n")


if __name__ == "__main__":
    unittest.main()
