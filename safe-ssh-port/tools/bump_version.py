#!/usr/bin/env python3
"""Increment the embedded patch version after a main-branch script update."""

import os
import re
import subprocess
from pathlib import Path


SCRIPT_RELATIVE_PATH = "safe-ssh-port/safe-ssh-port.sh"
SCRIPT = Path(__file__).resolve().parents[2] / SCRIPT_RELATIVE_PATH
VERSION_LINE = re.compile(r"^ALLENTOOL_VERSION=(\d+(?:\.\d+)+)$", re.MULTILINE)


def version_match(source):
    matches = list(VERSION_LINE.finditer(source))
    if len(matches) != 1:
        raise ValueError("Expected exactly one semantic ALLENTOOL_VERSION assignment")
    return matches[0]


def bumped_source(previous, current):
    old_version = version_match(previous)
    new_version = version_match(current)
    parts = new_version.group(1).split(".")
    if len(parts) != 3:
        raise ValueError("Current version must have three numeric components")
    if previous == current or old_version.group() != new_version.group():
        return None
    major, minor, patch = map(int, parts)
    replacement = f"ALLENTOOL_VERSION={major}.{minor}.{patch + 1}"
    return current[:new_version.start()] + replacement + current[new_version.end():]


def main():
    previous_ref = os.environ["PREVIOUS_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", previous_ref):
        raise ValueError("PREVIOUS_SHA must be a full commit SHA")
    previous = subprocess.check_output(
        ["git", "show", f"{previous_ref}:{SCRIPT_RELATIVE_PATH}"],
        cwd=SCRIPT.parent.parent,
        text=True,
    )
    current = SCRIPT.read_text()
    updated = bumped_source(previous, current)
    if updated is not None:
        SCRIPT.write_text(updated)
        print(f"Updated version to {version_match(updated).group(1)}")
    else:
        print("Version unchanged")


if __name__ == "__main__":
    main()
