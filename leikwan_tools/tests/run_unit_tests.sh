#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${LIQUN_TEST_OUT_DIR:-${PROJECT_DIR}/test-results-r2}"
mkdir -p "${OUT_DIR}"

echo "=== Running leikwan_tools unit tests ($(python3 --version)) ==="
python3 -m unittest discover -s "${SCRIPT_DIR}" -p "test_*.py" -v 2>&1 | tee "${OUT_DIR}/unit-test-output.txt"
