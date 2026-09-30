#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/install.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[[ "$RAW_BASE" == 'https://raw.githubusercontent.com/allen0039/vps_tools/main/bbr-tune' ]] || fail "default download source"
(
  BBR_TUNE_RAW_BASE='https://gitee.com/allen0039/vps_tools/raw/main/bbr-tune'
  source "${ROOT}/install.sh"
  [[ "$RAW_BASE" == "$BBR_TUNE_RAW_BASE" ]]
) || fail "alternate download source"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
installed="${tmp}/sbin/bbr-tune"
linked="${tmp}/bin/bbr-tune"
shortcut="${tmp}/bin/bbrtcp"
install_payload "${ROOT}/bbr-tune.sh" "$installed" "$linked"
[[ -x "$installed" ]] || fail "installed executable"
[[ -L "$linked" ]] || fail "command symlink"
[[ "$(readlink "$linked")" == "$installed" ]] || fail "symlink target"
[[ -L "$shortcut" ]] || fail "shortcut symlink"
[[ "$(readlink "$shortcut")" == "$installed" ]] || fail "shortcut target"
"$linked" --version | grep -q '^bbr-tune ' || fail "installed command version"
"$shortcut" --version | grep -q '^bbrtcp ' || fail "shortcut command version"
[[ -x "${installed}-kernel" ]] || fail "kernel helper not installed"
"$linked" kernel help | grep -q 'BBRv3 内核管理' || fail "installed kernel entrypoint"
# A mixed release must be rejected before overwriting either installed file.
cp "${ROOT}/bbr-kernel.sh" "$tmp/bad-kernel.sh"
sed 's/^KERNEL_HELPER_VERSION=.*/KERNEL_HELPER_VERSION="0.0.0"/' "$tmp/bad-kernel.sh" >"$tmp/mismatched.sh"
if (install_payload "${ROOT}/bbr-tune.sh" "$installed" "$linked" "$tmp/mismatched.sh") >/dev/null 2>&1; then
  fail "mismatched helper accepted"
fi
"$linked" kernel help | grep -q 'BBRv3 内核管理' || fail "failed update broke installed helper"
"$shortcut" --version | grep -q '^bbrtcp ' || fail "failed update broke shortcut"
# An existing command owned by someone else must survive installation.
mkdir -p "$tmp/conflict/bin"
printf 'original\n' >"$tmp/conflict/bin/bbrtcp"
if (install_payload "${ROOT}/bbr-tune.sh" "$tmp/conflict/sbin/bbr-tune" "$tmp/conflict/bin/bbr-tune") >/dev/null 2>&1; then
  fail "unrelated shortcut overwritten"
fi
[[ "$(cat "$tmp/conflict/bin/bbrtcp")" == original ]] || fail "unrelated command changed"
[[ ! -e "$tmp/conflict/sbin/bbr-tune" ]] || fail "collision caused partial installation"
# --install-only must exit successfully and never open the interactive menu.
(
  INSTALL_PATH="$tmp/only/sbin/bbr-tune"; LINK_PATH="$tmp/only/bin/bbr-tune"
  require_linux_root() { :; }; install_runtime_dependencies() { :; }
  acquire_install_lock() { :; }; flock() { :; }
  launch_tool() { fail 'install-only launched menu'; }
  main --install-only >/dev/null
) || fail "install-only exit status"
[[ -L "$tmp/only/bin/bbrtcp" ]] || fail "install-only shortcut missing"
bash -n "${ROOT}/install.sh"
cat "${ROOT}/install.sh" | bash -s -- --help | grep -q '一键安装脚本' || fail "piped installer entrypoint"

printf 'All installer tests passed.\n'
