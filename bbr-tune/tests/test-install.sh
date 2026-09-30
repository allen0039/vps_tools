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

DOWNLOAD_NONCE='test-refresh'
download_log="$(mktemp)"
curl() { printf '%s\n' "$*" >>"$download_log"; }
download_payload /dev/null
download_payload /dev/null bbr-kernel.sh
grep -q 'bbr-tune.sh?bbr_tune_refresh=test-refresh' "$download_log" || fail 'main download lacks refresh parameter'
grep -q 'bbr-kernel.sh?bbr_tune_refresh=test-refresh' "$download_log" || fail 'helper download lacks refresh parameter'
grep -q 'Cache-Control: no-cache' "$download_log" || fail 'download lacks no-cache header'
unset -f curl
rm -f "$download_log"
curl() {
  local previous='' argument destination=''
  for argument in "$@"; do
    if [[ "$previous" == -o ]]; then destination="$argument"; fi
    previous="$argument"
  done
  printf '{"sha":"7ef501bf6eb5e546dd0a2bdcf0dcbce537e1b134"}\n' >"$destination"
}
resolve_remote_base
[[ "$RAW_BASE" == 'https://raw.githubusercontent.com/allen0039/vps_tools/7ef501bf6eb5e546dd0a2bdcf0dcbce537e1b134/bbr-tune' ]] || fail 'GitHub base not pinned to commit'
RAW_BASE='https://gitee.com/allen0039/vps_tools/raw/main/bbr-tune'
resolve_remote_base
[[ "$RAW_BASE" == 'https://gitee.com/allen0039/vps_tools/raw/7ef501bf6eb5e546dd0a2bdcf0dcbce537e1b134/bbr-tune' ]] || fail 'Gitee base not pinned to commit'
unset -f curl
RAW_BASE='https://raw.githubusercontent.com/allen0039/vps_tools/main/bbr-tune'

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
version_is_older 2.10.0 2.10.2 || fail 'older version comparison'
if version_is_older 2.10.2 2.10.2 || version_is_older 2.10.3 2.10.2; then fail 'non-older version comparison'; fi
cp "${ROOT}/bbr-tune.sh" "$tmp/old-main.sh"
sed 's/^VERSION=.*/VERSION="2.10.0"/' "$tmp/old-main.sh" >"$tmp/old-main-version.sh"
cp "${ROOT}/bbr-kernel.sh" "$tmp/old-helper.sh"
sed 's/^KERNEL_HELPER_VERSION=.*/KERNEL_HELPER_VERSION="2.10.0"/' "$tmp/old-helper.sh" >"$tmp/old-helper-version.sh"
if (install_payload "$tmp/old-main-version.sh" "$installed" "$linked" "$tmp/old-helper-version.sh") >/dev/null 2>&1; then
  fail 'older release replaced installed version'
fi
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
