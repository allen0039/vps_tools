#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/bbr-tune.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

[[ "$(update_channel_base github)" == 'https://raw.githubusercontent.com/allen0039/vps_tools/main/bbr-tune' ]] || fail 'GitHub channel URL'
[[ "$(update_channel_base gitee)" == 'https://gitee.com/allen0039/vps_tools/raw/main/bbr-tune' ]] || fail 'Gitee channel URL'
if update_channel_base unknown >/dev/null; then fail 'unknown channel accepted'; fi

require_linux() { :; }; require_root() { :; }
export UPDATE_TEST_LOG="$tmp/installer.log"
export BBR_TUNE_INSTALL_PATH="$tmp/installed-bbr-tune"
export UPDATE_TEST_INSTALLED_VERSION="2.10.3"
UPDATE_TEST_SHA='7ef501bf6eb5e546dd0a2bdcf0dcbce537e1b134'
download_update_installer() {
  printf '%s\n' "$1" >>"$tmp/download-urls"
  if [[ "$1" == *'/commits/main?'* || "$1" == *'/branches/main?'* ]]; then
    printf '{"name":"main","commit":{"sha":"%s","other":{"sha":"0000000000000000000000000000000000000000"}}}\n' "$UPDATE_TEST_SHA" >"$2"
    return
  fi
  cat >"$2" <<'INSTALLER'
#!/usr/bin/env bash
printf '%s|%s\n' "$BBR_TUNE_RAW_BASE" "$*" >"$UPDATE_TEST_LOG"
printf '#!/usr/bin/env bash\nprintf "bbr-tune %%s\\n" "%s"\n' "$UPDATE_TEST_INSTALLED_VERSION" >"$BBR_TUNE_INSTALL_PATH"
chmod +x "$BBR_TUNE_INSTALL_PATH"
INSTALLER
}
UPDATE_CHANNEL=github
update_command >"$tmp/github.out" 2>&1 || fail 'GitHub update failed'
[[ "$(cat "$tmp/installer.log")" == "https://raw.githubusercontent.com/allen0039/vps_tools/${UPDATE_TEST_SHA}/bbr-tune|--install-only" ]] || fail 'GitHub source not passed to installer'
grep -q "https://api.github.com/repos/allen0039/vps_tools/commits/main?bbr_tune_refresh=" "$tmp/download-urls" || fail 'GitHub commit API not used'
grep -q "https://raw.githubusercontent.com/allen0039/vps_tools/${UPDATE_TEST_SHA}/bbr-tune/install.sh?bbr_tune_refresh=" "$tmp/download-urls" || fail 'GitHub installer not pinned to commit'
grep -q '仍是版本 2.10.3' "$tmp/github.out" || fail 'unchanged version not reported'
UPDATE_CHANNEL=gitee
UPDATE_TEST_INSTALLED_VERSION="2.10.4"
update_command >"$tmp/gitee.out" || fail 'Gitee update failed'
[[ "$(cat "$tmp/installer.log")" == "https://gitee.com/allen0039/vps_tools/raw/${UPDATE_TEST_SHA}/bbr-tune|--install-only" ]] || fail 'Gitee source not passed to installer'
grep -q "https://gitee.com/api/v5/repos/allen0039/vps_tools/branches/main?bbr_tune_refresh=" "$tmp/download-urls" || fail 'Gitee commit API not used'
grep -q "https://gitee.com/allen0039/vps_tools/raw/${UPDATE_TEST_SHA}/bbr-tune/install.sh?bbr_tune_refresh=" "$tmp/download-urls" || fail 'Gitee installer not pinned to commit'
grep -q '已从 2.10.3 更新到 2.10.4' "$tmp/gitee.out" || fail 'new version not reported'

UPDATE_CHANNEL=unknown
if update_command >"$tmp/invalid.out" 2>&1; then fail 'invalid channel updated'; fi
grep -q '只能是 github 或 gitee' "$tmp/invalid.out" || fail 'invalid channel explanation missing'

UPDATE_CHANNEL=github
download_update_installer() {
  if [[ "$1" == *'/commits/main?'* ]]; then printf '{"sha":"%s"}\n' "$UPDATE_TEST_SHA" >"$2"; else printf 'not a shell installer\n' >"$2"; fi
}
if update_command >"$tmp/invalid-installer.out" 2>&1; then fail 'invalid installer executed'; fi
grep -q '安装器无效' "$tmp/invalid-installer.out" || fail 'invalid installer explanation missing'

download_update_installer() {
  if [[ "$1" == *'/commits/main?'* ]]; then printf '{"sha":"%s"}\n' "$UPDATE_TEST_SHA" >"$2"; return; fi
  cat >"$2" <<'FAILED_INSTALLER'
#!/usr/bin/env bash
exit 7
FAILED_INSTALLER
}
if update_command >"$tmp/failed-installer.out" 2>&1; then fail 'installer failure reported success'; fi
grep -q '更新未完成' "$tmp/failed-installer.out" || fail 'installer failure explanation missing'

ui_yes_no() { return 0; }
ui_execute() { printf '%s\n' "$*" >"$tmp/menu-action"; }
printf '2\n' | ui_update >"$tmp/menu.out" || fail 'Gitee menu selection failed'
[[ "$(cat "$tmp/menu-action")" == '1 update --channel gitee' ]] || fail 'menu selected wrong update channel'
rm -f "$tmp/menu-action"
if printf '0\n' | ui_update >"$tmp/menu-cancel.out"; then fail 'menu cancellation reported success'; fi
[[ ! -e "$tmp/menu-action" ]] || fail 'cancelled menu started update'

printf 'All update channel and menu tests passed.\n'
