#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/bbr-kernel.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
eq() { [[ "$1" == "$2" ]] || fail "$3: expected '$2', got '$1'"; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

k_parse install --yes --console-available
eq "$K_ACTION:$K_YES:$K_CONSOLE" install:1:1 'kernel arguments'
for args in 'build' 'install --track lts' 'install --cpu-level 3' 'install --profile max' 'install --source arbitrary'; do
  if (k_parse $args) >/dev/null 2>&1; then fail "removed/invalid arguments accepted: $args"; fi
done
K_ARCH=x86_64; K_OS=debian; K_SUITE=bookworm; k_supported_os || fail 'Debian amd64 refused'
K_ARCH=aarch64; if k_supported_os; then fail 'arm64 cannot use amd64 packages'; fi
K_ARCH=x86_64; K_SUITE=bullseye; if k_supported_os; then fail 'unverified distro accepted'; fi

# Release selection must choose the highest complete standard x86_64 release,
# ignore Max/prerelease builds, require exact GitHub URLs and SHA-256 digests.
python3 - "$TMP/releases.json" <<'PY_RELEASE'
import json,sys
repo='byJoey/Actions-bbr-v3'
def asset(tag,name,digest='a'*64):
    size=141000000 if name.startswith('linux-image') else 13000000 if name.startswith('linux-headers') else 300000
    return {'name':name,'browser_download_url':f'https://github.com/{repo}/releases/download/{tag}/{name}','digest':'sha256:'+digest,'size':size}
def release(version,suffix='',draft=False,prerelease=False,complete=True):
    tag=f'x86_64-{version}{suffix}'; local='-joeyblog-bbrv3'+('-max' if suffix else '')
    names=[f'linux-image-{version}{local}_{version}-1_amd64.deb',f'linux-headers-{version}{local}_{version}-1_amd64.deb',f'x86_64-{version}.config']
    if not complete: names.pop()
    return {'tag_name':tag,'draft':draft,'prerelease':prerelease,'published_at':'2026-09-26T00:00:00Z','assets':[asset(tag,n,str(i+1)*64) for i,n in enumerate(names)]}
data=[release('7.2.7'),release('7.2.9','-max'),release('7.2.10',prerelease=True),release('7.2.9')]
json.dump(data,open(sys.argv[1],'w'))
PY_RELEASE
k_select_release "$TMP/releases.json" "$TMP/selected.json"
eq "$K_TAG" x86_64-7.2.9 'latest standard release tag'
eq "$K_TARGET" 7.2.9-joeyblog-bbrv3 'release-derived target'
eq "$K_META_VERSION" 7.2.9-1 'package version'
eq "$K_META" byJoey/Actions-bbr-v3:standard 'release source'
[[ "$K_IMAGE_NAME" == linux-image-7.2.9-joeyblog-bbrv3_7.2.9-1_amd64.deb ]] || fail 'image asset selection'
[[ "$K_HEADERS_NAME" == linux-headers-7.2.9-joeyblog-bbrv3_7.2.9-1_amd64.deb ]] || fail 'headers asset selection'
[[ "$K_CONFIG_NAME" == x86_64-7.2.9.config ]] || fail 'config asset selection'
[[ -s "$TMP/selected.json" ]] || fail 'selected release audit missing'
for mutation in missing-digest wrong-url invalid-size duplicate-image max-only; do
  python3 - "$TMP/releases.json" "$TMP/$mutation.json" "$mutation" <<'PY_BAD'
import json,sys
x=json.load(open(sys.argv[1])); mode=sys.argv[3]
if mode=='missing-digest': x[-1]['assets'][0].pop('digest')
elif mode=='wrong-url': x[-1]['assets'][0]['browser_download_url']='https://example.com/kernel.deb'
elif mode=='invalid-size': x[-1]['assets'][0]['size']=1
elif mode=='duplicate-image': x[-1]['assets'].append(dict(x[-1]['assets'][0]))
elif mode=='max-only': x=[r for r in x if r['tag_name'].endswith('-max')]
json.dump(x,open(sys.argv[2],'w'))
PY_BAD
  if k_select_release "$TMP/$mutation.json" "$TMP/$mutation-selected.json" >/dev/null 2>&1; then fail "unsafe release metadata accepted: $mutation"; fi
done
printf test >"$TMP/hash-file"
good="sha256:$(shasum -a 256 "$TMP/hash-file" | awk '{print $1}')"
k_verify_sha256 "$TMP/hash-file" "$good" || fail 'valid GitHub digest rejected'
if k_verify_sha256 "$TMP/hash-file" "sha256:$(printf '0%.0s' {1..64})"; then fail 'bad GitHub digest accepted'; fi
if k_verify_sha256 "$TMP/hash-file" 'sha256:not-a-digest'; then fail 'malformed digest accepted'; fi
(
  source_file="$TMP/hash-file"; output="$TMP/downloaded"
  k_fetch() { cp "$source_file" "$2"; }
  k_download_asset hash-file https://example.invalid/file "$good" 4 "$output" >/dev/null
  [[ "$(cat "$output")" == test ]] || fail 'verified asset not promoted'
  if (k_download_asset hash-file https://example.invalid/file "$good" 5 "$output.bad") >/dev/null 2>&1; then fail 'asset size mismatch accepted'; fi
)

cat >"$TMP/releases-kernel.json" <<'JSON'
{"releases":[{"version":"7.2.9","moniker":"stable"},{"version":"6.18.54","moniker":"longterm"},{"version":"7.3-rc5","moniker":"mainline"},{"version":"6.13.7","moniker":"stable","iseol":true}]}
JSON
k_check_maintained x86_64-7.2.9 "$TMP/releases-kernel.json" >/dev/null
for tag in x86_64-7.2.8 x86_64-6.13.7 x86_64-7.3.0-max invalid; do
  if k_check_maintained "$tag" "$TMP/releases-kernel.json" >/dev/null 2>&1; then fail "unmaintained/invalid release accepted: $tag"; fi
done

# Lightweight and annotated Git tags must resolve to a fixed source commit for audit.
(
  K_SESSION="$TMP/tag-light"; mkdir -p "$K_SESSION"; K_TAG=x86_64-7.2.9
  k_fetch_api() { printf '{"object":{"type":"commit","sha":"%040d"}}\n' 1 >"$2"; }
  k_resolve_tag_commit
  eq "$K_COMMIT" "$(printf '%040d' 1)" 'lightweight tag commit'
)
(
  K_SESSION="$TMP/tag-annotated"; mkdir -p "$K_SESSION"; K_TAG=x86_64-7.2.9
  k_fetch_api() {
    if [[ "$1" == */git/ref/* ]]; then printf '{"object":{"type":"tag","sha":"%040d"}}\n' 2 >"$2"
    else printf '{"object":{"type":"commit","sha":"%040d"}}\n' 3 >"$2"; fi
  }
  k_resolve_tag_commit
  eq "$K_COMMIT" "$(printf '%040d' 3)" 'annotated tag commit'
)

cat >"$TMP/grub.cfg" <<'GRUB'
menuentry 'Linux' $menuentry_id_option 'gnulinux-simple-uuid' {
}
submenu 'Advanced Linux' $menuentry_id_option 'gnulinux-advanced-uuid' {
 menuentry 'Old Linux' $menuentry_id_option 'gnulinux-5.15.0-old-advanced-uuid' {
 }
 menuentry 'Old Linux recovery' $menuentry_id_option 'gnulinux-5.15.0-old-recovery-uuid' {
 }
 menuentry 'New Linux' $menuentry_id_option 'gnulinux-7.2.9-joeyblog-bbrv3-advanced-uuid' {
 }
}
GRUB
eq "$(k_grub_entry 5.15.0-old "$TMP/grub.cfg")" 'gnulinux-advanced-uuid>gnulinux-5.15.0-old-advanced-uuid' 'stable, non-recovery GRUB ID'
if k_grub_entry missing "$TMP/grub.cfg" >/dev/null 2>&1; then fail 'missing GRUB entry accepted'; fi
cat "$TMP/grub.cfg" "$TMP/grub.cfg" >"$TMP/ambiguous.cfg"
if k_grub_entry 5.15.0-old "$TMP/ambiguous.cfg" >/dev/null 2>&1; then fail 'ambiguous GRUB entry accepted'; fi

# Use the actual Debian field contract, including held packages and query errors.
(
  dpkg-query() {
    [[ "$2" == '-f=${Status}\t${Version}\n' ]] || fail 'unsupported dpkg field'
    case "$3" in
      missing) return 1 ;;
      broken) return 2 ;;
      held) printf 'hold ok installed\t7.2.9-1\n' ;;
    esac
  }
  eq "$(k_package_status missing)" '' 'missing package'
  eq "$(k_package_status broken)" query-error-2 'query error fails closed'
  eq "$(k_package_status held)" $'hold ok installed\t7.2.9-1' 'held package status'
)

# Classify an existing target before downloading large image/header assets.
# Only an exact package, file, config and BBRv3 match may be adopted.
(
  K_SESSION="$TMP/existing-state"; K_BOOT_DIR="$TMP/existing-boot"; K_MODULES_DIR="$TMP/existing-modules"
  mkdir -p "$K_SESSION" "$K_BOOT_DIR" "$K_MODULES_DIR"
  K_OLD=5.15.0-old; K_TARGET=7.2.9-joeyblog-bbrv3; K_META_VERSION=7.2.9-1
  printf 'CONFIG_TCP_CONG_BBR=y\nCONFIG_NET_SCH_FQ=y\n' >"$K_SESSION/release.config"
  installed_image_version=''; installed_headers_version=''; installed_module_version=3; package_want=install
  dpkg-query() {
    [[ "$2" == '-f=${Status}\t${Version}\n' ]] || fail 'invalid dpkg status field'
    local package="${*: -1}" version=''
    case "$package" in
      "linux-image-$K_TARGET") version="$installed_image_version" ;;
      "linux-headers-$K_TARGET") version="$installed_headers_version" ;;
    esac
    [[ -n "$version" ]] || return 1
    printf '%s ok installed\t%s\n' "$package_want" "$version"
  }
  modinfo() { printf '%s\n' "$installed_module_version"; }

  eq "$(k_existing_target_state)" absent 'missing target classification'
  grep -Fqx $'state\tabsent' "$K_SESSION/existing-target.tsv" || fail 'absent target audit'

  installed_image_version=$K_META_VERSION; installed_headers_version=$K_META_VERSION
  printf image >"$K_BOOT_DIR/vmlinuz-$K_TARGET"
  printf initramfs >"$K_BOOT_DIR/initrd.img-$K_TARGET"
  cp "$K_SESSION/release.config" "$K_BOOT_DIR/config-$K_TARGET"
  mkdir -p "$K_MODULES_DIR/$K_TARGET"
  eq "$(k_existing_target_state)" complete 'complete target classification'
  grep -Fqx $'config_match\tyes' "$K_SESSION/existing-target.tsv" || fail 'complete config audit'
  grep -Fqx $'image_package_version\t7.2.9-1' "$K_SESSION/existing-target.tsv" || fail 'package version audit'

  package_want=hold
  eq "$(k_existing_target_state)" complete 'held installed target'
  package_want=install
  installed_headers_version=''
  eq "$(k_existing_target_state)" conflict 'missing headers conflict'
  installed_headers_version=$K_META_VERSION; installed_image_version=7.2.9-2
  eq "$(k_existing_target_state)" conflict 'package version conflict'
  installed_image_version=$K_META_VERSION; printf '# changed\n' >>"$K_BOOT_DIR/config-$K_TARGET"
  eq "$(k_existing_target_state)" conflict 'config mismatch conflict'
  cp "$K_SESSION/release.config" "$K_BOOT_DIR/config-$K_TARGET"; installed_module_version=1
  eq "$(k_existing_target_state)" conflict 'non-BBRv3 conflict'
  installed_module_version=3; rm -rf "$K_MODULES_DIR/$K_TARGET"
  eq "$(k_existing_target_state)" conflict 'missing modules conflict'

  rm -f "$K_BOOT_DIR/initrd.img-$K_TARGET" "$K_BOOT_DIR/config-$K_TARGET"
  rm -f "$K_BOOT_DIR/vmlinuz-$K_TARGET"; printf image >"$K_BOOT_DIR/vmlinuz-$K_TARGET"
  installed_image_version=''; installed_headers_version=''
  eq "$(k_existing_target_state)" conflict 'orphan vmlinuz conflict'

  rm -f "$K_BOOT_DIR/vmlinuz-$K_TARGET"
  ln -s missing "$K_BOOT_DIR/vmlinuz-$K_TARGET"
  eq "$(k_existing_target_state)" conflict 'broken target symlink'

  K_OLD=$K_TARGET
  eq "$(k_existing_target_state)" running 'running target classification'
)

# A fully matching preinstalled kernel is adopted through the main install path.
# Image/header downloads and package installation must not run again.
(
  K_ROOT="$TMP/adopt-state"; K_LATEST="$K_ROOT/latest"; K_SESSION="$K_ROOT/session"
  K_BOOT_DIR="$TMP/adopt-boot"; K_MODULES_DIR="$TMP/adopt-modules"; K_GRUB_CFG="$K_BOOT_DIR/grub.cfg"
  K_GRUB_ENV="$K_BOOT_DIR/grubenv"; K_GRUB_DROP="$TMP/adopt-default/grub.d/kernel.cfg"; K_GRUB_DEFAULT="$TMP/adopt-default/grub"
  mkdir -p "$K_SESSION" "$K_BOOT_DIR" "$K_MODULES_DIR/7.2.9-joeyblog-bbrv3" "$TMP/adopt-default"
  cp "$TMP/grub.cfg" "$K_GRUB_CFG"
  printf '\nload_env\nset default="${saved_entry}"\nsave_env next_entry\n' >>"$K_GRUB_CFG"
  echo 'GRUB_DEFAULT=0' >"$K_GRUB_DEFAULT"; : >"$K_GRUB_ENV"
  K_OLD=5.15.0-old; K_TARGET=7.2.9-joeyblog-bbrv3
  K_META=byJoey/Actions-bbr-v3:standard; K_TAG=x86_64-7.2.9; K_META_VERSION=7.2.9-1
  K_COMMIT="$(printf '%040d' 4)"; K_YES=1; K_CONSOLE=1; K_METHOD=github-release
  for item in vmlinuz initrd.img config; do echo old >"$K_BOOT_DIR/$item-$K_OLD"; done
  printf image >"$K_BOOT_DIR/vmlinuz-$K_TARGET"; printf initramfs >"$K_BOOT_DIR/initrd.img-$K_TARGET"
  printf 'CONFIG_TCP_CONG_BBR=y\nCONFIG_NET_SCH_FQ=y\n' >"$K_SESSION/release.config"
  cp "$K_SESSION/release.config" "$K_BOOT_DIR/config-$K_TARGET"

  k_linux() { :; }; k_root() { :; }; k_detect_os() { :; }; k_require_environment() { :; }
  k_confirm_install() { :; }; k_lock() { :; }; k_init_session() { :; }; k_prepare_tools() { :; }
  k_prepare_release() { :; }; k_download_release_config() { :; }; k_secure_boot() { echo disabled; }
  k_download_packages() { fail 'matching target triggered large package downloads'; }
  apt-get() { fail 'matching target triggered package installation'; }
  apt-mark() { printf '%s\n' "$*" >>"$TMP/adopt-apt-mark.log"; }
  dpkg-query() {
    if [[ "$1" == -S ]]; then
      echo "linux-image-$K_OLD: $K_BOOT_DIR/vmlinuz-$K_OLD"
    elif [[ "$1" == -W ]]; then
      [[ "$2" == '-f=${Status}\t${Version}\n' ]] || fail 'invalid dpkg status field'
      printf 'install ok installed\t%s\n' "$K_META_VERSION"
    else
      fail "unexpected package query: $*"
    fi
  }
  modinfo() { echo 3; }
  update-grub() { echo updated >>"$TMP/adopt-grub-updates"; }
  grub-set-default() {
    grep -v '^saved_entry=' "$K_GRUB_ENV" >"$K_GRUB_ENV.new" || true
    printf 'saved_entry=%s\n' "$1" >>"$K_GRUB_ENV.new"; mv "$K_GRUB_ENV.new" "$K_GRUB_ENV"
  }
  grub-editenv() {
    case "$2" in
      list) cat "$1" ;;
      unset) grep -v "^$3=" "$1" >"$1.new" || true; mv "$1.new" "$1" ;;
      *) fail "unexpected grub command: $*" ;;
    esac
  }

  k_install >"$TMP/adopt-install.log" 2>&1
  eq "$K_STATUS" installed 'adopted target status'
  grep -Fq '不会覆盖或重复安装' "$TMP/adopt-install.log" || fail 'adoption not reported'
  grep -Fqx $'state	complete' "$K_SESSION/existing-target.tsv" || fail 'adopted target audit'
  grep -Fqx "saved_entry=$K_OLD_ENTRY" "$K_GRUB_ENV" || fail 'adoption did not retain old default'
  [[ -L "$K_LATEST" && "$K_LATEST" -ef "$K_SESSION" ]] || fail 'adopted session not recorded'
)

# Exercise artifact installation and full boot lifecycle with fake package,
# kernel and boot commands. No actual /boot, sysctl, package manager or GRUB writes.
(
  K_ROOT="$TMP/state"; K_LATEST="$K_ROOT/latest"; K_SESSION="$K_ROOT/session"
  K_BOOT_DIR="$TMP/boot"; K_MODULES_DIR="$TMP/modules"; K_GRUB_CFG="$K_BOOT_DIR/grub.cfg"
  K_GRUB_ENV="$K_BOOT_DIR/grubenv"; K_GRUB_DROP="$TMP/default/grub.d/kernel.cfg"; K_GRUB_DEFAULT="$TMP/default/grub"
  mkdir -p "$K_BOOT_DIR" "$K_MODULES_DIR" "$K_SESSION/packages" "$TMP/default"
  cp "$TMP/grub.cfg" "$K_GRUB_CFG"
  printf '\nload_env\nset default="${saved_entry}"\nsave_env next_entry\n' >>"$K_GRUB_CFG"
  echo 'GRUB_DEFAULT=0' >"$K_GRUB_DEFAULT"; : >"$K_GRUB_ENV"
  K_OLD=5.15.0-old; K_TARGET=7.2.9-joeyblog-bbrv3
  K_META=byJoey/Actions-bbr-v3:standard; K_TAG=x86_64-7.2.9; K_META_VERSION=7.2.9-1
  K_COMMIT="$(printf '%040d' 4)"; K_YES=1; K_CONSOLE=1; K_METHOD=github-release
  for item in vmlinuz initrd.img config; do echo old >"$K_BOOT_DIR/$item-$K_OLD"; done
  printf 'CONFIG_TCP_CONG_BBR=y\nCONFIG_NET_SCH_FQ=y\n' >"$K_SESSION/release.config"
  for name in "linux-image-$K_TARGET" "linux-headers-$K_TARGET"; do echo "$name" >"$K_SESSION/packages/$name.deb"; done
  k_linux() { :; }; k_root() { :; }; k_lock() { :; }; k_secure_boot() { echo disabled; }
  dpkg-deb() { case "$3" in Package) cat "$2" ;; Architecture) echo amd64 ;; Version) echo "$K_META_VERSION" ;; *) fail "unexpected deb query: $*" ;; esac; }
  sha256sum() { shasum -a 256 "$@"; }
  apt-mark() { printf '%s\n' "$*" >>"$TMP/apt-mark.log"; }
  target_packages_installed=0
  dpkg-query() {
    if [[ "$1" == -S ]]; then
      echo "linux-image-$K_OLD: $K_BOOT_DIR/vmlinuz-$K_OLD"
    elif [[ "$1" == -W ]]; then
      [[ "$2" == '-f=${Status}\t${Version}\n' ]] || fail 'invalid dpkg status field'
      (( target_packages_installed )) || return 1
      printf 'install ok installed\t%s\n' "$K_META_VERSION"
    else
      fail "unexpected package query: $*"
    fi
  }
  update-grub() { echo updated >>"$TMP/grub-updates"; }
  grub-set-default() {
    grep -v '^saved_entry=' "$K_GRUB_ENV" >"$K_GRUB_ENV.new" || true
    printf 'saved_entry=%s\n' "$1" >>"$K_GRUB_ENV.new"; mv "$K_GRUB_ENV.new" "$K_GRUB_ENV"
  }
  grub-reboot() {
    grep -v '^next_entry=' "$K_GRUB_ENV" >"$K_GRUB_ENV.new" || true
    printf 'next_entry=%s\n' "$1" >>"$K_GRUB_ENV.new"; mv "$K_GRUB_ENV.new" "$K_GRUB_ENV"
  }
  grub-editenv() {
    case "$2" in
      list) cat "$1" ;;
      unset) grep -v "^$3=" "$1" >"$1.new" || true; mv "$1.new" "$1" ;;
      *) fail "unexpected grub command: $*" ;;
    esac
  }
  apt-get() {
    [[ "$1" == install && " $* " == *' --no-remove '* ]] || fail 'unsafe apt operation'
    grep -Fqx "saved_entry=$K_OLD_ENTRY" "$K_GRUB_ENV" || fail 'old default not protected before install'
    echo "$*" >"$TMP/apt-install.log"
    mkdir -p "$K_MODULES_DIR/$K_TARGET"
    echo image >"$K_BOOT_DIR/vmlinuz-$K_TARGET"; echo initramfs >"$K_BOOT_DIR/initrd.img-$K_TARGET"
    cp "$K_SESSION/release.config" "$K_BOOT_DIR/config-$K_TARGET"
    target_packages_installed=1
  }
  modinfo() { echo 3; }
  k_install_artifacts >"$TMP/install.log" 2>&1
  eq "$K_STATUS" installed 'installation does not claim running kernel switch'
  [[ -s "$K_BOOT_DIR/vmlinuz-$K_OLD" ]] || fail 'old kernel removed'
  grep -Fq "manual linux-image-$K_OLD" "$TMP/apt-mark.log" || fail 'old image not protected from autoremove'
  [[ -s "$K_SESSION/packages.sha256" ]] || fail 'package checksums missing'
  if grep -q '^next_entry=' "$K_GRUB_ENV"; then fail 'install automatically scheduled a reboot target'; fi
  if (k_install_artifacts) >/dev/null 2>&1; then fail 'existing kernel overwritten'; fi
  running="$K_OLD"; runtime_bbr=1
  uname() { if [[ "${1:-}" == -r ]]; then echo "$running"; else echo Linux; fi; }
  k_running_bbr_version() { echo "$runtime_bbr"; }
  modprobe() { [[ "$*" == tcp_bbr ]] || fail 'unexpected module load'; }
  sysctl() { [[ "$*" == '-n net.ipv4.tcp_congestion_control' ]] || fail 'kernel verifier wrote TCP parameters'; echo cubic; }
  reboot() { fail 'automatic reboot is forbidden'; }
  K_ACTION=trial; k_continue >"$TMP/trial.log" 2>&1
  eq "$K_STATUS" trial 'trial phase'
  grep -Fqx "saved_entry=$K_OLD_ENTRY" "$K_GRUB_ENV" || fail 'trial changed permanent default'
  grep -Fqx "next_entry=$K_TARGET_ENTRY" "$K_GRUB_ENV" || fail 'one-time new kernel target missing'
  if (K_ACTION=accept; k_continue) >/dev/null 2>&1; then fail 'accepted while still on old kernel'; fi
  running="$K_TARGET"
  if (K_ACTION=accept; k_continue) >/dev/null 2>&1; then fail 'accepted based on kernel name without BBR3'; fi
  runtime_bbr=3; K_ACTION=verify; k_continue >"$TMP/verify.log" 2>&1
  eq "$(k_read_field status)" trial 'verify does not permanently accept'
  K_ACTION=accept; k_continue >"$TMP/accept.log" 2>&1
  eq "$(k_read_field status)" accepted 'accepted phase'
  grep -Fqx "saved_entry=$K_TARGET_ENTRY" "$K_GRUB_ENV" || fail 'confirmed kernel not default'
  K_ACTION=fallback; k_continue >"$TMP/fallback.log" 2>&1
  eq "$(k_read_field status)" fallback-planned 'fallback phase'
  grep -Fqx "saved_entry=$K_OLD_ENTRY" "$K_GRUB_ENV" || fail 'fallback default not old kernel'
  grep -Fqx "next_entry=$K_OLD_ENTRY" "$K_GRUB_ENV" || fail 'fallback next boot not old kernel'
  [[ "$running" == "$K_TARGET" ]] || fail 'fallback claimed immediate kernel switch'
)

bash "$ROOT/bbr-tune.sh" kernel help | grep -q 'Actions-bbr-v3' || fail 'main kernel subcommand'
if rg -qi 'k_build_source|bbr-kbuild|XanMod|xanmod' "$ROOT/bbr-kernel.sh" "$ROOT/README.md"; then fail 'removed compiler/vendor path still present'; fi
if declare -F k_build_source >/dev/null; then fail 'source build function still defined'; fi
forbidden='pro''mpt'
if grep -qi "$forbidden" "$ROOT/bbr-kernel.sh"; then fail 'prohibited development wording'; fi
printf 'All GitHub-release kernel, artifact and boot-lifecycle tests passed.\n'
