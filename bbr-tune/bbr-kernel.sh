#!/usr/bin/env bash
# Remote Linux kernel lifecycle; kept separate from TCP measurement and rollback.
set -Eeuo pipefail
KERNEL_HELPER_VERSION="2.10.4"
K_ROOT="/var/lib/bbr-tcp-tuning/kernels"
K_LATEST="${K_ROOT}/latest"
K_YES=0
K_CONSOLE=0
K_METHOD=github-release
K_ACTION=menu
K_SOURCE_REPO="byJoey/Actions-bbr-v3"
K_SOURCE_URL="https://github.com/${K_SOURCE_REPO}"
K_API_URL="https://api.github.com/repos/${K_SOURCE_REPO}"
K_GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
K_BOOT_DIR="/boot"
K_MODULES_DIR="/lib/modules"
K_GRUB_CFG="/boot/grub/grub.cfg"
K_GRUB_ENV="/boot/grub/grubenv"
K_GRUB_DEFAULT="/etc/default/grub"
K_GRUB_DROP="/etc/default/grub.d/99-bbr-tune-kernel.cfg"
K_SESSION=""
K_STATUS=""
K_OLD=""
K_TARGET=""
K_OLD_ENTRY=""
K_TARGET_ENTRY=""
K_META=""
K_META_VERSION=""
K_TAG=""
K_COMMIT=""
K_IMAGE_NAME=""
K_IMAGE_URL=""
K_IMAGE_DIGEST=""
K_IMAGE_SIZE=""
K_HEADERS_NAME=""
K_HEADERS_URL=""
K_HEADERS_DIGEST=""
K_HEADERS_SIZE=""
K_CONFIG_NAME=""
K_CONFIG_URL=""
K_CONFIG_DIGEST=""
K_CONFIG_SIZE=""
K_RELEASE_PUBLISHED=""
K_BOOT_GUARDED=0

k_log() { printf '[%s] [KERNEL] %s\n' "$(date '+%H:%M:%S')" "$*"; }
k_die() { k_log "失败：$*" >&2; exit 1; }
k_have() { command -v "$1" >/dev/null 2>&1; }
k_linux() { [[ "$(uname -s)" == Linux ]] || k_die '内核操作只能在远程 Linux 服务器运行'; }
k_root() { (( EUID == 0 )) || k_die '请使用 sudo 或 root'; }
k_fetch() {
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 2 --connect-timeout 15 --max-time 600 --user-agent 'bbr-tune-kernel' "$1" -o "$2"
}
k_fetch_api() {
  local url="$1" output="$2"
  local args=(-H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28')
  [[ -z "$K_GITHUB_TOKEN" ]] || args+=(-H "Authorization: Bearer ${K_GITHUB_TOKEN}")
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 2 --connect-timeout 15 --max-time 180 --user-agent 'bbr-tune-kernel' \
    "${args[@]}" "$url" -o "$output"
}
k_yes_no() {
  local answer
  [[ -t 0 ]] || return 1
  read -r -p "$1 [y/N]：" answer || return 1
  [[ "$answer" == y || "$answer" == Y ]]
}
k_usage() {
  cat <<'HELP'
BBRv3 内核管理（仅远程服务器）
  bbr-tune kernel plan                 检测环境并说明内核来源，不安装
  bbr-tune kernel install              安装 Actions-bbr-v3 最新标准版预编译内核
  bbr-tune kernel trial                设置下一次启动试用新内核，不重启
  bbr-tune kernel verify               验证运行内核与 BBRv3，不更改 TCP 参数
  bbr-tune kernel accept               验证后将新内核设为默认启动项
  bbr-tune kernel fallback             下次启动旧内核，不重启、不卸载内核
  bbr-tune kernel status               查看已记录的内核操作

安装选项：
  --console-available                  确认具备云控制台/救援访问与重启恢复能力
  --yes                               非交互确认（不能绕过兼容性/启动检查）

只使用 byJoey/Actions-bbr-v3 的标准版 GitHub Release；不提供本机源码编译，也不安装 Max 激进版。
支持自动安装：Debian 12/13、Ubuntu 24.04/26.04，amd64，GRUB2。
不执行上游安装脚本，不导入其 sysctl，不在容器内换内核，不关闭 Secure Boot，
不自动重启，不删除旧内核。TCP 参数回滚不能回滚内核。
HELP
}
k_parse() {
  if (( $# )); then K_ACTION="$1"; shift; fi
  case "$K_ACTION" in menu|plan|install|trial|verify|accept|fallback|status|help|--help) ;; *) k_die "未知内核操作：$K_ACTION" ;; esac
  while (( $# )); do
    case "$1" in
      --console-available) K_CONSOLE=1; shift ;;
      --yes) K_YES=1; shift ;;
      --help|-h) K_ACTION=help; shift ;;
      *) k_die "未知内核参数：$1" ;;
    esac
  done
}
k_detect_os() {
  local ID=unknown VERSION_CODENAME=unknown
  [[ ! -r /etc/os-release ]] || source /etc/os-release
  K_OS="$ID"; K_SUITE="$VERSION_CODENAME"
  K_ARCH="$(uname -m)"; K_OLD="$(uname -r)"
}
k_supported_os() {
  [[ "$K_ARCH" == x86_64 ]] || return 1
  case "$K_OS:$K_SUITE" in debian:bookworm|debian:trixie|ubuntu:noble|ubuntu:resolute) return 0 ;; *) return 1 ;; esac
}
k_running_bbr_version() {
  if [[ -r /sys/module/tcp_bbr/version ]]; then cat /sys/module/tcp_bbr/version
  else printf 'unknown\n'; fi
}
k_plan() {
  k_linux; k_detect_os
  printf '\nBBRv3 内核环境评估\n%s\n' '----------------------------------------'
  printf '系统             : %s / %s\n架构             : %s\n当前内核         : %s\n' "$K_OS" "$K_SUITE" "$K_ARCH" "$K_OLD"
  printf '运行时 BBR 版本  : %s（unknown 不表示 v1）\n' "$(k_running_bbr_version)"
  printf 'Secure Boot      : %s\n' "$(k_secure_boot)"
  if [[ -f "$K_GRUB_CFG" ]] && k_have update-grub; then
    printf '启动管理         : 检测到 GRUB2（安装前仍需验证具体布局）\n'
  else
    printf '启动管理         : 未确认受支持的 GRUB2 布局，不自动更换内核\n'
  fi
  if k_supported_os; then
    printf '候选来源         : %s 的最新 x86_64 标准版 Release\n' "$K_SOURCE_URL"
    printf '版本确定         : 安装时从 GitHub API 解析最高稳定三段版本，不固定旧版本号\n'
  else
    printf '自动安装         : 当前发行版/架构未纳入验证范围，仅提供检测\n'
  fi
  if [[ "$(k_running_bbr_version)" == 3 ]]; then
    printf '当前已确认 BBRv3：不必仅为启用 v3 而更换内核；仍需维护安全更新。\n'
  fi
  printf '%s\n' \
    '配置选择         : 仅标准 BBRv3；不安装修改内部增益的 Max 版' \
    '完整性校验       : GitHub Release API 大小/SHA-256 + deb 元数据 + 安装后模块版本' \
    '信任边界         : 第三方 GitHub 构建；摘要一致不等于发行版签名' \
    '操作边界         : 不执行上游脚本、不导入上游 sysctl、不提供源码编译' \
    '启动原则         : 保留原内核 / 一次性试启动 / 验证后接受 / 可安排回退' \
    '安全限制         : 需非容器、GRUB2、Secure Boot 关闭、无 DKMS 依赖' ''
}
k_secure_boot() {
  [[ -d /sys/firmware/efi ]] || { echo disabled; return; }
  if k_have mokutil; then
    local status
    status="$(LC_ALL=C mokutil --sb-state 2>/dev/null)" || { echo unknown; return; }
    case "$status" in *'SecureBoot disabled'*) echo disabled ;; *'SecureBoot enabled'*) echo enabled ;; *) echo unknown ;; esac
  elif k_have python3; then
    python3 - <<'PY_SB'
import glob
paths=glob.glob('/sys/firmware/efi/efivars/SecureBoot-*')
try:
    data=open(paths[0],'rb').read()
    print({0:'disabled',1:'enabled'}.get(data[4],'unknown'))
except (OSError,IndexError): print('unknown')
PY_SB
  else echo unknown
  fi
}
k_grub_entry() {
  python3 - "$1" "${2:-$K_GRUB_CFG}" <<'PY_GRUB'
import re, sys
release=sys.argv[1]
parent=''; found=[]
for line in open(sys.argv[2], encoding='utf-8'):
    # Distribution-generated stable IDs, not display titles or executable shell.
    if re.match(r'^\s*submenu\s',line):
        ids=re.findall(r'''["'](gnulinux-advanced-[^"']+)["']''',line)
        parent=ids[-1] if ids else ''
    if not re.match(r'^\s*menuentry\s',line): continue
    ids=re.findall(r'''["'](gnulinux-[^"']+)["']''',line)
    for item in ids:
        if item.startswith('gnulinux-'+release+'-advanced-'):
            found.append((parent+'>' if parent else '')+item)
if len(found)!=1: sys.exit('Cannot identify exactly one non-recovery GRUB entry for '+release)
print(found[0])
PY_GRUB
}
k_require_console() {
  (( K_CONSOLE )) || {
    k_yes_no '已确认云控制台/救援可用，能在新内核无法启动时手动重启或选择旧内核？' || k_die '必须先确认带外恢复能力；非交互使用 --console-available'
    K_CONSOLE=1
  }
}
k_confirm_install() {
  printf '\n将从 %s 下载第三方预编译标准 BBRv3 内核。\n' "$K_SOURCE_URL"
  printf '%s\n' \
    '不会运行上游安装脚本，不会导入上游 TCP 参数或 Max 激进算法修改。' \
    'GitHub 摘要只能验证下载内容与 Release 元数据一致，不能替代发行版签名或本机硬件兼容验证。' \
    '安装会触发 initramfs、GRUB 及软件包维护脚本；保留旧内核为默认，不自动重启。'
  k_require_console
  (( K_YES )) || k_yes_no '继续下载、校验并安装？' || k_die '已取消'
}
k_lock() {
  umask 077
  mkdir -p "$K_ROOT"
  command -v flock >/dev/null || k_die '缺少 flock（util-linux），不能安全串行化内核操作'
  exec 8>"${K_ROOT%/*}/operation.lock"
  flock -n 8 || k_die '已有 TCP 调优、内核或更新操作正在运行，请等待完成'
  exec 9>"${K_ROOT}/lock"
  flock -n 9 || k_die '另一个内核操作正在运行'
}
k_init_session() {
  umask 077
  K_SESSION="${K_ROOT}/$(date +%Y%m%d-%H%M%S)-$$"
  mkdir -p "$K_SESSION"
  exec > >(tee -a "${K_SESSION}/run.log" 8>&- 9>&-) 2>&1
  trap k_failed EXIT
  k_log "审计目录：$K_SESSION"
}
k_save_state() {
  python3 - "$K_SESSION" "$K_STATUS" "$K_OLD" "$K_TARGET" "$K_OLD_ENTRY" "$K_TARGET_ENTRY" "$K_METHOD" "$K_META" "$K_META_VERSION" "$K_TAG" "$K_COMMIT" <<'PY_STATE'
import json, os, sys
keys=['status','old_kernel','target_kernel','old_entry','target_entry','method','package','package_version','source_tag','source_commit']
path=sys.argv[1]+'/state.json'
with open(path+'.tmp','w') as f: json.dump(dict(zip(keys,sys.argv[2:])),f,ensure_ascii=False,indent=2)
os.replace(path+'.tmp',path)
PY_STATE
}
k_failed() {
  local rc=$?
  trap - EXIT
  if (( rc )); then
    k_log "操作未完成（退出码 ${rc}）；不会自动重启或删除任何内核"
    if (( K_BOOT_GUARDED )); then
      k_log "已设置旧内核为默认；请先检查 ${K_SESSION}/run.log，勿盲目重启"
    fi
  fi
  exit "$rc"
}
k_require_environment() {
  k_linux; k_root; k_detect_os
  k_supported_os || k_die '自动内核安装仅支持 Debian 12/13、Ubuntu 24.04/26.04 的 amd64 服务器'
  [[ ! -e /.dockerenv && ! -e /run/.containerenv && ! -d /proc/vz ]] || k_die '容器不能更换宿主机内核'
  if k_have systemd-detect-virt && systemd-detect-virt --container --quiet; then k_die '容器环境不允许安装内核'; fi
  [[ ! -f /var/lib/bbr-tcp-tuning/pending-latest/armed ]] || k_die '存在待确认的 TCP 调优，请先 confirm 或 rollback'
  if [[ -f "${K_LATEST}/state.json" ]]; then
    local phase
    k_have python3 || k_die '已有内核操作记录但缺少 python3，请先恢复解析依赖后处理原会话'
    phase="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "${K_LATEST}/state.json")"
    case "$phase" in accepted|fallback-planned) ;; *) k_die '上次内核安装尚未完成确认，请先 verify/accept 或 fallback' ;; esac
  fi
  for cmd in apt-get apt-mark dpkg dpkg-deb dpkg-query findmnt lsblk modinfo modprobe update-grub grub-editenv grub-set-default grub-reboot; do
    k_have "$cmd" || k_die "不支持的启动/软件包环境，缺少 ${cmd}"
  done
  [[ "$(dpkg --print-architecture)" == amd64 ]] || k_die '软件包架构不是 amd64'
  [[ -f "$K_GRUB_CFG" && -f "$K_GRUB_DEFAULT" && -r "${K_BOOT_DIR}/config-${K_OLD}" && -s "${K_BOOT_DIR}/vmlinuz-${K_OLD}" && -s "${K_BOOT_DIR}/initrd.img-${K_OLD}" ]] || k_die '缺少标准 GRUB、运行内核、配置或 initramfs；不能保证旧内核可启动'
  [[ ! -d /sys/firmware/efi || -d /sys/firmware/efi/efivars ]] || k_die '无法验证 UEFI Secure Boot 状态'
  local boot_fs boot_source boot_type
  boot_fs="$(findmnt -nro FSTYPE -T /boot/grub)"; boot_source="$(findmnt -nro SOURCE -T /boot/grub)"
  case "$boot_fs" in ext2|ext3|ext4) ;; *) k_die '当前 /boot 文件系统未验证 GRUB 一次性启动环境写回，停止自动安装' ;; esac
  boot_type="$(lsblk -ndro TYPE "$boot_source")"
  case "$boot_type" in part|disk) ;; *) k_die 'LVM/RAID/特殊 /boot 设备不能保证 GRUB 一次性启动恢复，需人工管理' ;; esac
  local root_fs
  root_fs="$(findmnt -nro FSTYPE -T /)"
  case "$root_fs" in ext2|ext3|ext4|xfs|btrfs) ;; *) k_die '当前根文件系统依赖未纳入通用内核验证（例如 ZFS/网络根），停止自动安装' ;; esac
  # Fail closed for out-of-tree drivers; boot-critical ZFS/DKMS cannot be inferred from iperf.
  if [[ -d /var/lib/dkms ]] && find /var/lib/dkms -mindepth 2 -maxdepth 2 -type d -print -quit | grep -q .; then
    k_die '检测到 DKMS 模块；需先人工验证驱动兼容性，本工具不自动替换该服务器内核'
  fi
  [[ -z "$(dpkg --audit)" ]] || k_die 'dpkg 存在未完成配置，请先修复软件包状态'
  local free_boot free_root
  free_boot="$(df -Pk /boot | awk 'END {print $4}')"; free_root="$(df -Pk / | awk 'END {print $4}')"
  (( free_boot >= 524288 && free_root >= 2097152 )) || k_die '需要 /boot 至少 512 MiB、根文件系统至少 2 GiB 空闲空间'
}
k_prepare_tools() {
  local cmd missing=0
  for cmd in curl python3 sha256sum cmp; do k_have "$cmd" || missing=1; done
  if (( missing )); then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install --no-remove -y ca-certificates curl python3 coreutils diffutils
  fi
}
k_select_release() {
  local input="$1" selected="$2" values
  values="$(python3 - "$input" "$selected" "$K_SOURCE_REPO" <<'PY_RELEASE'
import json, os, re, sys
source, selected, repo = sys.argv[1:]
try:
    data=json.load(open(source,encoding='utf-8'))
    if not isinstance(data,list): raise ValueError('GitHub API response is not a release list')
    releases=[]
    for release in data:
        if not isinstance(release,dict) or release.get('draft') or release.get('prerelease'): continue
        tag=release.get('tag_name','')
        match=re.fullmatch(r'x86_64-(\d+)\.(\d+)\.(\d+)',tag)
        if match: releases.append((tuple(map(int,match.groups())),release))
    if not releases: raise ValueError('no standard x86_64 release')
    releases.sort(key=lambda x:x[0])
    version_tuple,release=releases[-1]
    if sum(1 for x in releases if x[0]==version_tuple) != 1: raise ValueError('ambiguous highest standard release')
    tag=release['tag_name']; version='.'.join(map(str,version_tuple))
    assets=release.get('assets')
    if not isinstance(assets,list): raise ValueError('latest standard release has no asset list')
    expected_prefix=f'https://github.com/{repo}/releases/download/{tag}/'
    parsed=[]
    for asset in assets:
        if not isinstance(asset,dict): continue
        name=asset.get('name',''); url=asset.get('browser_download_url',''); digest=asset.get('digest',''); size=asset.get('size')
        if not re.fullmatch(r'[A-Za-z0-9._+~-]+',name): continue
        if url != expected_prefix+name: continue
        if not re.fullmatch(r'sha256:[0-9a-fA-F]{64}',digest): continue
        if isinstance(size,bool) or not isinstance(size,int) or size <= 0: continue
        parsed.append((name,url,digest.lower(),size))
    image=[x for x in parsed if re.fullmatch(rf'linux-image-{re.escape(version)}-joeyblog-bbrv3_{re.escape(version)}-[0-9]+_amd64\.deb',x[0])]
    headers=[x for x in parsed if re.fullmatch(rf'linux-headers-{re.escape(version)}-joeyblog-bbrv3_{re.escape(version)}-[0-9]+_amd64\.deb',x[0])]
    config=[x for x in parsed if x[0]==f'x86_64-{version}.config']
    if len(image)!=1 or len(headers)!=1 or len(config)!=1:
        raise ValueError('latest standard release lacks unique image, headers, config, trusted URL, digest, or size')
    if not 10*1024*1024 <= image[0][3] <= 512*1024*1024: raise ValueError('image size outside safety range')
    if not 1024*1024 <= headers[0][3] <= 128*1024*1024: raise ValueError('headers size outside safety range')
    if not 50*1024 <= config[0][3] <= 5*1024*1024: raise ValueError('config size outside safety range')
    target=f'{version}-joeyblog-bbrv3'
    image_pkg=image[0][0].split('_',1)[1].rsplit('_',1)[0]
    headers_pkg=headers[0][0].split('_',1)[1].rsplit('_',1)[0]
    if image_pkg != headers_pkg: raise ValueError('image and headers package versions differ')
    package_version=image_pkg
    with open(selected+'.tmp','w',encoding='utf-8') as f: json.dump(release,f,ensure_ascii=False,indent=2)
    os.replace(selected+'.tmp',selected)
    fields=[release['tag_name'],target,package_version,*image[0],*headers[0],*config[0],release.get('published_at','')]
    if any(('\t' in str(v) or '\n' in str(v)) for v in fields): raise ValueError('unsafe release metadata')
    print('\t'.join(map(str,fields)))
except (ValueError,KeyError,TypeError,OSError,json.JSONDecodeError) as exc:
    print(f'Release metadata rejected: {exc}',file=sys.stderr); sys.exit(1)
PY_RELEASE
)" || return 1
  IFS=$'\t' read -r K_TAG K_TARGET K_META_VERSION \
    K_IMAGE_NAME K_IMAGE_URL K_IMAGE_DIGEST K_IMAGE_SIZE \
    K_HEADERS_NAME K_HEADERS_URL K_HEADERS_DIGEST K_HEADERS_SIZE \
    K_CONFIG_NAME K_CONFIG_URL K_CONFIG_DIGEST K_CONFIG_SIZE K_RELEASE_PUBLISHED <<<"$values"
  K_META="${K_SOURCE_REPO}:standard"
}
k_check_maintained() {
  python3 - "$1" "$2" <<'PY_MAINTAINED'
import json, re, sys
match=re.fullmatch(r'x86_64-(\d+)\.(\d+)\.(\d+)',sys.argv[1])
if not match: sys.exit('Invalid standard release tag')
version=tuple(map(int,match.groups()))
for item in json.load(open(sys.argv[2]))['releases']:
    if item.get('moniker') not in ('stable','longterm') or item.get('iseol'): continue
    if not re.fullmatch(r'\d+\.\d+\.\d+',item['version']): continue
    current=tuple(map(int,item['version'].split('.')))
    if current[:2]==version[:2] and version>=current:
        print('维护检查：Release 不落后于 kernel.org 同系列稳定/LTS 修订（不含 RC 或 EOL 分支）')
        break
else: sys.exit('Release is EOL, unlisted, or behind current upstream security revision')
PY_MAINTAINED
}
k_resolve_tag_commit() {
  local object_type object_sha
  k_fetch_api "${K_API_URL}/git/ref/tags/${K_TAG}" "${K_SESSION}/tag-ref.json"
  read -r object_type object_sha < <(python3 - "${K_SESSION}/tag-ref.json" <<'PY_REF'
import json,re,sys
x=json.load(open(sys.argv[1])).get('object',{})
t=x.get('type',''); sha=x.get('sha','')
if t not in ('commit','tag') or not re.fullmatch(r'[0-9a-f]{40}',sha): sys.exit('Invalid GitHub tag ref')
print(t,sha)
PY_REF
)
  if [[ "$object_type" == tag ]]; then
    k_fetch_api "${K_API_URL}/git/tags/${object_sha}" "${K_SESSION}/annotated-tag.json"
    K_COMMIT="$(python3 - "${K_SESSION}/annotated-tag.json" <<'PY_TAG'
import json,re,sys
x=json.load(open(sys.argv[1])).get('object',{})
sha=x.get('sha','')
if x.get('type')!='commit' or not re.fullmatch(r'[0-9a-f]{40}',sha): sys.exit('Annotated tag does not resolve to a commit')
print(sha)
PY_TAG
)"
  else K_COMMIT="$object_sha"; fi
}
k_prepare_release() {
  mkdir -p "${K_SESSION}/packages"
  k_fetch_api "${K_API_URL}/releases?per_page=100" "${K_SESSION}/releases.json"
  k_select_release "${K_SESSION}/releases.json" "${K_SESSION}/selected-release.json" || k_die '无法从 GitHub Release 元数据确定唯一标准版内核'
  k_fetch https://www.kernel.org/releases.json "${K_SESSION}/kernel-releases.json"
  k_check_maintained "$K_TAG" "${K_SESSION}/kernel-releases.json"
  k_resolve_tag_commit
  k_log "候选：${K_TAG}；内核 release：${K_TARGET}；Release 提交：${K_COMMIT}"
}
k_verify_sha256() {
  local file="$1" digest="$2" expected actual
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  expected="${digest#sha256:}"
  actual="$(sha256sum "$file" | awk '{print tolower($1)}')"
  [[ "$actual" == "$expected" ]]
}
k_download_asset() {
  local name="$1" url="$2" digest="$3" expected_size="$4" output="$5" actual_size
  k_log "下载并校验：${name}"
  k_fetch "$url" "${output}.part"
  actual_size="$(wc -c <"${output}.part" | tr -d '[:space:]')"
  [[ "$actual_size" == "$expected_size" ]] || k_die "${name} 的文件大小与 GitHub Release API 不一致"
  k_verify_sha256 "${output}.part" "$digest" || k_die "${name} 的 SHA-256 与 GitHub Release API 不一致"
  mv -f "${output}.part" "$output"
}
k_write_release_assets() {
  printf 'type\tname\tsize\tdigest\turl\nimage\t%s\t%s\t%s\t%s\nheaders\t%s\t%s\t%s\t%s\nconfig\t%s\t%s\t%s\t%s\n' \
    "$K_IMAGE_NAME" "$K_IMAGE_SIZE" "$K_IMAGE_DIGEST" "$K_IMAGE_URL" \
    "$K_HEADERS_NAME" "$K_HEADERS_SIZE" "$K_HEADERS_DIGEST" "$K_HEADERS_URL" \
    "$K_CONFIG_NAME" "$K_CONFIG_SIZE" "$K_CONFIG_DIGEST" "$K_CONFIG_URL" >"${K_SESSION}/release-assets.tsv"
}
k_download_release_config() {
  k_write_release_assets
  k_download_asset "$K_CONFIG_NAME" "$K_CONFIG_URL" "$K_CONFIG_DIGEST" "$K_CONFIG_SIZE" "${K_SESSION}/release.config"
  for required in CONFIG_TCP_CONG_BBR=y CONFIG_NET_SCH_FQ=y; do
    grep -Fxq "$required" "${K_SESSION}/release.config" || k_die "发布配置缺少 ${required}"
  done
}
k_package_status() {
  local rc
  if LC_ALL=C dpkg-query -W -f='${Status}\t${Version}\n' "$1" 2>/dev/null; then return 0; else rc=$?; fi
  # Exit 1 means no matching package; other failures must not mean “absent”.
  (( rc == 1 )) || printf 'query-error-%s\n' "$rc"
}
k_existing_target_state() {
  local image_package="linux-image-${K_TARGET}" headers_package="linux-headers-${K_TARGET}"
  local image_status headers_status image_version="" headers_version="" module_version="" state=conflict
  local image_state headers_state
  image_status="$(k_package_status "$image_package")"
  headers_status="$(k_package_status "$headers_package")"
  [[ "$image_status" == $'install ok installed\t'* || "$image_status" == $'hold ok installed\t'* ]] && image_version="${image_status#*$'\t'}"
  [[ "$headers_status" == $'install ok installed\t'* || "$headers_status" == $'hold ok installed\t'* ]] && headers_version="${headers_status#*$'\t'}"
  [[ ! -d "${K_MODULES_DIR}/${K_TARGET}" ]] || module_version="$(modinfo -k "$K_TARGET" -F version tcp_bbr 2>/dev/null || true)"

  if [[ "$K_TARGET" == "$K_OLD" ]]; then
    state=running
  elif [[ "$image_version" == "$K_META_VERSION" && "$headers_version" == "$K_META_VERSION" \
      && -s "${K_BOOT_DIR}/vmlinuz-${K_TARGET}" && -s "${K_BOOT_DIR}/initrd.img-${K_TARGET}" \
      && -d "${K_MODULES_DIR}/${K_TARGET}" && -r "${K_BOOT_DIR}/config-${K_TARGET}" \
      && "$module_version" == 3 ]] \
      && cmp -s "${K_SESSION}/release.config" "${K_BOOT_DIR}/config-${K_TARGET}"; then
    state=complete
  elif [[ -z "$image_status" && -z "$headers_status" \
      && ! -e "${K_BOOT_DIR}/vmlinuz-${K_TARGET}" && ! -L "${K_BOOT_DIR}/vmlinuz-${K_TARGET}" \
      && ! -e "${K_BOOT_DIR}/initrd.img-${K_TARGET}" && ! -L "${K_BOOT_DIR}/initrd.img-${K_TARGET}" \
      && ! -e "${K_BOOT_DIR}/config-${K_TARGET}" && ! -L "${K_BOOT_DIR}/config-${K_TARGET}" \
      && ! -e "${K_MODULES_DIR}/${K_TARGET}" && ! -L "${K_MODULES_DIR}/${K_TARGET}" ]]; then
    state=absent
  fi

  image_state="${image_status%%$'\t'*}"; headers_state="${headers_status%%$'\t'*}"
  [[ -n "$image_state" ]] || image_state='<未安装>'
  [[ -n "$headers_state" ]] || headers_state='<未安装>'
  {
    printf 'field\tvalue\nstate\t%s\n' "$state"
    printf 'running_kernel\t%s\ntarget_kernel\t%s\n' "$K_OLD" "$K_TARGET"
    printf 'image_package_status\t%s\nimage_package_version\t%s\n' \
      "$image_state" "${image_version:-<未安装>}"
    printf 'headers_package_status\t%s\nheaders_package_version\t%s\n' \
      "$headers_state" "${headers_version:-<未安装>}"
    printf 'expected_package_version\t%s\nmodule_version\t%s\n' "$K_META_VERSION" "${module_version:-<未取得>}"
    printf 'vmlinuz\t%s\ninitramfs\t%s\nmodules\t%s\nconfig\t%s\n' \
      "$([[ -s "${K_BOOT_DIR}/vmlinuz-${K_TARGET}" ]] && echo present || echo missing)" \
      "$([[ -s "${K_BOOT_DIR}/initrd.img-${K_TARGET}" ]] && echo present || echo missing)" \
      "$([[ -d "${K_MODULES_DIR}/${K_TARGET}" ]] && echo present || echo missing)" \
      "$([[ -r "${K_BOOT_DIR}/config-${K_TARGET}" ]] && echo present || echo missing)"
    if [[ -r "${K_BOOT_DIR}/config-${K_TARGET}" ]]; then
      if cmp -s "${K_SESSION}/release.config" "${K_BOOT_DIR}/config-${K_TARGET}"; then printf 'config_match\tyes\n'; else printf 'config_match\tno\n'; fi
    else printf 'config_match\tunknown\n'; fi
  } >"${K_SESSION}/existing-target.tsv"
  printf '%s\n' "$state"
}
k_download_packages() {
  local image_pkg headers_pkg image_ver headers_ver
  k_download_asset "$K_IMAGE_NAME" "$K_IMAGE_URL" "$K_IMAGE_DIGEST" "$K_IMAGE_SIZE" "${K_SESSION}/packages/${K_IMAGE_NAME}"
  k_download_asset "$K_HEADERS_NAME" "$K_HEADERS_URL" "$K_HEADERS_DIGEST" "$K_HEADERS_SIZE" "${K_SESSION}/packages/${K_HEADERS_NAME}"
  image_pkg="$(dpkg-deb -f "${K_SESSION}/packages/${K_IMAGE_NAME}" Package)"
  headers_pkg="$(dpkg-deb -f "${K_SESSION}/packages/${K_HEADERS_NAME}" Package)"
  image_ver="$(dpkg-deb -f "${K_SESSION}/packages/${K_IMAGE_NAME}" Version)"
  headers_ver="$(dpkg-deb -f "${K_SESSION}/packages/${K_HEADERS_NAME}" Version)"
  [[ "$image_pkg" == "linux-image-${K_TARGET}" && "$headers_pkg" == "linux-headers-${K_TARGET}" ]] || k_die 'deb 包名与 Release 标签不匹配'
  [[ "$image_ver" == "$K_META_VERSION" && "$headers_ver" == "$K_META_VERSION" ]] || k_die 'image 与 headers 软件包版本不一致'
}
k_guard_old_boot() {
  [[ ! -f /var/lib/bbr-tcp-tuning/pending-latest/armed ]] || k_die '下载期间出现待确认 TCP 调优，先处理后再安装内核'
  [[ "$(k_secure_boot)" == disabled ]] || k_die 'Secure Boot 已启用或状态未知；不自动关闭、不自动注册签名密钥'
  K_OLD_ENTRY="$(k_grub_entry "$K_OLD")" || k_die '无法确定运行内核的稳定启动项 ID'
  grub-editenv "$K_GRUB_ENV" list >"${K_SESSION}/grubenv.before"
  if grep -q '^next_entry=.' "${K_SESSION}/grubenv.before"; then k_die '已有一次性启动项，需先处理，不能覆盖'; fi
  cp -a "$K_GRUB_DEFAULT" "${K_SESSION}/grub.before"
  if [[ -f "$K_GRUB_DROP" ]]; then cp -a "$K_GRUB_DROP" "${K_SESSION}/grub-drop.before"; fi
  mkdir -p "$(dirname "$K_GRUB_DROP")"
  # Save the old ID before generating any new GRUB config or installing an image.
  grub-set-default "$K_OLD_ENTRY"
  printf '# Managed by bbr-tune kernel; retain the verified default\nGRUB_DEFAULT=saved\nGRUB_SAVEDEFAULT=false\n' >"${K_GRUB_DROP}.tmp"
  chmod 0644 "${K_GRUB_DROP}.tmp"; mv "${K_GRUB_DROP}.tmp" "$K_GRUB_DROP"
  update-grub
  grep -Fq 'set default="${saved_entry}"' "$K_GRUB_CFG" && grep -Fq 'save_env next_entry' "$K_GRUB_CFG" || k_die 'GRUB 未生成 saved 默认项及可清除的一次性启动逻辑'
  local old_package
  old_package="$(dpkg-query -S "${K_BOOT_DIR}/vmlinuz-${K_OLD}" | sed -n 's/: .*vmlinuz-.*$//p')"
  [[ "$old_package" =~ ^linux-image[-a-zA-Z0-9.+~]+$ ]] || k_die '无法确认旧内核的软件包归属'
  apt-mark manual "$old_package"
  grub-editenv "$K_GRUB_ENV" list | grep -Fxq "saved_entry=${K_OLD_ENTRY}" || k_die '旧内核默认项未能读回验证'
  K_BOOT_GUARDED=1; K_STATUS=prepared
  k_save_state
  ln -sfn "$K_SESSION" "$K_LATEST"
  k_log "旧内核保持默认：${K_OLD}；不会删除或自动重启"
}
k_validate_installed_target() {
  [[ -s "${K_BOOT_DIR}/vmlinuz-${K_TARGET}" && -s "${K_BOOT_DIR}/initrd.img-${K_TARGET}" && -d "${K_MODULES_DIR}/${K_TARGET}" ]] || k_die '目标内核、initramfs 或 modules 不完整，不安排启动'
  cmp -s "${K_SESSION}/release.config" "${K_BOOT_DIR}/config-${K_TARGET}" || k_die '已安装内核配置与已校验的 Release 配置不一致'
  grep -Eq '^CONFIG_TCP_CONG_BBR=[ym]$' "${K_BOOT_DIR}/config-${K_TARGET}" || k_die '已安装内核不包含 BBR'
  local version
  version="$(modinfo -k "$K_TARGET" -F version tcp_bbr 2>/dev/null || true)"
  [[ "$version" == 3 ]] || k_die '已安装内核不能通过模块元数据确认为 BBRv3；保留旧默认项，不安排试用'
}
k_finalize_installed_target() {
  k_validate_installed_target
  update-grub
  K_TARGET_ENTRY="$(k_grub_entry "$K_TARGET")" || k_die '新内核缺少可识别启动项'
  [[ "$(k_grub_entry "$K_OLD")" == "$K_OLD_ENTRY" ]] || k_die '旧内核启动项发生变化，停止'
  grub-editenv "$K_GRUB_ENV" list | grep -Fxq "saved_entry=${K_OLD_ENTRY}" || k_die '默认启动项不再是旧内核，请检查 GRUB'
  K_STATUS=installed; k_save_state
  k_log "目标内核已纳入安全试用流程：${K_TARGET}；当前仍运行 ${K_OLD}"
  k_log '下一步：sudo bbr-tune kernel trial；阅读恢复说明后自行安排重启'
  k_log '重启后：sudo bbr-tune kernel verify；验证业务后 sudo bbr-tune kernel accept'
  k_log '未添加软件源、未运行上游脚本；后续安全更新需重新执行 install 并经过试启动/验证'
}
k_adopt_existing_target() {
  [[ "$(k_existing_target_state)" == complete ]] || k_die "接管前目标状态发生变化，未修改启动项；详情：${K_SESSION}/existing-target.tsv"
  k_log "检测到完全匹配的目标内核已安装：${K_TARGET}；不会覆盖或重复安装"
  k_guard_old_boot
  k_finalize_installed_target
}
k_install_artifacts() {
  local deb name arch images=0 headers=0 preinstall_state
  local debs=()
  [[ "$K_TARGET" != "$K_OLD" ]] || k_die '目标内核正是当前运行内核，不能从当前状态建立旧内核回退基线'
  preinstall_state="$(k_existing_target_state)"
  [[ "$preinstall_state" == absent ]] || k_die "安装前目标状态已变为 ${preinstall_state}；拒绝覆盖或重复安装。详情：${K_SESSION}/existing-target.tsv"
  for deb in "${K_SESSION}/packages/"*.deb; do
    [[ -f "$deb" ]] || continue
    name="$(dpkg-deb -f "$deb" Package)"; arch="$(dpkg-deb -f "$deb" Architecture)"
    [[ "$arch" == amd64 ]] || k_die "包架构错误：${name} ${arch}"
    case "$name" in
      "linux-image-${K_TARGET}") images=$((images+1)) ;;
      "linux-headers-${K_TARGET}") headers=$((headers+1)) ;;
      *) k_die "不安装未经选择的软件包：$name" ;;
    esac
    debs+=("$deb")
  done
  (( images == 1 && headers == 1 )) || k_die '必须恰有一个内核 image 和一个 headers 包'
  sha256sum "${debs[@]}" >"${K_SESSION}/packages.sha256"
  k_guard_old_boot
  DEBIAN_FRONTEND=noninteractive apt-get install --no-remove -y "${debs[@]}"
  k_finalize_installed_target
}
k_install() {
  local target_state
  k_linux; k_root; k_lock; k_detect_os
  k_require_environment
  k_confirm_install
  k_init_session
  k_prepare_tools
  [[ "$(k_secure_boot)" == disabled ]] || k_die 'Secure Boot 已启用或未知，停止自动安装'
  k_grub_entry "$K_OLD" >/dev/null || k_die '原内核启动项不明确，拒绝开始内核下载'
  k_prepare_release
  k_download_release_config
  target_state="$(k_existing_target_state)"
  case "$target_state" in
    absent)
      k_download_packages
      k_install_artifacts ;;
    complete)
      k_adopt_existing_target ;;
    running)
      k_die "目标 ${K_TARGET} 已是当前运行内核；无需重复安装。若它不是由本工具试用，不能从当前状态自动建立旧内核回退基线" ;;
    conflict)
      k_die "检测到同名目标内核残缺、版本不符或配置不一致；拒绝覆盖。详情：${K_SESSION}/existing-target.tsv" ;;
    *) k_die "无法识别目标内核状态：${target_state}" ;;
  esac
  trap - EXIT
}
k_read_field() {
  python3 - "$K_SESSION/state.json" "$1" <<'PY_FIELD'
import json,sys
v=json.load(open(sys.argv[1]))[sys.argv[2]]
if not isinstance(v,str) or '\n' in v or '\t' in v: sys.exit('Invalid kernel state')
print(v)
PY_FIELD
}
k_load_last() {
  [[ -f "${K_LATEST}/state.json" ]] || k_die '没有可继续的内核操作记录'
  K_SESSION="$(cd "$K_LATEST" && pwd -P)"
  K_STATUS="$(k_read_field status)"; K_OLD="$(k_read_field old_kernel)"; K_TARGET="$(k_read_field target_kernel)"
  K_OLD_ENTRY="$(k_read_field old_entry)"; K_TARGET_ENTRY="$(k_read_field target_entry)"
  K_METHOD="$(k_read_field method)"; K_META="$(k_read_field package)"; K_META_VERSION="$(k_read_field package_version)"
  K_TAG="$(k_read_field source_tag)"; K_COMMIT="$(k_read_field source_commit)"
}
k_verify() {
  [[ "$(uname -r)" == "$K_TARGET" ]] || k_die "当前运行 $(uname -r)，不是目标 ${K_TARGET}；尚未完成内核切换"
  modprobe tcp_bbr
  [[ "$(k_running_bbr_version)" == 3 ]] || k_die '运行时 BBR 版本不能确认为 3；不以算法名称 bbr 或内核包后缀代替证明'
  printf '\n运行内核     : %s\n运行时 BBR   : 3\n拥塞控制默认 : %s\n' "$K_TARGET" "$(sysctl -n net.ipv4.tcp_congestion_control)"
  printf '验证通过；只验证内核能力，未修改 TCP 参数。请检查代理业务后再 accept。\n'
}
k_continue() {
  k_linux; k_root; k_lock; k_load_last
  exec > >(tee -a "${K_SESSION}/run.log" 8>&- 9>&-) 2>&1
  case "$K_ACTION" in
    verify) k_verify ;;
    trial)
      [[ "$K_STATUS" == installed || "$K_STATUS" == trial ]] || k_die "当前阶段 ${K_STATUS} 不能安排试用"
      [[ "$(uname -r)" == "$K_OLD" ]] || k_die '已不在原内核，先 verify，不重复安排试用'
      k_require_console
      local next
      next="$(grub-editenv "$K_GRUB_ENV" list | sed -n 's/^next_entry=//p')"
      [[ -z "$next" || "$next" == "$K_TARGET_ENTRY" ]] || k_die '存在其他一次性启动请求，不能覆盖'
      grep -Fq 'set default="${saved_entry}"' "$K_GRUB_CFG" || k_die 'GRUB 不再使用 saved 默认项，不能安全安排试用'
      [[ "$(k_grub_entry "$K_OLD")" == "$K_OLD_ENTRY" && "$(k_grub_entry "$K_TARGET")" == "$K_TARGET_ENTRY" ]] || k_die '启动项变化，不能安全试用'
      grub-set-default "$K_OLD_ENTRY"
      grub-reboot "$K_TARGET_ENTRY"
      grub-editenv "$K_GRUB_ENV" list | grep -Fxq "next_entry=${K_TARGET_ENTRY}" || k_die '一次性启动项未能读回'
      K_STATUS=trial; k_save_state
      k_log '仅下一次启动试用新内核；请自行安排重启，本工具没有执行 reboot'
      k_log '若新内核无法启动，需使用控制台手动重启/选择旧内核；不保证无人值守自动恢复' ;;
    accept)
      [[ "$K_STATUS" == installed || "$K_STATUS" == trial || "$K_STATUS" == accepted ]] || k_die '当前阶段不能确认新内核'
      k_verify
      (( K_YES )) || k_yes_no '代理业务、网卡、存储与 SSH 已验证，确认新内核为默认？' || k_die '未确认'
      K_TARGET_ENTRY="$(k_grub_entry "$K_TARGET")"
      grub-set-default "$K_TARGET_ENTRY"; grub-editenv "$K_GRUB_ENV" unset next_entry
      grub-editenv "$K_GRUB_ENV" list | grep -Fxq "saved_entry=${K_TARGET_ENTRY}" || k_die '默认项读回失败'
      K_STATUS=accepted; k_save_state
      k_log '已确认默认内核；现在可以运行 sudo bbr-tune，对 BBRv3 重新做单/多连接实测' ;;
    fallback)
      [[ -s "${K_BOOT_DIR}/vmlinuz-${K_OLD}" && -s "${K_BOOT_DIR}/initrd.img-${K_OLD}" ]] || k_die '旧内核文件缺失，需使用云救援环境'
      K_OLD_ENTRY="$(k_grub_entry "$K_OLD")"
      (( K_YES )) || k_yes_no "将下次启动和默认项恢复为 ${K_OLD}？不会立即重启" || k_die '已取消'
      grub-set-default "$K_OLD_ENTRY"; grub-reboot "$K_OLD_ENTRY"
      grub-editenv "$K_GRUB_ENV" list | grep -Fxq "saved_entry=${K_OLD_ENTRY}" || k_die '旧默认项读回失败'
      K_STATUS=fallback-planned; k_save_state
      k_log "下次启动旧内核 ${K_OLD}；当前内核不变，请自行安排重启" ;;
  esac
}
k_status() {
  k_linux
  printf '当前运行内核：%s\n运行时 BBR 版本：%s\n' "$(uname -r)" "$(k_running_bbr_version)"
  if [[ -r "${K_LATEST}/state.json" ]]; then
    k_load_last
    printf '操作阶段：%s\n原内核：%s\n目标内核：%s\n来源：%s\nRelease：%s\n提交：%s\n日志目录：%s\n' "$K_STATUS" "$K_OLD" "$K_TARGET" "$K_META" "$K_TAG" "$K_COMMIT" "$K_SESSION"
  else printf '尚无内核操作记录，或当前用户无权读取。\n'; fi
}
k_menu() {
  local choice
  [[ -t 0 ]] || { k_usage; return; }
  cat <<'MENU'

BBRv3 内核管理
----------------------------------------------------------------
  环境与安装
  1) 检测环境与来源说明
  2) 安装 Actions-bbr-v3 最新标准版内核

  启动与验证
  3) 下一次启动试用新内核
  4) 重启后验证 BBRv3
  5) 确认新内核为默认
  6) 下次恢复旧内核

  7) 查看操作状态
  0) 返回

  仅标准版 · 保留旧内核 · 不自动重启
MENU
  read -r -p '请选择：' choice || return
  case "$choice" in 1) K_ACTION=plan ;; 2) K_ACTION=install ;; 3) K_ACTION=trial ;; 4) K_ACTION=verify ;; 5) K_ACTION=accept ;; 6) K_ACTION=fallback ;; 7) K_ACTION=status ;; 0) return ;; *) k_die '无效选择' ;; esac
  k_dispatch
}
k_dispatch() {
  case "$K_ACTION" in
    menu) k_menu ;; plan) k_plan ;; install) k_install ;;
    trial|verify|accept|fallback) k_continue ;; status) k_status ;; help|--help) k_usage ;;
  esac
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then k_parse "$@"; k_dispatch; fi
