#!/usr/bin/env bash
# 在 Linux 上创建 /swapfile，兼容 Btrfs 的 NOCOW 和预分配要求。
set -Eeuo pipefail
umask 077

VERSION=0.1.3
SWAP_FILE=/swapfile
FSTAB=/etc/fstab
INSTALL_PATH=/usr/local/bin/swaptool
BACKUP_PREFIX=/swapfile.swaptool.bak.
TEMP_SWAP=
OLD_BACKUP=
NEW_AT_TARGET=0
ACTIVATED=0
OLD_DISABLED=0

log() { printf '[swaptool] %s\n' "$*"; }
die() { printf '[swaptool] 错误: %s\n' "$*" >&2; exit 1; }

usage() {
    printf 'swaptool v%s\n\n' "$VERSION"
    cat <<'EOF'
用法：
  sudo bash swap_tool.sh install        安装 swaptool 并打开交互菜单
  swaptool                             打开交互菜单，自选或输入 swap 大小
  sudo bash swap_tool.sh setup [大小]   创建或修复 /swapfile；默认沿用旧文件大小，无旧文件时为 2G
  sudo swaptool cleanup                清理以前版本留下的旧 swap 文件
  swaptool status                       查看实际启用状态
  swaptool --version                    查看工具版本

安装时也可指定大小以跳过菜单，例如 install 1536M。交互菜单支持直接输入 MiB 数字。
EOF
}

active_swap_path() {
    awk -v path="$1" 'NR > 1 && $1 == path { found = 1 } END { exit !found }' /proc/swaps
}

active_swapfile() {
    active_swap_path "$SWAP_FILE"
}

cleanup_swap_backups() {
    local path suffix count=0
    active_swapfile || die '当前 /swapfile 未启用，暂不清理旧文件。'
    for path in "${BACKUP_PREFIX}"*; do
        [[ -f $path && ! -L $path ]] || continue
        suffix=${path#"$BACKUP_PREFIX"}
        [[ $suffix =~ ^[0-9]{14}\.[0-9]+$ ]] || continue
        if [[ $(blkid -p -o value -s TYPE "$path" 2>/dev/null || :) != swap ]]; then
            log "跳过没有 swap 签名的文件: $path"
            continue
        fi
        if active_swap_path "$path"; then
            log "跳过正在使用的旧文件: $path"
            continue
        fi
        rm -- "$path" || die "无法删除旧文件: $path"
        log "已删除旧文件: $path"
        (( count += 1 ))
    done
    if (( count == 0 )); then log '没有需要清理的旧 swap 文件。'; fi
}

parse_size() {
    local value=$1 number unit bytes
    [[ $value =~ ^([1-9][0-9]*)([MmGg])$ ]] || die '大小格式应为正整数加 M 或 G，例如 512M、2G。'
    number=${BASH_REMATCH[1]}
    unit=${BASH_REMATCH[2]}
    if [[ $unit == M || $unit == m ]]; then
        (( ${#number} <= 7 )) || die '大小不能超过 1024G。'
        (( 10#$number <= 1048576 )) || die '大小不能超过 1024G。'
        bytes=$((10#$number * 1024 * 1024))
    else
        (( ${#number} <= 4 )) || die '大小不能超过 1024G。'
        (( 10#$number <= 1024 )) || die '大小不能超过 1024G。'
        bytes=$((10#$number * 1024 * 1024 * 1024))
    fi
    (( bytes >= 64 * 1024 * 1024 )) || die 'swapfile 至少需要 64M。'
    printf '%s\n' "$bytes"
}

fstab_has_swapfile() {
    awk -v path="$SWAP_FILE" '$1 == path && $3 == "swap" { found = 1 } END { exit !found }' "$FSTAB"
}

fstab_is_canonical() {
    awk -v path="$SWAP_FILE" '
        $1 == path {
            count++
            if ($2 == "none" && $3 == "swap" && $4 == "sw" && $5 == 0 && $6 == 0 && NF == 6) valid++
        }
        END { exit !(count == 1 && valid == 1) }
    ' "$FSTAB"
}

ensure_fstab() {
    local temp backup
    # 删除旧的 /swapfile 行（包括重复或错误的行），保留其他交换设备。
    temp=$(mktemp /etc/.fstab.swaptool.XXXXXX) || die '无法创建 fstab 临时文件。'
    if ! awk -v path="$SWAP_FILE" '$1 == path { next } { print } END { print "/swapfile none swap sw 0 0" }' "$FSTAB" > "$temp"; then
        rm -f -- "$temp"
        die '无法生成新的 fstab。'
    fi
    chmod --reference="$FSTAB" "$temp" || { rm -f -- "$temp"; die '无法设置 fstab 权限。'; }
    chown --reference="$FSTAB" "$temp" || { rm -f -- "$temp"; die '无法设置 fstab 所有者。'; }
    backup="${FSTAB}.swaptool.bak.$(date +%Y%m%d%H%M%S).$$"
    cp -p -- "$FSTAB" "$backup" || { rm -f -- "$temp"; die '无法备份 fstab。'; }
    mv -f -- "$temp" "$FSTAB" || die "无法更新 fstab；备份位置: $backup"
    log "已写入 fstab；原文件备份: $backup"
}

on_exit() {
    local code=$1
    trap - EXIT
    set +e
    if (( code != 0 && ACTIVATED == 0 )); then
        if (( NEW_AT_TARGET == 1 )) && active_swapfile; then
            printf '[swaptool] 错误: 新文件意外处于启用状态，保留 /swapfile 以免中断交换空间。\n' >&2
        else
            if (( NEW_AT_TARGET == 1 )); then rm -f -- "$SWAP_FILE"; fi
            if [[ -n $OLD_BACKUP ]]; then
                mv -- "$OLD_BACKUP" "$SWAP_FILE" || printf '[swaptool] 错误: 无法自动恢复旧文件：%s\n' "$OLD_BACKUP" >&2
            fi
            if (( OLD_DISABLED == 1 )) && [[ -f $SWAP_FILE ]] && ! active_swapfile; then
                swapon "$SWAP_FILE" || printf '[swaptool] 错误: 无法重新启用旧 /swapfile，请检查备份和系统状态。\n' >&2
            fi
        fi
    elif (( code != 0 && ACTIVATED == 1 )); then
        printf '[swaptool] /swapfile 已启用，但后续步骤失败；请重新运行 setup 检查开机配置。\n' >&2
    fi
    [[ -z $TEMP_SWAP ]] || rm -f -- "$TEMP_SWAP"
    exit "$code"
}
trap 'on_exit $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

create_swapfile() {
    local fs_type=$1 size=$2
    if [[ $fs_type == btrfs ]]; then
        # 新版 btrfs-progs 会同时处理 NOCOW、预分配和 Btrfs 特有约束。
        if command -v btrfs >/dev/null 2>&1 && btrfs filesystem mkswapfile --size "$size" "$TEMP_SWAP"; then
            :
        else
            # 兼容旧版 btrfs-progs：+C 必须在写入任何数据之前设置。
            command -v chattr >/dev/null 2>&1 || die '旧版 Btrfs 工具需要 chattr（通常由 e2fsprogs 提供）。'
            rm -f -- "$TEMP_SWAP"
            : > "$TEMP_SWAP"
            chattr +C "$TEMP_SWAP" || die '无法为 Btrfs 交换文件设置 NOCOW（chattr +C）。'
            fallocate -l "$size" "$TEMP_SWAP" || die '无法预分配 Btrfs 交换文件。'
        fi
    else
        fallocate -l "$size" "$TEMP_SWAP" || die '无法预分配交换文件。'
    fi
    chmod 600 "$TEMP_SWAP"
    mkswap "$TEMP_SWAP" >/dev/null || die 'mkswap 失败。'
}

setup() {
    local fs_type size old_size old_used_kib backup_path requested=${1:-}
    TEMP_SWAP=
    OLD_BACKUP=
    NEW_AT_TARGET=0
    ACTIVATED=0
    OLD_DISABLED=0
    [[ $(uname -s) == Linux ]] || die '此脚本只能在 Linux 上运行。'
    (( EUID == 0 )) || die 'setup 必须以 root 身份运行。'
    for cmd in awk blkid fallocate findmnt mkswap stat swapon swapoff mktemp; do
        command -v "$cmd" >/dev/null 2>&1 || die "缺少命令: $cmd"
    done
    [[ -f $FSTAB && ! -L $FSTAB ]] || die '找不到普通文件 /etc/fstab。'
    [[ ! -L $SWAP_FILE ]] || die '/swapfile 是符号链接，拒绝覆盖。'
    [[ ! -e $SWAP_FILE || -f $SWAP_FILE ]] || die '/swapfile 不是普通文件，拒绝覆盖。'

    if active_swapfile; then
        old_size=$(stat -c %s "$SWAP_FILE")
        if [[ -z $requested ]]; then
            if ! fstab_is_canonical; then ensure_fstab; fi
            log '/swapfile 已在运行，保留当前交换空间。'
            status
            cleanup_swap_backups
            return
        fi
        size=$(parse_size "$requested")
        if (( size == old_size )); then
            if ! fstab_is_canonical; then ensure_fstab; fi
            log '/swapfile 已是指定大小，保留当前交换空间。'
            status
            cleanup_swap_backups
            return
        fi
        old_used_kib=$(awk -v path="$SWAP_FILE" 'NR > 1 && $1 == path { print $4 }' /proc/swaps)
        [[ $old_used_kib =~ ^[0-9]+$ ]] || die '无法读取现有 /swapfile 的使用量。'
        (( old_used_kib == 0 )) || die '/swapfile 正在使用中；为避免影响运行，不自动调整大小。'
        log '当前 /swapfile 使用量为 0，准备安全切换到新大小。'
    fi

    if [[ -e $SWAP_FILE ]]; then
        [[ $(blkid -p -o value -s TYPE "$SWAP_FILE" 2>/dev/null || :) == swap ]] ||
            die '现有 /swapfile 没有 swap 签名；为避免覆盖其他数据，已停止。'
        old_size=$(stat -c %s "$SWAP_FILE")
    fi
    if [[ -n $requested ]]; then
        size=$(parse_size "$requested")
    elif [[ ${old_size:-0} -ge $((64 * 1024 * 1024)) ]]; then
        size=$old_size
    else
        size=$((2 * 1024 * 1024 * 1024))
    fi
    fs_type=$(findmnt -n -o FSTYPE -T /) || die '无法确定根分区文件系统。'
    log "根分区: $fs_type；目标大小: $((size / 1024 / 1024)) MiB。"
    TEMP_SWAP="/.swapfile.swaptool.$$.${RANDOM}"
    [[ ! -e $TEMP_SWAP && ! -L $TEMP_SWAP ]] || die '临时路径已存在，请重试。'
    create_swapfile "$fs_type" "$size"

    if active_swapfile; then
        old_used_kib=$(awk -v path="$SWAP_FILE" 'NR > 1 && $1 == path { print $4 }' /proc/swaps)
        (( ${old_used_kib:-1} == 0 )) || die '创建新文件期间，旧 /swapfile 开始被使用；已停止切换。'
        if ! swapoff "$SWAP_FILE"; then
            if ! active_swapfile; then OLD_DISABLED=1; fi
            die '无法完成旧 /swapfile 的关闭，已停止切换。'
        fi
        OLD_DISABLED=1
    fi
    if [[ -e $SWAP_FILE ]]; then
        backup_path="${BACKUP_PREFIX}$(date +%Y%m%d%H%M%S).$$"
        [[ ! -e $backup_path && ! -L $backup_path ]] || die "备份路径已存在: $backup_path"
        mv -- "$SWAP_FILE" "$backup_path" || die '无法备份旧 /swapfile。'
        OLD_BACKUP=$backup_path
        log '旧文件已临时保存，切换成功后会自动删除。'
    fi
    mv -- "$TEMP_SWAP" "$SWAP_FILE" || die '无法安装新的 /swapfile。'
    TEMP_SWAP=
    NEW_AT_TARGET=1
    if ! swapon "$SWAP_FILE"; then
        die '内核拒绝启用交换文件；请检查上方错误（Btrfs 多设备、文件系统或内核限制）。'
    fi
    active_swapfile || die 'swapon 返回成功，但 /proc/swaps 中没有 /swapfile。'
    ACTIVATED=1
    ensure_fstab
    log '交换空间已实际启用，并将在重启后自动启用。'
    status
    OLD_BACKUP=
    NEW_AT_TARGET=0
    ACTIVATED=0
    OLD_DISABLED=0
    cleanup_swap_backups
}

cleanup_command() {
    [[ $(uname -s) == Linux ]] || die '此脚本只能在 Linux 上运行。'
    (( EUID == 0 )) || die 'cleanup 必须以 root 身份运行。'
    command -v blkid >/dev/null 2>&1 || die '缺少命令: blkid'
    cleanup_swap_backups
}

menu() {
    local choice custom size summary
    [[ $(uname -s) == Linux ]] || die '此脚本只能在 Linux 上运行。'
    [[ -t 0 && -t 1 ]] || die '交互菜单需要终端；自动化场景请使用 setup <大小>。'
    if (( EUID != 0 )); then
        command -v sudo >/dev/null 2>&1 || die '请使用 sudo swaptool 打开菜单。'
        exec sudo -- "$0" menu
    fi
    while :; do
        summary=$(awk '
            /^SwapTotal:/ { total=$2 }
            /^SwapFree:/ { free=$2 }
            END { used=total-free; pct=(total > 0 ? int(used*100/total) : 0);
                  printf "%dM/%dM (%d%%)", int(used/1024), int(total/1024), pct }
        ' /proc/meminfo)
        printf '\nswaptool v%s | 设置虚拟内存（swap）\n当前虚拟内存：%s\n' "$VERSION" "$summary"
        printf '%s\n' '------------------------------'
        printf '%s\n' '1. 分配 1024M    2. 分配 2048M    3. 分配 4096M    4. 自定义大小'
        printf '%s\n' '------------------------------' '0. 退出' '------------------------------'
        read -r -p '请输入你的选择：' choice || return
        case $choice in
            1) size=1024M ;;
            2) size=2048M ;;
            3) size=4096M ;;
            4)
                read -r -p '请输入大小（例如 1536M、3G；纯数字按 M）：' custom || return
                [[ $custom =~ ^[1-9][0-9]*$ ]] && custom="${custom}M"
                if ! (parse_size "$custom" >/dev/null); then continue; fi
                size=$custom
                ;;
            0) return ;;
            *) log '无效选项，请重新输入。'; continue ;;
        esac
        setup "$size"
        read -r -p '按回车返回菜单...' choice || return
    done
}

status() {
    [[ $(uname -s) == Linux ]] || die '此脚本只能在 Linux 上运行。'
    printf 'swaptool v%s\n' "$VERSION"
    printf '根分区文件系统: %s\n' "$(findmnt -n -o FSTYPE -T /)"
    if active_swapfile; then
        printf '/swapfile: 已启用\n'
    else
        printf '/swapfile: 未启用\n'
    fi
    if [[ -f $SWAP_FILE ]]; then
        printf '文件大小: %s MiB\n' "$(( $(stat -c %s "$SWAP_FILE") / 1024 / 1024 ))"
    fi
    if [[ -f $FSTAB ]] && fstab_has_swapfile; then
        printf 'fstab: 已配置\n'
    else
        printf 'fstab: 未配置\n'
    fi
    printf '当前交换空间:\n'
    swapon --show
}

install_tool() {
    [[ $(uname -s) == Linux ]] || die '此脚本只能在 Linux 上运行。'
    (( EUID == 0 )) || die 'install 必须以 root 身份运行。'
    command -v install >/dev/null 2>&1 || die '缺少 install 命令。'
    [[ -f $0 && -r $0 ]] || die '请先将脚本下载为文件，再运行 install。'
    if [[ ! $0 -ef $INSTALL_PATH ]]; then
        install -m 0755 -- "$0" "$INSTALL_PATH" || die "无法安装到 $INSTALL_PATH。"
        log "命令已安装: $INSTALL_PATH"
    fi
    if [[ -n ${1:-} ]]; then
        "$INSTALL_PATH" setup "$1"
    elif [[ -t 0 && -t 1 ]]; then
        "$INSTALL_PATH" menu
    else
        log '安装完成。请在终端运行 swaptool，进入大小选择菜单。'
    fi
}

case ${1:-} in
    install) (( $# <= 2 )) || die 'install 最多接受一个大小参数。'; install_tool "${2:-}" ;;
    menu|'') (( $# <= 1 )) || die '菜单不接受参数。'; menu ;;
    setup) (( $# <= 2 )) || die 'setup 最多接受一个大小参数。'; setup "${2:-}" ;;
    cleanup) (( $# == 1 )) || die 'cleanup 不接受参数。'; cleanup_command ;;
    status) (( $# == 1 )) || die 'status 不接受参数。'; status ;;
    -V|--version|version) (( $# == 1 )) || die 'version 不接受参数。'; printf 'swaptool %s\n' "$VERSION" ;;
    -h|--help|help) usage ;;
    *) usage >&2; exit 2 ;;
esac
