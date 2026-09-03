#!/usr/bin/env bash

set -Eeuo pipefail

PROGRAM=${0##*/}
INSTALL_PATH=${DNS_TOOL_INSTALL_PATH:-/usr/local/bin/dnstool}
RESOLV_CONF=${DNS_TOOL_RESOLV_CONF:-/etc/resolv.conf}
RESOLVED_DROPIN=${DNS_TOOL_RESOLVED_DROPIN:-/etc/systemd/resolved.conf.d/90-vps-tools-dns.conf}
NM_DROPIN=${DNS_TOOL_NM_DROPIN:-/etc/NetworkManager/conf.d/90-vps-tools-dns.conf}
RESOLVCONF_HEAD=${DNS_TOOL_RESOLVCONF_HEAD:-/etc/resolvconf/resolv.conf.d/head}
STATE_DIR=${DNS_TOOL_STATE_DIR:-/var/lib/dns_tool}
BACKUP_ROOT=$STATE_DIR/backups
ACTIVE_BACKUP_FILE=$STATE_DIR/original-backup
ACTIVE_CONFIG_FILE=$STATE_DIR/active.conf
ORIGINAL_ARGS=("$@")
APPLY_IN_PROGRESS=no
ROLLBACK_DIR=
PROVIDER_ADDRESSES=()

log() {
    printf '[dnstool] %s\n' "$*"
}

warn() {
    printf '[dnstool] 警告: %s\n' "$*" >&2
}

die() {
    printf '[dnstool] 错误: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<EOF
一键切换 VPS DNS

用法：
  $PROGRAM
  $PROGRAM status
  $PROGRAM set <cloudflare|google|quad9|adguard|alidns>
  $PROGRAM set custom <DNS地址> [DNS地址...]
  $PROGRAM restore
  $PROGRAM install

不带参数运行时进入中文交互菜单。首次安装或首次进入菜单会保存固定的初始配置，
后续安装和切换都不会覆盖它；restore 可一键恢复初始文件、权限、符号链接和
DNS 管理配置。
EOF
}

lowercase() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

require_root() {
    [[ ${DNS_TOOL_ALLOW_NON_ROOT:-0} == 1 ]] && return 0
    [[ $EUID -eq 0 ]] && return 0
    if [[ -t 0 ]] && command -v sudo >/dev/null 2>&1; then
        log '需要管理员权限，正在通过 sudo 重新运行。'
        exec sudo -- "$0" "${ORIGINAL_ARGS[@]}"
    fi
    die '必须以 root 身份运行。'
}

require_absolute_paths() {
    local path
    for path in "$INSTALL_PATH" "$RESOLV_CONF" "$RESOLVED_DROPIN" "$NM_DROPIN" \
        "$RESOLVCONF_HEAD" "$STATE_DIR"; do
        [[ $path == /* ]] || die "路径必须是绝对路径: $path"
    done
}

provider_addresses() {
    case $(lowercase "$1") in
        cloudflare)
            printf '%s\n' 1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001
            ;;
        google)
            printf '%s\n' 8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844
            ;;
        quad9)
            printf '%s\n' 9.9.9.9 149.112.112.112 2620:fe::fe 2620:fe::9
            ;;
        adguard)
            printf '%s\n' 94.140.14.14 94.140.15.15 2a10:50c0::ad1:ff 2a10:50c0::ad2:ff
            ;;
        alidns)
            printf '%s\n' 223.5.5.5 223.6.6.6 2400:3200::1 2400:3200:baba::1
            ;;
        *) return 1 ;;
    esac
}

load_provider_addresses() {
    local provider=$1 address
    PROVIDER_ADDRESSES=()
    while IFS= read -r address; do
        PROVIDER_ADDRESSES+=("$address")
    done < <(provider_addresses "$provider")
    (( ${#PROVIDER_ADDRESSES[@]} > 0 ))
}

validate_ipv4() {
    local address=$1 octet
    local -a octets
    [[ $address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS=. read -r -a octets <<<"$address"
    (( ${#octets[@]} == 4 )) || return 1
    for octet in "${octets[@]}"; do
        [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
}

valid_ipv6_group() {
    [[ $1 =~ ^[0-9A-Fa-f]{1,4}$ ]]
}

validate_ipv6() {
    local address=$1 left right group
    local -a groups
    [[ $address == *:* && $address =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    [[ $address != *:::* ]] || return 1

    if [[ $address == *::* ]]; then
        left=${address%%::*}
        right=${address#*::}
        [[ $right != *::* ]] || return 1
        groups=()
        if [[ -n $left ]]; then
            IFS=: read -r -a groups <<<"$left"
        fi
        local left_count=${#groups[@]}
        for group in "${groups[@]}"; do valid_ipv6_group "$group" || return 1; done
        groups=()
        if [[ -n $right ]]; then
            IFS=: read -r -a groups <<<"$right"
        fi
        local right_count=${#groups[@]}
        for group in "${groups[@]}"; do valid_ipv6_group "$group" || return 1; done
        ((left_count + right_count < 8)) || return 1
        return 0
    fi

    IFS=: read -r -a groups <<<"$address"
    (( ${#groups[@]} == 8 )) || return 1
    for group in "${groups[@]}"; do valid_ipv6_group "$group" || return 1; done
}

validate_address() {
    validate_ipv4 "$1" || validate_ipv6 "$1"
}

validate_addresses() {
    local address
    (( $# >= 1 && $# <= 4 )) || die 'DNS 地址数量必须为 1 到 4 个。'
    for address in "$@"; do
        validate_address "$address" || die "无效的 IPv4/IPv6 DNS 地址: $address"
    done
}

service_is_active() {
    command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$1"
}

detect_manager() {
    local target=
    if service_is_active systemd-resolved; then
        printf 'systemd-resolved\n'
        return
    fi
    if [[ -L $RESOLV_CONF ]]; then
        target=$(readlink "$RESOLV_CONF" 2>/dev/null || true)
        if [[ $target == *resolvconf* ]] && command -v resolvconf >/dev/null 2>&1; then
            printf 'resolvconf\n'
            return
        fi
    fi
    if service_is_active NetworkManager; then
        printf 'NetworkManager\n'
        return
    fi
    printf 'static\n'
}

ensure_state_dirs() {
    install -d -m 700 "$STATE_DIR" "$BACKUP_ROOT"
}

new_snapshot_dir() {
    local label=${1:-backup} destination
    destination=$(mktemp -d "$BACKUP_ROOT/${label}-$(date +%Y%m%d-%H%M%S).XXXXXX")
    chmod 700 "$destination"
    printf '%s\n' "$destination"
}

snapshot_path() {
    local path=$1 key=$2 destination=$3
    if [[ -L $path ]]; then
        printf 'symlink\n' >"$destination/$key.type"
        readlink "$path" >"$destination/$key.target"
    elif [[ -f $path ]]; then
        printf 'file\n' >"$destination/$key.type"
        cp -a "$path" "$destination/$key.file"
    elif [[ -e $path ]]; then
        die "拒绝备份非普通文件: $path"
    else
        printf 'missing\n' >"$destination/$key.type"
    fi
}

create_snapshot() {
    local destination=$1
    install -d -m 700 "$destination"
    snapshot_path "$RESOLV_CONF" resolv_conf "$destination"
    snapshot_path "$RESOLVED_DROPIN" resolved_dropin "$destination"
    snapshot_path "$NM_DROPIN" nm_dropin "$destination"
    snapshot_path "$RESOLVCONF_HEAD" resolvconf_head "$destination"
}

ensure_initial_backup() {
    local existing snapshot temp
    ensure_state_dirs
    if [[ -f $ACTIVE_BACKUP_FILE ]]; then
        existing=$(<"$ACTIVE_BACKUP_FILE")
        [[ $existing == "$BACKUP_ROOT/"* && -d $existing ]] ||
            die '初始备份记录已损坏；为避免覆盖原始配置，已停止操作。'
        return 0
    fi

    snapshot=$(new_snapshot_dir initial)
    create_snapshot "$snapshot"
    temp=$(mktemp "$STATE_DIR/.original-backup.XXXXXX")
    printf '%s\n' "$snapshot" >"$temp"
    chmod 600 "$temp"
    mv -f "$temp" "$ACTIVE_BACKUP_FILE"
    log '已自动保存首次部署时的初始 DNS 配置。此备份不会被后续操作覆盖。'
}

restore_path() {
    local path=$1 key=$2 source=$3 type target
    type=$(<"$source/$key.type")
    [[ ! -d $path || -L $path ]] || die "拒绝用文件覆盖目录: $path"
    mkdir -p "${path%/*}"
    case $type in
        file)
            rm -f -- "$path"
            cp -a "$source/$key.file" "$path"
            ;;
        symlink)
            target=$(<"$source/$key.target")
            rm -f -- "$path"
            ln -s -- "$target" "$path"
            ;;
        missing)
            rm -f -- "$path"
            ;;
        *) die "备份元数据损坏: $key" ;;
    esac
}

restore_snapshot() {
    local source=$1
    [[ -d $source ]] || die "备份不存在: $source"
    restore_path "$RESOLV_CONF" resolv_conf "$source"
    restore_path "$RESOLVED_DROPIN" resolved_dropin "$source"
    restore_path "$NM_DROPIN" nm_dropin "$source"
    restore_path "$RESOLVCONF_HEAD" resolvconf_head "$source"
}

refresh_dns_manager() {
    local resolv_target=
    if service_is_active systemd-resolved; then
        systemctl restart systemd-resolved
        command -v resolvectl >/dev/null 2>&1 && resolvectl flush-caches >/dev/null 2>&1 || true
    fi
    if [[ -L $RESOLV_CONF ]]; then
        resolv_target=$(readlink "$RESOLV_CONF" 2>/dev/null || true)
    fi
    if command -v resolvconf >/dev/null 2>&1 &&
       { [[ -e $RESOLVCONF_HEAD ]] || [[ $resolv_target == *resolvconf* ]]; }; then
        resolvconf -u
    fi
    if service_is_active NetworkManager && command -v nmcli >/dev/null 2>&1; then
        nmcli general reload >/dev/null
    fi
}

rollback_on_exit() {
    local exit_code=$1
    if [[ $APPLY_IN_PROGRESS == yes && -n $ROLLBACK_DIR ]]; then
        set +e
        warn '应用未完成，正在自动恢复原配置。'
        restore_snapshot "$ROLLBACK_DIR"
        refresh_dns_manager >/dev/null 2>&1
    fi
    exit "$exit_code"
}
trap 'rollback_on_exit $?' EXIT

write_generated_file() {
    local path=$1 content=$2 mode=${3:-644} temp
    [[ ! -d $path || -L $path ]] || die "拒绝用文件覆盖目录: $path"
    mkdir -p "${path%/*}"
    temp=$(mktemp "${path%/*}/.dns_tool.XXXXXX")
    printf '%s' "$content" >"$temp"
    chmod "$mode" "$temp"
    rm -f -- "$path"
    mv -f -- "$temp" "$path"
}

resolv_content() {
    local source=$1 address
    shift
    printf '# Managed by dnstool. Use dnstool restore to recover the original.\n'
    for address in "$@"; do
        printf 'nameserver %s\n' "$address"
    done
    if [[ -r $source && ! -d $source ]]; then
        awk '$1 != "nameserver" && $0 !~ /^# Managed by (dns_tool|dnstool)\./' "$source"
    fi
}

resolved_content() {
    local joined
    joined=$(printf '%s ' "$@")
    joined=${joined% }
    printf '# Managed by dnstool.\n[Resolve]\nDNS=%s\nFallbackDNS=%s\nDomains=~.\n' "$joined" "$joined"
}

network_manager_content() {
    printf '# Managed by dnstool.\n[main]\ndns=none\nrc-manager=unmanaged\n'
}

apply_resolved() {
    local content
    content=$(resolved_content "$@")
    write_generated_file "$RESOLVED_DROPIN" "$content"
    systemctl restart systemd-resolved
    command -v resolvectl >/dev/null 2>&1 && resolvectl flush-caches >/dev/null 2>&1 || true

    local target=
    [[ -L $RESOLV_CONF ]] && target=$(readlink "$RESOLV_CONF" 2>/dev/null || true)
    if [[ $target != *systemd/resolve/* ]]; then
        content=$(resolv_content "$RESOLV_CONF" "$@")
        write_generated_file "$RESOLV_CONF" "$content"
        warn "$RESOLV_CONF 未连接到 systemd-resolved，已同步写入 DNS 地址。"
    fi
}

apply_resolvconf() {
    local content
    content=$(resolv_content "$RESOLVCONF_HEAD" "$@")
    write_generated_file "$RESOLVCONF_HEAD" "$content"
    resolvconf -u
}

apply_network_manager() {
    local content
    content=$(network_manager_content)
    write_generated_file "$NM_DROPIN" "$content"
    content=$(resolv_content "$RESOLV_CONF" "$@")
    write_generated_file "$RESOLV_CONF" "$content"
    if command -v nmcli >/dev/null 2>&1; then
        nmcli general reload >/dev/null
    else
        systemctl reload NetworkManager
    fi
}

apply_static() {
    local content
    content=$(resolv_content "$RESOLV_CONF" "$@")
    write_generated_file "$RESOLV_CONF" "$content"
    warn '未检测到受支持的 DNS 管理服务；已更新 resolv.conf，但 DHCP 客户端以后可能覆盖它。'
}

record_active_config() {
    local provider=$1 manager=$2
    shift 2
    local temp address
    temp=$(mktemp "$STATE_DIR/.active.XXXXXX")
    {
        printf 'provider=%s\nmanager=%s\n' "$provider" "$manager"
        for address in "$@"; do printf 'dns=%s\n' "$address"; done
    } >"$temp"
    chmod 600 "$temp"
    mv -f "$temp" "$ACTIVE_CONFIG_FILE"
}

set_dns() {
    local provider=$1
    shift
    local -a addresses=("$@")
    validate_addresses "${addresses[@]}"
    require_root
    ensure_initial_backup

    local snapshot manager
    snapshot=$(new_snapshot_dir backup)
    create_snapshot "$snapshot"

    manager=$(detect_manager)
    APPLY_IN_PROGRESS=yes
    ROLLBACK_DIR=$snapshot
    case $manager in
        systemd-resolved) apply_resolved "${addresses[@]}" ;;
        resolvconf) apply_resolvconf "${addresses[@]}" ;;
        NetworkManager) apply_network_manager "${addresses[@]}" ;;
        static) apply_static "${addresses[@]}" ;;
        *) die "未知 DNS 管理方式: $manager" ;;
    esac
    record_active_config "$provider" "$manager" "${addresses[@]}"
    APPLY_IN_PROGRESS=no
    ROLLBACK_DIR=

    log "DNS 已切换为 ${provider}（${manager}）。"
    printf 'DNS: %s\n' "${addresses[*]}"
    log '未重启网络接口；当前 SSH 会话不会因本工具主动断开。'
}

original_backup_dir() {
    local backup
    [[ -f $ACTIVE_BACKUP_FILE ]] || return 1
    backup=$(<"$ACTIVE_BACKUP_FILE")
    [[ $backup == "$BACKUP_ROOT/"* && -d $backup ]] || return 1
    printf '%s\n' "$backup"
}

restore_original() {
    require_root
    local backup rollback manager_before
    backup=$(original_backup_dir) || die '没有可恢复的原始 DNS 配置。'
    ensure_state_dirs
    rollback=$(new_snapshot_dir restore)
    create_snapshot "$rollback"
    manager_before=$(detect_manager)
    APPLY_IN_PROGRESS=yes
    ROLLBACK_DIR=$rollback
    restore_snapshot "$backup"
    refresh_dns_manager
    APPLY_IN_PROGRESS=no
    ROLLBACK_DIR=
    rm -f -- "$ACTIVE_CONFIG_FILE"
    log "已一键恢复首次修改前的初始 DNS 配置（恢复前管理方式: ${manager_before}）。"
    log '初始配置备份已保留，可随时再次执行 restore。'
}

show_status() {
    local manager target
    manager=$(detect_manager)
    printf 'DNS 管理方式: %s\n' "$manager"
    if [[ -L $RESOLV_CONF ]]; then
        target=$(readlink "$RESOLV_CONF" 2>/dev/null || true)
        printf 'resolv.conf: 符号链接 -> %s\n' "$target"
    elif [[ -f $RESOLV_CONF ]]; then
        printf 'resolv.conf: 普通文件\n'
    else
        printf 'resolv.conf: 不存在\n'
    fi
    printf '当前 resolv.conf nameserver:\n'
    if [[ -r $RESOLV_CONF ]]; then
        awk '$1 == "nameserver" { print "  " $2 }' "$RESOLV_CONF"
    fi
    if [[ -r $ACTIVE_CONFIG_FILE ]]; then
        printf 'dnstool 当前配置:\n'
        awk -F= '$1 == "provider" { print "  提供商: " $2 }
                   $1 == "manager" { print "  应用方式: " $2 }
                   $1 == "dns" { print "  DNS: " $2 }' "$ACTIVE_CONFIG_FILE"
    else
        printf 'dnstool 当前配置: 未应用\n'
    fi
    if original_backup_dir >/dev/null 2>&1; then
        printf '原始配置备份: 可恢复\n'
    else
        printf '原始配置备份: 无\n'
    fi
}

show_initial_backup_summary() {
    local backup type target dns_list
    if ! backup=$(original_backup_dir); then
        printf '初始 DNS 备份: 尚未保存\n'
        return
    fi
    type=$(<"$backup/resolv_conf.type")
    case $type in
        file)
            dns_list=$(awk '$1 == "nameserver" { values = values (values ? ", " : "") $2 }
                             END { print values }' "$backup/resolv_conf.file")
            printf '初始 DNS 备份: 已保存（DNS: %s）\n' "${dns_list:-未配置 nameserver}"
            ;;
        symlink)
            target=$(<"$backup/resolv_conf.target")
            printf '初始 DNS 备份: 已保存（resolv.conf 链接: %s）\n' "$target"
            ;;
        missing) printf '初始 DNS 备份: 已保存（原 resolv.conf 不存在）\n' ;;
        *) printf '初始 DNS 备份: 记录异常\n' ;;
    esac
}

prompt_yes_no() {
    local prompt=$1 answer
    printf '%s [y/N]: ' "$prompt"
    IFS= read -r answer || return 1
    [[ $answer == y || $answer == Y ]]
}

interactive_menu() {
    require_root
    ensure_initial_backup
    while true; do
        printf '\n=== VPS DNS 切换工具 ===\n'
        show_initial_backup_summary
        printf '\n'
        printf '1. Cloudflare\n2. Google\n3. Quad9\n4. AdGuard\n5. AliDNS\n'
        printf '6. 自定义 DNS\n7. 查看状态\n8. 一键恢复首次修改前的初始配置\n0. 退出\n'
        printf '请选择: '
        local choice provider input
        local -a addresses
        IFS= read -r choice || return 0
        case $choice in
            1) provider=cloudflare ;;
            2) provider=google ;;
            3) provider=quad9 ;;
            4) provider=adguard ;;
            5) provider=alidns ;;
            6)
                printf '请输入 1-4 个 IPv4/IPv6 DNS 地址（空格分隔）: '
                IFS= read -r input || continue
                read -r -a addresses <<<"$input"
                validate_addresses "${addresses[@]}"
                prompt_yes_no "确认切换为 ${addresses[*]}？" && set_dns custom "${addresses[@]}"
                continue
                ;;
            7) show_status; continue ;;
            8)
                prompt_yes_no '确认一键恢复首次修改前的初始 DNS 配置？' && restore_original
                continue
                ;;
            0) return 0 ;;
            *) printf '无效选项。\n'; continue ;;
        esac
        load_provider_addresses "$provider" || die "未知 DNS 提供商: $provider"
        addresses=("${PROVIDER_ADDRESSES[@]}")
        prompt_yes_no "确认切换为 ${provider}（${addresses[*]}）？" && set_dns "$provider" "${addresses[@]}"
    done
}

install_tool() {
    require_root
    command -v install >/dev/null 2>&1 || die '缺少命令: install'
    command -v cmp >/dev/null 2>&1 || die '缺少命令: cmp'
    local source_file=${BASH_SOURCE[0]}
    [[ -f $source_file && ! -L $source_file ]] || die '无法从当前脚本安全执行安装。'
    if [[ -e $INSTALL_PATH && ! -f $INSTALL_PATH ]]; then
        die "安装目标不是普通文件: $INSTALL_PATH"
    fi
    if [[ -f $INSTALL_PATH ]] && ! cmp -s "$source_file" "$INSTALL_PATH"; then
        [[ -t 0 ]] || die "安装目标已存在: $INSTALL_PATH"
        prompt_yes_no "$INSTALL_PATH 已存在，确认覆盖？" || die '安装已取消。'
    fi
    install -d -m 755 "${INSTALL_PATH%/*}"
    install -m 755 "$source_file" "$INSTALL_PATH"
    log "已安装: $INSTALL_PATH"
    ensure_initial_backup
    log '以后直接运行 dnstool 即可进入中文菜单。'
}

main() {
    require_absolute_paths
    case ${1:-menu} in
        -h|--help|help) usage ;;
        menu)
            (( $# <= 1 )) || die 'menu 不接受额外参数。'
            interactive_menu
            ;;
        status)
            (( $# == 1 )) || die 'status 不接受额外参数。'
            show_status
            ;;
        set)
            (( $# >= 2 )) || die 'set 需要 DNS 提供商或 custom。'
            local provider
            provider=$(lowercase "$2")
            shift 2
            local -a addresses
            if [[ $provider == custom ]]; then
                addresses=("$@")
            else
                (( $# == 0 )) || die '公共 DNS 提供商后面不能附加地址。'
                load_provider_addresses "$provider" || die "未知 DNS 提供商: $provider"
                addresses=("${PROVIDER_ADDRESSES[@]}")
            fi
            set_dns "$provider" "${addresses[@]}"
            ;;
        restore)
            (( $# == 1 )) || die 'restore 不接受额外参数。'
            restore_original
            ;;
        install)
            (( $# == 1 )) || die 'install 不接受额外参数。'
            install_tool
            ;;
        *) usage >&2; exit 2 ;;
    esac
}

main "$@"
