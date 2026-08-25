#!/usr/bin/env bash

set -Eeuo pipefail

PROGRAM=${0##*/}
INSTALL_PATH=${SAFE_SSH_PORT_INSTALL_PATH:-/usr/local/sbin/safe-ssh-port}
ALLENTOOL_PATH=${ALLENTOOL_PATH:-/usr/local/bin/allentool}
SSHD_CONFIG=${SAFE_SSH_PORT_CONFIG:-/etc/ssh/sshd_config}
SSHD_DROPIN_DIR=${SAFE_SSH_PORT_DROPIN_DIR:-/etc/ssh/sshd_config.d}
MANAGED_CONFIG=${SAFE_SSH_PORT_MANAGED_CONFIG:-$SSHD_DROPIN_DIR/00-safe-ssh-port.conf}
STATE_DIR=${SAFE_SSH_PORT_STATE_DIR:-/var/lib/safe-ssh-port}
STATE_FILE=$STATE_DIR/state
BACKUP_ROOT=$STATE_DIR/backups
FIREWALL_CHAIN=ALLENTOOL_INPUT
ACCESS_CHAIN=ALLENTOOL_ACCESS
IP_ALLOW_CHAIN=ALLENTOOL_IP_ALLOW
IP_DENY_CHAIN=ALLENTOOL_IP_DENY
COUNTRY_CHAIN=ALLENTOOL_COUNTRY
IPSET_STATE_FILE=${ALLENTOOL_IPSET_STATE_FILE:-/etc/iptables/ipsets.allentool}
IPSET_SERVICE_FILE=${ALLENTOOL_IPSET_SERVICE_FILE:-/etc/systemd/system/allentool-ipset-restore.service}
IPDENY_V4_BASE=https://www.ipdeny.com/ipblocks/data/aggregated
IPDENY_V6_BASE=https://www.ipdeny.com/ipv6/ipaddresses/aggregated
ISO_ALPHA2_CODES='ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw'
SSHD_BIN=${SAFE_SSH_PORT_SSHD_BIN:-sshd}
SS_BIN=${SAFE_SSH_PORT_SS_BIN:-ss}

STATE_STATUS=
STATE_NEW_PORT=
STATE_OLD_PORTS=
STATE_BACKUP_DIR=
STATE_SERVICE_MODE=
STATE_SERVICE_NAME=
STATE_FIREWALL_MANAGER=none
STATE_FIREWALL_RULE_ADDED=no
STATE_FIREWALL_IPTABLES_FAMILIES=
STATE_MAIN_PASSWORD_CHANGED=no
ORIGINAL_ARGS=()

log() {
    printf '[safe-ssh-port] %s\n' "$*"
}

warn() {
    printf '[safe-ssh-port] 警告: %s\n' "$*" >&2
}

lowercase() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

uppercase() {
    printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

die() {
    printf '[safe-ssh-port] 错误: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<EOF
安全修改 OpenSSH 端口（单端口直接切换）

用法：
  $PROGRAM
  $PROGRAM menu
  $PROGRAM interactive
  $PROGRAM restore
  $PROGRAM firewall
  $PROGRAM install
  $PROGRAM install-shortcut
  sudo $PROGRAM switch <新端口> [--cloud-firewall-ready] [--skip-host-firewall]
                               [--enable-main-password]
  sudo $PROGRAM status

流程：
  1. 先在云厂商安全组/防火墙中放行新端口。
  2. 自动在启用中的 UFW、firewalld 或 restrictive iptables 放行新端口。
  3. 备份配置，把唯一有效的 Port 写入 /etc/ssh/sshd_config，并验证 SSH 配置和认证设置。
  4. reload 后确认新端口监听、旧端口关闭，然后自动提交。
  5. 任一检查失败时自动恢复原配置并清理本次新增的防火墙规则。

不带参数运行时显示功能菜单，可修改/恢复 SSH 配置，或管理主机防火墙。
防火墙菜单会显示明确放行/关闭的 TCP/UDP 端口，并支持 SSH 放行修复、
入站保护、IP/国家黑白名单和 iptables/ipset 持久化。防火墙修改直接生效，
不创建快照备份。国家规则同时使用经完整校验的 IPv4 和 IPv6 HTTPS 数据。
原生自定义 nftables 仅显示状态。
interactive 会检测主配置中的 PasswordAuthentication no，并询问是否改为 yes；
需要密码登录时直接回车采用推荐的 yes，输入 n 则保持原认证配置。
脚本不会删除 /etc/ssh/sshd_config.d 中的云厂商配置。
Debian/Ubuntu 缺少持久化工具时会自动安装 iptables-persistent 并保存规则。
安装或保存失败不会中断端口切换，但会明确警告重启后规则可能失效。
EOF
}

require_root() {
    [[ $EUID -eq 0 ]] && return 0
    if [[ -t 0 ]] && command -v sudo >/dev/null 2>&1; then
        log '需要管理员权限，正在通过 sudo 重新运行。'
        exec sudo -- "$0" "${ORIGINAL_ARGS[@]}"
    fi
    die '必须以 root 身份运行。'
}

require_install_commands() {
    command -v install >/dev/null 2>&1 || die '缺少命令: install'
    command -v cmp >/dev/null 2>&1 || die '缺少命令: cmp'
}

confirm_install_target() {
    local source_file=$1 target=$2 label=$3
    [[ $target == /* ]] || die "${label}安装路径必须是绝对路径。"
    if [[ -e $target || -L $target ]]; then
        [[ -f $target && ! -L $target ]] ||
            die "目标已存在且不是普通文件，拒绝覆盖: $target"
        if [[ $source_file -ef $target ]] || cmp -s "$source_file" "$target"; then
            return 0
        fi
        [[ -t 0 ]] || die "目标已存在；请在交互终端中确认是否覆盖: $target"
        prompt_yes_no "${target} 已存在，是否用当前版本覆盖（推荐）？" yes || die '安装已取消。'
    fi
}

install_copy() {
    local source_file=$1 target=$2 label=$3
    if [[ -e $target ]] &&
       { [[ $source_file -ef $target ]] || cmp -s "$source_file" "$target"; }; then
        log "${label}已经是最新版本: $target"
        return 0
    fi
    install -m 755 "$source_file" "$target"
    log "${label}已安装：$target"
}

install_tool() {
    require_install_commands
    [[ $INSTALL_PATH != "$ALLENTOOL_PATH" ]] || die '正式命令和快捷命令的安装路径不能相同。'

    local source_file=${BASH_SOURCE[0]}
    [[ -f $source_file && ! -L $source_file ]] || die '无法从当前脚本安全执行安装。'
    confirm_install_target "$source_file" "$INSTALL_PATH" '正式命令'
    confirm_install_target "$source_file" "$ALLENTOOL_PATH" '快捷命令'
    install_copy "$source_file" "$INSTALL_PATH" '正式命令'
    install_copy "$source_file" "$ALLENTOOL_PATH" '快捷命令'
    log '安装完成，以后直接输入 allentool 即可打开功能菜单。'
}

install_shortcut() {
    require_install_commands

    local source_file=${BASH_SOURCE[0]}
    [[ -f $source_file && ! -L $source_file ]] || die '无法从当前脚本安全安装快捷命令。'
    confirm_install_target "$source_file" "$ALLENTOOL_PATH" '快捷命令'
    install_copy "$source_file" "$ALLENTOOL_PATH" '快捷命令'

    log '以后直接输入 allentool 即可打开功能菜单。'
}

require_commands() {
    local command_name
    for command_name in "$SSHD_BIN" "$SS_BIN" awk grep sed sort tr mktemp cp mv chmod chown mkdir find rm date stat sleep; do
        command -v "$command_name" >/dev/null 2>&1 || die "缺少命令: $command_name"
    done
}

validate_port() {
    local port=${1:-}
    [[ $port =~ ^[0-9]+$ ]] || return 1
    ((10#$port >= 1 && 10#$port <= 65535)) || return 1
}

effective_ports() {
    "$SSHD_BIN" -T 2>/dev/null |
        awk '$1 == "port" && $2 ~ /^[0-9]+$/ { print $2 }' |
        sort -nu
}

auth_fingerprint() {
    "$SSHD_BIN" -T 2>/dev/null |
        awk '$1 == "passwordauthentication" ||
             $1 == "kbdinteractiveauthentication" ||
             $1 == "permitrootlogin" ||
             $1 == "pubkeyauthentication" ||
             $1 == "usepam" { print $1 "=" $2 }' |
        sort
}

auth_fingerprint_without_password() {
    auth_fingerprint | grep -v '^passwordauthentication=' || true
}

effective_password_setting() {
    "$SSHD_BIN" -T 2>/dev/null |
        awk '$1 == "passwordauthentication" && !found { print $2; found=1 }'
}

main_password_setting() {
    awk '
        tolower($1) == "match" { exit }
        tolower($1) == "passwordauthentication" {
            print tolower($2)
            exit
        }
    ' "$SSHD_CONFIG"
}

prompt_yes_no() {
    local prompt=$1 default=${2:-no} answer suffix
    [[ $default == yes || $default == no ]] || die "无效的默认选项：$default"
    if [[ $default == yes ]]; then suffix='[Y/n]'; else suffix='[y/N]'; fi
    while true; do
        printf '%s %s: ' "$prompt" "$suffix"
        if ! IFS= read -r answer; then
            return 1
        fi
        case $answer in
            y|Y) return 0 ;;
            n|N) return 1 ;;
            '')
                if [[ $default == yes ]]; then return 0; else return 1; fi
                ;;
            *) printf '请输入 y、n，或直接按回车使用默认选项。\n' ;;
        esac
    done
}

port_in_list() {
    local wanted=$1
    shift
    local port
    for port in "$@"; do
        [[ $port == "$wanted" ]] && return 0
    done
    return 1
}

port_is_listening() {
    local wanted=$1
    "$SS_BIN" -H -ltn 2>/dev/null |
        awk -v wanted="$wanted" '
            {
                address=$4
                sub(/^.*:/, "", address)
                if (address == wanted) found=1
            }
            END { exit(found ? 0 : 1) }
        '
}

wait_for_port() {
    local port=$1
    local attempt
    for attempt in {1..20}; do
        port_is_listening "$port" && return 0
        sleep 0.25
    done
    return 1
}

wait_for_port_closed() {
    local port=$1 attempt
    for attempt in {1..20}; do
        ! port_is_listening "$port" && return 0
        sleep 0.25
    done
    return 1
}

detect_service() {
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet ssh; then
            STATE_SERVICE_MODE=systemctl
            STATE_SERVICE_NAME=ssh
            return 0
        fi
        if systemctl is-active --quiet sshd; then
            STATE_SERVICE_MODE=systemctl
            STATE_SERVICE_NAME=sshd
            return 0
        fi
    fi

    if command -v service >/dev/null 2>&1; then
        if service ssh status >/dev/null 2>&1; then
            STATE_SERVICE_MODE=service
            STATE_SERVICE_NAME=ssh
            return 0
        fi
        if service sshd status >/dev/null 2>&1; then
            STATE_SERVICE_MODE=service
            STATE_SERVICE_NAME=sshd
            return 0
        fi
    fi

    die '未找到正在运行的 ssh.service 或 sshd.service。'
}

reload_ssh() {
    case $STATE_SERVICE_MODE in
        systemctl) systemctl reload "$STATE_SERVICE_NAME" ;;
        service) service "$STATE_SERVICE_NAME" reload ;;
        *) return 1 ;;
    esac
}

collect_config_files() {
    CONFIG_FILES=("$SSHD_CONFIG")
    if [[ -d $SSHD_DROPIN_DIR ]]; then
        local file
        while IFS= read -r -d '' file; do
            CONFIG_FILES+=("$file")
        done < <(find "$SSHD_DROPIN_DIR" -maxdepth 1 \( -type f -o -type l \) -name '*.conf' -print0 | sort -z)
    fi
}

reject_unsupported_config() {
    local file
    [[ -f $SSHD_CONFIG && ! -L $SSHD_CONFIG ]] || die "$SSHD_CONFIG 必须是普通文件，不能是符号链接。"
    for file in "${CONFIG_FILES[@]}"; do
        if [[ -L $file ]] && grep -Eq '^[[:space:]]*Port[[:space:]]+' "$file"; then
            die "包含 Port 的配置是符号链接，拒绝自动修改: $file"
        fi
        if grep -Eq '^[[:space:]]*Port[[:space:]]+' "$file" &&
           grep -Ev '^[[:space:]]*(#|$)|^[[:space:]]*Port[[:space:]]+[0-9]+([[:space:]]*(#.*)?)?$' "$file" |
               grep -q '^[[:space:]]*Port[[:space:]]+'; then
            die "发现无法安全解析的 Port 指令: $file"
        fi
        if grep -Eq '^[[:space:]]*ListenAddress[[:space:]]+.*:[0-9]+([[:space:]]|$)' "$file"; then
            die "发现带端口的 ListenAddress，需人工处理: $file"
        fi
    done
}

make_backup() {
    local include_main=${1:-no} include_all=${2:-no} timestamp candidate counter=0
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    mkdir -p "$STATE_DIR" "$BACKUP_ROOT"
    candidate=$BACKUP_ROOT/$timestamp
    while [[ -e $candidate || -L $candidate ]]; do
        ((counter += 1))
        printf -v candidate '%s/%s-%02d' "$BACKUP_ROOT" "$timestamp" "$counter"
    done
    mkdir "$candidate"
    STATE_BACKUP_DIR=$candidate
    mkdir "$STATE_BACKUP_DIR/dropins"
    chmod 700 "$STATE_DIR" "$BACKUP_ROOT" "$STATE_BACKUP_DIR" "$STATE_BACKUP_DIR/dropins"
    cp -a "$SSHD_CONFIG" "$STATE_BACKUP_DIR/sshd_config"

    local file
    : > "$STATE_BACKUP_DIR/modified-files"
    chmod 600 "$STATE_BACKUP_DIR/modified-files"
    for file in "${CONFIG_FILES[@]}"; do
        if [[ $include_all == yes ]] ||
           grep -Eq '^[[:space:]]*Port[[:space:]]+[0-9]+([[:space:]]*(#.*)?)?$' "$file" ||
           [[ $include_main == yes && $file == "$SSHD_CONFIG" ]]; then
            if [[ $file != "$SSHD_CONFIG" ]]; then
                cp -a "$file" "$STATE_BACKUP_DIR/dropins/${file##*/}"
            fi
            printf '%s\n' "$file" >> "$STATE_BACKUP_DIR/modified-files"
        fi
    done
}

replace_file_preserving_metadata() {
    local original=$1 temporary=$2 file_mode file_uid file_gid
    if file_mode=$(stat -c '%a' "$original" 2>/dev/null); then
        file_uid=$(stat -c '%u' "$original")
        file_gid=$(stat -c '%g' "$original")
    else
        file_mode=$(stat -f '%Lp' "$original")
        file_uid=$(stat -f '%u' "$original")
        file_gid=$(stat -f '%g' "$original")
    fi
    chmod "$file_mode" "$temporary"
    if [[ $EUID -eq 0 ]]; then
        chown "$file_uid:$file_gid" "$temporary"
    fi
    mv "$temporary" "$original"
}

comment_active_ports() {
    local file temporary
    while IFS= read -r file; do
        [[ -n $file ]] || continue
        temporary=$(mktemp "${file}.safe-ssh-port.XXXXXX")
        awk '
            /^[[:space:]]*Port[[:space:]]+[0-9]+([[:space:]]*(#.*)?)?$/ {
                print "# safe-ssh-port disabled original: " $0
                next
            }
            { print }
        ' "$file" > "$temporary"
        replace_file_preserving_metadata "$file" "$temporary"
    done < "$STATE_BACKUP_DIR/modified-files"
}

set_main_password_yes() {
    local temporary
    [[ $(main_password_setting) == no ]] || return 0
    temporary=$(mktemp "${SSHD_CONFIG}.safe-ssh-password.XXXXXX")
    awk '
        tolower($1) == "match" { in_match=1 }
        !in_match && tolower($1) == "passwordauthentication" && tolower($2) == "no" {
            print "PasswordAuthentication yes"
            next
        }
        { print }
    ' "$SSHD_CONFIG" > "$temporary"
    replace_file_preserving_metadata "$SSHD_CONFIG" "$temporary"
    [[ $(main_password_setting) == yes ]]
}

ensure_main_in_backup() {
    [[ -n $STATE_BACKUP_DIR && -f $STATE_BACKUP_DIR/sshd_config && -f $STATE_BACKUP_DIR/modified-files ]] || return 1
    grep -Fxq "$SSHD_CONFIG" "$STATE_BACKUP_DIR/modified-files" ||
        printf '%s\n' "$SSHD_CONFIG" >> "$STATE_BACKUP_DIR/modified-files"
}

write_main_port() {
    local port=$1 temporary
    validate_port "$port" || return 1
    temporary=$(mktemp "${SSHD_CONFIG}.safe-ssh-port.XXXXXX")
    awk -v port="$port" '
        !inserted && tolower($1) == "match" {
            print "Port " port
            inserted=1
        }
        { print }
        END {
            if (!inserted) print "Port " port
        }
    ' "$SSHD_CONFIG" > "$temporary"
    replace_file_preserving_metadata "$SSHD_CONFIG" "$temporary"
    rm -f "$MANAGED_CONFIG"
    [[ $(awk '
        tolower($1) == "match" { exit }
        tolower($1) == "port" { print $2; exit }
    ' "$SSHD_CONFIG") == "$port" ]]
}

restore_config_files() {
    local file source
    [[ -n $STATE_BACKUP_DIR && -d $STATE_BACKUP_DIR ]] || return 1

    if [[ -f $STATE_BACKUP_DIR/modified-files ]]; then
        while IFS= read -r file; do
            [[ -n $file ]] || continue
            if [[ $file == "$SSHD_CONFIG" ]]; then
                source=$STATE_BACKUP_DIR/sshd_config
            else
                source=$STATE_BACKUP_DIR/dropins/${file##*/}
            fi
            [[ -f $source ]] || return 1
            cp -a "$source" "$file"
        done < "$STATE_BACKUP_DIR/modified-files"
    fi
    if [[ -f $STATE_BACKUP_DIR/modified-files ]] &&
       grep -Fxq "$MANAGED_CONFIG" "$STATE_BACKUP_DIR/modified-files"; then
        : # The prior managed file was restored above.
    else
        rm -f "$MANAGED_CONFIG"
    fi
}

backup_source_for_target() {
    local backup_dir=$1 target=$2
    if [[ $target == "$SSHD_CONFIG" ]]; then
        printf '%s/sshd_config\n' "$backup_dir"
    else
        printf '%s/dropins/%s\n' "$backup_dir" "${target##*/}"
    fi
}

valid_backup_target() {
    local target=$1 relative
    [[ $target == "$SSHD_CONFIG" ]] && return 0
    [[ $target == "$SSHD_DROPIN_DIR/"* ]] || return 1
    relative=${target#"$SSHD_DROPIN_DIR"/}
    [[ -n $relative && $relative != */* && $relative == *.conf ]]
}

validate_backup_dir() {
    local backup_dir=$1 backup_name target source seen=$'\n'
    [[ -d $backup_dir && ! -L $backup_dir ]] || return 1
    [[ ${backup_dir%/*} == "$BACKUP_ROOT" ]] || return 1
    backup_name=${backup_dir##*/}
    [[ $backup_name =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]{2,})?$ ]] || return 1
    [[ -f $backup_dir/sshd_config && ! -L $backup_dir/sshd_config ]] || return 1
    [[ -f $backup_dir/modified-files && ! -L $backup_dir/modified-files ]] || return 1
    [[ -d $backup_dir/dropins && ! -L $backup_dir/dropins ]] || return 1

    while IFS= read -r target; do
        [[ -n $target ]] || continue
        valid_backup_target "$target" || return 1
        [[ $seen != *$'\n'"$target"$'\n'* ]] || return 1
        seen+="$target"$'\n'
        source=$(backup_source_for_target "$backup_dir" "$target")
        [[ -f $source && ! -L $source ]] || return 1
    done < "$backup_dir/modified-files"
}

backup_declared_ports() {
    local backup_dir=$1 target source
    {
        awk '
            /^[[:space:]]*Port[[:space:]]+[0-9]+([[:space:]]*(#.*)?)?$/ {
                print $2
            }
        ' "$backup_dir/sshd_config"
        while IFS= read -r target; do
            [[ -n $target && $target != "$SSHD_CONFIG" ]] || continue
            source=$(backup_source_for_target "$backup_dir" "$target")
            awk '
                /^[[:space:]]*Port[[:space:]]+[0-9]+([[:space:]]*(#.*)?)?$/ {
                    print $2
                }
            ' "$source"
        done < "$backup_dir/modified-files"
    } | sort -nu | awk 'NF { found=1; print } END { if (!found) print 22 }'
}

BACKUP_CHOICES=()
SELECTED_BACKUP_DIR=

list_backups() {
    BACKUP_CHOICES=()
    [[ -d $BACKUP_ROOT ]] || return 1
    local backup_dir ports
    while IFS= read -r backup_dir; do
        [[ -n $backup_dir ]] || continue
        if ! validate_backup_dir "$backup_dir"; then
            warn "已忽略格式无效的备份: $backup_dir"
            continue
        fi
        BACKUP_CHOICES+=("$backup_dir")
    done < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print | sort -r)
    ((${#BACKUP_CHOICES[@]} > 0)) || return 1

    printf '可用 SSH 配置备份（最新在前）：\n'
    local index
    for index in "${!BACKUP_CHOICES[@]}"; do
        backup_dir=${BACKUP_CHOICES[$index]}
        ports=$(backup_declared_ports "$backup_dir")
        ports=${ports//$'\n'/,}
        printf '  %d. %s（端口: %s）\n' "$((index + 1))" "${backup_dir##*/}" "$ports"
    done
}

select_backup() {
    list_backups || die "没有找到可用备份：$BACKUP_ROOT"
    local answer index
    while true; do
        printf '请选择要恢复的备份编号（输入 q 退出）: '
        read -r answer
        [[ $answer == q || $answer == Q ]] && return 1
        if [[ $answer =~ ^[0-9]+$ ]]; then
            index=$((10#$answer - 1))
            if ((index >= 0 && index < ${#BACKUP_CHOICES[@]})); then
                SELECTED_BACKUP_DIR=${BACKUP_CHOICES[$index]}
                return 0
            fi
        fi
        printf '编号无效，请重新输入。\n'
    done
}

RESTORE_CREATED_FILES=()

restore_selected_snapshot() {
    local backup_dir=$1 target source
    validate_backup_dir "$backup_dir" || return 1
    RESTORE_CREATED_FILES=()

    cp -a "$backup_dir/sshd_config" "$SSHD_CONFIG" || return 1
    while IFS= read -r target; do
        [[ -n $target && $target != "$SSHD_CONFIG" ]] || continue
        source=$(backup_source_for_target "$backup_dir" "$target")
        if [[ ! -e $target && ! -L $target ]]; then
            RESTORE_CREATED_FILES+=("$target")
        fi
        [[ ! -L $target ]] || return 1
        cp -a "$source" "$target" || return 1
    done < "$backup_dir/modified-files"

    if ! grep -Fxq "$MANAGED_CONFIG" "$backup_dir/modified-files"; then
        rm -f "$MANAGED_CONFIG"
    fi
}

RESTORE_ADDED_FIREWALL_PORTS=()
RESTORE_ADDED_FIREWALL_MANAGERS=()
RESTORE_ADDED_FIREWALL_FAMILIES=()

open_restore_firewall_ports() {
    local port
    RESTORE_ADDED_FIREWALL_PORTS=()
    RESTORE_ADDED_FIREWALL_MANAGERS=()
    RESTORE_ADDED_FIREWALL_FAMILIES=()
    for port in "$@"; do
        open_host_firewall "$port" no
        if [[ $STATE_FIREWALL_RULE_ADDED == yes ]]; then
            RESTORE_ADDED_FIREWALL_PORTS+=("$port")
            RESTORE_ADDED_FIREWALL_MANAGERS+=("$STATE_FIREWALL_MANAGER")
            RESTORE_ADDED_FIREWALL_FAMILIES+=("$STATE_FIREWALL_IPTABLES_FAMILIES")
        fi
    done
}

close_restore_firewall_ports() {
    local index=0 port manager families
    while ((index < ${#RESTORE_ADDED_FIREWALL_PORTS[@]})); do
        port=${RESTORE_ADDED_FIREWALL_PORTS[$index]}
        manager=${RESTORE_ADDED_FIREWALL_MANAGERS[$index]}
        families=${RESTORE_ADDED_FIREWALL_FAMILIES[$index]}
        case $manager in
            ufw) ufw --force delete allow "${port}/tcp" >/dev/null || return 1 ;;
            firewalld)
                firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null || return 1
                firewall-cmd --reload >/dev/null || return 1
                ;;
            iptables) delete_iptables_allow_rules "$port" "$families" || return 1 ;;
        esac
        ((index += 1))
    done
}

restore_after_restore_failure() {
    local reason=$1 emergency_backup=$2 old_ports=$3 created recovered=yes port
    warn "${reason}，正在恢复操作前的配置。"
    for created in "${RESTORE_CREATED_FILES[@]-}"; do
        [[ -n $created ]] || continue
        valid_backup_target "$created" && rm -f "$created"
    done
    STATE_BACKUP_DIR=$emergency_backup
    if ! restore_config_files; then
        warn '无法从紧急备份恢复配置文件。'
        recovered=no
    elif ! "$SSHD_BIN" -t 2>/dev/null; then
        warn '紧急备份恢复后未通过 sshd -t。'
        recovered=no
    elif ! reload_ssh; then
        warn '紧急备份恢复后 SSH reload 失败。'
        recovered=no
    else
        for port in $old_ports; do
            if ! wait_for_port "$port"; then
                warn "紧急恢复后原端口 $port 未监听。"
                recovered=no
            fi
        done
    fi
    close_restore_firewall_ports || warn '无法清理由恢复操作新增的主机防火墙规则。'
    rm -f "$STATE_FILE"
    if [[ $recovered == yes ]]; then
        die "${reason}；已自动恢复操作前配置。紧急备份保留在 $emergency_backup"
    fi
    die "${reason}；自动恢复不完整，请通过云控制台检查。紧急备份位于 $emergency_backup"
}

restore_backup_interactive() {
    [[ ! -e $STATE_FILE ]] || die '存在未结束的端口切换状态，请先从菜单执行端口修改以自动处理。'
    if ! select_backup; then
        log '恢复操作已取消。'
        return 0
    fi

    local selected_backup=$SELECTED_BACKUP_DIR expected_ports expected_display
    local emergency_backup actual_ports old_ports port
    local -a expected_port_array old_port_array
    validate_backup_dir "$selected_backup" || die '所选备份无效，拒绝恢复。'
    expected_ports=$(backup_declared_ports "$selected_backup")
    expected_display=${expected_ports//$'\n'/, }
    printf '将恢复备份：%s\n' "$selected_backup"
    printf '预计恢复 SSH 端口：%s\n' "$expected_display"
    warn '恢复也会还原该备份中的 SSH 认证设置；请保持当前 SSH 会话。'
    prompt_yes_no "是否已在云厂商安全组/防火墙放行 ${expected_display}/TCP？" no || {
        log '恢复操作已取消。'
        return 0
    }
    prompt_yes_no '确认开始恢复这份备份？' no || {
        log '恢复操作已取消。'
        return 0
    }

    "$SSHD_BIN" -t || die '当前 SSH 配置本身无法通过 sshd -t，拒绝恢复。'
    detect_service
    collect_config_files
    reject_unsupported_config
    old_ports=$(effective_ports)
    [[ -n $old_ports ]] || die '无法读取当前有效 SSH 端口。'
    old_port_array=()
    while IFS= read -r port; do
        [[ -n $port ]] && old_port_array+=("$port")
    done <<< "$old_ports"
    expected_port_array=()
    while IFS= read -r port; do
        [[ -n $port ]] && expected_port_array+=("$port")
    done <<< "$expected_ports"

    make_backup yes yes
    emergency_backup=$STATE_BACKUP_DIR
    open_restore_firewall_ports "${expected_port_array[@]}"
    comment_active_ports
    if ! restore_selected_snapshot "$selected_backup"; then
        restore_after_restore_failure '无法完整应用所选备份' "$emergency_backup" "$old_ports"
    fi
    if ! "$SSHD_BIN" -t; then
        restore_after_restore_failure '恢复后的 SSH 配置未通过 sshd -t' "$emergency_backup" "$old_ports"
    fi
    actual_ports=$(effective_ports)
    if [[ $actual_ports != "$expected_ports" ]]; then
        restore_after_restore_failure "恢复后的有效端口与备份不一致（实际: ${actual_ports//$'\n'/, }）" "$emergency_backup" "$old_ports"
    fi
    if ! reload_ssh; then
        restore_after_restore_failure '恢复配置后 SSH reload 失败' "$emergency_backup" "$old_ports"
    fi
    for port in "${expected_port_array[@]}"; do
        if ! wait_for_port "$port"; then
            restore_after_restore_failure "恢复后 SSH 未监听端口 $port" "$emergency_backup" "$old_ports"
        fi
    done
    for port in "${old_port_array[@]}"; do
        if ! port_in_list "$port" "${expected_port_array[@]}" && ! wait_for_port_closed "$port"; then
            restore_after_restore_failure "恢复后原端口 $port 仍在监听" "$emergency_backup" "$old_ports"
        fi
    done

    rm -f "$STATE_FILE"
    log "恢复成功：SSH 当前端口为 ${expected_display}。"
    printf '当前实际生效认证设置：\n'
    "$SSHD_BIN" -T 2>/dev/null | grep -E '^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication|pubkeyauthentication|usepam) '
    log "恢复前配置的紧急备份保留在：$emergency_backup"
}

write_state() {
    local temporary
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    temporary=$(mktemp "$STATE_DIR/.state.XXXXXX")
    {
        printf 'version=1\n'
        printf 'status=%s\n' "$STATE_STATUS"
        printf 'new_port=%s\n' "$STATE_NEW_PORT"
        printf 'old_ports=%s\n' "$STATE_OLD_PORTS"
        printf 'backup_dir=%s\n' "$STATE_BACKUP_DIR"
        printf 'service_mode=%s\n' "$STATE_SERVICE_MODE"
        printf 'service_name=%s\n' "$STATE_SERVICE_NAME"
        printf 'firewall_manager=%s\n' "$STATE_FIREWALL_MANAGER"
        printf 'firewall_rule_added=%s\n' "$STATE_FIREWALL_RULE_ADDED"
        printf 'firewall_iptables_families=%s\n' "$STATE_FIREWALL_IPTABLES_FAMILIES"
        printf 'main_password_changed=%s\n' "$STATE_MAIN_PASSWORD_CHANGED"
    } > "$temporary"
    chmod 600 "$temporary"
    chown root:root "$temporary"
    mv "$temporary" "$STATE_FILE"
}

load_state() {
    [[ -f $STATE_FILE ]] || die '没有进行中的端口迁移。'
    local key value version=
    STATE_MAIN_PASSWORD_CHANGED=no
    STATE_FIREWALL_IPTABLES_FAMILIES=
    while IFS='=' read -r key value; do
        case $key in
            version) version=$value ;;
            status) STATE_STATUS=$value ;;
            new_port) STATE_NEW_PORT=$value ;;
            old_ports) STATE_OLD_PORTS=$value ;;
            backup_dir) STATE_BACKUP_DIR=$value ;;
            service_mode) STATE_SERVICE_MODE=$value ;;
            service_name) STATE_SERVICE_NAME=$value ;;
            firewall_manager) STATE_FIREWALL_MANAGER=$value ;;
            firewall_rule_added) STATE_FIREWALL_RULE_ADDED=$value ;;
            firewall_iptables_families) STATE_FIREWALL_IPTABLES_FAMILIES=$value ;;
            main_password_changed) STATE_MAIN_PASSWORD_CHANGED=$value ;;
        esac
    done < "$STATE_FILE"

    [[ $version == 1 ]] || die '不支持的状态文件版本。'
    validate_port "$STATE_NEW_PORT" || die '状态文件中的端口无效。'
    [[ $STATE_OLD_PORTS =~ ^[0-9]+([[:space:]][0-9]+)*$ ]] || die '状态文件中的旧端口列表无效。'
    [[ $STATE_BACKUP_DIR == "$BACKUP_ROOT/"* && -d $STATE_BACKUP_DIR ]] || die '状态文件中的备份目录无效。'
    [[ $STATE_SERVICE_MODE == systemctl || $STATE_SERVICE_MODE == service ]] || die '状态文件中的服务模式无效。'
    [[ $STATE_SERVICE_NAME == ssh || $STATE_SERVICE_NAME == sshd ]] || die '状态文件中的服务名无效。'
    [[ $STATE_FIREWALL_MANAGER == none || $STATE_FIREWALL_MANAGER == ufw || $STATE_FIREWALL_MANAGER == firewalld || $STATE_FIREWALL_MANAGER == iptables ]] || die '状态文件中的防火墙类型无效。'
    [[ $STATE_FIREWALL_RULE_ADDED == yes || $STATE_FIREWALL_RULE_ADDED == no ]] || die '状态文件中的防火墙状态无效。'
    [[ -z $STATE_FIREWALL_IPTABLES_FAMILIES || $STATE_FIREWALL_IPTABLES_FAMILIES =~ ^(iptables|ip6tables)([[:space:]]+(iptables|ip6tables))*$ ]] || die '状态文件中的 iptables 协议族无效。'
    if [[ $STATE_FIREWALL_MANAGER == iptables && $STATE_FIREWALL_RULE_ADDED == yes ]]; then
        [[ -n $STATE_FIREWALL_IPTABLES_FAMILIES ]] || die '状态文件缺少脚本添加的 iptables 协议族。'
    fi
    [[ $STATE_MAIN_PASSWORD_CHANGED == yes || $STATE_MAIN_PASSWORD_CHANGED == no ]] || die '状态文件中的密码配置状态无效。'
}

confirm_cloud_firewall() {
    local port=$1 confirmed=$2 answer
    [[ $confirmed == yes ]] && return 0
    [[ -t 0 ]] || die "请先在云安全组放行 ${port}/TCP，并添加 --cloud-firewall-ready。"
    printf '请确认已在云厂商安全组/防火墙放行 %s/TCP。输入 OPEN 继续: ' "$port"
    read -r answer
    [[ $answer == OPEN ]] || die '未确认云防火墙规则，操作已取消。'
}

iptables_input_is_restrictive() {
    local firewall_command=$1 rules
    if "$firewall_command" -S "$FIREWALL_CHAIN" >/dev/null 2>&1 &&
       "$firewall_command" -C INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1; then
        return 0
    fi
    rules=$("$firewall_command" -S INPUT 2>/dev/null) || return 1
    grep -Eq '^-P INPUT (DROP|REJECT)$' <<< "$rules"
}

debian_apt_supported() {
    [[ -f /etc/debian_version ]] && command -v apt-get >/dev/null 2>&1
}

install_netfilter_persistence() {
    debian_apt_supported || return 1
    log '未检测到 netfilter-persistent，正在自动安装 iptables-persistent。'
    if ! DEBIAN_FRONTEND=noninteractive apt-get update -qq; then
        warn 'apt-get update 失败，将尝试使用现有软件包索引继续安装。'
    fi
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent; then
        warn 'iptables-persistent 自动安装失败。'
        return 1
    fi
    hash -r
    if ! command -v netfilter-persistent >/dev/null 2>&1; then
        warn 'iptables-persistent 安装完成，但未找到 netfilter-persistent 命令。'
        return 1
    fi
    log 'iptables-persistent 已安装。'
}

persist_iptables_rules() {
    local warn_if_missing=${1:-yes}
    if ! command -v netfilter-persistent >/dev/null 2>&1; then
        if [[ $warn_if_missing != yes ]]; then
            return 0
        fi
        if ! install_netfilter_persistence; then
            warn '端口已在当前 iptables/ip6tables 防火墙放行，但无法安装持久化工具；重启后规则可能失效。'
            return 0
        fi
    fi
    if netfilter-persistent save >/dev/null 2>&1; then
        log 'iptables/ip6tables 规则已通过 netfilter-persistent 保存。'
    else
        warn '端口已在当前防火墙放行，但 netfilter-persistent 保存失败；重启后规则可能失效。'
    fi
}

delete_iptables_allow_rules() {
    local port=$1 families=$2 firewall_command target_chain
    for firewall_command in $families; do
        command -v "$firewall_command" >/dev/null 2>&1 || continue
        target_chain=$(iptables_target_chain "$firewall_command")
        if "$firewall_command" -C "$target_chain" -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
            "$firewall_command" -D "$target_chain" -p tcp --dport "$port" -j ACCEPT || return 1
        fi
    done
    [[ -z $families ]] || persist_iptables_rules no
}

iptables_target_chain() {
    local firewall_command=$1
    if "$firewall_command" -S "$FIREWALL_CHAIN" >/dev/null 2>&1 &&
       "$firewall_command" -C INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1; then
        printf '%s\n' "$FIREWALL_CHAIN"
    else
        printf 'INPUT\n'
    fi
}

open_iptables_firewall() {
    local port=$1 firewall_command restrictive=no added=no added_families= target_chain
    for firewall_command in iptables ip6tables; do
        command -v "$firewall_command" >/dev/null 2>&1 || continue
        iptables_input_is_restrictive "$firewall_command" || continue
        restrictive=yes
        target_chain=$(iptables_target_chain "$firewall_command")
        if "$firewall_command" -C "$target_chain" -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
            log "${firewall_command} 已放行 ${port}/TCP。"
            continue
        fi
        if [[ $target_chain == "$FIREWALL_CHAIN" ]]; then
            "$firewall_command" -I "$target_chain" 1 -p tcp --dport "$port" -j ACCEPT || {
                delete_iptables_allow_rules "$port" "$added_families" || true
                die "无法通过 ${firewall_command} 放行 ${port}/TCP。"
            }
        elif ! "$firewall_command" -A INPUT -p tcp --dport "$port" -j ACCEPT; then
            delete_iptables_allow_rules "$port" "$added_families" || true
            die "无法通过 ${firewall_command} 放行 ${port}/TCP。"
        fi
        added=yes
        added_families="${added_families:+$added_families }$firewall_command"
        log "已通过 ${firewall_command} 放行 ${port}/TCP。"
    done
    [[ $restrictive == yes ]] || return 1
    STATE_FIREWALL_MANAGER=iptables
    STATE_FIREWALL_IPTABLES_FAMILIES=$added_families
    if [[ $added == yes ]]; then
        STATE_FIREWALL_RULE_ADDED=yes
        persist_iptables_rules yes
    fi
}

open_host_firewall() {
    local port=$1 skip=$2
    validate_port "$port" || die '防火墙端口必须是 1 到 65535 之间的整数。'
    STATE_FIREWALL_MANAGER=none
    STATE_FIREWALL_RULE_ADDED=no
    STATE_FIREWALL_IPTABLES_FAMILIES=

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        STATE_FIREWALL_MANAGER=ufw
        if ufw status 2>/dev/null | grep -Eq "^${port}/tcp[[:space:]]"; then
            log "UFW 已放行 ${port}/TCP。"
        else
            ufw allow "${port}/tcp" comment 'safe-ssh-port switch'
            STATE_FIREWALL_RULE_ADDED=yes
        fi
        return 0
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        STATE_FIREWALL_MANAGER=firewalld
        if firewall-cmd --quiet --query-port="${port}/tcp"; then
            log "firewalld 已放行 ${port}/TCP。"
        else
            firewall-cmd --permanent --add-port="${port}/tcp"
            firewall-cmd --reload
            STATE_FIREWALL_RULE_ADDED=yes
        fi
        return 0
    fi

    if [[ $skip == yes ]]; then
        warn '已按参数跳过主机防火墙管理。'
        return 0
    fi

    if open_iptables_firewall "$port"; then
        return 0
    fi
    if command -v nft >/dev/null 2>&1 &&
       nft list ruleset 2>/dev/null | grep -Eq 'hook input[^;]*;[^}]*policy (drop|reject)'; then
        die '检测到自定义 nftables 默认拒绝策略；请先手动放行新端口，再使用 --skip-host-firewall。'
    fi

    log '未检测到启用中的 UFW、firewalld 或 restrictive iptables；未修改主机防火墙。'
}

close_staged_firewall_rule() {
    [[ $STATE_FIREWALL_RULE_ADDED == yes ]] || return 0
    case $STATE_FIREWALL_MANAGER in
        ufw) ufw --force delete allow "${STATE_NEW_PORT}/tcp" >/dev/null ;;
        firewalld)
            firewall-cmd --permanent --remove-port="${STATE_NEW_PORT}/tcp" >/dev/null
            firewall-cmd --reload >/dev/null
            ;;
        iptables)
            delete_iptables_allow_rules "$STATE_NEW_PORT" "$STATE_FIREWALL_IPTABLES_FAMILIES"
            ;;
    esac
}

detect_firewall_backend() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        printf 'ufw\n'
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        printf 'firewalld\n'
    elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT >/dev/null 2>&1; then
        printf 'iptables\n'
    elif command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
        printf 'nftables\n'
    else
        printf 'none\n'
    fi
}

protected_ssh_ports() {
    {
        effective_ports || true
        if [[ ${SSH_CONNECTION:-} =~ ^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+([0-9]+)$ ]]; then
            printf '%s\n' "${BASH_REMATCH[1]}"
        fi
    } | awk '$1 ~ /^[0-9]+$/ && $1 >= 1 && $1 <= 65535 { print $1 }' | sort -nu
}

public_listeners() {
    local protocol option
    for protocol in tcp udp; do
        if [[ $protocol == tcp ]]; then option=-ltnp; else option=-lunp; fi
        "$SS_BIN" -H "$option" 2>/dev/null | awk -v protocol="$protocol" '
            {
                endpoint=$4
                port=endpoint
                sub(/^.*:/, "", port)
                address=endpoint
                sub(/:[^:]*$/, "", address)
                gsub(/^\[/, "", address)
                gsub(/\]$/, "", address)
                numeric_port=port + 0
                if (port !~ /^[0-9]+$/ || numeric_port < 1 || numeric_port > 65535) next
                if (address == "::1" || address ~ /^127\./) next
                print protocol, numeric_port
            }
        '
    done | sort -k1,1 -k2,2n -u
}

iptables_rule_records_for_command() {
    local command_name=$1 family=$2
    if "$command_name" -S "$FIREWALL_CHAIN" >/dev/null 2>&1 &&
       "$command_name" -C INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1; then
        "$command_name" -S "$FIREWALL_CHAIN" 2>/dev/null
    else
        "$command_name" -S INPUT 2>/dev/null
    fi | awk -v family="$family" '
        $1 == "-A" {
            protocol=""; port=""; verdict=""
            for (i=1; i<=NF; i++) {
                if ($i == "-p" && i < NF) protocol=$(i+1)
                if ($i == "--dport" && i < NF) port=$(i+1)
                if ($i == "-j" && i < NF) verdict=$(i+1)
            }
            if ((protocol == "tcp" || protocol == "udp") &&
                port ~ /^[0-9]+$/ && port >= 1 && port <= 65535 &&
                (verdict == "ACCEPT" || verdict == "DROP" || verdict == "REJECT")) {
                print family, verdict, protocol, port + 0
            }
        }
    '
}

ufw_rule_records() {
    ufw status 2>/dev/null | awk '
        {
            split($1, spec, "/")
            port=spec[1]; protocol=tolower(spec[2]); family="IPv4"
            if ($2 == "(v6)") { family="IPv6"; verdict=toupper($3) }
            else verdict=toupper($2)
            if (port !~ /^[0-9]+$/ || (protocol != "tcp" && protocol != "udp")) next
            if (verdict == "ALLOW") verdict="ACCEPT"
            else if (verdict == "DENY" || verdict == "REJECT") verdict="DROP"
            else next
            print family, verdict, protocol, port + 0
        }
    '
}

firewalld_rule_records() {
    local item
    for item in $(firewall-cmd --list-ports 2>/dev/null || true); do
        if [[ $item =~ ^([0-9]+)/(tcp|udp)$ ]]; then
            printf '双栈 ACCEPT %s %s\n' "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}"
        fi
    done
    firewall-cmd --list-rich-rules 2>/dev/null | awk '
        {
            family="双栈"; protocol=""; port=""; verdict=""
            for (i=1; i<=NF; i++) {
                field=$i
                gsub(/"/, "", field)
                if (field ~ /^family=/) {
                    sub(/^family=/, "", field)
                    family=(field == "ipv6") ? "IPv6" : "IPv4"
                } else if (field ~ /^protocol=/) {
                    sub(/^protocol=/, "", field); protocol=field
                } else if (field ~ /^port=/) {
                    sub(/^port=/, "", field); port=field
                } else if (field == "drop" || field == "reject") {
                    verdict="DROP"
                }
            }
            if ((protocol == "tcp" || protocol == "udp") && port ~ /^[0-9]+$/ && verdict == "DROP") {
                print family, verdict, protocol, port + 0
            }
        }
    '
}

firewall_rule_records() {
    local backend=${1:-$(detect_firewall_backend)}
    case $backend in
        iptables)
            if command -v iptables >/dev/null 2>&1; then
                iptables_rule_records_for_command iptables IPv4
            fi
            if command -v ip6tables >/dev/null 2>&1; then
                iptables_rule_records_for_command ip6tables IPv6
            fi
            ;;
        ufw) ufw_rule_records ;;
        firewalld) firewalld_rule_records ;;
    esac | sort -k2,2 -k3,3 -k4,4n -u
}

show_firewall_port_overview() {
    local backend records ports protection=不适用 protected_families= default_allowed_families=
    local policy command_name family family_protected
    backend=$(detect_firewall_backend)
    records=$(firewall_rule_records "$backend" || true)

    printf '\n防火墙端口规则\n'
    printf '%s\n' '----------------------------------------'
    printf '后端: %s\n' "$backend"
    printf 'SSH 保护端口: '
    protected_ssh_ports | awk 'BEGIN { first=1 } { printf "%s%s/tcp", first ? "" : ", ", $1; first=0 } END { if (first) printf "未知"; print "" }'

    if [[ $backend == iptables ]]; then
        for command_name in iptables ip6tables; do
            command -v "$command_name" >/dev/null 2>&1 || continue
            if [[ $command_name == iptables ]]; then family=IPv4; else family=IPv6; fi
            family_protected=no
            if "$command_name" -S "$FIREWALL_CHAIN" >/dev/null 2>&1 &&
               "$command_name" -C INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1; then
                protected_families="${protected_families:+$protected_families+}$family"
                family_protected=yes
            fi
            policy=$("$command_name" -S INPUT 2>/dev/null | awk '$1=="-P" && $2=="INPUT" {print $3; exit}')
            printf '%s 默认入站策略: %s\n' "$family" "${policy:-未知}"
            if [[ $policy == ACCEPT && $family_protected == no ]]; then
                default_allowed_families="${default_allowed_families:+$default_allowed_families+}$family"
            fi
        done
        if [[ -n $protected_families ]]; then
            protection="已启用（${protected_families}）"
        else
            protection=未启用
        fi
    fi
    printf '入站保护模式: %s\n' "$protection"
    if [[ -n $protected_families ]]; then
        printf '  %s 中未列入保留清单的宿主机入站将被统一拒绝。\n' "$protected_families"
    fi
    if [[ -n $default_allowed_families ]]; then
        printf '  注意：%s 默认策略为 ACCEPT，未列出的端口也可能被允许。\n' "$default_allowed_families"
    fi

    printf '\n明确放行的端口：\n'
    ports=$(awk '$2=="ACCEPT" {printf "  %-6s %s/%s\n", $1, $4, $3}' <<< "$records")
    if [[ -n $ports ]]; then printf '%s\n' "$ports"; else printf '  （未检测到明确的单端口放行规则）\n'; fi

    printf '\n明确关闭的端口：\n'
    ports=$(awk '$2=="DROP" || $2=="REJECT" {printf "  %-6s %s/%s\n", $1, $4, $3}' <<< "$records")
    if [[ -n $ports ]]; then printf '%s\n' "$ports"; else printf '  （没有指定关闭的单端口规则）\n'; fi

    if [[ $backend == nftables ]]; then
        printf '\n原生 nftables 规则结构不统一，请从“详细状态”查看原始规则。\n'
    elif [[ $backend == none ]]; then
        printf '\n未检测到可管理的主机防火墙。\n'
    fi
}

current_ssh_client_ip() {
    if [[ ${SSH_CONNECTION:-} =~ ^([^[:space:]]+)[[:space:]] ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    fi
}

install_ipset_tool() {
    command -v ipset >/dev/null 2>&1 && return 0
    log 'IP/国家规则需要 ipset。'
    prompt_yes_no '是否现在安装 ipset（推荐）？' yes || return 1
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq || warn 'apt-get update 失败，将尝试现有软件包索引。'
        DEBIAN_FRONTEND=noninteractive apt-get install -y ipset || return 1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ipset || return 1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y ipset || return 1
    else
        warn '无法识别软件包管理器，请手动安装 ipset。'
        return 1
    fi
    hash -r
    command -v ipset >/dev/null 2>&1
}

require_access_control_backend() {
    [[ $(detect_firewall_backend) == iptables ]] || {
        warn 'IP/国家黑白名单目前仅支持 iptables/iptables-nft 后端。'
        return 1
    }
    install_ipset_tool || {
        warn 'ipset 不可用，无法管理 IP/国家规则。'
        return 1
    }
}

install_country_download_tool() {
    command -v curl >/dev/null 2>&1 && return 0
    log '国家规则需要 curl 下载 HTTPS 国家网段数据。'
    prompt_yes_no '是否现在安装 curl（推荐）？' yes || return 1
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq || warn 'apt-get update 失败，将尝试现有软件包索引。'
        DEBIAN_FRONTEND=noninteractive apt-get install -y curl || return 1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl || return 1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl || return 1
    else
        warn '无法识别软件包管理器，请手动安装 curl。'
        return 1
    fi
    hash -r
    command -v curl >/dev/null 2>&1
}

VALIDATED_IP_FAMILY=

validate_ip_or_cidr() {
    local value=${1:-} family family_option temp_set result=1
    VALIDATED_IP_FAMILY=
    [[ $value != '0.0.0.0/0' && $value != '::/0' ]] || return 1
    if [[ $value == *:* ]]; then
        [[ $value =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ ]] || return 1
        family=6
        family_option=inet6
    else
        [[ $value =~ ^[0-9.]+(/[0-9]{1,2})?$ ]] || return 1
        family=4
        family_option=inet
    fi
    printf -v temp_set 'at_val%s_%s_%s' "$family" "$$" "$RANDOM"
    ipset create "$temp_set" hash:net family "$family_option" maxelem 4 >/dev/null 2>&1 || return 1
    if ipset add "$temp_set" "$value" >/dev/null 2>&1; then
        VALIDATED_IP_FAMILY=$family
        result=0
    fi
    ipset destroy "$temp_set" >/dev/null 2>&1 || true
    return "$result"
}

network_contains_ip() {
    local network=$1 ip=$2 family family_option temp_set result=1
    if [[ $network == *:* ]]; then family=6; family_option=inet6; else family=4; family_option=inet; fi
    if [[ $ip == *:* ]]; then [[ $family == 6 ]] || return 1; else [[ $family == 4 ]] || return 1; fi
    printf -v temp_set 'at_tst%s_%s_%s' "$family" "$$" "$RANDOM"
    ipset create "$temp_set" hash:net family "$family_option" maxelem 4 >/dev/null 2>&1 || return 1
    if ipset add "$temp_set" "$network" >/dev/null 2>&1 &&
       ipset test "$temp_set" "$ip" >/dev/null 2>&1; then
        result=0
    fi
    ipset destroy "$temp_set" >/dev/null 2>&1 || true
    return "$result"
}

ensure_access_framework() {
    local command_name=$1 chain
    for chain in "$ACCESS_CHAIN" "$IP_ALLOW_CHAIN" "$IP_DENY_CHAIN" "$COUNTRY_CHAIN"; do
        if ! "$command_name" -S "$chain" >/dev/null 2>&1; then
            "$command_name" -N "$chain" || return 1
        fi
    done
    while "$command_name" -C INPUT -j "$ACCESS_CHAIN" >/dev/null 2>&1; do
        "$command_name" -D INPUT -j "$ACCESS_CHAIN" || return 1
    done
    "$command_name" -F "$ACCESS_CHAIN" || return 1
    "$command_name" -A "$ACCESS_CHAIN" -i lo -j RETURN || return 1
    "$command_name" -A "$ACCESS_CHAIN" -j "$IP_ALLOW_CHAIN" || return 1
    "$command_name" -A "$ACCESS_CHAIN" -j "$IP_DENY_CHAIN" || return 1
    "$command_name" -A "$ACCESS_CHAIN" -j "$COUNTRY_CHAIN" || return 1
    "$command_name" -A "$ACCESS_CHAIN" -j RETURN || return 1
    "$command_name" -I INPUT 1 -j "$ACCESS_CHAIN"
}

managed_country_set_names() {
    command -v ipset >/dev/null 2>&1 || return 0
    ipset list -name 2>/dev/null | awk '
        /^at_cc_[a-z][a-z]_[ab][46]$/ { print }
    ' | sort -u
}

persist_ipset_state() {
    local set_name state_dir state_tmp service_dir service_tmp ipset_path
    local -a set_names=()
    while IFS= read -r set_name; do
        [[ -n $set_name ]] && set_names+=("$set_name")
    done < <(managed_country_set_names)
    ((${#set_names[@]} > 0)) || {
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable allentool-ipset-restore.service >/dev/null 2>&1 || true
        fi
        rm -f "$IPSET_STATE_FILE" "$IPSET_SERVICE_FILE"
        command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
        return 0
    }

    state_dir=${IPSET_STATE_FILE%/*}
    service_dir=${IPSET_SERVICE_FILE%/*}
    mkdir -p "$state_dir" "$service_dir" || return 1
    state_tmp=$(mktemp "${state_dir}/.ipsets.allentool.XXXXXX") || return 1
    for set_name in "${set_names[@]}"; do
        if ! ipset save "$set_name" >> "$state_tmp"; then
            rm -f "$state_tmp"
            return 1
        fi
    done
    chmod 600 "$state_tmp" || { rm -f "$state_tmp"; return 1; }
    mv -f "$state_tmp" "$IPSET_STATE_FILE" || { rm -f "$state_tmp"; return 1; }

    ipset_path=$(command -v ipset)
    service_tmp=$(mktemp "${service_dir}/.allentool-ipset-restore.XXXXXX") || return 1
    cat > "$service_tmp" <<EOF
[Unit]
Description=Restore allentool country ipsets
DefaultDependencies=no
After=local-fs.target
Before=netfilter-persistent.service

[Service]
Type=oneshot
ExecStart=$ipset_path restore -exist -file $IPSET_STATE_FILE
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$service_tmp" || { rm -f "$service_tmp"; return 1; }
    mv -f "$service_tmp" "$IPSET_SERVICE_FILE" || { rm -f "$service_tmp"; return 1; }
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || warn '无法刷新 systemd 单元。'
        systemctl enable allentool-ipset-restore.service >/dev/null 2>&1 ||
            warn '无法自动启用国家集合恢复服务。'
    fi
}

persist_access_control() {
    if ! persist_ipset_state; then
        warn '国家 IP 集合持久化失败；当前规则仍然生效，但重启后国家规则可能失效。'
    fi
    persist_iptables_rules yes
}

remove_ip_access_rule() {
    local command_name=$1 chain=$2 source=$3 comment=$4 verdict=$5 removed=no
    while "$command_name" -C "$chain" -s "$source" -m comment --comment "$comment" -j "$verdict" >/dev/null 2>&1; do
        "$command_name" -D "$chain" -s "$source" -m comment --comment "$comment" -j "$verdict" || return 1
        removed=yes
    done
    [[ $removed == yes ]] && ACCESS_RULE_REMOVED=yes
}

apply_ip_access_rule() {
    local action=$1 source=$2 command_name chain verdict opposite_chain opposite_comment opposite_verdict
    local client_ip
    require_access_control_backend || return 1
    [[ $action == allow || $action == deny ]] || { warn 'IP 规则动作无效。'; return 1; }
    validate_ip_or_cidr "$source" || {
        warn 'IP/CIDR 格式无效，或使用了不允许的全网段 0.0.0.0/0、::/0。'
        return 1
    }
    if [[ $VALIDATED_IP_FAMILY == 6 ]]; then command_name=ip6tables; else command_name=iptables; fi
    command -v "$command_name" >/dev/null 2>&1 || {
        warn "缺少 ${command_name}，无法管理该协议族。"
        return 1
    }
    if [[ $action == deny ]]; then
        client_ip=$(current_ssh_client_ip)
        if [[ -n $client_ip ]] && network_contains_ip "$source" "$client_ip"; then
            warn "拒绝拉黑 ${source}：它包含当前 SSH 客户端 ${client_ip}。"
            return 1
        fi
        chain=$IP_DENY_CHAIN; verdict=DROP
        opposite_chain=$IP_ALLOW_CHAIN; opposite_comment=allentool-ip-allow; opposite_verdict=ACCEPT
    else
        chain=$IP_ALLOW_CHAIN; verdict=ACCEPT
        opposite_chain=$IP_DENY_CHAIN; opposite_comment=allentool-ip-deny; opposite_verdict=DROP
    fi
    ensure_access_framework "$command_name" || return 1
    remove_ip_access_rule "$command_name" "$opposite_chain" "$source" "$opposite_comment" "$opposite_verdict" || return 1
    local comment="allentool-ip-${action}"
    if ! "$command_name" -C "$chain" -s "$source" -m comment --comment "$comment" -j "$verdict" >/dev/null 2>&1; then
        "$command_name" -I "$chain" 1 -s "$source" -m comment --comment "$comment" -j "$verdict" || return 1
    fi
    persist_access_control
    if [[ $action == allow ]]; then log "已加入 IP 白名单：$source"; else log "已加入 IP 黑名单：$source"; fi
}

delete_ip_access_rules() {
    local source=$1 command_name
    require_access_control_backend || return 1
    validate_ip_or_cidr "$source" || {
        warn 'IP/CIDR 格式无效。'
        return 1
    }
    if [[ $VALIDATED_IP_FAMILY == 6 ]]; then command_name=ip6tables; else command_name=iptables; fi
    ensure_access_framework "$command_name" || return 1
    ACCESS_RULE_REMOVED=no
    remove_ip_access_rule "$command_name" "$IP_ALLOW_CHAIN" "$source" allentool-ip-allow ACCEPT || return 1
    remove_ip_access_rule "$command_name" "$IP_DENY_CHAIN" "$source" allentool-ip-deny DROP || return 1
    persist_access_control
    if [[ $ACCESS_RULE_REMOVED == yes ]]; then log "已清除 IP 规则：$source"; else log "未找到 allentool 管理的 IP 规则：$source"; fi
}

ip_access_rule_records_for_command() {
    local command_name=$1 family=$2 chain action
    for chain in "$IP_ALLOW_CHAIN" "$IP_DENY_CHAIN"; do
        if [[ $chain == "$IP_ALLOW_CHAIN" ]]; then action=ALLOW; else action=DENY; fi
        "$command_name" -S "$chain" 2>/dev/null | awk -v family="$family" -v action="$action" '
            $1=="-A" {
                source=""
                for (i=1; i<=NF; i++) if ($i=="-s" && i<NF) source=$(i+1)
                if (source != "") print action, family, source
            }
        ' || true
    done
}

ip_access_rule_records() {
    command -v iptables >/dev/null 2>&1 && ip_access_rule_records_for_command iptables IPv4
    command -v ip6tables >/dev/null 2>&1 && ip_access_rule_records_for_command ip6tables IPv6
}

show_ip_access_summary() {
    local records values
    records=$(ip_access_rule_records | sort -u)
    printf '\nIP 黑白名单\n%s\n' '----------------------------------------'
    printf '白名单（允许全部宿主机端口）：\n'
    values=$(awk '$1=="ALLOW" {printf "  %-6s %s\n", $2, $3}' <<< "$records")
    if [[ -n $values ]]; then printf '%s\n' "$values"; else printf '  （空）\n'; fi
    printf '黑名单（拒绝全部宿主机端口）：\n'
    values=$(awk '$1=="DENY" {printf "  %-6s %s\n", $2, $3}' <<< "$records")
    if [[ -n $values ]]; then printf '%s\n' "$values"; else printf '  （空）\n'; fi
}

prompt_ip_or_cidr() {
    local prompt=$1 answer
    SELECTED_IP_OR_CIDR=
    while true; do
        printf '%s（输入 q 取消）: ' "$prompt"
        read -r answer
        [[ $answer == q || $answer == Q ]] && return 1
        if validate_ip_or_cidr "$answer"; then SELECTED_IP_OR_CIDR=$answer; return 0; fi
        printf 'IP/CIDR 无效，请重新输入。\n'
    done
}

ip_access_menu() {
    local choice
    require_access_control_backend || return 0
    while true; do
        show_ip_access_summary
        printf '  1. 添加 IP 白名单       2. 添加 IP 黑名单\n'
        printf '  3. 清除指定 IP 规则     0. 返回\n'
        printf '请选择 [0-3]: '
        read -r choice
        case $choice in
            1) prompt_ip_or_cidr '请输入允许的 IP 或 CIDR' && apply_ip_access_rule allow "$SELECTED_IP_OR_CIDR" ;;
            2) prompt_ip_or_cidr '请输入拒绝的 IP 或 CIDR' && apply_ip_access_rule deny "$SELECTED_IP_OR_CIDR" ;;
            3) prompt_ip_or_cidr '请输入要清除的 IP 或 CIDR' && delete_ip_access_rules "$SELECTED_IP_OR_CIDR" ;;
            0|q|Q) return 0 ;;
            *) printf '选项无效，请重新输入。\n' ;;
        esac
    done
}

VALIDATED_COUNTRY_CODE=

validate_country_code() {
    local code
    code=$(lowercase "${1:-}")
    VALIDATED_COUNTRY_CODE=
    [[ $code =~ ^[a-z]{2}$ ]] || return 1
    [[ " $ISO_ALPHA2_CODES " == *" $code "* ]] || return 1
    VALIDATED_COUNTRY_CODE=$code
}

country_set_name() {
    local mode=$1 code=$2 family=$3 marker
    if [[ $mode == allow ]]; then marker=a; else marker=b; fi
    printf 'at_cc_%s_%s%s\n' "$code" "$marker" "$family"
}

country_set_names_for() {
    local mode=$1 family=$2 marker
    if [[ $mode == allow ]]; then marker=a; else marker=b; fi
    managed_country_set_names | awk -v suffix="_${marker}${family}" 'index($0, suffix) == length($0)-length(suffix)+1'
}

country_access_records() {
    local set_name code marker family mode count
    while IFS= read -r set_name; do
        [[ $set_name =~ ^at_cc_([a-z]{2})_([ab])([46])$ ]] || continue
        code=${BASH_REMATCH[1]}
        marker=${BASH_REMATCH[2]}
        family=${BASH_REMATCH[3]}
        if [[ $marker == a ]]; then mode=ALLOW; else mode=BLOCK; fi
        count=$(ipset list "$set_name" 2>/dev/null | awk -F ': ' '$1=="Number of entries" {print $2; exit}')
        printf '%s IPv%s %s %s\n' "$mode" "$family" "${count:-0}" "$(uppercase "$code")"
    done < <(managed_country_set_names)
}

show_country_access_summary() {
    local records values
    records=$(country_access_records | sort -k1,1 -k4,4 -k2,2)
    printf '\n国家黑白名单\n%s\n' '----------------------------------------'
    printf '白名单（命中后继续检查端口；未命中国家拒绝）：\n'
    values=$(awk '$1=="ALLOW" {printf "  %-4s %-6s %s 个网段\n", $4, $2, $3}' <<< "$records")
    if [[ -n $values ]]; then printf '%s\n' "$values"; else printf '  （空，未启用仅允许国家模式）\n'; fi
    printf '黑名单（命中国家直接拒绝）：\n'
    values=$(awk '$1=="BLOCK" {printf "  %-4s %-6s %s 个网段\n", $4, $2, $3}' <<< "$records")
    if [[ -n $values ]]; then printf '%s\n' "$values"; else printf '  （空）\n'; fi
    printf '数据源: IPdeny HTTPS aggregated（IPv4 + IPv6）\n'
}

show_access_control_overview() {
    local backend ip_records country_records values
    backend=$(detect_firewall_backend)
    [[ $backend == iptables ]] || return 0
    ip_records=$(ip_access_rule_records | sort -u)
    country_records=$(country_access_records | sort -u)
    printf '\n来源访问规则\n%s\n' '----------------------------------------'
    values=$(awk '$1=="ALLOW" {printf "%s%s:%s", found ? ", " : "", $2, $3; found=1}' <<< "$ip_records")
    printf 'IP 白名单: %s\n' "${values:-（空）}"
    values=$(awk '$1=="DENY" {printf "%s%s:%s", found ? ", " : "", $2, $3; found=1}' <<< "$ip_records")
    printf 'IP 黑名单: %s\n' "${values:-（空）}"
    values=$(awk '$1=="ALLOW" {print $4}' <<< "$country_records" | sort -u | awk '{printf "%s%s", found ? ", " : "", $1; found=1}')
    printf '国家白名单: %s\n' "${values:-（空）}"
    values=$(awk '$1=="BLOCK" {print $4}' <<< "$country_records" | sort -u | awk '{printf "%s%s", found ? ", " : "", $1; found=1}')
    printf '国家黑名单: %s\n' "${values:-（空）}"
}

prompt_country_code() {
    local answer
    SELECTED_COUNTRY_CODE=
    while true; do
        printf '请输入两位国家代码（如 CN、US，输入 q 取消）: '
        read -r answer
        [[ $answer == q || $answer == Q ]] && return 1
        if validate_country_code "$answer"; then
            SELECTED_COUNTRY_CODE=$VALIDATED_COUNTRY_CODE
            return 0
        fi
        printf '国家代码无效，请输入有效的 ISO 3166-1 alpha-2 代码。\n'
    done
}

download_country_file() {
    local code=$1 family=$2 output=$3 url
    if [[ $family == 4 ]]; then
        url="${IPDENY_V4_BASE}/${code}-aggregated.zone"
    else
        url="${IPDENY_V6_BASE}/${code}-aggregated.zone"
    fi
    curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 120 "$url" -o "$output"
}

build_country_temp_set() {
    local file=$1 family=$2 temp_set=$3 family_option restore_file
    [[ -s $file ]] || return 1
    if [[ $family == 6 ]]; then family_option=inet6; else family_option=inet; fi
    ipset create "$temp_set" hash:net family "$family_option" hashsize 4096 maxelem 200000 >/dev/null 2>&1 || return 1
    restore_file=$(mktemp) || { ipset destroy "$temp_set" >/dev/null 2>&1 || true; return 1; }
    if ! awk -v set_name="$temp_set" -v family="$family" '
        BEGIN { valid=1; count=0 }
        {
            sub(/\r$/, "")
            if (NF != 1) { valid=0; next }
            if (family == 4 && $1 !~ /^[0-9.]+\/[0-9]{1,2}$/) { valid=0; next }
            if (family == 6 && $1 !~ /^[0-9A-Fa-f:]+\/[0-9]{1,3}$/) { valid=0; next }
            print "add", set_name, $1
            count++
        }
        END { if (!valid || count == 0) exit 1 }
    ' "$file" > "$restore_file"; then
        rm -f "$restore_file"
        ipset destroy "$temp_set" >/dev/null 2>&1 || true
        return 1
    fi
    if ! ipset restore -file "$restore_file" >/dev/null 2>&1; then
        rm -f "$restore_file"
        ipset destroy "$temp_set" >/dev/null 2>&1 || true
        return 1
    fi
    rm -f "$restore_file"
}

rollback_activated_country_set() {
    local temp_set=$1 permanent_set=$2 had_old=$3
    if [[ $had_old == yes ]]; then
        ipset swap "$temp_set" "$permanent_set" >/dev/null 2>&1 || return 1
        ipset destroy "$temp_set" >/dev/null 2>&1 || true
    else
        ipset rename "$permanent_set" "$temp_set" >/dev/null 2>&1 || return 1
        ipset destroy "$temp_set" >/dev/null 2>&1 || true
    fi
}

activate_country_temp_sets() {
    local temp4=$1 set4=$2 temp6=$3 set6=$4 old4=no old6=no
    if ipset list "$set4" >/dev/null 2>&1; then
        old4=yes
        ipset swap "$temp4" "$set4" || return 1
    else
        ipset rename "$temp4" "$set4" || return 1
    fi

    if ipset list "$set6" >/dev/null 2>&1; then
        old6=yes
        if ! ipset swap "$temp6" "$set6"; then
            rollback_activated_country_set "$temp4" "$set4" "$old4" || true
            return 1
        fi
    elif ! ipset rename "$temp6" "$set6"; then
        rollback_activated_country_set "$temp4" "$set4" "$old4" || true
        return 1
    fi

    [[ $old4 == no ]] || ipset destroy "$temp4" >/dev/null 2>&1 || true
    [[ $old6 == no ]] || ipset destroy "$temp6" >/dev/null 2>&1 || true
}

flush_country_chains() {
    local command_name
    for command_name in iptables ip6tables; do
        command -v "$command_name" >/dev/null 2>&1 || continue
        if "$command_name" -S "$COUNTRY_CHAIN" >/dev/null 2>&1; then
            "$command_name" -F "$COUNTRY_CHAIN" || return 1
            "$command_name" -A "$COUNTRY_CHAIN" -j RETURN || return 1
        fi
    done
}

rebuild_country_chain() {
    local command_name=$1 family=$2 set_name code client_ip has_allow=no
    ensure_access_framework "$command_name" || return 1
    "$command_name" -F "$COUNTRY_CHAIN" || return 1
    if [[ -n $(country_set_names_for allow "$family") ]]; then has_allow=yes; fi
    client_ip=$(current_ssh_client_ip)
    if [[ $has_allow == yes && -n $client_ip ]] &&
       { [[ $family == 4 && $client_ip != *:* ]] || [[ $family == 6 && $client_ip == *:* ]]; }; then
        "$command_name" -A "$COUNTRY_CHAIN" -s "$client_ip" -m comment --comment allentool-country-ssh -j RETURN || return 1
    fi
    while IFS= read -r set_name; do
        [[ -n $set_name ]] || continue
        code=${set_name#at_cc_}; code=${code%%_*}
        "$command_name" -A "$COUNTRY_CHAIN" -m set --match-set "$set_name" src \
            -m comment --comment "allentool-country-block-${code}" -j DROP || return 1
    done < <(country_set_names_for block "$family")
    while IFS= read -r set_name; do
        [[ -n $set_name ]] || continue
        code=${set_name#at_cc_}; code=${code%%_*}
        "$command_name" -A "$COUNTRY_CHAIN" -m set --match-set "$set_name" src \
            -m comment --comment "allentool-country-allow-${code}" -j RETURN || return 1
    done < <(country_set_names_for allow "$family")
    if [[ $has_allow == yes ]]; then
        "$command_name" -A "$COUNTRY_CHAIN" -m comment --comment allentool-country-allow-guard -j DROP || return 1
    fi
    "$command_name" -A "$COUNTRY_CHAIN" -j RETURN
}

rebuild_all_country_chains() {
    command -v iptables >/dev/null 2>&1 && rebuild_country_chain iptables 4 || return 1
    if command -v ip6tables >/dev/null 2>&1; then
        rebuild_country_chain ip6tables 6 || return 1
    fi
}

apply_country_access_rule() {
    local mode=$1 code=$2 save_after=${3:-yes} temp_dir file4 file6 temp4 temp6 set4 set6 opposite4 opposite6
    local client_ip opposite_mode
    [[ $mode == allow || $mode == block ]] || return 1
    require_access_control_backend || return 1
    install_country_download_tool || { warn 'curl 不可用，无法下载国家网段。'; return 1; }
    validate_country_code "$code" || { warn '国家代码无效。'; return 1; }
    code=$VALIDATED_COUNTRY_CODE
    command -v ip6tables >/dev/null 2>&1 || { warn '缺少 ip6tables；为避免只限制 IPv4 造成绕过，拒绝应用国家规则。'; return 1; }

    temp_dir=$(mktemp -d) || return 1
    file4=$temp_dir/ipv4.zone; file6=$temp_dir/ipv6.zone
    temp4="at_tmp4_${$}_${RANDOM}"; temp6="at_tmp6_${$}_${RANDOM}"
    if ! download_country_file "$code" 4 "$file4" || ! download_country_file "$code" 6 "$file6" ||
       ! build_country_temp_set "$file4" 4 "$temp4" || ! build_country_temp_set "$file6" 6 "$temp6"; then
        ipset destroy "$temp4" >/dev/null 2>&1 || true
        ipset destroy "$temp6" >/dev/null 2>&1 || true
        rm -r -- "$temp_dir"
        warn "$(uppercase "$code") 国家网段下载或完整校验失败；没有替换现有规则。"
        return 1
    fi
    rm -r -- "$temp_dir"

    client_ip=$(current_ssh_client_ip)
    if [[ $mode == block && -n $client_ip ]]; then
        if { [[ $client_ip == *:* ]] && ipset test "$temp6" "$client_ip" >/dev/null 2>&1; } ||
           { [[ $client_ip != *:* ]] && ipset test "$temp4" "$client_ip" >/dev/null 2>&1; }; then
            ipset destroy "$temp4" >/dev/null 2>&1 || true
            ipset destroy "$temp6" >/dev/null 2>&1 || true
            warn "拒绝屏蔽 $(uppercase "$code")：当前 SSH 客户端 ${client_ip} 位于该国家网段。"
            return 1
        fi
    fi

    set4=$(country_set_name "$mode" "$code" 4); set6=$(country_set_name "$mode" "$code" 6)
    if [[ $mode == allow ]]; then opposite_mode=block; else opposite_mode=allow; fi
    opposite4=$(country_set_name "$opposite_mode" "$code" 4)
    opposite6=$(country_set_name "$opposite_mode" "$code" 6)
    if ! activate_country_temp_sets "$temp4" "$set4" "$temp6" "$set6"; then
        ipset destroy "$temp4" >/dev/null 2>&1 || true
        ipset destroy "$temp6" >/dev/null 2>&1 || true
        warn '国家 IPv4/IPv6 集合切换失败；已尝试恢复原有集合。'
        return 1
    fi
    flush_country_chains || return 1
    ipset destroy "$opposite4" >/dev/null 2>&1 || true
    ipset destroy "$opposite6" >/dev/null 2>&1 || true
    rebuild_all_country_chains || return 1
    [[ $save_after == yes ]] && persist_access_control
    if [[ $mode == allow ]]; then
        log "已加入国家白名单：$(uppercase "$code")（IPv4 + IPv6）。"
    else
        log "已加入国家黑名单：$(uppercase "$code")（IPv4 + IPv6）。"
    fi
}

remove_country_access_rule() {
    local code=$1 mode family set_name removed=no
    require_access_control_backend || return 1
    validate_country_code "$code" || { warn '国家代码无效。'; return 1; }
    code=$VALIDATED_COUNTRY_CODE
    flush_country_chains || return 1
    for mode in allow block; do
        for family in 4 6; do
            set_name=$(country_set_name "$mode" "$code" "$family")
            if ipset list "$set_name" >/dev/null 2>&1; then
                ipset destroy "$set_name" || return 1
                removed=yes
            fi
        done
    done
    rebuild_all_country_chains || return 1
    persist_access_control
    if [[ $removed == yes ]]; then log "已解除 $(uppercase "$code") 的国家限制。"; else log "未找到 $(uppercase "$code") 的国家规则。"; fi
}

refresh_country_access_rules() {
    local record mode code failed=no found=no
    require_access_control_backend || return 1
    install_country_download_tool || return 1
    while read -r mode code; do
        [[ -n $mode && -n $code ]] || continue
        found=yes
        if [[ $mode == ALLOW ]]; then mode=allow; else mode=block; fi
        apply_country_access_rule "$mode" "$(lowercase "$code")" no || failed=yes
    done < <(country_access_records | awk '{print $1, $4}' | sort -u)
    [[ $found == yes ]] || { log '当前没有需要刷新的国家规则。'; return 0; }
    persist_access_control
    [[ $failed == no ]] || { warn '部分国家数据刷新失败，失败项保留原有集合。'; return 1; }
    log '所有国家网段数据已刷新。'
}

country_apply_interactive() {
    local mode=$1 action_label
    prompt_country_code || return 0
    if [[ $mode == allow ]]; then
        action_label="启用/扩展国家白名单 ${SELECTED_COUNTRY_CODE}"
        warn '国家白名单启用后，未命中任何白名单国家的来源会被拒绝；当前 SSH 客户端会保留精确例外。'
    else
        action_label="加入国家黑名单 ${SELECTED_COUNTRY_CODE}"
    fi
    prompt_yes_no "确认${action_label}？" no || return 0
    apply_country_access_rule "$mode" "$SELECTED_COUNTRY_CODE"
}

country_access_menu() {
    local choice
    require_access_control_backend || return 0
    while true; do
        show_country_access_summary
        printf '  1. 仅允许指定国家     2. 阻止指定国家\n'
        printf '  3. 解除指定国家限制   4. 刷新全部国家数据\n'
        printf '  0. 返回\n'
        printf '请选择 [0-4]: '
        read -r choice
        case $choice in
            1) country_apply_interactive allow ;;
            2) country_apply_interactive block ;;
            3) prompt_country_code && remove_country_access_rule "$SELECTED_COUNTRY_CODE" ;;
            4) prompt_yes_no '确认从 IPdeny 刷新全部已配置国家数据（推荐）？' yes && refresh_country_access_rules ;;
            0|q|Q) return 0 ;;
            *) printf '选项无效，请重新输入。\n' ;;
        esac
    done
}

prompt_firewall_protocols() {
    local choice
    SELECTED_PROTOCOLS=
    printf '请选择协议：\n  1. TCP（推荐）\n  2. UDP\n  3. TCP + UDP\n  0. 取消\n'
    while true; do
        printf '请选择 [0-3，默认 1]: '
        read -r choice
        case $choice in
            ''|1) SELECTED_PROTOCOLS=tcp; return 0 ;;
            2) SELECTED_PROTOCOLS=udp; return 0 ;;
            3) SELECTED_PROTOCOLS='tcp udp'; return 0 ;;
            0|q|Q) return 1 ;;
            *) printf '选项无效，请重新输入。\n' ;;
        esac
    done
}

prompt_firewall_port() {
    local answer
    SELECTED_FIREWALL_PORT=
    while true; do
        printf '请输入端口（1-65535，输入 q 取消）: '
        read -r answer
        [[ $answer == q || $answer == Q ]] && return 1
        if validate_port "$answer"; then
            SELECTED_FIREWALL_PORT=$answer
            return 0
        fi
        printf '端口无效，请重新输入。\n'
    done
}

iptables_remove_tagged_rule() {
    local command_name=$1 chain=$2 protocol=$3 port=$4 verdict=$5
    while "$command_name" -C "$chain" -p "$protocol" --dport "$port" -m comment --comment allentool-managed -j "$verdict" 2>/dev/null; do
        "$command_name" -D "$chain" -p "$protocol" --dport "$port" -m comment --comment allentool-managed -j "$verdict" || return 1
    done
}

iptables_apply_tagged_port() {
    local action=$1 port=$2 protocols=$3 command_name protocol chain verdict opposite failed=no
    for command_name in iptables ip6tables; do
        command -v "$command_name" >/dev/null 2>&1 || continue
        chain=$(iptables_target_chain "$command_name")
        for protocol in $protocols; do
            if [[ $action == open ]]; then verdict=ACCEPT; opposite=DROP; else verdict=DROP; opposite=ACCEPT; fi
            if ! iptables_remove_tagged_rule "$command_name" "$chain" "$protocol" "$port" "$opposite"; then
                failed=yes
            elif ! "$command_name" -C "$chain" -p "$protocol" --dport "$port" -m comment --comment allentool-managed -j "$verdict" 2>/dev/null; then
                "$command_name" -I "$chain" 1 -p "$protocol" --dport "$port" -m comment --comment allentool-managed -j "$verdict" || failed=yes
            fi
            if [[ $failed == yes ]]; then
                warn '防火墙端口规则修改失败；已完成的规则保持现状，请查看菜单中的实时规则。'
                return 1
            fi
        done
    done
    persist_iptables_rules yes
}

firewall_apply_port() {
    local action=$1 port=$2 protocols=$3 backend protocol action_label rich_rule
    [[ $action == open || $action == close ]] || {
        warn "不支持的防火墙操作：$action"
        return 1
    }
    validate_port "$port" || {
        warn '防火墙端口必须是 1 到 65535 之间的整数。'
        return 1
    }
    for protocol in $protocols; do
        [[ $protocol == tcp || $protocol == udp ]] || {
            warn "不支持的协议：$protocol"
            return 1
        }
    done
    [[ -n $protocols ]] || {
        warn '没有选择 TCP 或 UDP 协议。'
        return 1
    }
    backend=$(detect_firewall_backend)
    case $backend in
        ufw)
            for protocol in $protocols; do
                if [[ $action == open ]]; then
                    ufw --force delete deny "${port}/${protocol}" >/dev/null 2>&1 || true
                    ufw allow "${port}/${protocol}"
                else
                    ufw --force delete allow "${port}/${protocol}" >/dev/null 2>&1 || true
                    ufw deny "${port}/${protocol}"
                fi
            done
            ;;
        firewalld)
            for protocol in $protocols; do
                rich_rule="rule priority=\"-100\" port port=\"${port}\" protocol=\"${protocol}\" drop"
                if [[ $action == open ]]; then
                    firewall-cmd --permanent --remove-rich-rule="$rich_rule" >/dev/null 2>&1 || true
                    firewall-cmd --permanent --add-port="${port}/${protocol}"
                else
                    firewall-cmd --permanent --remove-port="${port}/${protocol}" || true
                    firewall-cmd --permanent --add-rich-rule="$rich_rule"
                fi
            done
            firewall-cmd --reload
            ;;
        iptables) iptables_apply_tagged_port "$action" "$port" "$protocols" ;;
        nftables)
            warn '检测到原生 nftables 自定义规则，拒绝猜测表和链；请人工处理。'
            return 1
            ;;
        none)
            warn '没有检测到可管理的主机防火墙。'
            return 1
            ;;
    esac
    if [[ $action == open ]]; then action_label=开放; else action_label=关闭; fi
    log "已${action_label}端口 ${port}（${protocols// /+}）。"
}

firewall_open_interactive() {
    prompt_firewall_port || return 0
    prompt_firewall_protocols || return 0
    firewall_apply_port open "$SELECTED_FIREWALL_PORT" "$SELECTED_PROTOCOLS"
}

firewall_close_interactive() {
    prompt_firewall_port || return 0
    prompt_firewall_protocols || return 0
    local ssh_port listener protocol
    if [[ $SELECTED_PROTOCOLS == *tcp* ]]; then
        while IFS= read -r ssh_port; do
            if [[ $ssh_port == "$SELECTED_FIREWALL_PORT" ]]; then
                warn "端口 $ssh_port 是当前 SSH 端口，拒绝关闭。"
                return 0
            fi
        done < <(protected_ssh_ports)
    fi
    while read -r protocol listener; do
        if [[ $listener == "$SELECTED_FIREWALL_PORT" && $SELECTED_PROTOCOLS == *"$protocol"* ]]; then
            prompt_yes_no "端口 ${listener}/${protocol} 当前正在公网监听，仍要关闭吗？" no || return 0
        fi
    done < <(public_listeners)
    firewall_apply_port close "$SELECTED_FIREWALL_PORT" "$SELECTED_PROTOCOLS"
}

repair_ssh_firewall() {
    local port found=no
    while IFS= read -r port; do
        [[ -n $port ]] || continue
        found=yes
        firewall_apply_port open "$port" tcp || return 1
    done < <(protected_ssh_ports)
    [[ $found == yes ]] || {
        warn '无法读取当前 SSH 端口。'
        return 1
    }
    log '当前所有 SSH 端口均已重新放行。'
}

repair_firewall_persistence() {
    [[ $(detect_firewall_backend) == iptables ]] || {
        warn '当前后端不使用 netfilter-persistent。'
        return 0
    }
    if ! command -v netfilter-persistent >/dev/null 2>&1; then
        install_netfilter_persistence || {
            warn '持久化工具安装失败。'
            return 1
        }
    fi
    netfilter-persistent save >/dev/null 2>&1 || return 1
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable netfilter-persistent.service >/dev/null 2>&1 || warn '无法自动启用 netfilter-persistent.service。'
    fi
    log '防火墙持久化已经安装并保存当前规则。'
}

show_firewall_status() {
    local offer_install=${1:-no} backend service_enabled=未知 service_active=未知 answer
    backend=$(detect_firewall_backend)
    show_firewall_port_overview
    printf '当前非回环监听端口:\n'
    public_listeners | sed 's/^/  /'
    case $backend in
        iptables)
            printf '\nIPv4 INPUT 原始规则：\n'
            iptables -L INPUT -n --line-numbers 2>/dev/null || true
            if iptables -S "$FIREWALL_CHAIN" >/dev/null 2>&1 &&
               iptables -C INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1; then
                printf '\nIPv4 入站保护规则：\n'
                iptables -L "$FIREWALL_CHAIN" -n --line-numbers 2>/dev/null || true
            fi
            if command -v ip6tables >/dev/null 2>&1; then
                printf '\nIPv6 INPUT 原始规则：\n'
                ip6tables -L INPUT -n --line-numbers 2>/dev/null || true
                if ip6tables -S "$FIREWALL_CHAIN" >/dev/null 2>&1 &&
                   ip6tables -C INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1; then
                    printf '\nIPv6 入站保护规则：\n'
                    ip6tables -L "$FIREWALL_CHAIN" -n --line-numbers 2>/dev/null || true
                fi
            fi
            if command -v netfilter-persistent >/dev/null 2>&1; then
                if command -v systemctl >/dev/null 2>&1; then
                    service_enabled=$(systemctl is-enabled netfilter-persistent.service 2>/dev/null || true)
                    service_active=$(systemctl is-active netfilter-persistent.service 2>/dev/null || true)
                fi
                printf '持久化工具: 已安装（enabled=%s, active=%s）\n' "$service_enabled" "$service_active"
                printf 'IPv4规则文件: %s\n' "$([[ -s /etc/iptables/rules.v4 ]] && printf 已存在 || printf 缺失)"
                printf 'IPv6规则文件: %s\n' "$([[ -f /etc/iptables/rules.v6 ]] && printf 已存在 || printf 缺失)"
            else
                printf '持久化工具: 未安装\n'
                if [[ $offer_install == yes ]]; then
                    printf '  1. 安装 iptables-persistent 并保存规则（推荐）\n  0. 返回\n请选择 [0-1，默认 1]: '
                    read -r answer
                    [[ -z $answer || $answer == 1 ]] && repair_firewall_persistence
                fi
            fi
            ;;
        ufw) ufw status verbose || true ;;
        firewalld) firewall-cmd --list-all || true ;;
        nftables)
            warn '原生 nftables 仅提供状态展示，不执行自动规则变更。'
            nft list ruleset 2>/dev/null || true
            ;;
        none) warn '未检测到防火墙后端。' ;;
    esac
}

build_lockdown_chain() {
    local command_name=$1 allowlist=$2 protocol port insert_position=1
    if ! "$command_name" -S "$FIREWALL_CHAIN" >/dev/null 2>&1; then
        "$command_name" -N "$FIREWALL_CHAIN" || return 1
    fi
    while "$command_name" -C INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1; do
        "$command_name" -D INPUT -j "$FIREWALL_CHAIN" || return 1
    done
    "$command_name" -F "$FIREWALL_CHAIN" || return 1
    if "$command_name" -C INPUT -j "$ACCESS_CHAIN" >/dev/null 2>&1; then
        insert_position=2
    fi
    "$command_name" -I INPUT "$insert_position" -j "$FIREWALL_CHAIN" || return 1
    "$command_name" -A "$FIREWALL_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    "$command_name" -A "$FIREWALL_CHAIN" -i lo -j ACCEPT || return 1
    if [[ $command_name == ip6tables ]]; then
        # IPv6 邻居发现、路径 MTU 等依赖 ICMPv6，不能作为普通“入站端口”关闭。
        "$command_name" -A "$FIREWALL_CHAIN" -p ipv6-icmp -j ACCEPT || return 1
    else
        # 保留 IPv4 错误报告、路径 MTU 和诊断能力；ICMP 不开放 TCP/UDP 端口。
        "$command_name" -A "$FIREWALL_CHAIN" -p icmp -j ACCEPT || return 1
    fi
    while read -r protocol port; do
        [[ -n $protocol && -n $port ]] || continue
        "$command_name" -A "$FIREWALL_CHAIN" -p "$protocol" --dport "$port" -j ACCEPT || return 1
    done <<< "$allowlist"
    "$command_name" -A "$FIREWALL_CHAIN" -j DROP
}

firewall_lockdown_interactive() {
    local mode=$1 backend allowlist command_name port
    backend=$(detect_firewall_backend)
    [[ $backend == iptables ]] || {
        warn '“关闭所有宿主机入站”目前仅支持 iptables/iptables-nft。'
        return 0
    }
    allowlist=$(while IFS= read -r port; do [[ -n $port ]] && printf 'tcp %s\n' "$port"; done < <(protected_ssh_ports))
    if [[ $mode == listeners ]]; then
        allowlist=$(printf '%s\n%s\n' "$allowlist" "$(public_listeners)" | awk 'NF==2' | sort -k1,1 -k2,2n -u)
    fi
    [[ -n $allowlist ]] || {
        warn '无法生成安全的端口保留列表。'
        return 0
    }
    printf '即将保留的宿主机入站端口：\n'
    printf '%s\n' "$allowlist" | awk '{printf "  %s/%s\n", $2, $1}'
    warn '其他宿主机 INPUT 流量将被入站保护规则拒绝；会保留 ICMP/ICMPv6，Docker 转发端口不属于 INPUT。'
    prompt_yes_no '确认应用此入站保护规则？' no || return 0
    for command_name in iptables ip6tables; do
        command -v "$command_name" >/dev/null 2>&1 || continue
        if ! build_lockdown_chain "$command_name" "$allowlist"; then
            warn '入站保护规则应用失败；已完成的协议族保持现状，请查看实时规则。'
            return 1
        fi
    done
    persist_iptables_rules yes
    log '宿主机入站保护规则已应用。'
}

firewall_menu() {
    local choice
    while true; do
        show_firewall_port_overview
        show_access_control_overview
        printf '\n防火墙管理\n'
        printf '%s\n' '----------------------------------------'
        printf '  1. 开放指定端口        2. 关闭指定端口\n'
        printf '  3. 修复 SSH 放行       4. 查看详细状态\n'
        printf '%s\n' '----------------------------------------'
        printf '  5. 仅保留 SSH 入站\n'
        printf '  6. 保留 SSH 和当前公网监听端口\n'
        printf '  7. 安装/修复防火墙持久化\n'
        printf '  8. IP 黑白名单         9. 国家黑白名单\n'
        printf '%s\n' '----------------------------------------'
        printf '  0. 返回上一级菜单\n'
        printf '请选择 [0-9]: '
        read -r choice
        case $choice in
            1) firewall_open_interactive ;;
            2) firewall_close_interactive ;;
            3) repair_ssh_firewall ;;
            4) show_firewall_status yes ;;
            5) firewall_lockdown_interactive ssh ;;
            6) firewall_lockdown_interactive listeners ;;
            7) repair_firewall_persistence ;;
            8) ip_access_menu ;;
            9) country_access_menu ;;
            0|q|Q) return 0 ;;
            *) printf '选项无效，请重新输入。\n' ;;
        esac
    done
}

rollback_after_failure() {
    local reason=$1
    warn "${reason}，正在自动回滚。"
    restore_config_files || warn '配置文件自动恢复失败，请使用控制台从备份恢复。'
    if "$SSHD_BIN" -t 2>/dev/null; then
        reload_ssh || warn '恢复后 SSH reload 失败。'
    else
        warn '恢复后的 SSH 配置校验失败。'
    fi
    close_staged_firewall_rule || warn '新端口防火墙规则清理失败。'
    rm -f "$STATE_FILE"
    die "${reason}；备份保留在 $STATE_BACKUP_DIR"
}

switch_port() {
    local new_port=$1 cloud_ready=$2 skip_host_firewall=$3 enable_main_password=${4:-no}
    local -a old_ports effective_after
    local discovered_port
    validate_port "$new_port" || die '端口必须是 1 到 65535 之间的整数。'
    [[ ! -e $STATE_FILE ]] || die "已有迁移状态；先运行 $PROGRAM status、finalize 或 rollback。"

    "$SSHD_BIN" -t || die '当前 SSH 配置本身无法通过 sshd -t，拒绝修改。'
    detect_service
    collect_config_files
    reject_unsupported_config

    local auth_before auth_without_password_before
    auth_before=$(auth_fingerprint)
    auth_without_password_before=$(auth_fingerprint_without_password)
    old_ports=()
    while IFS= read -r discovered_port; do
        [[ -n $discovered_port ]] && old_ports+=("$discovered_port")
    done < <(effective_ports)
    ((${#old_ports[@]} > 0)) || die '无法读取当前有效 SSH 端口。'
    port_in_list "$new_port" "${old_ports[@]}" && die "端口 $new_port 已经是有效 SSH 端口。"
    port_is_listening "$new_port" && die "端口 $new_port 已被其他服务监听。"

    confirm_cloud_firewall "$new_port" "$cloud_ready"
    open_host_firewall "$new_port" "$skip_host_firewall"

    STATE_STATUS=staging
    STATE_NEW_PORT=$new_port
    STATE_OLD_PORTS=${old_ports[*]}
    STATE_MAIN_PASSWORD_CHANGED=$enable_main_password
    make_backup yes
    write_state

    comment_active_ports
    if [[ $enable_main_password == yes ]]; then
        set_main_password_yes || rollback_after_failure '无法把主配置 PasswordAuthentication 改为 yes'
    fi
    write_main_port "$new_port" || rollback_after_failure '无法把新端口写入 SSH 主配置'

    "$SSHD_BIN" -t || rollback_after_failure '新 SSH 配置未通过 sshd -t'

    local auth_after
    auth_after=$(auth_fingerprint)
    if [[ $enable_main_password == yes ]]; then
        [[ $(auth_fingerprint_without_password) == "$auth_without_password_before" ]] ||
            rollback_after_failure '除密码登录外的认证配置发生意外变化'
        [[ $(effective_password_setting) == yes ]] ||
            rollback_after_failure 'PasswordAuthentication 未实际生效为 yes'
    else
        [[ $auth_after == "$auth_before" ]] || rollback_after_failure '认证配置发生意外变化'
    fi

    effective_after=()
    while IFS= read -r discovered_port; do
        [[ -n $discovered_port ]] && effective_after+=("$discovered_port")
    done < <(effective_ports)
    local port
    port_in_list "$new_port" "${effective_after[@]}" ||
        rollback_after_failure "有效配置中缺少端口 $new_port"
    for port in "${old_ports[@]}"; do
        ! port_in_list "$port" "${effective_after[@]}" ||
            rollback_after_failure "有效配置中仍包含旧端口 $port"
    done

    reload_ssh || rollback_after_failure 'SSH reload 失败'
    wait_for_port "$new_port" || rollback_after_failure "SSH 未监听端口 $new_port"
    for port in "${old_ports[@]}"; do
        wait_for_port_closed "$port" || rollback_after_failure "旧端口 $port 仍在监听"
    done

    STATE_STATUS=finalized
    write_state
    log "切换完成：SSH 现在仅监听端口 ${STATE_NEW_PORT}。"
}

interactive_resume() {
    load_state
    case $STATE_STATUS in
        staged)
            warn '检测到旧版双端口状态，正在关闭旧端口并自动提交。'
            finalize_port yes yes
            commit_port
            ;;
        finalized)
            commit_port
            ;;
        staging)
            warn '检测到中断的切换操作，正在自动恢复原配置。'
            rollback_port
            die '原配置已恢复，请重新运行 allentool。'
            ;;
        *)
            die "无法处理迁移状态: $STATE_STATUS"
            ;;
    esac
}

interactive_mode() {
    if [[ -e $STATE_FILE ]]; then
        interactive_resume
        return 0
    fi
    "$SSHD_BIN" -t || die '当前 SSH 配置本身无法通过 sshd -t，拒绝修改。'

    local main_setting effective_setting enable_main_password=no new_port answer
    local -a current_ports
    main_setting=$(main_password_setting)
    effective_setting=$(effective_password_setting)

    printf '主配置 PasswordAuthentication: %s\n' "${main_setting:-未显式设置}"
    printf '当前实际生效 PasswordAuthentication: %s\n' "${effective_setting:-未知}"
    if [[ $main_setting == no ]]; then
        if prompt_yes_no '检测到主配置为 PasswordAuthentication no，是否改为 yes（需要密码登录时推荐）？' yes; then
            enable_main_password=yes
        else
            warn '选择了 n；主配置将保持 no。端口迁移不会删除 cloud-init 配置。'
        fi
    else
        log '主配置不是 PasswordAuthentication no，无需修改。'
    fi

    current_ports=()
    while IFS= read -r answer; do
        [[ -n $answer ]] && current_ports+=("$answer")
    done < <(effective_ports)
    printf '当前 SSH 端口: %s\n' "${current_ports[*]:-未知}"

    while true; do
        printf '请输入新的 SSH 端口（1-65535，输入 q 退出）: '
        read -r new_port
        [[ $new_port == q || $new_port == Q ]] && die '操作已取消。'
        if ! validate_port "$new_port"; then
            printf '端口无效，请重新输入。\n'
            continue
        fi
        if port_in_list "$new_port" "${current_ports[@]}"; then
            printf '该端口已经是当前 SSH 端口，请重新输入。\n'
            continue
        fi
        if port_is_listening "$new_port"; then
            printf '该端口已被其他服务监听，请重新输入。\n'
            continue
        fi
        break
    done

    if ! prompt_yes_no "是否已在云厂商安全组/防火墙放行 ${new_port}/TCP？" no; then
        die '请先开放云防火墙端口后再运行脚本。'
    fi

    warn '将直接切换到新端口并关闭旧端口；请保持当前 SSH 会话。'
    switch_port "$new_port" yes no "$enable_main_password"
    commit_port
}

finalize_port() {
    local verified=$1 suppress_followup=${2:-no} answer auth_before auth_after
    load_state
    [[ $STATE_STATUS == staged ]] || die "当前状态是 ${STATE_STATUS}，不能 finalize。"

    if [[ $verified != yes ]]; then
        [[ -t 0 ]] || die '请先验证新端口登录，并添加 --verified-new-login。'
        printf '请先从第二个终端成功登录新端口。输入新端口号 %s 确认: ' "$STATE_NEW_PORT"
        read -r answer
        [[ $answer == "$STATE_NEW_PORT" ]] || die '确认不匹配，未关闭旧端口。'
    fi

    "$SSHD_BIN" -t || die '当前 SSH 配置无法通过 sshd -t，拒绝 finalize。'
    auth_before=$(auth_fingerprint)
    ensure_main_in_backup || die '旧版迁移备份不完整，无法安全写入 SSH 主配置。'
    write_main_port "$STATE_NEW_PORT" || rollback_after_failure '无法把新端口写入 SSH 主配置'
    "$SSHD_BIN" -t || rollback_after_failure 'finalize 后配置未通过 sshd -t'
    auth_after=$(auth_fingerprint)
    [[ $auth_after == "$auth_before" ]] || rollback_after_failure 'finalize 导致认证配置变化'
    reload_ssh || rollback_after_failure 'finalize 时 SSH reload 失败'
    wait_for_port "$STATE_NEW_PORT" || rollback_after_failure "SSH 未监听新端口 $STATE_NEW_PORT"

    local old_port
    for old_port in $STATE_OLD_PORTS; do
        if [[ $old_port != "$STATE_NEW_PORT" ]] && port_is_listening "$old_port"; then
            rollback_after_failure "旧端口 $old_port 仍在监听"
        fi
    done

    STATE_STATUS=finalized
    write_state
    log "完成：SSH 现在仅监听端口 ${STATE_NEW_PORT}。"
    [[ $suppress_followup == yes ]] && return 0
    log "备份和 rollback 状态仍保留；确认稳定后可保留，或自行归档 ${STATE_BACKUP_DIR}。"
    log "再次确认稳定后运行：sudo $PROGRAM interactive"
    log "也可以运行：sudo $PROGRAM commit"
}

commit_port() {
    load_state
    [[ $STATE_STATUS == finalized ]] || die "当前状态是 ${STATE_STATUS}，只有 finalized 状态可以 commit。"
    "$SSHD_BIN" -t || die '当前 SSH 配置无法通过 sshd -t，拒绝 commit。'
    wait_for_port "$STATE_NEW_PORT" || die "新端口 $STATE_NEW_PORT 未监听，拒绝 commit。"
    rm -f "$STATE_FILE"
    log "已确认新端口 ${STATE_NEW_PORT}，并结束迁移状态。"
    log "配置备份仍保留在：$STATE_BACKUP_DIR"
}

rollback_port() {
    load_state
    restore_config_files || die "无法从 $STATE_BACKUP_DIR 恢复配置。"
    "$SSHD_BIN" -t || die '恢复后的 SSH 配置未通过 sshd -t；尚未 reload。'
    reload_ssh || die '配置已恢复，但 SSH reload 失败。'

    local old_port
    for old_port in $STATE_OLD_PORTS; do
        wait_for_port "$old_port" || die "配置已恢复，但旧端口 $old_port 未监听。"
    done
    close_staged_firewall_rule || warn '无法删除脚本添加的新端口防火墙规则。'
    rm -f "$STATE_FILE"
    log "已恢复原 SSH 配置和端口：$STATE_OLD_PORTS"
    log "备份仍保留在：$STATE_BACKUP_DIR"
}

show_status() {
    if [[ ! -f $STATE_FILE ]]; then
        log '没有进行中的端口迁移。'
        "$SSHD_BIN" -T 2>/dev/null | grep -E '^(port|passwordauthentication|permitrootlogin) '
        return 0
    fi

    load_state
    printf '状态: %s\n新端口: %s\n旧端口: %s\n备份: %s\n' \
        "$STATE_STATUS" "$STATE_NEW_PORT" "$STATE_OLD_PORTS" "$STATE_BACKUP_DIR"
    printf '主配置密码登录由脚本修改: %s\n' "$STATE_MAIN_PASSWORD_CHANGED"
    printf '当前有效配置:\n'
    "$SSHD_BIN" -T 2>/dev/null | grep -E '^(port|passwordauthentication|permitrootlogin) '
    printf '当前监听:\n'
    local port
    for port in $STATE_OLD_PORTS "$STATE_NEW_PORT"; do
        if port_is_listening "$port"; then
            printf '  %s: listening\n' "$port"
        else
            printf '  %s: not listening\n' "$port"
        fi
    done
}

menu_mode() {
    local choice
    while true; do
        printf '\nallentool VPS 工具\n'
        printf '  1. 修改 SSH 端口\n'
        printf '  2. 从备份恢复 SSH 设置\n'
        printf '  3. 查看 SSH 状态\n'
        printf '  4. 防火墙管理\n'
        printf '  5. 退出\n'
        printf '请选择 [1-5]: '
        if ! read -r choice; then
            log '输入已结束，脚本退出。'
            return 0
        fi
        case $choice in
            1) interactive_mode; return 0 ;;
            2) restore_backup_interactive; return 0 ;;
            3) show_status; return 0 ;;
            4) firewall_menu ;;
            5|q|Q) log '已退出。'; return 0 ;;
            *) printf '选项无效，请输入 1、2、3、4 或 5。\n' ;;
        esac
    done
}

main() {
    ORIGINAL_ARGS=("$@")
    local action=${1:-menu}
    (($# == 0)) || shift

    case $action in
        -h|--help|help)
            usage
            return 0
            ;;
        menu)
            require_root
            require_commands
            (($# == 0)) || die 'menu 不接受额外参数。'
            menu_mode
            ;;
        interactive)
            require_root
            require_commands
            (($# == 0)) || die 'interactive 不接受额外参数。'
            interactive_mode
            ;;
        restore)
            require_root
            require_commands
            (($# == 0)) || die 'restore 不接受额外参数。'
            restore_backup_interactive
            ;;
        firewall)
            require_root
            require_commands
            (($# == 0)) || die 'firewall 不接受额外参数。'
            firewall_menu
            ;;
        install)
            require_root
            (($# == 0)) || die 'install 不接受额外参数。'
            install_tool
            ;;
        install-shortcut)
            require_root
            (($# == 0)) || die 'install-shortcut 不接受额外参数。'
            install_shortcut
            ;;
        switch)
            require_root
            require_commands
            local new_port=${1:-} cloud_ready=no skip_host_firewall=no enable_main_password=no option
            [[ -n $new_port ]] || die 'switch 需要新端口。'
            shift || true
            for option in "$@"; do
                case $option in
                    --cloud-firewall-ready) cloud_ready=yes ;;
                    --skip-host-firewall) skip_host_firewall=yes ;;
                    --enable-main-password) enable_main_password=yes ;;
                    *) die "未知参数: $option" ;;
                esac
            done
            switch_port "$new_port" "$cloud_ready" "$skip_host_firewall" "$enable_main_password"
            commit_port
            ;;
        status)
            require_root
            require_commands
            (($# == 0)) || die 'status 不接受额外参数。'
            show_status
            ;;
        *)
            usage
            exit 2
            ;;
    esac
}

script_source=${BASH_SOURCE[0]}
script_invoked=$0
if [[ $script_invoked != */* ]]; then
    script_invoked=$(command -v -- "$script_invoked" 2>/dev/null || true)
fi
if [[ $script_source == "$0" ]] ||
   [[ -n $script_invoked && -e $script_invoked && $script_source -ef $script_invoked ]]; then
    main "$@"
fi
