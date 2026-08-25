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
STATE_MAIN_PASSWORD_CHANGED=no
ORIGINAL_ARGS=()

log() {
    printf '[safe-ssh-port] %s\n' "$*"
}

warn() {
    printf '[safe-ssh-port] 警告: %s\n' "$*" >&2
}

die() {
    printf '[safe-ssh-port] 错误: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<EOF
安全修改 OpenSSH 端口（分阶段迁移）

用法：
  $PROGRAM
  $PROGRAM interactive
  $PROGRAM install
  $PROGRAM install-shortcut
  sudo $PROGRAM stage <新端口> [--cloud-firewall-ready] [--skip-host-firewall]
                              [--enable-main-password]
  sudo $PROGRAM finalize [--verified-new-login]
  sudo $PROGRAM commit
  sudo $PROGRAM status
  sudo $PROGRAM rollback

流程：
  1. 先在云厂商安全组/防火墙中放行新端口。
  2. stage 同时保留旧端口和新端口，并验证 SSH 配置及监听。
  3. 使用第二个终端从公网登录新端口。
  4. finalize 仅保留新端口。

不带参数运行时默认进入 interactive。interactive 会根据迁移状态引导
stage、finalize 和 commit，并检测主配置中的
PasswordAuthentication no，用 y/n 询问是否改为 yes。除非明确选择 y，
否则脚本不会修改认证配置。
脚本不会删除 /etc/ssh/sshd_config.d 中的云厂商配置。
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
        prompt_yes_no "${target} 已存在，是否用当前版本覆盖？" || die '安装已取消。'
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
    log '安装完成，以后直接输入 allentool 即可进入交互模式。'
}

install_shortcut() {
    require_install_commands

    local source_file=${BASH_SOURCE[0]}
    [[ -f $source_file && ! -L $source_file ]] || die '无法从当前脚本安全安装快捷命令。'
    confirm_install_target "$source_file" "$ALLENTOOL_PATH" '快捷命令'
    install_copy "$source_file" "$ALLENTOOL_PATH" '快捷命令'

    log '以后直接输入 allentool 即可进入交互模式。'
}

require_commands() {
    local command_name
    for command_name in "$SSHD_BIN" "$SS_BIN" awk grep sed sort mktemp cp mv chmod chown mkdir find rm date stat sleep; do
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
    local prompt=$1 answer
    while true; do
        printf '%s [y/n]: ' "$prompt"
        read -r answer
        case $answer in
            y|Y) return 0 ;;
            n|N) return 1 ;;
            *) printf '请输入 y 或 n。\n' ;;
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
    local include_main=${1:-no} timestamp
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    STATE_BACKUP_DIR=$BACKUP_ROOT/$timestamp
    mkdir -p "$STATE_BACKUP_DIR/dropins"
    chmod 700 "$STATE_DIR" "$BACKUP_ROOT" "$STATE_BACKUP_DIR" "$STATE_BACKUP_DIR/dropins"
    cp -a "$SSHD_CONFIG" "$STATE_BACKUP_DIR/sshd_config"

    local file
    : > "$STATE_BACKUP_DIR/modified-files"
    chmod 600 "$STATE_BACKUP_DIR/modified-files"
    for file in "${CONFIG_FILES[@]}"; do
        if grep -Eq '^[[:space:]]*Port[[:space:]]+[0-9]+([[:space:]]*(#.*)?)?$' "$file" ||
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

write_managed_config() {
    local temporary port
    mkdir -p "$SSHD_DROPIN_DIR"
    temporary=$(mktemp "$SSHD_DROPIN_DIR/.00-safe-ssh-port.XXXXXX")
    {
        printf '%s\n' '# Managed by safe_ssh_port.sh. Do not edit during migration.'
        for port in "$@"; do
            printf 'Port %s\n' "$port"
        done
    } > "$temporary"
    chmod 644 "$temporary"
    chown root:root "$temporary"
    mv "$temporary" "$MANAGED_CONFIG"
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
            main_password_changed) STATE_MAIN_PASSWORD_CHANGED=$value ;;
        esac
    done < "$STATE_FILE"

    [[ $version == 1 ]] || die '不支持的状态文件版本。'
    validate_port "$STATE_NEW_PORT" || die '状态文件中的端口无效。'
    [[ $STATE_OLD_PORTS =~ ^[0-9]+([[:space:]][0-9]+)*$ ]] || die '状态文件中的旧端口列表无效。'
    [[ $STATE_BACKUP_DIR == "$BACKUP_ROOT/"* && -d $STATE_BACKUP_DIR ]] || die '状态文件中的备份目录无效。'
    [[ $STATE_SERVICE_MODE == systemctl || $STATE_SERVICE_MODE == service ]] || die '状态文件中的服务模式无效。'
    [[ $STATE_SERVICE_NAME == ssh || $STATE_SERVICE_NAME == sshd ]] || die '状态文件中的服务名无效。'
    [[ $STATE_FIREWALL_MANAGER == none || $STATE_FIREWALL_MANAGER == ufw || $STATE_FIREWALL_MANAGER == firewalld ]] || die '状态文件中的防火墙类型无效。'
    [[ $STATE_FIREWALL_RULE_ADDED == yes || $STATE_FIREWALL_RULE_ADDED == no ]] || die '状态文件中的防火墙状态无效。'
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

open_host_firewall() {
    local port=$1 skip=$2
    STATE_FIREWALL_MANAGER=none
    STATE_FIREWALL_RULE_ADDED=no

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        STATE_FIREWALL_MANAGER=ufw
        if ufw status 2>/dev/null | grep -Eq "^${port}/tcp[[:space:]]"; then
            log "UFW 已放行 ${port}/TCP。"
        else
            ufw allow "${port}/tcp" comment 'safe-ssh-port staged'
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

    if command -v iptables >/dev/null 2>&1 &&
       iptables -S INPUT 2>/dev/null | grep -Eq '^-P INPUT (DROP|REJECT)$'; then
        die '检测到自定义 iptables 默认拒绝策略；请先手动放行新端口，再使用 --skip-host-firewall。'
    fi
    if command -v nft >/dev/null 2>&1 &&
       nft list ruleset 2>/dev/null | grep -Eq 'hook input[^;]*;[^}]*policy (drop|reject)'; then
        die '检测到自定义 nftables 默认拒绝策略；请先手动放行新端口，再使用 --skip-host-firewall。'
    fi

    log '未检测到启用中的 UFW/firewalld；未修改主机防火墙。'
}

close_staged_firewall_rule() {
    [[ $STATE_FIREWALL_RULE_ADDED == yes ]] || return 0
    case $STATE_FIREWALL_MANAGER in
        ufw) ufw --force delete allow "${STATE_NEW_PORT}/tcp" >/dev/null ;;
        firewalld)
            firewall-cmd --permanent --remove-port="${STATE_NEW_PORT}/tcp" >/dev/null
            firewall-cmd --reload >/dev/null
            ;;
    esac
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

stage_port() {
    local new_port=$1 cloud_ready=$2 skip_host_firewall=$3 enable_main_password=${4:-no}
    local -a old_ports staged_ports
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
    make_backup "$enable_main_password"
    write_state

    comment_active_ports
    if [[ $enable_main_password == yes ]]; then
        set_main_password_yes || rollback_after_failure '无法把主配置 PasswordAuthentication 改为 yes'
    fi
    write_managed_config "${old_ports[@]}" "$new_port"

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

    staged_ports=()
    while IFS= read -r discovered_port; do
        [[ -n $discovered_port ]] && staged_ports+=("$discovered_port")
    done < <(effective_ports)
    local port
    for port in "${old_ports[@]}" "$new_port"; do
        port_in_list "$port" "${staged_ports[@]}" || rollback_after_failure "有效配置中缺少端口 $port"
    done

    reload_ssh || rollback_after_failure 'SSH reload 失败'
    for port in "${old_ports[@]}" "$new_port"; do
        wait_for_port "$port" || rollback_after_failure "SSH 未监听端口 $port"
    done

    STATE_STATUS=staged
    write_state
    log "阶段一完成：SSH 正在同时监听 ${STATE_OLD_PORTS} 和 ${STATE_NEW_PORT}。"
    log "请保持当前会话，另开终端测试：ssh -p $STATE_NEW_PORT user@服务器地址"
    log "验证新端口登录成功后再次运行：sudo $PROGRAM interactive"
    log "也可以运行：sudo $PROGRAM finalize --verified-new-login"
    log "如有问题运行：sudo $PROGRAM rollback"
}

interactive_resume() {
    load_state
    case $STATE_STATUS in
        staged)
            printf '当前处于双端口验证阶段：旧端口 %s，新端口 %s。\n' \
                "$STATE_OLD_PORTS" "$STATE_NEW_PORT"
            if ! prompt_yes_no "是否已从第二个终端使用新端口 ${STATE_NEW_PORT} 成功登录？"; then
                warn "仍保留新旧端口。验证成功后再次运行 sudo $PROGRAM interactive；如需恢复请运行 rollback。"
                return 0
            fi
            finalize_port yes
            ;;
        finalized)
            printf '当前已关闭旧端口，SSH 仅监听新端口 %s。\n' "$STATE_NEW_PORT"
            ;;
        *)
            die "无法交互处理迁移状态: $STATE_STATUS"
            ;;
    esac

    if prompt_yes_no '是否已确认新端口稳定，并结束迁移状态？结束后脚本将不能一键 rollback'; then
        commit_port
    else
        warn "已保留 finalized 状态和一键回滚能力；确认稳定后再次运行 sudo $PROGRAM interactive。"
    fi
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
        if prompt_yes_no '检测到主配置为 PasswordAuthentication no，是否改为 yes？'; then
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

    if ! prompt_yes_no "是否已在云厂商安全组/防火墙放行 ${new_port}/TCP？"; then
        die '请先开放云防火墙端口后再运行脚本。'
    fi

    stage_port "$new_port" yes no "$enable_main_password"
}

finalize_port() {
    local verified=$1 answer auth_before auth_after
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
    write_managed_config "$STATE_NEW_PORT"
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

main() {
    ORIGINAL_ARGS=("$@")
    local action=${1:-interactive}
    (($# == 0)) || shift

    case $action in
        -h|--help|help)
            usage
            return 0
            ;;
        interactive)
            require_root
            require_commands
            (($# == 0)) || die 'interactive 不接受额外参数。'
            interactive_mode
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
        stage)
            require_root
            require_commands
            local new_port=${1:-} cloud_ready=no skip_host_firewall=no enable_main_password=no option
            [[ -n $new_port ]] || die 'stage 需要新端口。'
            shift || true
            for option in "$@"; do
                case $option in
                    --cloud-firewall-ready) cloud_ready=yes ;;
                    --skip-host-firewall) skip_host_firewall=yes ;;
                    --enable-main-password) enable_main_password=yes ;;
                    *) die "未知参数: $option" ;;
                esac
            done
            stage_port "$new_port" "$cloud_ready" "$skip_host_firewall" "$enable_main_password"
            ;;
        finalize)
            require_root
            require_commands
            local verified=no option
            for option in "$@"; do
                case $option in
                    --verified-new-login) verified=yes ;;
                    *) die "未知参数: $option" ;;
                esac
            done
            finalize_port "$verified"
            ;;
        rollback)
            require_root
            require_commands
            (($# == 0)) || die 'rollback 不接受额外参数。'
            rollback_port
            ;;
        commit)
            require_root
            require_commands
            (($# == 0)) || die 'commit 不接受额外参数。'
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
