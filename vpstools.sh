#!/usr/bin/env bash
# VPS Tools 的统一入口；具体操作交给独立工具。
set -Eeuo pipefail
VERSION=0.3.0
BIN_DIR=${VPS_TOOLS_BIN_DIR:-/usr/local/bin}
SBIN_DIR=${VPS_TOOLS_SBIN_DIR:-/usr/local/sbin}
LIB_DIR=${VPS_TOOLS_LIB_DIR:-/usr/local/lib/vpstools}

usage() {
    cat <<'EOF'
VPS Tools 中文工具箱
用法：
  vpstools                    打开中文菜单
  vpstools list               查看各工具是否已安装
  vpstools run <工具> [参数]   调用工具，原样传递参数
  vpstools update [github|gitee]  安装或更新全部工具
  vpstools --version

工具：ssh、sshkey、sshpass、firewall、dns、swap、bbr、agent、netcheck、iperf、fail2ban、ipv6、tcp（别名 tcptool）
示例：vpstools run dns status
      vpstools run ssh interactive
      vpstools run bbr status
EOF
}

tool_path() {
    case $1 in
        ssh|firewall) printf '%s/safe-ssh-port\n' "$SBIN_DIR" ;;
        sshkey) printf '%s/sshkeytool\n' "$SBIN_DIR" ;;
        sshpass|sshpasswdtool) printf '%s/sshpasswdtool\n' "$SBIN_DIR" ;;
        dns) printf '%s/dnstool\n' "$BIN_DIR" ;;
        swap) printf '%s/swaptool\n' "$BIN_DIR" ;;
        bbr) printf '%s/bbr-tune\n' "$SBIN_DIR" ;;
        agent) printf '%s/restart-mmw-agent\n' "$SBIN_DIR" ;;
        netcheck) printf '%s/netcheck\n' "$BIN_DIR" ;;
        iperf) printf '%s/iperfprobe\n' "$BIN_DIR" ;;
        fail2ban) printf '%s/f2btool\n' "$SBIN_DIR" ;;
        tcp|tcptool) printf '%s/tcptool\n' "$SBIN_DIR" ;;
        ipv6) printf '%s/ipv6tool\n' "$SBIN_DIR" ;;
        *) printf '未知工具：%s\n' "$1" >&2; return 2 ;;
    esac
}

list_tools() {
    local id path state
    for id in ssh sshkey sshpass firewall dns swap bbr agent netcheck iperf fail2ban ipv6 tcp; do
        path=$(tool_path "$id")
        state=未安装
        [[ ! -x $path ]] || state=已安装
        printf '%-10s %s  %s\n' "$id" "$state" "$path"
    done
}

run_tool() {
    local id=${1:?缺少工具名称} path
    shift
    path=$(tool_path "$id") || return $?
    [[ -x $path ]] || { printf '工具未安装：%s。请运行 vpstools update。\n' "$id" >&2; return 1; }
    if [[ $id == firewall ]]; then set -- firewall "$@"; fi
    if [[ $EUID != 0 ]] && { [[ $id == agent && ${1:-} != --help && ${1:-} != -h ]] || [[ ( $id == tcp || $id == tcptool || $id == sshkey ) && $# == 0 ]]; }; then
        command -v sudo >/dev/null || { printf '需要 root 或 sudo 权限。\n' >&2; return 1; }
        if [[ $id == sshkey ]]; then
            sudo --preserve-env=SSH_CONNECTION,SSH_USER_AUTH -- "$path" "$@"
        else
            sudo -- "$path" "$@"
        fi
    else
        "$path" "$@"
    fi
}

update_tools() {
    local channel=${1:-github}
    [[ $channel == github || $channel == gitee ]] || { printf '渠道必须为 github 或 gitee。\n' >&2; return 2; }
    [[ -f $LIB_DIR/install.sh ]] || { printf '安装器缺失，请重新运行统一安装命令。\n' >&2; return 1; }
    if (( EUID == 0 )); then
        bash "$LIB_DIR/install.sh" --channel "$channel"
    else
        command -v sudo >/dev/null || { printf '需要 root 或 sudo 权限。\n' >&2; return 1; }
        sudo -- bash "$LIB_DIR/install.sh" --channel "$channel"
    fi
}

menu_item() {
    local number=$1 id=$2 label=$3 path suffix=
    path=$(tool_path "$id")
    [[ -x $path ]] || suffix=' [未安装]'
    printf '    %s. %s%s\n' "$number" "$label" "$suffix"
}

category_menu() {
    local category=$1 title choice index id label
    local -a ids labels
    case $category in
        system)
            title=系统管理
            ids=(ssh sshkey sshpass firewall fail2ban dns ipv6 swap)
            labels=('SSH 端口与配置恢复' 'SSH 密钥登录管理' 'SSH 密码登录管理' '防火墙管理' 'Fail2ban 防暴力破解' 'DNS 设置与恢复' 'IPv4 / IPv6 管理' 'Swap 管理') ;;
        network)
            title=网络检测与测速
            ids=(netcheck iperf)
            labels=('网址与网络检测' 'iperf3 带宽测速') ;;
        tuning)
            title=网络调优
            ids=(bbr tcp)
            labels=('TCP / BBR 调优' 'TCP 参数导入与回滚') ;;
        services)
            title=服务管理
            ids=(agent)
            labels=('妙妙屋 Agent 重启') ;;
        *) return 2 ;;
    esac
    while :; do
        printf '\nVPS Tools > %s\n' "$title"
        for (( index=0; index<${#ids[@]}; index++ )); do
            if [[ $category == system ]]; then
                case $index in
                    0) printf '\n  SSH 与访问防护\n' ;;
                    5) printf '\n  网络基础配置\n' ;;
                    7) printf '\n  系统资源\n' ;;
                esac
            fi
            menu_item "$((index + 1))" "${ids[index]}" "${labels[index]}"
        done
        printf '\n    0. 返回主菜单\n'
        read -r -p '请选择：' choice || return 1
        [[ $choice != 0 ]] || return 0
        # 先校验字符，再转十进制，避免把输入当作 Bash 算术表达式。
        if [[ ! $choice =~ ^[1-9][0-9]?$ ]]; then
            printf '无效选项，请重新输入。\n'
            continue
        fi
        index=$((10#$choice - 1))
        if (( index >= ${#ids[@]} )); then
            printf '无效选项，请重新输入。\n'
            continue
        fi
        id=${ids[index]}
        label=${labels[index]}
        if [[ ! -x $(tool_path "$id") ]]; then
            printf '工具未安装：%s。请返回主菜单，选择「6. 安装 / 更新工具箱」。\n' "$label"
            continue
        fi
        if [[ $id == agent ]]; then
            read -r -p '重启会短暂中断代理连接，确认继续？[y/N] ' choice || return 1
            [[ $choice == y || $choice == Y ]] || continue
        fi
        run_tool "$id" || printf '%s已取消、有项目未通过或执行失败，请查看上方输出。\n' "$label"
    done
}

menu() {
    [[ -t 0 && -t 1 ]] || { printf '菜单需要交互终端；可使用 vpstools list 或 vpstools run。\n' >&2; return 1; }
    local choice channel
    while :; do
        printf '\nVPS Tools 工具箱 v%s\n\n' "$VERSION"
        printf '%s\n' '  1. 系统管理' '  2. 网络检测与测速' '  3. 网络调优' '  4. 服务管理' '' '  5. 查看工具安装状态' '  6. 安装 / 更新工具箱' '  0. 退出'
        read -r -p '请选择：' choice || return 0
        case $choice in
            1) category_menu system || return 0 ;;
            2) category_menu network || return 0 ;;
            3) category_menu tuning || return 0 ;;
            4) category_menu services || return 0 ;;
            5) list_tools ;;
            # 更新始终放在所有其他功能下方、退出上方。
            6)
                read -r -p '下载渠道：1. GitHub（默认）  2. Gitee：' channel || return 0
                case $channel in
                    1|'') channel=github ;;
                    2) channel=gitee ;;
                    *) printf '无效渠道。\n'; continue ;;
                esac
                if update_tools "$channel"; then
                    if [[ -x $BIN_DIR/vpstools ]]; then
                        printf '更新完成，正在重新打开工具箱……\n'
                        exec bash "$BIN_DIR/vpstools" menu
                    else
                        printf '更新完成，但未找到新入口：%s/vpstools。请退出后重新打开工具箱。\n' "$BIN_DIR"
                    fi
                else
                    printf '安装未完成，请查看上方错误。\n'
                fi ;;
            0) return 0 ;;
            *) printf '无效选项，请重新输入。\n' ;;
        esac
    done
}

main() {
    case ${1:-menu} in
        menu) (( $# <= 1 )) || return 2; menu ;;
        list) (( $# == 1 )) || return 2; list_tools ;;
        run) (( $# >= 2 )) || { usage >&2; return 2; }; shift; run_tool "$@" ;;
        update) (( $# <= 2 )) || return 2; update_tools "${2:-github}" ;;
        --version|-V) (( $# == 1 )) || return 2; printf 'vpstools %s\n' "$VERSION" ;;
        --help|-h|help) usage ;;
        *) usage >&2; return 2 ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
