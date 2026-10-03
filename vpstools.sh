#!/usr/bin/env bash
# VPS Tools 的统一入口；具体操作交给独立工具。
set -Eeuo pipefail
VERSION=0.2.5
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

工具：ssh、firewall、dns、swap、bbr、agent、netcheck、iperf、fail2ban、ipv6
示例：vpstools run dns status
      vpstools run ssh interactive
      vpstools run bbr status
EOF
}

tool_path() {
    case $1 in
        ssh|firewall) printf '%s/safe-ssh-port\n' "$SBIN_DIR" ;;
        dns) printf '%s/dnstool\n' "$BIN_DIR" ;;
        swap) printf '%s/swaptool\n' "$BIN_DIR" ;;
        bbr) printf '%s/bbr-tune\n' "$SBIN_DIR" ;;
        agent) printf '%s/restart-mmw-agent\n' "$SBIN_DIR" ;;
        netcheck) printf '%s/netcheck\n' "$BIN_DIR" ;;
        iperf) printf '%s/iperfprobe\n' "$BIN_DIR" ;;
        fail2ban) printf '%s/f2btool\n' "$SBIN_DIR" ;;
        ipv6) printf '%s/ipv6tool\n' "$SBIN_DIR" ;;
        *) printf '未知工具：%s\n' "$1" >&2; return 2 ;;
    esac
}

list_tools() {
    local id path state
    for id in ssh firewall dns swap bbr agent netcheck iperf fail2ban ipv6; do
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
    if [[ $id == agent && $EUID != 0 && ${1:-} != --help && ${1:-} != -h ]]; then
        command -v sudo >/dev/null || { printf '需要 root 或 sudo 权限。\n' >&2; return 1; }
        sudo -- "$path" "$@"
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

menu() {
    [[ -t 0 && -t 1 ]] || { printf '菜单需要交互终端；可使用 vpstools list 或 vpstools run。\n' >&2; return 1; }
    local choice channel
    while :; do
        printf '\nVPS Tools 工具箱 v%s\n' "$VERSION"
        printf '%s\n' '  1. SSH 端口与备份恢复' '  2. 防火墙管理' '  3. DNS 切换与恢复' '  4. Swap 虚拟内存' '  5. TCP / BBR 调优' '  6. 重启妙妙屋 Agent' '  7. 查看工具安装状态' '  8. 网址与网络检测' '  9. iperf3 本地与 VPS 测速'
        # 安装 / 更新始终放在所有其他功能下方、退出上方；新增功能项应放在上方。
        printf '%s\n' '  10. Fail2ban SSH 防暴力破解' '  11. IPv6 优先级、禁用与恢复' '  12. 安装 / 更新全部工具' '  0. 退出'
        read -r -p '请选择：' choice || return 0
        case $choice in
            1) run_tool ssh || printf 'SSH 工具已取消或执行失败。\n' ;;
            2) run_tool firewall || printf '防火墙工具已取消或执行失败。\n' ;;
            3) run_tool dns || printf 'DNS 工具已取消或执行失败。\n' ;;
            4) run_tool swap || printf 'Swap 工具已取消或执行失败。\n' ;;
            5) run_tool bbr || printf 'BBR 工具已取消或执行失败。\n' ;;
            6)
                read -r -p '重启会短暂中断代理连接，确认继续？[y/N] ' choice || return 0
                if [[ $choice == y || $choice == Y ]]; then
                    run_tool agent || printf 'Agent 重启失败，请查看上方日志。\n'
                fi ;;
            7) list_tools ;;
            8) run_tool netcheck || printf '检测已取消或有项目未通过。\n' ;;
            9) run_tool iperf || printf '测速已取消或有项目未完成。\n' ;;
            10) run_tool fail2ban || printf 'Fail2ban 工具已取消或执行失败。\n' ;;
            11) run_tool ipv6 || printf 'IPv6 工具已取消或执行失败。\n' ;;
            12)
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
