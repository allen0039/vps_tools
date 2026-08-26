from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from .runtime import health, load_runtime_config
from .settings import (
    THRESHOLD_SPECS,
    add_monitored_user,
    remove_monitored_user,
    set_monitoring_mode,
    set_subscription_monitoring_enabled,
    set_telegram_option,
    set_threshold,
)


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def _pause() -> None:
    input("\n按回车返回...")


def _print_status(config_path: str) -> None:
    result = health(config_path)
    monitoring = result["subscription_monitoring"]
    print("\nVPSPC 运行状态")
    print(f"状态：{result['status']}")
    print(f"订阅监测：{'开启' if monitoring['enabled'] else '关闭'} / {monitoring['mode']}")
    print(f"重点用户名单：{len(monitoring['users'])} 个")
    print(f"Telegram 推送：{'开启' if result['telegram_enabled'] else '关闭'}")
    print(f"Telegram 双向管理：{'开启' if result['telegram_management_enabled'] else '关闭'}")
    print(f"最近巡查：{(result.get('last_run') or {}).get('generated_at', '尚未运行')}")
    if result.get("last_error"):
        print(f"最近错误：{result['last_error']}")


def _run_audit() -> None:
    print("正在执行巡查...")
    completed = subprocess.run(["systemctl", "start", "vps-audit.service"], check=False)
    if completed.returncode:
        raise RuntimeError("巡查失败，请执行 journalctl -u vps-audit.service -n 50 查看日志")
    print("巡查完成。")


def _users_menu(config_path: str) -> None:
    while True:
        config = load_runtime_config(config_path)
        monitoring = config["subscription_monitoring"]
        print("\n订阅用户管理")
        print(f"当前模式：{monitoring['mode']}（all=全部日志用户，allowlist=仅重点名单）")
        if monitoring["users"]:
            for index, user in enumerate(monitoring["users"], 1):
                print(f"  {index}. {user}")
        else:
            print("  重点名单为空")
        print("1. 监测日志中的全部订阅用户")
        print("2. 仅监测重点名单中的多个用户")
        print("3. 添加重点用户")
        print("4. 删除重点用户")
        print("5. 启用 / 暂停订阅监测")
        print("0. 返回")
        choice = _ask("请选择", "0")
        if choice == "0":
            return
        if choice == "1":
            set_monitoring_mode(config_path, "all")
        elif choice == "2":
            set_monitoring_mode(config_path, "allowlist")
            if not monitoring["users"]:
                print("提示：重点名单为空时不会产生订阅用户告警，请先添加用户。")
        elif choice == "3":
            add_monitored_user(config_path, _ask("用户名或订阅 ID"))
        elif choice == "4":
            remove_monitored_user(config_path, _ask("要删除的用户名或订阅 ID"))
        elif choice == "5":
            set_subscription_monitoring_enabled(config_path, not monitoring["enabled"])
        else:
            print("无效选择。")


def _threshold_menu(config_path: str) -> None:
    keys = list(THRESHOLD_SPECS)
    while True:
        config = load_runtime_config(config_path)
        thresholds = config["rules"]["thresholds"]
        print("\n检测参数")
        for index, key in enumerate(keys, 1):
            label, minimum, maximum = THRESHOLD_SPECS[key]
            print(f"{index}. {label}: {thresholds[key]}（范围 {minimum}-{maximum}）")
        print("0. 返回")
        raw = _ask("选择要修改的参数", "0")
        if raw == "0":
            return
        try:
            selected = int(raw)
            if not 1 <= selected <= len(keys):
                raise ValueError
            index = selected - 1
            key = keys[index]
        except (ValueError, IndexError):
            print("无效选择。")
            continue
        value = _ask("新值", str(thresholds[key]))
        set_threshold(config_path, key, value)
        print("参数已保存。")


def _telegram_menu(config_path: str) -> None:
    while True:
        config = load_runtime_config(config_path)
        telegram = config["telegram"]
        print("\nTelegram 参数")
        print(f"1. 最低推送等级：{telegram['minimum_severity']}")
        print(f"2. 同账号同规则冷却小时：{telegram['cooldown_hours']}")
        print(f"3. 推送完整 IP：{'是' if telegram['include_source_ip'] else '否（脱敏）'}")
        print(f"双向管理：{'开启' if telegram['bot_management_enabled'] else '关闭'}")
        print("提示：Token、Chat ID 和管理员 ID 请通过“完整重新配置”修改。")
        print("0. 返回")
        choice = _ask("请选择", "0")
        if choice == "0":
            return
        if choice == "1":
            set_telegram_option(config_path, "minimum_severity", _ask("low/medium/high/critical", telegram["minimum_severity"]))
        elif choice == "2":
            set_telegram_option(config_path, "cooldown_hours", _ask("冷却小时", str(telegram["cooldown_hours"])))
        elif choice == "3":
            set_telegram_option(config_path, "include_source_ip", not telegram["include_source_ip"])
        else:
            print("无效选择。")


def _run_installer(installer: str, action: str, *extra: str) -> None:
    path = Path(installer)
    if not path.is_file():
        raise RuntimeError(f"找不到管理安装器：{path}")
    completed = subprocess.run([str(path), action, *extra], check=False)
    if completed.returncode:
        raise RuntimeError(f"管理操作失败：{action}")


def interactive_menu(config_path: str, installer: str) -> None:
    if os.geteuid() != 0:
        raise PermissionError("请使用 sudo vpspc（root 登录时可直接输入 vpspc）")
    while True:
        print("\n================ VPSPC 审计管理 ================")
        print("1. 查看运行状态")
        print("2. 立即巡查")
        print("3. 多订阅用户管理")
        print("4. 检测阈值管理")
        print("5. Telegram 参数管理")
        print("6. 完整重新配置")
        print("7. 回滚上一次配置")
        print("8. 卸载 / 彻底清理")
        print("0. 退出")
        choice = _ask("请选择", "0")
        try:
            if choice == "0":
                return
            if choice == "1":
                _print_status(config_path)
                _pause()
            elif choice == "2":
                _run_audit()
                _pause()
            elif choice == "3":
                _users_menu(config_path)
            elif choice == "4":
                _threshold_menu(config_path)
            elif choice == "5":
                _telegram_menu(config_path)
            elif choice == "6":
                _run_installer(installer, "configure")
            elif choice == "7":
                if _ask("确认回滚上一次配置？输入 yes", "no").lower() == "yes":
                    _run_installer(installer, "rollback")
            elif choice == "8":
                mode = _ask("输入 uninstall 保留数据，或 destroy 彻底清理", "uninstall").lower()
                if mode == "destroy" and _ask("彻底清理不可恢复，输入 DESTROY 确认", "").upper() == "DESTROY":
                    _run_installer(installer, "destroy")
                    return
                if mode == "uninstall":
                    _run_installer(installer, "uninstall")
                    return
            else:
                print("无效选择。")
        except (OSError, ValueError, RuntimeError, PermissionError) as exc:
            print(f"操作失败：{exc}", file=sys.stderr)
            _pause()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpspc", description="VPSPC interactive audit manager")
    parser.add_argument("--config", default="/etc/vps-audit/config.json")
    parser.add_argument("--installer", default="")
    parser.add_argument("command", nargs="?", choices=["menu", "status", "run", "config-json"], default="menu")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "status":
            _print_status(args.config)
        elif args.command == "run":
            _run_audit()
        elif args.command == "config-json":
            print(json.dumps(load_runtime_config(args.config), ensure_ascii=False, indent=2))
        else:
            installer = args.installer
            if not installer:
                remote_source = Path("/opt/vps-audit-src/install.sh")
                installer = str(remote_source if remote_source.is_file() else Path("/opt/vps-audit/manager/install.sh"))
            interactive_menu(args.config, installer)
        return 0
    except (OSError, ValueError, RuntimeError, PermissionError, json.JSONDecodeError) as exc:
        print(f"vpspc: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
