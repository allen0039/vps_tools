from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from .activity import query_active_subscription_ips, render_active_ip_query
from .node_reporting import (
    create_install_command,
    list_registered_nodes,
    request_registered_node_uninstall,
    revoke_registered_node,
)
from .runtime import health, load_runtime_config, test_configured_ai_provider
from .settings import (
    THRESHOLD_SPECS,
    add_monitored_user,
    remove_ai_provider,
    remove_monitored_user,
    set_active_ai_provider,
    set_ai_enabled,
    set_ai_provider_model,
    set_monitoring_mode,
    set_subscription_monitoring_enabled,
    set_telegram_option,
    set_threshold,
    upsert_ai_provider,
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
    print(f"节点上报：{result['node_reporting']['mode']}")
    print(
        f"AI 复核：{'开启' if result['openai_review_enabled'] else '关闭'}"
        f" / {result.get('openai_active_provider') or '未配置'}"
    )
    print(f"最近巡查：{(result.get('last_run') or {}).get('generated_at', '尚未运行')}")
    if result.get("last_error"):
        print(f"最近错误：{result['last_error']}")


def _run_audit() -> None:
    print("正在执行巡查...")
    completed = subprocess.run(["systemctl", "start", "vps-audit.service"], check=False)
    if completed.returncode:
        raise RuntimeError("巡查失败，请执行 journalctl -u vps-audit.service -n 50 查看日志")
    print("巡查完成。")


def _web_service_state() -> str:
    try:
        completed = subprocess.run(
            ["systemctl", "is-active", "vps-audit-web.service"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return "无法查询"
    state = (completed.stdout or "").strip()
    return state or "未运行"


def _restart_web_service() -> None:
    completed = subprocess.run(["systemctl", "restart", "vps-audit-web.service"], check=False)
    if completed.returncode:
        raise RuntimeError("Web 服务启动失败，请执行 journalctl -u vps-audit-web.service -n 50 查看日志")
    if _web_service_state() != "active":
        raise RuntimeError("Web 服务未进入 active 状态，请执行 systemctl status vps-audit-web.service 查看日志")


def _web_menu(config_path: str) -> None:
    while True:
        config = load_runtime_config(config_path)
        web = config["web"]
        token_path = Path(str(web["token_file"]))
        print("\nWeb 管理台")
        print(f"启用：{'是' if web['enabled'] else '否'}")
        print(f"监听：{web['listen_host']}:{web['listen_port']}")
        print(f"服务状态：{_web_service_state()}")
        print("1. 查看 Web Token")
        print("2. 重新生成 Web Token")
        print("3. 重启并检查 Web 服务")
        print("4. 停止 Web 服务")
        print("0. 返回")
        choice = _ask("请选择", "0")
        if choice == "0":
            return
        if choice == "1":
            if not token_path.is_file():
                raise RuntimeError(f"找不到 Web Token 文件：{token_path}")
            print(f"Web Token：{token_path.read_text(encoding='utf-8').strip()}")
        elif choice == "2":
            if not web["enabled"]:
                raise RuntimeError("Web 管理台未启用，请先通过完整重新配置启用")
            if _ask("确认重新生成 Token？输入 REGENERATE", "").upper() != "REGENERATE":
                print("已取消。")
                continue
            _atomic_secret(token_path, secrets.token_urlsafe(32))
            _restart_web_service()
            print("Web Token 已重新生成，Web 服务已重启。")
        elif choice == "3":
            if not web["enabled"]:
                raise RuntimeError("Web 管理台未启用，请先通过完整重新配置启用")
            _restart_web_service()
            print("Web 服务已启动并通过 active 检查。")
        elif choice == "4":
            completed = subprocess.run(["systemctl", "stop", "vps-audit-web.service"], check=False)
            if completed.returncode:
                raise RuntimeError("停止 Web 服务失败")
            print("Web 服务已停止。")
        else:
            print("无效选择。")


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
        print("6. 查询重点用户活跃 IP")
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
        elif choice == "6":
            _active_ips_menu(config_path)
        else:
            print("无效选择。")


def _active_ips_menu(config_path: str) -> None:
    while True:
        config = load_runtime_config(config_path)
        users = list(config["subscription_monitoring"]["users"])
        window = config["rules"]["thresholds"]["subscription_window_minutes"]
        print("\n重点用户活跃 IP 查询")
        print(f"统计口径：最近 {window} 分钟订阅拉取或节点活动；不是严格同时在线数。")
        if not users:
            print("重点用户名单为空，请先添加用户。")
            _pause()
            return
        for index, user in enumerate(users, 1):
            print(f"  {index}. {user}")
        print("0. 返回")
        raw = _ask("请选择用户", "0")
        if raw == "0":
            return
        try:
            selected = int(raw)
            if not 1 <= selected <= len(users):
                raise ValueError
        except ValueError:
            print("无效选择。")
            continue
        result = query_active_subscription_ips(config, users[selected - 1])
        print("\n" + render_active_ip_query(result, include_source_ip=True, max_items=100))
        _pause()


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


def _atomic_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        temporary.write_text(value.strip() + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _configure_ai_provider(config_path: str) -> str:
    config = load_runtime_config(config_path)
    providers = config["openai_review"]["providers"]
    provider_id = _ask("供应商 ID（小写字母/数字/._-，例如 openai）").lower()
    existing = providers.get(provider_id, {})
    display_name = _ask("显示名称", str(existing.get("display_name", provider_id)))
    base_url = _ask("OpenAI 兼容 Base URL", str(existing.get("base_url", "https://api.openai.com/v1")))
    if base_url.startswith("http://"):
        print("警告：HTTP 会明文传输 API Key，仅应对可信内网或本机端点使用。")
    api_mode = _ask("接口模式 responses/chat_completions", str(existing.get("api_mode", "chat_completions")))
    model = _ask("模型名称", str(existing.get("model", "")))
    timeout = _ask("测试/复核超时秒数", str(existing.get("timeout_seconds", 30)))
    key_path = Path(
        str(existing.get("api_key_file", Path(config_path).parent / "ai-providers" / f"{provider_id}.key"))
    )
    prompt = "API Key（留空保留现有密钥）" if key_path.is_file() else "API Key（输入内容不回显）"
    api_key = getpass.getpass(prompt + ": ").strip()
    if not api_key and not key_path.is_file():
        raise ValueError("新增 AI 供应商时 API Key 不能为空")
    previous = key_path.read_bytes() if key_path.is_file() else None
    if api_key:
        _atomic_secret(key_path, api_key)
    try:
        upsert_ai_provider(
            config_path,
            provider_id,
            display_name,
            base_url,
            api_mode,
            str(key_path),
            model,
            timeout,
        )
    except (OSError, ValueError):
        if api_key:
            if previous is None:
                try:
                    key_path.unlink()
                except FileNotFoundError:
                    pass
            else:
                temporary = key_path.with_name(key_path.name + f".restore.{os.getpid()}")
                temporary.write_bytes(previous)
                os.chmod(temporary, 0o600)
                os.replace(temporary, key_path)
        raise
    return provider_id


def _ai_menu(config_path: str) -> None:
    while True:
        config = load_runtime_config(config_path)
        ai = config["openai_review"]
        active = ai["active_provider"]
        print("\nAI 复核供应商")
        print(f"AI 复核：{'开启' if ai['enabled'] else '关闭'}")
        for provider_id, provider in ai["providers"].items():
            marker = "*" if provider_id == active else " "
            print(f" {marker} {provider_id}: {provider['display_name']} / {provider['model']} / {provider['api_mode']}")
        if not ai["providers"]:
            print("  尚未配置供应商")
        print("1. 切换当前供应商")
        print("2. 新增或修改供应商（含 API Key）")
        print("3. 修改当前模型名称")
        print("4. 测试当前模型")
        print("5. 启用 / 暂停 AI 复核")
        print("6. 删除供应商")
        print("0. 返回")
        choice = _ask("请选择", "0")
        if choice == "0":
            return
        if choice == "1":
            set_active_ai_provider(config_path, _ask("供应商 ID", active))
        elif choice == "2":
            provider_id = _configure_ai_provider(config_path)
            if _ask("是否立即测试该模型？yes/no", "yes").lower() == "yes":
                result = test_configured_ai_provider(config_path, provider_id)
                print(f"测试成功：{result['display_name']} / {result['model']} / {result['latency_ms']} ms")
        elif choice == "3":
            if not active:
                raise ValueError("请先配置 AI 供应商")
            set_ai_provider_model(config_path, active, _ask("新模型名称", ai["providers"][active]["model"]))
        elif choice == "4":
            result = test_configured_ai_provider(config_path)
            print(f"测试成功：{result['display_name']} / {result['model']} / {result['latency_ms']} ms")
        elif choice == "5":
            set_ai_enabled(config_path, not ai["enabled"])
        elif choice == "6":
            provider_id = _ask("要删除的供应商 ID", active)
            provider = ai["providers"].get(provider_id)
            if not provider:
                raise ValueError(f"AI 供应商不存在：{provider_id}")
            updated = remove_ai_provider(config_path, provider_id)
            key_path = Path(str(provider["api_key_file"]))
            managed_root = Path(config_path).parent / "ai-providers"
            still_referenced = any(
                str(item["api_key_file"]) == str(key_path)
                for item in updated["openai_review"]["providers"].values()
            )
            if not still_referenced and key_path.parent == managed_root and key_path.is_file():
                key_path.unlink()
        else:
            print("无效选择。")


def _nodes_menu(config_path: str) -> None:
    while True:
        config = load_runtime_config(config_path)
        node_reporting = config["node_reporting"]
        print("\n节点上报与注册链接")
        print(f"当前模式：{node_reporting['mode']}")
        if node_reporting["mode"] != "node_reporting":
            print("当前仅主控监控；请通过“完整重新配置”启用节点上报并设置 HTTPS 公网地址。")
        nodes = list_registered_nodes(config_path)
        for index, node in enumerate(nodes, 1):
            state = "已撤销" if node.get("revoked") else "等待卸载" if node.get("pending_command") else "有效"
            print(
                f"  {index}. {node['node_id']} | {node.get('name', '-')} | {state} | "
                f"最后上报 {node.get('last_seen') or '从未'}"
            )
        if not nodes:
            print("  尚无注册节点")
        print("1. 生成普通安装/修复链接")
        print("2. 生成允许覆盖重绑的链接")
        print("3. 撤销节点凭据")
        print("4. 请求节点自卸载并撤销")
        print("0. 返回")
        choice = _ask("请选择", "0")
        if choice == "0":
            return
        if choice in {"1", "2"}:
            command = create_install_command(
                config_path,
                _ask("节点显示名称"),
                replace=choice == "2",
            )
            print("\n请在被控端执行以下一次性命令：")
            print(command)
        elif choice == "3":
            revoke_registered_node(config_path, _ask("节点 ID"))
            print("节点凭据已立即撤销。")
        elif choice == "4":
            command = request_registered_node_uninstall(config_path, _ask("节点 ID"))
            print(f"固定自卸载命令已排队：{command['id']}")
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
        print("4. 查询重点用户活跃 IP")
        print("5. 检测阈值管理")
        print("6. Telegram 参数管理")
        print("7. AI 供应商与模型")
        print("8. 节点上报与注册链接")
        print("9. Web 管理台与 Token")
        print("10. 完整重新配置")
        print("11. 回滚上一次配置")
        print("12. 卸载 / 彻底清理")
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
                _active_ips_menu(config_path)
            elif choice == "5":
                _threshold_menu(config_path)
            elif choice == "6":
                _telegram_menu(config_path)
            elif choice == "7":
                _ai_menu(config_path)
            elif choice == "8":
                _nodes_menu(config_path)
            elif choice == "9":
                _web_menu(config_path)
            elif choice == "10":
                _run_installer(installer, "configure")
            elif choice == "11":
                if _ask("确认回滚上一次配置？输入 yes", "no").lower() == "yes":
                    _run_installer(installer, "rollback")
            elif choice == "12":
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
