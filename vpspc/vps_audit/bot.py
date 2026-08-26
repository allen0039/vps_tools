from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .runtime import _atomic_json, _read_secret, health, load_runtime_config
from .settings import (
    THRESHOLD_SPECS,
    add_monitored_user,
    remove_monitored_user,
    set_monitoring_mode,
    set_subscription_monitoring_enabled,
    set_telegram_option,
    set_threshold,
)
from .telegram import answer_callback_query, get_updates, send_message


def _button(text: str, data: str) -> Dict[str, str]:
    return {"text": text, "callback_data": data}


def _main_keyboard() -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("📊 状态", "menu:status"), _button("👥 订阅用户", "menu:users")],
        [_button("⚙️ 检测参数", "menu:thresholds"), _button("🔔 推送参数", "menu:telegram")],
        [_button("▶️ 立即巡查", "menu:run"), _button("❓ 帮助", "menu:help")],
    ]}


def _users_keyboard() -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("监测全部用户", "mode:all"), _button("仅重点名单", "mode:allowlist")],
        [_button("启用/暂停订阅监测", "toggle:subscription_enabled")],
        [_button("➕ 添加用户", "prompt:adduser"), _button("➖ 删除用户", "prompt:deluser")],
        [_button("⬅️ 主菜单", "menu:main")],
    ]}


def _threshold_keyboard() -> Dict[str, Any]:
    buttons = [_button(label, f"prompt:threshold:{key}") for key, (label, _, _) in THRESHOLD_SPECS.items()]
    rows = [buttons[index : index + 2] for index in range(0, len(buttons), 2)]
    rows.append([_button("⬅️ 主菜单", "menu:main")])
    return {"inline_keyboard": rows}


def _telegram_keyboard() -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("最低等级", "prompt:telegram:minimum_severity")],
        [_button("冷却小时", "prompt:telegram:cooldown_hours")],
        [_button("切换完整 IP 显示", "toggle:include_source_ip")],
        [_button("⬅️ 主菜单", "menu:main")],
    ]}


def _monitoring_text(config: Dict[str, Any]) -> str:
    monitoring = config["subscription_monitoring"]
    mode = "全部日志用户" if monitoring["mode"] == "all" else "仅重点名单"
    users = monitoring["users"]
    header = f"订阅监测：{'开启' if monitoring['enabled'] else '关闭'}\n模式：{mode}\n重点用户数：{len(users)}\n\n"
    if not users:
        return header + "（名单为空）"
    lines: List[str] = []
    for index, user in enumerate(users, 1):
        line = f"{index}. {user}"
        if len(header) + sum(len(item) + 1 for item in lines) + len(line) > 3400:
            lines.append(f"……另有 {len(users) - index + 1} 个用户，请在 VPS 本机使用 vpspc 查看。")
            break
        lines.append(line)
    return header + "\n".join(lines)


def _threshold_text(config: Dict[str, Any]) -> str:
    thresholds = config["rules"]["thresholds"]
    lines = ["当前检测参数："]
    for key, (label, _, _) in THRESHOLD_SPECS.items():
        lines.append(f"• {label}: {thresholds[key]}  ({key})")
    return "\n".join(lines)


def _telegram_text(config: Dict[str, Any]) -> str:
    telegram = config["telegram"]
    return (
        "Telegram 推送参数：\n"
        f"• 最低等级：{telegram['minimum_severity']}\n"
        f"• 同账号同规则冷却：{telegram['cooldown_hours']} 小时\n"
        f"• 推送完整来源 IP：{'是' if telegram['include_source_ip'] else '否（脱敏）'}\n"
        "\nBot 只能预警和管理配置，不具备封禁能力。"
    )


def _status_text(config_path: str) -> str:
    result = health(config_path)
    last_run = result.get("last_run") or {}
    summary = result.get("last_summary") or {}
    monitoring = result["subscription_monitoring"]
    mode = "全部" if monitoring["mode"] == "all" else f"重点名单 {len(monitoring['users'])} 人"
    return (
        f"VPSPC 状态：{result['status']}\n"
        f"订阅监测：{'开启' if monitoring['enabled'] else '关闭'} / {mode}\n"
        f"最近巡查：{last_run.get('generated_at', '尚未运行')}\n"
        f"事件：{summary.get('event_count', 0)}，发现：{summary.get('finding_count', 0)}\n"
        f"Telegram 管理：{'开启' if result['telegram_management_enabled'] else '关闭'}"
    )


def _help_text() -> str:
    return (
        "VPSPC 管理命令：\n"
        "/menu 或 /vpspc - 打开菜单\n"
        "/status - 查看状态\n"
        "/users - 查看监测名单\n"
        "/mode all|allowlist - 全部用户或重点名单\n"
        "/monitor on|off - 启用或暂停订阅监测\n"
        "/adduser <用户名或订阅ID>\n"
        "/deluser <用户名或订阅ID>\n"
        "/thresholds - 查看参数\n"
        "/set <参数名> <整数>\n"
        "/run - 立即巡查\n"
        "\n所有操作只会审计、记录和预警，不会自动封禁。"
    )


def _update_context(update: Dict[str, Any]) -> Tuple[Dict[str, Any], int, str, str | None]:
    callback = update.get("callback_query")
    if isinstance(callback, dict):
        message = callback.get("message") or {}
        sender = callback.get("from") or {}
        chat = message.get("chat") or {}
        return chat, int(sender.get("id", 0)), str(callback.get("data", "")), str(callback.get("id", ""))
    message = update.get("message") or {}
    sender = message.get("from") or {}
    chat = message.get("chat") or {}
    return chat, int(sender.get("id", 0)), str(message.get("text", "")).strip(), None


def _authorized(config: Dict[str, Any], chat: Dict[str, Any], sender_id: int) -> bool:
    telegram = config["telegram"]
    return str(chat.get("id", "")) == str(telegram.get("chat_id", "")) and sender_id in set(telegram["admin_user_ids"])


def _run_audit(config_path: str) -> str:
    completed = subprocess.run(
        ["systemctl", "start", "vps-audit.service"],
        capture_output=True,
        text=True,
        timeout=190,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError("首次巡查失败" + (f"：{detail[:300]}" if detail else "，请查看 systemd 日志"))
    return "巡查已完成。\n\n" + _status_text(config_path)


def _apply_pending(config_path: str, pending: Dict[str, Any], sender_id: int, text: str) -> str | None:
    entry = pending.pop(str(sender_id), None)
    if not entry:
        return None
    action = entry.get("action")
    if action == "adduser":
        config = add_monitored_user(config_path, text)
        return "已添加重点用户。\n\n" + _monitoring_text(config)
    if action == "deluser":
        config = remove_monitored_user(config_path, text)
        return "已删除重点用户。\n\n" + _monitoring_text(config)
    if action == "threshold":
        config = set_threshold(config_path, str(entry["key"]), text)
        return "检测参数已更新。\n\n" + _threshold_text(config)
    if action == "telegram":
        config = set_telegram_option(config_path, str(entry["key"]), text)
        return "推送参数已更新。\n\n" + _telegram_text(config)
    raise ValueError("未知的待处理操作")


def _handle(config_path: str, sender_id: int, value: str, pending: Dict[str, Any]) -> Tuple[str, Dict[str, Any] | None]:
    if not value.startswith("/") and not value.startswith(("menu:", "mode:", "prompt:", "toggle:")):
        result = _apply_pending(config_path, pending, sender_id, value)
        if result:
            return result, _main_keyboard()
    config = load_runtime_config(config_path)
    command, *arguments = value.split(maxsplit=2)
    command = command.split("@", 1)[0].lower()
    if command in {"/start", "/menu", "/vpspc", "menu:main"}:
        return "VPSPC 审计管理\n请选择操作。", _main_keyboard()
    if command in {"/status", "menu:status"}:
        return _status_text(config_path), _main_keyboard()
    if command in {"/users", "menu:users"}:
        return _monitoring_text(config), _users_keyboard()
    if command in {"/thresholds", "menu:thresholds"}:
        return _threshold_text(config), _threshold_keyboard()
    if command == "menu:telegram":
        return _telegram_text(config), _telegram_keyboard()
    if command in {"/help", "menu:help"}:
        return _help_text(), _main_keyboard()
    if command in {"/run", "menu:run"}:
        return _run_audit(config_path), _main_keyboard()
    if command.startswith("mode:"):
        mode = command.split(":", 1)[1]
        config = set_monitoring_mode(config_path, mode)
        return "监测模式已更新。\n\n" + _monitoring_text(config), _users_keyboard()
    if command == "/mode":
        if not arguments:
            raise ValueError("用法：/mode all 或 /mode allowlist")
        config = set_monitoring_mode(config_path, arguments[0].lower())
        return "监测模式已更新。\n\n" + _monitoring_text(config), _users_keyboard()
    if command == "/monitor":
        if not arguments or arguments[0].lower() not in {"on", "off"}:
            raise ValueError("用法：/monitor on 或 /monitor off")
        config = set_subscription_monitoring_enabled(config_path, arguments[0].lower() == "on")
        return "订阅监测开关已更新。\n\n" + _monitoring_text(config), _users_keyboard()
    if command in {"/adduser", "/deluser"}:
        if not arguments:
            raise ValueError(f"用法：{command} <用户名或订阅ID>")
        config = add_monitored_user(config_path, arguments[0]) if command == "/adduser" else remove_monitored_user(config_path, arguments[0])
        return _monitoring_text(config), _users_keyboard()
    if command == "/set":
        if len(arguments) != 2:
            raise ValueError("用法：/set <参数名> <整数>")
        config = set_threshold(config_path, arguments[0], arguments[1])
        return "检测参数已更新。\n\n" + _threshold_text(config), _threshold_keyboard()
    if command.startswith("prompt:"):
        parts = command.split(":")
        if parts[1] in {"adduser", "deluser"}:
            pending[str(sender_id)] = {"action": parts[1]}
            action_text = "添加" if parts[1] == "adduser" else "删除"
            return f"请发送需要{action_text}的用户名或订阅 ID。发送 /cancel 可取消。", None
        if len(parts) == 3 and parts[1] in {"threshold", "telegram"}:
            pending[str(sender_id)] = {"action": parts[1], "key": parts[2]}
            return f"请发送 {parts[2]} 的新值。发送 /cancel 可取消。", None
    if command == "/cancel":
        pending.pop(str(sender_id), None)
        return "已取消。", _main_keyboard()
    if command == "toggle:include_source_ip":
        config = set_telegram_option(config_path, "include_source_ip", not config["telegram"]["include_source_ip"])
        return "完整 IP 显示设置已切换。\n\n" + _telegram_text(config), _telegram_keyboard()
    if command == "toggle:subscription_enabled":
        config = set_subscription_monitoring_enabled(
            config_path, not config["subscription_monitoring"]["enabled"]
        )
        return "订阅监测开关已更新。\n\n" + _monitoring_text(config), _users_keyboard()
    return "无法识别该操作。\n\n" + _help_text(), _main_keyboard()


def run_bot(config_path: str, once: bool = False) -> None:
    config = load_runtime_config(config_path)
    telegram = config["telegram"]
    if not telegram.get("bot_management_enabled"):
        raise ValueError("Telegram 双向管理未启用")
    token = _read_secret(str(telegram["token_file"]), "Telegram token")
    state_path = Path(config["state_dir"]) / "bot-state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    except (OSError, ValueError, json.JSONDecodeError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    pending = state.get("pending")
    if not isinstance(pending, dict):
        pending = {}
        state["pending"] = pending
    offset = state.get("offset")
    while True:
        config = load_runtime_config(config_path)
        telegram = config["telegram"]
        updates = get_updates(token, offset, int(telegram["poll_timeout_seconds"]))
        for update in updates:
            update_id = int(update.get("update_id", 0))
            offset = max(int(offset or 0), update_id + 1)
            state["offset"] = offset
            _atomic_json(state_path, state)
            chat, sender_id, value, callback_id = _update_context(update)
            if not _authorized(config, chat, sender_id):
                if callback_id:
                    answer_callback_query(token, callback_id, "无权操作")
                elif str(chat.get("id", "")) == str(telegram.get("chat_id", "")):
                    send_message(token, str(chat.get("id")), "该 Telegram 用户未被授权管理 VPSPC。")
                _atomic_json(state_path, state)
                continue
            try:
                response, keyboard = _handle(config_path, sender_id, value, pending)
                if callback_id:
                    answer_callback_query(token, callback_id)
                send_message(token, str(chat["id"]), response, reply_markup=keyboard)
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                if callback_id:
                    answer_callback_query(token, callback_id, "操作失败")
                send_message(token, str(chat["id"]), f"操作失败：{str(exc)[:500]}")
            _atomic_json(state_path, state)
        if once:
            return
        if not updates:
            time.sleep(0.2)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vps-audit-bot", description="Telegram management bot for VPSPC")
    parser.add_argument("--config", default="/etc/vps-audit/config.json")
    parser.add_argument("--once", action="store_true", help="process one getUpdates response and exit")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        run_bot(args.config, args.once)
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"vps-audit-bot: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
