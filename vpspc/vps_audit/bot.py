from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .activity import query_active_subscription_ips, render_active_ip_query
from .behavior_audit import list_incidents, load_incident, render_ai_review, render_incident
from .runtime import (
    _atomic_json,
    _read_secret,
    health,
    load_runtime_config,
    review_behavior_incident,
    test_configured_ai_provider,
)
from .settings import (
    THRESHOLD_SPECS,
    add_monitored_user,
    remove_monitored_user,
    set_active_ai_provider,
    set_ai_enabled,
    set_ai_provider_model,
    set_monitoring_mode,
    set_subscription_monitoring_enabled,
    set_telegram_option,
    set_threshold,
)
from .telegram import (
    TelegramTransientError,
    answer_callback_query,
    edit_message_text,
    get_updates,
    set_chat_menu_button,
    set_my_commands,
    send_message,
)


DISCOVERY_PAGE_SIZE = 8
_DISCOVERY_CACHE: Dict[str, Any] = {}


def _register_command_menu(token: str) -> None:
    try:
        set_my_commands(token)
        set_chat_menu_button(token)
    except TelegramTransientError as exc:
        print(f"vps-audit-bot: command menu registration deferred: {exc}", file=sys.stderr)


def _button(text: str, data: str) -> Dict[str, str]:
    return {"text": text, "callback_data": data}


def _main_keyboard() -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("📊 状态", "menu:status"), _button("👥 订阅用户", "menu:users")],
        [_button("🌐 查询重点用户活跃 IP", "activeips:0")],
        [_button("🧾 行为事件", "incident:list")],
        [_button("⚙️ 检测参数", "menu:thresholds"), _button("🔔 推送参数", "menu:telegram")],
        [_button("🤖 AI 复核", "menu:ai")],
        [_button("▶️ 立即巡查", "menu:run"), _button("❓ 帮助", "menu:help")],
    ]}


def _users_keyboard() -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("监测全部用户", "mode:all"), _button("仅重点名单", "mode:allowlist")],
        [_button("启用/暂停订阅监测", "toggle:subscription_enabled")],
        [_button("🔎 从日志发现并点选", "discover:0")],
        [_button("🌐 查询重点用户活跃 IP", "activeips:0")],
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


def _ai_keyboard(config: Dict[str, Any]) -> Dict[str, Any]:
    ai = config["openai_review"]
    rows: List[List[Dict[str, str]]] = []
    for provider_id, provider in ai["providers"].items():
        marker = "✅" if provider_id == ai["active_provider"] else "切换"
        label = f"{marker} {provider['display_name']}"
        if len(label) > 42:
            label = label[:39] + "..."
        rows.append([_button(label, f"ai:use:{provider_id}")])
    rows.extend([
        [_button("启用/暂停 AI", "ai:toggle"), _button("测试当前模型", "ai:test")],
        [_button("修改当前模型名", "prompt:ai:model")],
        [_button("⬅️ 主菜单", "menu:main")],
    ])
    return {"inline_keyboard": rows}


def _incident_ai_available(config: Dict[str, Any]) -> bool:
    ai = config["openai_review"]
    active = str(ai.get("active_provider", ""))
    return bool(active and active in ai.get("providers", {}))


def _incident_list_view(config: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    behavior = config["behavior_audit"]
    if not behavior["enabled"]:
        return (
            "完整连接元数据审计尚未启用。",
            {"inline_keyboard": [[_button("⬅️ 主菜单", "menu:main")]]},
        )
    records = list_incidents(Path(str(behavior["archive_dir"])), limit=10)
    if not records:
        return (
            "尚无行为事件。完成一次巡查并命中节点或行为规则后会显示在这里。",
            {"inline_keyboard": [[_button("🔄 刷新", "incident:list")], [_button("⬅️ 主菜单", "menu:main")]]},
        )
    lines = [f"最近行为事件（{len(records)} 条）："]
    rows: List[List[Dict[str, str]]] = []
    for record in records:
        identifier = str(record.get("incident_id", ""))
        lines.append(
            f"{identifier} | {record.get('severity', '-')} | {record.get('user', '-')} | "
            f"{record.get('title', record.get('rule_id', '-'))}"
        )
        rows.append([_button(f"查看 {identifier}", f"incident:view:{identifier}")])
    rows.extend([[_button("🔄 刷新", "incident:list")], [_button("⬅️ 主菜单", "menu:main")]])
    return "\n".join(lines)[:3900], {"inline_keyboard": rows}


def _incident_detail_view(config: Dict[str, Any], identifier: str) -> Tuple[str, Dict[str, Any]]:
    record = load_incident(Path(str(config["behavior_audit"]["archive_dir"])), identifier.upper())
    rows: List[List[Dict[str, str]]] = []
    if _incident_ai_available(config):
        rows.append([_button("🤖 AI 审计", f"incident:ai:{identifier.upper()}")])
        rows.append([_button("💬 向 AI 追问", f"incident:ask:{identifier.upper()}")])
    rows.extend([[_button("⬅️ 事件列表", "incident:list")], [_button("⬅️ 主菜单", "menu:main")]])
    return render_incident(record), {"inline_keyboard": rows}


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


def _discovered_users(config: Dict[str, Any]) -> List[str]:
    path = Path(config["state_dir"]) / "events.jsonl"
    try:
        stat = path.stat()
    except OSError:
        return []
    cache_key = f"{path}:{stat.st_mtime_ns}:{stat.st_size}"
    if _DISCOVERY_CACHE.get("key") == cache_key:
        return list(_DISCOVERY_CACHE.get("users", []))
    latest: Dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(event, dict) or event.get("event_type") != "subscription_access":
                    continue
                user = str(event.get("user", "")).strip()
                if not user or len(user) > 128 or any(ord(char) < 32 for char in user):
                    continue
                timestamp = str(event.get("timestamp", ""))
                if timestamp >= latest.get(user, ""):
                    latest[user] = timestamp
    except OSError:
        return []
    users = sorted(latest, key=lambda user: (latest[user], user), reverse=True)
    _DISCOVERY_CACHE.clear()
    _DISCOVERY_CACHE.update({"key": cache_key, "users": users})
    return users


def _user_token(user: str) -> str:
    return hashlib.sha256(user.encode("utf-8")).hexdigest()[:24]


def _safe_button_label(user: str, selected: bool) -> str:
    clean = "".join(char if ord(char) >= 32 else "?" for char in user)
    if len(clean) > 42:
        clean = clean[:39] + "..."
    return ("✅ " if selected else "➕ ") + clean


def _plain_user_label(user: str) -> str:
    clean = "".join(char if ord(char) >= 32 else "?" for char in user)
    return clean if len(clean) <= 44 else clean[:41] + "..."


def _active_ip_selection_view(config: Dict[str, Any], page: int) -> Tuple[str, Dict[str, Any]]:
    users = list(config["subscription_monitoring"]["users"])
    if not users:
        return (
            "重点用户名单为空，请先添加用户后再查询活跃 IP。",
            {"inline_keyboard": [[_button("⬅️ 用户管理", "menu:users")]]},
        )
    page_count = max(1, (len(users) + DISCOVERY_PAGE_SIZE - 1) // DISCOVERY_PAGE_SIZE)
    page = max(0, min(page, page_count - 1))
    start = page * DISCOVERY_PAGE_SIZE
    rows = [
        [_button(_plain_user_label(user), f"activeips:user:{_user_token(user)}:{page}")]
        for user in users[start : start + DISCOVERY_PAGE_SIZE]
    ]
    navigation: List[Dict[str, str]] = []
    if page > 0:
        navigation.append(_button("⬅️ 上一页", f"activeips:{page - 1}"))
    if page + 1 < page_count:
        navigation.append(_button("下一页 ➡️", f"activeips:{page + 1}"))
    if navigation:
        rows.append(navigation)
    rows.append([_button("⬅️ 用户管理", "menu:users")])
    window = config["rules"]["thresholds"]["subscription_window_minutes"]
    return (
        f"请选择要查询的重点用户（第 {page + 1}/{page_count} 页）。\n"
        f"“活跃”表示最近 {window} 分钟内出现过订阅访问，并非严格同时在线。",
        {"inline_keyboard": rows},
    )


def _active_ip_result(config: Dict[str, Any], user: str, page: int = 0) -> Tuple[str, Dict[str, Any]]:
    if user not in config["subscription_monitoring"]["users"]:
        raise ValueError("只能快捷查询已经添加的重点用户")
    result = query_active_subscription_ips(config, user)
    text = render_active_ip_query(
        result,
        include_source_ip=bool(config["telegram"].get("include_source_ip")),
        max_items=20,
    )
    keyboard = {"inline_keyboard": [
        [_button("🔄 刷新", f"activeips:user:{_user_token(user)}:{page}")],
        [_button("⬅️ 选择其他用户", f"activeips:{page}")],
        [_button("⬅️ 主菜单", "menu:main")],
    ]}
    return text[:3900], keyboard


def _discovery_view(config: Dict[str, Any], page: int) -> Tuple[str, Dict[str, Any]]:
    users = _discovered_users(config)
    if not users:
        return (
            "尚未从本地日志发现订阅用户。完成一次订阅访问和巡查后再试。",
            {"inline_keyboard": [[_button("⬅️ 用户管理", "menu:users")]]},
        )
    page_count = max(1, (len(users) + DISCOVERY_PAGE_SIZE - 1) // DISCOVERY_PAGE_SIZE)
    page = max(0, min(page, page_count - 1))
    start = page * DISCOVERY_PAGE_SIZE
    selected = set(config["subscription_monitoring"]["users"])
    rows: List[List[Dict[str, str]]] = []
    for user in users[start : start + DISCOVERY_PAGE_SIZE]:
        action = "remove" if user in selected else "add"
        rows.append([_button(_safe_button_label(user, user in selected), f"discover:{action}:{_user_token(user)}:{page}")])
    navigation: List[Dict[str, str]] = []
    if page > 0:
        navigation.append(_button("⬅️ 上一页", f"discover:{page - 1}"))
    if page + 1 < page_count:
        navigation.append(_button("下一页 ➡️", f"discover:{page + 1}"))
    if navigation:
        rows.append(navigation)
    rows.append([_button("⬅️ 用户管理", "menu:users")])
    mode_note = "当前 all 模式仍监测全部用户；勾选项会保存为重点名单。" if config["subscription_monitoring"]["mode"] == "all" else "当前仅监测已勾选的重点用户。"
    return (
        f"从本地日志发现 {len(users)} 个订阅用户（第 {page + 1}/{page_count} 页）。\n"
        "点击可连续加入或移出重点名单。\n"
        f"{mode_note}",
        {"inline_keyboard": rows},
    )


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


def _ai_text(config: Dict[str, Any]) -> str:
    ai = config["openai_review"]
    active = ai["active_provider"]
    lines = [
        f"AI 复核：{'开启' if ai['enabled'] else '关闭'}",
        f"当前供应商：{active or '未配置'}",
    ]
    if active and active in ai["providers"]:
        provider = ai["providers"][active]
        lines.extend([
            f"显示名称：{provider['display_name']}",
            f"模型：{provider['model']}",
            f"接口模式：{provider['api_mode']}",
        ])
    lines.append("\nTelegram 只允许切换、改模型名和测试；新增端点/API Key 请在 VPS 本机运行 vpspc。")
    return "\n".join(lines)


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
        "/discover - 从本地日志点选用户\n"
        "/ips [用户名] - 查询已添加用户的活跃 IP 与位置\n"
        "/incidents - 查看最近行为事件\n"
        "/incident <INC-ID> - 查看完整连接时间线\n"
        "/incidentai <INC-ID> - 使用 AI 复核单个事件\n"
        "/ask <INC-ID> <问题> - 针对单个事件向 AI 追问\n"
        "/mode all|allowlist - 全部用户或重点名单\n"
        "/monitor on|off - 启用或暂停订阅监测\n"
        "/adduser <用户名或订阅ID>\n"
        "/deluser <用户名或订阅ID>\n"
        "/thresholds - 查看参数\n"
        "/set <参数名> <整数>\n"
        "/ai - 查看 AI 供应商\n"
        "/aiuse <供应商ID> - 切换供应商\n"
        "/aimodel <模型名> - 修改当前模型\n"
        "/aitest - 用合成数据测试当前模型\n"
        "/aion 或 /aioff - 开关 AI 复核\n"
        "/run - 立即巡查\n"
        "\n所有操作只会审计、记录和预警，不会自动封禁。"
    )


def _update_context(update: Dict[str, Any]) -> Tuple[Dict[str, Any], int, str, str | None, int | None]:
    callback = update.get("callback_query")
    if isinstance(callback, dict):
        message = callback.get("message") or {}
        sender = callback.get("from") or {}
        chat = message.get("chat") or {}
        message_id = message.get("message_id")
        return chat, int(sender.get("id", 0)), str(callback.get("data", "")), str(callback.get("id", "")), int(message_id) if message_id is not None else None
    message = update.get("message") or {}
    sender = message.get("from") or {}
    chat = message.get("chat") or {}
    return chat, int(sender.get("id", 0)), str(message.get("text", "")).strip(), None, None


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


def _answer_callback_safely(token: str, callback_id: str, text: str = "") -> None:
    try:
        answer_callback_query(token, callback_id, text)
    except RuntimeError as exc:
        print(f"vps-audit-bot: callback acknowledgement failed: {exc}", file=sys.stderr)


def _send_error_safely(token: str, chat_id: str, text: str) -> None:
    try:
        send_message(token, chat_id, text)
    except RuntimeError as exc:
        print(f"vps-audit-bot: unable to send operation error: {exc}", file=sys.stderr)


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
    if action == "ai_model":
        config = set_ai_provider_model(config_path, str(entry["provider_id"]), text)
        return "AI 模型已更新。\n\n" + _ai_text(config)
    if action == "incident_question":
        review = review_behavior_incident(config_path, str(entry["incident_id"]), text)
        return render_ai_review(review)
    raise ValueError("未知的待处理操作")


def _handle(config_path: str, sender_id: int, value: str, pending: Dict[str, Any]) -> Tuple[str, Dict[str, Any] | None]:
    if not value.startswith("/") and not value.startswith(("menu:", "mode:", "prompt:", "toggle:", "discover:", "activeips:", "ai:", "incident:")):
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
    if command == "/discover":
        return _discovery_view(config, 0)
    if command in {"/ips", "/activeips"}:
        if not arguments:
            return _active_ip_selection_view(config, 0)
        return _active_ip_result(config, " ".join(arguments))
    if command in {"/thresholds", "menu:thresholds"}:
        return _threshold_text(config), _threshold_keyboard()
    if command == "menu:telegram":
        return _telegram_text(config), _telegram_keyboard()
    if command in {"/ai", "menu:ai"}:
        return _ai_text(config), _ai_keyboard(config)
    if command in {"/incidents", "incident:list"}:
        return _incident_list_view(config)
    if command == "/incident":
        if not arguments:
            raise ValueError("用法：/incident <INC-ID>")
        return _incident_detail_view(config, arguments[0])
    if command == "/incidentai":
        if not arguments:
            raise ValueError("用法：/incidentai <INC-ID>")
        review = review_behavior_incident(config_path, arguments[0].upper())
        return render_ai_review(review), _main_keyboard()
    if command == "/ask":
        if len(arguments) != 2:
            raise ValueError("用法：/ask <INC-ID> <问题>")
        review = review_behavior_incident(config_path, arguments[0].upper(), arguments[1])
        return render_ai_review(review), _main_keyboard()
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
    if command == "/aiuse":
        if not arguments:
            raise ValueError("用法：/aiuse <供应商ID>")
        config = set_active_ai_provider(config_path, arguments[0])
        return "AI 供应商已切换。\n\n" + _ai_text(config), _ai_keyboard(config)
    if command == "/aimodel":
        if not arguments:
            raise ValueError("用法：/aimodel <模型名>")
        active = config["openai_review"]["active_provider"]
        if not active:
            raise ValueError("请先在 VPS 本机配置 AI 供应商")
        config = set_ai_provider_model(config_path, active, arguments[0])
        return "AI 模型已更新。\n\n" + _ai_text(config), _ai_keyboard(config)
    if command == "/aitest":
        result = test_configured_ai_provider(config_path)
        config = load_runtime_config(config_path)
        return (
            f"AI 模型测试成功。\n供应商：{result['display_name']}\n模型：{result['model']}\n"
            f"接口：{result['api_mode']}\n耗时：{result['latency_ms']} ms",
            _ai_keyboard(config),
        )
    if command in {"/aion", "/aioff"}:
        config = set_ai_enabled(config_path, command == "/aion")
        return "AI 复核开关已更新。\n\n" + _ai_text(config), _ai_keyboard(config)
    if command.startswith("prompt:"):
        parts = command.split(":")
        if parts[1] in {"adduser", "deluser"}:
            pending[str(sender_id)] = {"action": parts[1]}
            action_text = "添加" if parts[1] == "adduser" else "删除"
            return f"请发送需要{action_text}的用户名或订阅 ID。发送 /cancel 可取消。", None
        if len(parts) == 3 and parts[1] in {"threshold", "telegram"}:
            pending[str(sender_id)] = {"action": parts[1], "key": parts[2]}
            return f"请发送 {parts[2]} 的新值。发送 /cancel 可取消。", None
        if parts[1:] == ["ai", "model"]:
            active = config["openai_review"]["active_provider"]
            if not active:
                raise ValueError("请先在 VPS 本机配置 AI 供应商")
            pending[str(sender_id)] = {"action": "ai_model", "provider_id": active}
            return "请发送新的模型名称。发送 /cancel 可取消。", None
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
    if command == "ai:toggle":
        config = set_ai_enabled(config_path, not config["openai_review"]["enabled"])
        return "AI 复核开关已更新。\n\n" + _ai_text(config), _ai_keyboard(config)
    if command == "ai:test":
        result = test_configured_ai_provider(config_path)
        config = load_runtime_config(config_path)
        return (
            f"AI 模型测试成功。\n供应商：{result['display_name']}\n模型：{result['model']}\n"
            f"接口：{result['api_mode']}\n耗时：{result['latency_ms']} ms",
            _ai_keyboard(config),
        )
    if command.startswith("ai:use:"):
        config = set_active_ai_provider(config_path, command.split(":", 2)[2])
        return "AI 供应商已切换。\n\n" + _ai_text(config), _ai_keyboard(config)
    if command.startswith("incident:view:"):
        return _incident_detail_view(config, command.split(":", 2)[2])
    if command.startswith("incident:ai:"):
        identifier = command.split(":", 2)[2].upper()
        review = review_behavior_incident(config_path, identifier)
        return render_ai_review(review), _incident_detail_view(config, identifier)[1]
    if command.startswith("incident:ask:"):
        identifier = command.split(":", 2)[2].upper()
        load_incident(Path(str(config["behavior_audit"]["archive_dir"])), identifier)
        if not _incident_ai_available(config):
            raise ValueError("请先在 VPS 本机配置 AI 供应商")
        pending[str(sender_id)] = {"action": "incident_question", "incident_id": identifier}
        return f"请发送针对事件 {identifier} 的问题。发送 /cancel 可取消。", None
    if command.startswith("activeips:"):
        parts = command.split(":")
        if len(parts) == 2:
            try:
                page = int(parts[1])
            except ValueError as exc:
                raise ValueError("无效的活跃 IP 查询页码") from exc
            return _active_ip_selection_view(config, page)
        if len(parts) == 4 and parts[1] == "user":
            token = parts[2]
            try:
                page = int(parts[3])
            except ValueError as exc:
                raise ValueError("无效的活跃 IP 查询页码") from exc
            matches = [
                user for user in config["subscription_monitoring"]["users"]
                if _user_token(user) == token
            ]
            if len(matches) != 1:
                raise ValueError("重点用户名单已变化，请重新选择")
            return _active_ip_result(config, matches[0], page)
    if command.startswith("discover:"):
        parts = command.split(":")
        if len(parts) == 2:
            try:
                page = int(parts[1])
            except ValueError as exc:
                raise ValueError("无效的发现用户页码") from exc
            return _discovery_view(config, page)
        if len(parts) == 4 and parts[1] in {"add", "remove"}:
            action, token = parts[1], parts[2]
            try:
                page = int(parts[3])
            except ValueError as exc:
                raise ValueError("无效的发现用户页码") from exc
            matches = [user for user in _discovered_users(config) if _user_token(user) == token]
            if len(matches) != 1:
                raise ValueError("候选用户已变化，请重新打开发现用户列表")
            if action == "add":
                config = add_monitored_user(config_path, matches[0])
            else:
                config = remove_monitored_user(config_path, matches[0])
            return _discovery_view(config, page)
    return "无法识别该操作。\n\n" + _help_text(), _main_keyboard()


def run_bot(config_path: str, once: bool = False) -> None:
    config = load_runtime_config(config_path)
    telegram = config["telegram"]
    if not telegram.get("bot_management_enabled"):
        raise ValueError("Telegram 双向管理未启用")
    token = _read_secret(str(telegram["token_file"]), "Telegram token")
    if not once:
        _register_command_menu(token)
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
    retry_delay = 1.0
    while True:
        config = load_runtime_config(config_path)
        telegram = config["telegram"]
        try:
            updates = get_updates(token, offset, int(telegram["poll_timeout_seconds"]))
            retry_delay = 1.0
        except TelegramTransientError as exc:
            print(f"vps-audit-bot: temporary Telegram polling error; retrying in {retry_delay:g}s: {exc}", file=sys.stderr)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 30.0)
            continue
        for update in updates:
            update_id = int(update.get("update_id", 0))
            offset = max(int(offset or 0), update_id + 1)
            state["offset"] = offset
            _atomic_json(state_path, state)
            chat, sender_id, value, callback_id, message_id = _update_context(update)
            if not _authorized(config, chat, sender_id):
                if callback_id:
                    _answer_callback_safely(token, callback_id, "无权操作")
                elif str(chat.get("id", "")) == str(telegram.get("chat_id", "")):
                    _send_error_safely(token, str(chat.get("id")), "该 Telegram 用户未被授权管理 VPSPC。")
                _atomic_json(state_path, state)
                continue
            try:
                response, keyboard = _handle(config_path, sender_id, value, pending)
                if callback_id:
                    _answer_callback_safely(token, callback_id)
                if callback_id and message_id is not None:
                    edit_message_text(token, str(chat["id"]), message_id, response, reply_markup=keyboard)
                else:
                    send_message(token, str(chat["id"]), response, reply_markup=keyboard)
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                if callback_id:
                    _answer_callback_safely(token, callback_id, "操作失败")
                _send_error_safely(token, str(chat["id"]), f"操作失败：{str(exc)[:500]}")
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
