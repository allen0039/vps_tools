from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .activity import query_active_subscription_ips, render_active_ip_query
from .behavior_audit import list_incidents, load_incident, render_ai_review, render_incident
from .node_reporting import (
    create_install_command,
    delete_registered_node,
    list_registered_nodes,
    request_registered_node_uninstall,
    revoke_registered_node,
)
from .maintenance.client import MaintenanceClient
from .operations import OperationStore
from .runtime import (
    _atomic_json,
    _read_secret,
    health,
    load_runtime_config,
    review_behavior_incident,
    run_cycle,
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
PENDING_TTL_SECONDS = 15 * 60


def _container_mode() -> bool:
    return os.environ.get("VPSPC_RUNTIME_MODE", "").lower() == "docker" or Path("/.dockerenv").exists()


def _register_command_menu(token: str) -> None:
    try:
        set_my_commands(token)
        set_chat_menu_button(token)
    except Exception as exc:
        print(f"vps-audit-bot: command menu registration deferred: {exc}", file=sys.stderr)


def _button(text: str, data: str) -> Dict[str, str]:
    return {"text": text, "callback_data": data}


def _main_keyboard() -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("📊 状态", "menu:status"), _button("👥 订阅用户", "menu:users")],
        [_button("🌐 查询重点用户活跃 IP", "activeips:0")],
        [_button("🧾 行为事件", "incident:list")],
        [_button("🖥️ 节点部署与管理", "menu:nodes")],
        [_button("🔄 更新管理", "maint:menu"), _button("🧹 彻底卸载", "destroy:menu")],
        [_button("🌐 Web 管理台", "menu:web")],
        [_button("⚙️ 检测参数", "menu:thresholds"), _button("🔔 推送参数", "menu:telegram")],
        [_button("🤖 AI 复核", "menu:ai")],
        [_button("▶️ 立即巡查", "menu:run"), _button("🕒 最近任务", "menu:tasks")],
        [_button("❓ 帮助", "menu:help")],
    ]}


def _web_service_state() -> str:
    if _container_mode():
        return "由容器编排器管理"
    try:
        completed = subprocess.run(
            ["systemctl", "is-active", "vps-audit-web.service"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "无法查询"
    return (completed.stdout or "").strip() or "未运行"


def _web_text(config: Dict[str, Any]) -> str:
    web = config["web"]
    return (
        "Web 管理台\n"
        f"启用：{'是' if web['enabled'] else '否'}\n"
        f"监听：{web['listen_host']}:{web['listen_port']}\n"
        f"服务状态：{_web_service_state()}\n\n"
        "查看或重新生成 Token 后，如果浏览器仍使用旧 Token，请重新打开页面。"
    )


def _web_keyboard() -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("🔑 查看 Web Token", "web:show")],
        [_button("♻️ 重新生成 Token", "web:regenerate")],
        [_button("🔄 重启 Web 服务", "web:restart")],
        [_button("⬅️ 主菜单", "menu:main")],
    ]}


def _web_regenerate_keyboard() -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("确认重新生成", "web:regenerate:yes"), _button("取消", "menu:web")],
    ]}


def _nodes_text(config_path: str, config: Dict[str, Any] | None = None) -> str:
    current = config or load_runtime_config(config_path)
    node_reporting = current["node_reporting"]
    lines = [
        "节点上报与部署",
        f"当前模式：{node_reporting['mode']}",
        f"接收服务：{_service_state('vps-audit-node-receiver.service')}",
        f"主控地址：{node_reporting.get('public_base_url') or '未配置'}",
        f"部署命令有效期：{node_reporting.get('enrollment_ttl_minutes', 15)} 分钟",
    ]
    nodes = list_registered_nodes(config_path)
    if not nodes:
        lines.append("已注册节点：0")
    else:
        lines.append(f"已注册节点：{len(nodes)}")
        for node in nodes:
            state = "已撤销" if node.get("revoked") else "等待卸载" if node.get("pending_command") else "有效"
            lines.append(
                f"{node.get('name', '-')} | {node.get('node_id', '-')} | {state} | "
                f"最后上报：{node.get('last_seen') or '从未'}"
            )
    if node_reporting["mode"] != "node_reporting":
        lines.append("\n请先在主控执行完整重新配置并选择“允许节点轻量上报”。")
    return "\n".join(lines)[:3900]


def _service_state(unit: str) -> str:
    if _container_mode():
        return "由容器编排器管理"
    try:
        completed = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "无法查询"
    return (completed.stdout or "").strip() or "未运行"


def _nodes_keyboard(config_path: str) -> Dict[str, Any]:
    rows: List[List[Dict[str, str]]] = [
        [_button("➕ 生成普通部署命令", "prompt:node:normal")],
        [_button("♻️ 生成允许覆盖重绑命令", "prompt:node:replace")],
    ]
    for node in list_registered_nodes(config_path):
        node_id = str(node.get("node_id", ""))
        if not node_id:
            continue
        label = str(node.get("name") or node_id)
        if len(label) > 28:
            label = label[:25] + "..."
        if node.get("revoked"):
            rows.append([_button(f"删除记录 {label}", f"node:delete:{node_id}")])
        else:
            rows.append([_button(f"撤销 {label}", f"node:revoke:{node_id}")])
            rows.append([_button(f"请求卸载 {label}", f"node:uninstall:{node_id}")])
    rows.append([_button("🔄 刷新", "menu:nodes")])
    rows.append([_button("⬅️ 主菜单", "menu:main")])
    return {"inline_keyboard": rows}


def _node_confirm_keyboard(action: str, node_id: str) -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("确认", f"node:{action}:yes:{node_id}"), _button("取消", "menu:nodes")],
    ]}


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


def _restart_web_service() -> None:
    if _container_mode():
        raise RuntimeError("Docker 部署由 Compose 管理 Web 重启；Token 已即时生效，无需重启服务")
    completed = subprocess.run(
        ["systemctl", "restart", "vps-audit-web.service"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError("Web 服务启动失败，请检查 journalctl -u vps-audit-web.service")
    if _web_service_state() != "active":
        raise RuntimeError("Web 服务未进入 active 状态，请检查 systemctl status vps-audit-web.service")


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
        "/web - 管理 Web 服务与 Token\n"
        "/nodes - 管理节点并生成一键部署命令\n"
        "/maintenance - 管理主控与在线节点更新\n"
        "/destroy - 彻底卸载 VPSPC 受管资源\n"
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
    if _container_mode():
        run_cycle(config_path)
        return "巡查已完成。\n\n" + _status_text(config_path)
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
    except Exception as exc:
        print(f"vps-audit-bot: callback acknowledgement failed: {exc}", file=sys.stderr)


def _send_error_safely(token: str, chat_id: str, text: str) -> None:
    try:
        send_message(token, chat_id, text)
    except Exception as exc:
        print(f"vps-audit-bot: unable to send operation error: {exc}", file=sys.stderr)


def _set_pending(pending: Dict[str, Any], sender_id: int, value: Dict[str, Any]) -> None:
    pending[str(sender_id)] = {**value, "created_at": time.time()}


def _take_pending(pending: Dict[str, Any], sender_id: int) -> Dict[str, Any] | None:
    entry = pending.pop(str(sender_id), None)
    if not isinstance(entry, dict):
        return None
    created_at = entry.get("created_at")
    if created_at is not None:
        try:
            if time.time() - float(created_at) > PENDING_TTL_SECONDS:
                return None
        except (TypeError, ValueError):
            return None
    return entry


def _apply_pending(config_path: str, pending: Dict[str, Any], sender_id: int, text: str) -> str | None:
    entry = _take_pending(pending, sender_id)
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
    if action == "node_create":
        command = create_install_command(
            config_path,
            text,
            replace=bool(entry.get("replace")),
        )
        mode = "允许覆盖重绑" if entry.get("replace") else "普通"
        return f"已生成{mode}节点部署命令，请在被控端以 root 执行：\n\n{command}"
    if action == "incident_question":
        review = review_behavior_incident(config_path, str(entry["incident_id"]), text)
        return render_ai_review(review)
    if action == "maintenance_destroy_code":
        client = MaintenanceClient()
        kind = str(entry["kind"])
        if kind == "controller_destroy":
            result = client.request(
                "POST",
                "/v1/confirm-controller-destroy",
                {"confirmation_id": entry["confirmation_id"], "confirmation_code": text.strip()},
            )
        else:
            result = client.request(
                "POST",
                "/v1/start",
                {
                    "action": kind,
                    "channel": None,
                    "version": None,
                    "node_ids": list(entry.get("node_ids", [])),
                    "actor": f"tg:{sender_id}",
                    "confirmation_id": entry["confirmation_id"],
                    "confirmation_code": text.strip(),
                },
            )
        return "维护任务已提交。\n\n" + _maintenance_job_text(result.get("job"))
    raise ValueError("未知的待处理操作")


def _maintenance_client() -> MaintenanceClient:
    return MaintenanceClient()


def _maintenance_job_text(job: Any) -> str:
    if not isinstance(job, dict):
        return "当前没有维护任务。"
    result = job.get("result") if isinstance(job.get("result"), dict) else {}
    nodes = result.get("nodes") if isinstance(result.get("nodes"), dict) else {}
    complete = sum(1 for item in nodes.values() if isinstance(item, dict) and item.get("status") in {"success", "failed", "rolled_back", "expired", "cancelled", "safely_retained", "skipped"})
    failures = [item for item in nodes.values() if isinstance(item, dict) and item.get("status") not in {"success", "skipped"}]
    lines = [
        "维护任务",
        f"类型：{job.get('kind', '-')}",
        f"状态：{job.get('status', '-')}",
        f"节点进度：{complete}/{len(nodes)}，失败：{len(failures)}",
    ]
    for item in failures[:8]:
        lines.append(
            f"失败：{item.get('node_name', item.get('node_id', '-'))} | "
            f"{item.get('from_version', 'unknown')} -> {item.get('target_version', result.get('target_version', '-'))} | "
            f"{item.get('stage', item.get('status', '-'))}"
        )
    if job.get("status") == "awaiting_controller_confirmation":
        lines.append("所有在线被控端已完成，仍需最后确认才会清理主控。")
    if job.get("status") == "blocked_before_controller_destroy":
        lines.append("存在未成功清理的被控端，主控已安全保留。")
    return "\n".join(lines)[:3900]


def _maintenance_keyboard(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    label = "检测到可用更新" if snapshot.get("update_available") else "检查更新"
    preferences = snapshot.get("preferences") if isinstance(snapshot.get("preferences"), dict) else {}
    toggle = "关闭每日版本检查" if preferences.get("version_check_enabled", True) else "开启每日版本检查"
    return {"inline_keyboard": [
        [_button(label, "maint:check")],
        [_button("仅升级主控", "maint:controller")],
        [_button("升级被控端", "maint:nodes")],
        [_button("升级主控＋全部在线被控端", "maint:all")],
        [_button(toggle, "maint:check:toggle")],
        [_button("🕒 当前维护任务", "maint:job")],
        [_button("🧹 彻底卸载", "destroy:menu")],
        [_button("⬅️ 主菜单", "menu:main")],
    ]}


def _maintenance_text(snapshot: Dict[str, Any]) -> str:
    catalog = snapshot.get("catalog") if isinstance(snapshot.get("catalog"), dict) else {}
    stable = catalog.get("stable") if isinstance(catalog.get("stable"), dict) else None
    edge = catalog.get("edge") if isinstance(catalog.get("edge"), dict) else None
    return (
        "更新管理\n"
        f"主控当前版本：{snapshot.get('controller_version', '未知')}\n"
        f"部署方式：{snapshot.get('deployment_mode', '未知')}\n"
        f"最新稳定版：{stable.get('version') if stable else '尚未检查'}\n"
        f"最新测试版：{edge.get('version') if edge else '尚未检查'}\n"
        f"在线被控端：{snapshot.get('online_node_count', 0)}\n"
        f"每日版本检查：{'开启' if snapshot.get('preferences', {}).get('version_check_enabled', True) else '关闭'}"
    )


def _maintenance_version_keyboard(snapshot: Dict[str, Any], action: str, page: int = 0) -> Dict[str, Any]:
    catalog = snapshot.get("catalog") if isinstance(snapshot.get("catalog"), dict) else {}
    releases = [item for item in catalog.get("releases", []) if isinstance(item, dict)]
    rows: List[List[Dict[str, str]]] = [
        [_button("稳定版", "maint:pick:stable")],
        [_button("测试版", "maint:pick:edge")],
    ]
    if releases:
        page_count = max(1, (len(releases) + DISCOVERY_PAGE_SIZE - 1) // DISCOVERY_PAGE_SIZE)
        page = max(0, min(page, page_count - 1))
        for item in releases[page * DISCOVERY_PAGE_SIZE : (page + 1) * DISCOVERY_PAGE_SIZE]:
            version = str(item.get("version", ""))
            if version:
                rows.append([_button(f"指定 {version}", f"maint:pick:{version}")])
        navigation: List[Dict[str, str]] = []
        if page:
            navigation.append(_button("⬅️", f"maint:releases:{page - 1}"))
        if page + 1 < page_count:
            navigation.append(_button("➡️", f"maint:releases:{page + 1}"))
        if navigation:
            rows.append(navigation)
    rows.append([_button("⬅️ 更新管理", "maint:menu")])
    return {"inline_keyboard": rows}


def _maintenance_node_selection(
    client: MaintenanceClient, pending: Dict[str, Any], sender_id: int
) -> Tuple[str, Dict[str, Any]]:
    entry = pending.get(str(sender_id))
    if not isinstance(entry, dict) or entry.get("action") != "maintenance_nodes":
        raise ValueError("节点选择已过期，请重新开始")
    selected = set(entry.get("node_ids", []))
    nodes = client.request("GET", "/v1/nodes").get("nodes", [])
    rows: List[List[Dict[str, str]]] = []
    online_count = 0
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("node_id", ""))
        if not node_id or not node.get("online"):
            continue
        online_count += 1
        label = str(node.get("name") or node_id)
        if len(label) > 36:
            label = label[:33] + "..."
        rows.append([_button(("✅ " if node_id in selected else "☐ ") + label, f"maint:toggle:{node_id}")])
    rows.append([_button("完成选择", "maint:nodes:done")])
    rows.append([_button("⬅️ 取消", "maint:menu" if entry.get("kind") == "node_update" else "destroy:menu")])
    return (
        f"请选择在线被控端（已选 {len(selected)} / 在线 {online_count}）。\n"
        "离线节点不会加入队列，也不会在以后上线时自动执行。",
        {"inline_keyboard": rows},
    )


def _maintenance_confirm_view(pending: Dict[str, Any], sender_id: int, snapshot: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    entry = pending.get(str(sender_id))
    if not isinstance(entry, dict) or entry.get("action") != "maintenance_update":
        raise ValueError("更新选择已过期，请重新开始")
    names = {str(item.get("node_id")): str(item.get("name") or item.get("node_id")) for item in snapshot.get("nodes", []) if isinstance(item, dict)}
    selected = list(entry.get("node_ids", []))
    target = "全部在线被控端" if entry.get("kind") == "all_update" else "、".join(names.get(item, item) for item in selected) or "主控"
    return (
        "升级确认\n"
        f"目标：{target}\n"
        f"版本：{entry.get('version')}\n"
        f"部署方式：{snapshot.get('deployment_mode')}\n\n"
        "相关 VPSPC 服务会短暂重启。失败的被控端会自动回滚，后续批次继续执行。",
        {"inline_keyboard": [
            [_button("确认升级", "maint:start"), _button("取消", "maint:menu")],
        ]},
    )


def _destroy_keyboard() -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("彻底卸载被控端", "destroy:nodes")],
        [_button("彻底卸载主控＋被控端", "destroy:all")],
        [_button("🕒 当前维护任务", "maint:job")],
        [_button("⬅️ 主菜单", "menu:main")],
    ]}


def _handle(config_path: str, sender_id: int, value: str, pending: Dict[str, Any]) -> Tuple[str, Dict[str, Any] | None]:
    if not value.startswith("/") and not value.startswith(("menu:", "mode:", "prompt:", "toggle:", "discover:", "activeips:", "ai:", "incident:", "web:", "node:", "maint:", "destroy:")):
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
    if command in {"/nodes", "menu:nodes"}:
        return _nodes_text(config_path, config), _nodes_keyboard(config_path)
    if command in {"/maintenance", "maint:menu"}:
        snapshot = _maintenance_client().request("GET", "/v1/status")["status"]
        return _maintenance_text(snapshot), _maintenance_keyboard(snapshot)
    if command in {"/destroy", "destroy:menu"}:
        return (
            "彻底卸载\n\n"
            "只会清理 VPSPC 明确创建且归属标记匹配的程序、服务、配置、密钥、状态、缓存和日志。"
            "不会修改 Xray、sing-box、V2Board、妙妙屋 X、xrayagent 或它们的日志。\n\n"
            "在线被控端可选择指定节点或全部；整套清理任一节点失败时，主控会安全保留。",
            _destroy_keyboard(),
        )
    if command in {"/web", "menu:web"}:
        return _web_text(config), _web_keyboard()
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
    if command == "maint:check":
        snapshot = _maintenance_client().request("POST", "/v1/check", {})["catalog"]
        return (
            f"版本检查完成。\n稳定版：{(snapshot.get('stable') or {}).get('version', '无')}\n"
            f"测试版：{(snapshot.get('edge') or {}).get('version', '无')}",
            _maintenance_keyboard(_maintenance_client().request("GET", "/v1/status")["status"]),
        )
    if command == "maint:check:toggle":
        snapshot = _maintenance_client().request("GET", "/v1/status")["status"]
        enabled = not bool(snapshot.get("preferences", {}).get("version_check_enabled", True))
        _maintenance_client().request("POST", "/v1/preferences", {"version_check_enabled": enabled})
        snapshot = _maintenance_client().request("GET", "/v1/status")["status"]
        return _maintenance_text(snapshot), _maintenance_keyboard(snapshot)
    if command in {"maint:controller", "maint:all"}:
        kind = "controller_update" if command == "maint:controller" else "all_update"
        _set_pending(pending, sender_id, {"action": "maintenance_update", "kind": kind, "node_ids": []})
        snapshot = _maintenance_client().request("GET", "/v1/status")["status"]
        return "请选择更新通道或指定正式版本。", _maintenance_version_keyboard(snapshot, kind)
    if command == "maint:nodes":
        _set_pending(pending, sender_id, {"action": "maintenance_nodes", "kind": "node_update", "node_ids": []})
        return _maintenance_node_selection(_maintenance_client(), pending, sender_id)
    if command == "destroy:nodes":
        _set_pending(pending, sender_id, {"action": "maintenance_nodes", "kind": "node_destroy", "node_ids": []})
        return _maintenance_node_selection(_maintenance_client(), pending, sender_id)
    if command == "destroy:all":
        confirmation = _maintenance_client().request("POST", "/v1/confirmation", {"action": "full_destroy"})["confirmation"]
        _set_pending(
            pending,
            sender_id,
            {"action": "maintenance_destroy_code", "kind": "full_destroy", "node_ids": [], "confirmation_id": confirmation["id"]},
        )
        return (
            "将先彻底清理所有当前在线被控端；任一失败会保留主控。\n"
            f"确认码：{confirmation['code']}\n请发送这 6 位确认码继续。发送 /cancel 可取消。",
            None,
        )
    if command == "destroy:final":
        confirmation = _maintenance_client().request("POST", "/v1/confirmation", {"action": "controller_destroy"})["confirmation"]
        _set_pending(
            pending,
            sender_id,
            {"action": "maintenance_destroy_code", "kind": "controller_destroy", "confirmation_id": confirmation["id"]},
        )
        return (
            "所有在线被控端已完成。确认后将开始清理主控，Telegram 与 Web 会离线。\n"
            f"最终确认码：{confirmation['code']}\n请发送这 6 位确认码继续。发送 /cancel 可取消。",
            None,
        )
    if command.startswith("maint:toggle:"):
        node_id = command.split(":", 2)[2]
        entry = pending.get(str(sender_id))
        if not isinstance(entry, dict) or entry.get("action") != "maintenance_nodes":
            raise ValueError("节点选择已过期，请重新开始")
        nodes = _maintenance_client().request("GET", "/v1/nodes")["nodes"]
        if node_id not in {str(item.get("node_id")) for item in nodes if isinstance(item, dict) and item.get("online")}:
            raise ValueError("该节点当前离线或不存在，无法加入任务")
        selected = set(entry.get("node_ids", []))
        if node_id in selected:
            selected.remove(node_id)
        else:
            selected.add(node_id)
        entry["node_ids"] = sorted(selected)
        entry["created_at"] = time.time()
        return _maintenance_node_selection(_maintenance_client(), pending, sender_id)
    if command == "maint:nodes:done":
        entry = pending.get(str(sender_id))
        if not isinstance(entry, dict) or entry.get("action") != "maintenance_nodes":
            raise ValueError("节点选择已过期，请重新开始")
        node_ids = list(entry.get("node_ids", []))
        if not node_ids:
            raise ValueError("请至少选择一台在线被控端")
        if entry.get("kind") == "node_destroy":
            confirmation = _maintenance_client().request("POST", "/v1/confirmation", {"action": "node_destroy"})["confirmation"]
            _set_pending(
                pending,
                sender_id,
                {"action": "maintenance_destroy_code", "kind": "node_destroy", "node_ids": node_ids, "confirmation_id": confirmation["id"]},
            )
            return (
                "将彻底清理所选在线被控端的 VPSPC 探针、服务、配置、密钥、状态与日志。\n"
                "不会修改节点自身的代理或其他第三方服务。\n"
                f"确认码：{confirmation['code']}\n请发送这 6 位确认码继续。发送 /cancel 可取消。",
                None,
            )
        entry["action"] = "maintenance_update"
        entry["kind"] = "node_update"
        entry["created_at"] = time.time()
        snapshot = _maintenance_client().request("GET", "/v1/status")["status"]
        return "请选择更新通道或指定正式版本。", _maintenance_version_keyboard(snapshot, "node_update")
    if command.startswith("maint:releases:"):
        entry = pending.get(str(sender_id))
        if not isinstance(entry, dict) or entry.get("action") != "maintenance_update":
            raise ValueError("更新选择已过期，请重新开始")
        try:
            page = int(command.rsplit(":", 1)[1])
        except ValueError as exc:
            raise ValueError("版本页码无效") from exc
        snapshot = _maintenance_client().request("GET", "/v1/status")["status"]
        return "请选择更新通道或指定正式版本。", _maintenance_version_keyboard(snapshot, str(entry.get("kind")), page)
    if command.startswith("maint:pick:"):
        entry = pending.get(str(sender_id))
        if not isinstance(entry, dict) or entry.get("action") != "maintenance_update":
            raise ValueError("更新选择已过期，请重新开始")
        selected = command.split(":", 2)[2]
        if selected == "stable":
            entry["channel"], entry["version"] = "stable", None
        elif selected == "edge":
            entry["channel"], entry["version"] = "edge", None
        else:
            entry["channel"], entry["version"] = "stable", selected
        entry["created_at"] = time.time()
        snapshot = _maintenance_client().request("GET", "/v1/status")["status"]
        return _maintenance_confirm_view(pending, sender_id, snapshot)
    if command == "maint:start":
        entry = _take_pending(pending, sender_id)
        if not isinstance(entry, dict) or entry.get("action") != "maintenance_update":
            raise ValueError("更新确认已过期，请重新开始")
        response = _maintenance_client().request(
            "POST",
            "/v1/start",
            {
                "action": entry["kind"],
                "channel": entry.get("channel"),
                "version": entry.get("version"),
                "node_ids": list(entry.get("node_ids", [])),
                "actor": f"tg:{sender_id}",
            },
        )
        return "维护任务已提交。\n\n" + _maintenance_job_text(response.get("job")), {"inline_keyboard": [[_button("刷新进度", "maint:job")], [_button("⬅️ 更新管理", "maint:menu")]]}
    if command == "maint:job":
        job = _maintenance_client().request("GET", "/v1/job").get("job")
        rows: List[List[Dict[str, str]]] = [[_button("刷新进度", "maint:job")]]
        if isinstance(job, dict) and job.get("status") == "awaiting_controller_confirmation":
            rows.append([_button("确认彻底删除主控", "destroy:final")])
        rows.append([_button("⬅️ 更新管理", "maint:menu")])
        return _maintenance_job_text(job), {"inline_keyboard": rows}
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
            _set_pending(pending, sender_id, {"action": parts[1]})
            action_text = "添加" if parts[1] == "adduser" else "删除"
            return f"请发送需要{action_text}的用户名或订阅 ID。发送 /cancel 可取消。", None
        if len(parts) == 3 and parts[1] == "node" and parts[2] in {"normal", "replace"}:
            if config["node_reporting"]["mode"] != "node_reporting":
                raise ValueError("请先在主控执行完整重新配置并选择允许节点轻量上报")
            _set_pending(pending, sender_id, {"action": "node_create", "replace": parts[2] == "replace"})
            return "请发送 被控端 名称，例如：服务商+地区。发送 /cancel 可取消。", None
        if len(parts) == 3 and parts[1] in {"threshold", "telegram"}:
            _set_pending(pending, sender_id, {"action": parts[1], "key": parts[2]})
            return f"请发送 {parts[2]} 的新值。发送 /cancel 可取消。", None
        if parts[1:] == ["ai", "model"]:
            active = config["openai_review"]["active_provider"]
            if not active:
                raise ValueError("请先在 VPS 本机配置 AI 供应商")
            _set_pending(pending, sender_id, {"action": "ai_model", "provider_id": active})
            return "请发送新的模型名称。发送 /cancel 可取消。", None
    if command == "/cancel":
        pending.pop(str(sender_id), None)
        return "已取消。", _main_keyboard()
    if command == "web:show":
        token_path = Path(str(config["web"]["token_file"]))
        token = _read_secret(str(token_path), "Web Token")
        return f"Web Token：\n{token}", _web_keyboard()
    if command == "web:regenerate":
        return "重新生成后，当前浏览器中的旧 Token 会立即失效。确认继续？", _web_regenerate_keyboard()
    if command == "web:regenerate:yes":
        if not config["web"]["enabled"]:
            raise ValueError("Web 管理台未启用，请先在 VPS 本机运行 vpspc 完整重新配置")
        token_path = Path(str(config["web"]["token_file"]))
        _atomic_secret(token_path, secrets.token_urlsafe(32))
        if _container_mode():
            return "Web Token 已重新生成并即时生效。请点击“查看 Web Token”获取新 Token。", _web_keyboard()
        _restart_web_service()
        return "Web Token 已重新生成，服务已重启。请点击“查看 Web Token”获取新 Token。", _web_keyboard()
    if command == "web:restart":
        if not config["web"]["enabled"]:
            raise ValueError("Web 管理台未启用，请先在 VPS 本机运行 vpspc 完整重新配置")
        if _container_mode():
            return "Docker 部署由 Compose 管理服务重启；当前 Web Token 已支持即时读取，无需重启。", _web_keyboard()
        _restart_web_service()
        config = load_runtime_config(config_path)
        return "Web 服务已重启并通过 active 检查。\n\n" + _web_text(config), _web_keyboard()
    if command.startswith("node:revoke:yes:"):
        node_id = command.split(":", 3)[3]
        revoke_registered_node(config_path, node_id)
        return f"节点 {node_id} 的凭据已撤销。\n\n" + _nodes_text(config_path), _nodes_keyboard(config_path)
    if command.startswith("node:uninstall:yes:"):
        node_id = command.split(":", 3)[3]
        request = request_registered_node_uninstall(config_path, node_id)
        return f"节点 {node_id} 已排队自卸载命令：{request['id']}\n\n" + _nodes_text(config_path), _nodes_keyboard(config_path)
    if command.startswith("node:delete:yes:"):
        node_id = command.split(":", 3)[3]
        delete_registered_node(config_path, node_id)
        return f"节点 {node_id} 的注册记录已删除。\n\n" + _nodes_text(config_path), _nodes_keyboard(config_path)
    if command.startswith("node:revoke:") or command.startswith("node:uninstall:") or command.startswith("node:delete:"):
        parts = command.split(":", 2)
        action, node_id = parts[1], parts[2]
        labels = {"revoke": "撤销凭据", "uninstall": "请求自卸载", "delete": "删除注册记录"}
        return f"确认对节点 {node_id} 执行{labels[action]}？", _node_confirm_keyboard(action, node_id)
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
        _set_pending(pending, sender_id, {"action": "incident_question", "incident_id": identifier})
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


def _is_background_interaction(value: str, pending: Dict[str, Any], sender_id: int) -> bool:
    """Return whether an interaction can block or change persistent state."""

    # Maintenance uses several callback-only selection steps.  They must stay
    # on the polling path so the selected channel/node IDs are atomically
    # written to bot-state before the next callback arrives.  Only the final
    # submission is slow enough to move into the durable worker.
    entry = pending.get(str(sender_id))
    if isinstance(entry, dict):
        action = str(entry.get("action", ""))
        if action in {"maintenance_update", "maintenance_nodes"}:
            return value == "maint:start"
        if not value.startswith("/"):
            return True
    command = value.split(maxsplit=1)[0].split("@", 1)[0].lower() if value else ""
    if command in {
        "/run", "menu:run", "/aitest", "ai:test", "/incidentai", "/ask",
        "web:restart", "web:regenerate:yes", "toggle:include_source_ip",
        "toggle:subscription_enabled", "ai:toggle", "/mode", "/monitor",
        "/adduser", "/deluser", "/set", "/aiuse", "/aimodel", "/aion", "/aioff",
        "/incidents", "incident:list", "maint:check",
    }:
        return True
    if command.startswith(("incident:ai:", "discover:", "node:revoke:yes:", "node:uninstall:yes:", "node:delete:yes:")):
        return True
    if command.startswith("activeips:user:"):
        return True
    if command.startswith("mode:") or command.startswith("ai:use:"):
        return True
    if command in {"/ips", "/activeips"} and len(value.split(maxsplit=1)) == 2:
        return True
    return False


def _operation_keyboard(job_id: str) -> Dict[str, Any]:
    return {"inline_keyboard": [
        [_button("🔄 刷新任务状态", f"job:status:{job_id}")],
        [_button("⬅️ 主菜单", "menu:main")],
    ]}


def _operation_text(job: Dict[str, Any]) -> str:
    labels = {"queued": "等待执行", "running": "正在执行", "success": "已完成", "failed": "执行失败", "cancelled": "已取消"}
    text = [
        "VPSPC 后台任务",
        f"编号：{job.get('id', '-')}",
        f"状态：{labels.get(str(job.get('status')), str(job.get('status', '-')))}",
    ]
    result = job.get("result")
    if isinstance(result, dict) and result.get("text"):
        text.extend(["", str(result["text"])])
    return "\n".join(text)[:3900]


def _deliver_operation_result(token: str, job: Dict[str, Any]) -> None:
    result = job.get("result") if isinstance(job.get("result"), dict) else {}
    text = str(result.get("text") or "任务已结束。")[:3900]
    keyboard = result.get("keyboard") if isinstance(result.get("keyboard"), dict) else _main_keyboard()
    try:
        message_id = job.get("message_id")
        if isinstance(message_id, int) and message_id > 0:
            edit_message_text(token, str(job["chat_id"]), message_id, text, reply_markup=keyboard)
        else:
            send_message(token, str(job["chat_id"]), text, reply_markup=keyboard)
    except Exception as exc:
        print(f"vps-audit-bot: operation result delivery deferred: {exc}", file=sys.stderr)


def _operation_worker(stop: threading.Event, store: OperationStore, config_path: str, token: str) -> None:
    while not stop.is_set():
        try:
            job = store.claim_next()
        except Exception as exc:
            print(f"vps-audit-bot: operation queue unavailable: {exc}", file=sys.stderr)
            stop.wait(1.0)
            continue
        if job is None:
            stop.wait(0.2)
            continue
        started = time.monotonic()
        pending = job.get("pending") if isinstance(job.get("pending"), dict) else {}
        try:
            response, keyboard = _handle(config_path, int(job["actor_id"]), str(job["value"]), pending)
            completed = store.complete(job["id"], success=True, text=response, keyboard=keyboard or _main_keyboard())
        except Exception as exc:
            completed = store.complete(
                job["id"],
                success=False,
                text=f"操作失败：{str(exc)[:500]}",
                keyboard=_main_keyboard(),
            )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        print(
            f"vps-audit-bot: operation {job['id']} {completed['status']} in {elapsed_ms}ms",
            file=sys.stderr,
        )
        _deliver_operation_result(token, completed)


def run_bot(config_path: str, once: bool = False) -> None:
    config = load_runtime_config(config_path)
    telegram = config["telegram"]
    if not telegram.get("bot_management_enabled"):
        raise ValueError("Telegram 双向管理未启用")
    token = _read_secret(str(telegram["token_file"]), "Telegram token")
    if not once:
        threading.Thread(target=_register_command_menu, args=(token,), daemon=True).start()
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
    store = OperationStore(Path(config["state_dir"]) / "bot-operations.json")
    store.recover_running()
    stop = threading.Event()
    if not once:
        threading.Thread(
            target=_operation_worker,
            args=(stop, store, config_path, token),
            name="vps-audit-bot-worker",
            daemon=True,
        ).start()
    retry_delay = 1.0
    while True:
        config = load_runtime_config(config_path)
        telegram = config["telegram"]
        try:
            updates = get_updates(token, offset, int(telegram["poll_timeout_seconds"]))
            retry_delay = 1.0
            state["last_poll_at"] = time.time()
            _atomic_json(state_path, state)
        except Exception as exc:
            print(f"vps-audit-bot: Telegram polling error; retrying in {retry_delay:g}s: {str(exc)[:500]}", file=sys.stderr)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60.0)
            continue
        for update in updates:
            try:
                update_id = int(update.get("update_id", 0))
                chat, sender_id, value, callback_id, message_id = _update_context(update)
                if not _authorized(config, chat, sender_id):
                    if callback_id:
                        _answer_callback_safely(token, callback_id, "无权操作")
                    elif str(chat.get("id", "")) == str(telegram.get("chat_id", "")):
                        _send_error_safely(token, str(chat.get("id")), "该 Telegram 用户未被授权管理 VPSPC。")
                    offset = max(int(offset or 0), update_id + 1)
                    state["offset"] = offset
                    _atomic_json(state_path, state)
                    continue
                if callback_id:
                    _answer_callback_safely(token, callback_id)
                if value == "menu:tasks":
                    job = store.latest(sender_id)
                    response = _operation_text(job) if job else "当前没有待处理或最近完成的后台任务。"
                    keyboard = _operation_keyboard(str(job["id"])) if job else _main_keyboard()
                elif value.startswith("job:status:"):
                    job = store.read(value.split(":", 2)[2])
                    response = _operation_text(job) if job else "任务不存在或结果已自动清理。"
                    keyboard = _operation_keyboard(str(job["id"])) if job else _main_keyboard()
                elif _is_background_interaction(value, pending, sender_id):
                    job_pending: Dict[str, Any] = {}
                    entry = pending.pop(str(sender_id), None)
                    if isinstance(entry, dict):
                        entry = dict(entry)
                        entry["created_at"] = time.time()
                        job_pending[str(sender_id)] = entry
                    job = store.enqueue(
                        update_id=update_id,
                        actor_id=sender_id,
                        chat_id=str(chat["id"]),
                        message_id=message_id if callback_id else None,
                        value=value,
                        pending=job_pending,
                    )
                    response = "任务已提交。\n\n" + _operation_text(job)
                    keyboard = _operation_keyboard(str(job["id"]))
                    offset = max(int(offset or 0), update_id + 1)
                    state["offset"] = offset
                    _atomic_json(state_path, state)
                else:
                    response, keyboard = _handle(config_path, sender_id, value, pending)
                if callback_id and message_id is not None:
                    edit_message_text(token, str(chat["id"]), message_id, response, reply_markup=keyboard)
                else:
                    send_message(token, str(chat["id"]), response, reply_markup=keyboard)
                offset = max(int(offset or 0), update_id + 1)
                state["offset"] = offset
            except Exception as exc:
                chat_id = str(update.get("message", {}).get("chat", {}).get("id", ""))
                if chat_id:
                    _send_error_safely(token, chat_id, f"操作失败：{str(exc)[:500]}")
                print(f"vps-audit-bot: update handling failed: {str(exc)[:500]}", file=sys.stderr)
                try:
                    update_id = int(update.get("update_id", 0))
                    offset = max(int(offset or 0), update_id + 1)
                    state["offset"] = offset
                except (TypeError, ValueError):
                    pass
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
