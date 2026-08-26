from __future__ import annotations

import copy
import fcntl
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

from .runtime import load_runtime_config, normalize_runtime_config


THRESHOLD_SPECS: Dict[str, Tuple[str, int, int]] = {
    "multi_ip_window_minutes": ("SSH 多 IP 窗口（分钟）", 1, 1440),
    "multi_ip_count": ("SSH 不同 IP 数", 2, 1000),
    "multi_asn_count": ("SSH 不同 ASN 数", 2, 1000),
    "failed_login_window_minutes": ("登录失败窗口（分钟）", 1, 1440),
    "failed_login_count": ("登录失败次数", 1, 100000),
    "impossible_travel_min_km": ("不可能旅行距离（km）", 1, 40000),
    "impossible_travel_kmh": ("不可能旅行速度（km/h）", 1, 50000),
    "repeat_process_window_minutes": ("重复进程窗口（分钟）", 1, 1440),
    "repeat_process_count": ("重复进程次数", 1, 100000),
    "network_burst_window_minutes": ("网络爆发窗口（分钟）", 1, 1440),
    "network_burst_unique_destinations": ("不同网络目标数", 1, 100000),
    "subscription_window_minutes": ("订阅活跃窗口（分钟）", 1, 1440),
    "subscription_ip_count": ("同订阅不同 IP 数", 2, 1000),
    "subscription_region_count": ("同订阅地区数", 2, 1000),
    "subscription_city_count": ("同订阅城市数", 2, 1000),
    "subscription_asn_count": ("同订阅 ASN 数", 2, 1000),
}


def _atomic_write(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def update_runtime_config(config_path: str, mutate: Callable[[Dict[str, Any]], None]) -> Dict[str, Any]:
    path = Path(config_path)
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        current = load_runtime_config(str(path))
        updated = copy.deepcopy(current)
        mutate(updated)
        normalized = normalize_runtime_config(updated)
        _atomic_write(path, normalized)
        return normalized


def set_monitoring_mode(config_path: str, mode: str) -> Dict[str, Any]:
    if mode not in {"all", "allowlist"}:
        raise ValueError("监测模式只能是 all 或 allowlist")
    return update_runtime_config(
        config_path,
        lambda config: config["subscription_monitoring"].update({"enabled": True, "mode": mode}),
    )


def set_subscription_monitoring_enabled(config_path: str, enabled: bool) -> Dict[str, Any]:
    return update_runtime_config(
        config_path,
        lambda config: config["subscription_monitoring"].update({"enabled": bool(enabled)}),
    )


def add_monitored_user(config_path: str, user: str) -> Dict[str, Any]:
    identifier = user.strip()
    if not identifier:
        raise ValueError("用户标识不能为空")

    def mutate(config: Dict[str, Any]) -> None:
        users = config["subscription_monitoring"]["users"]
        if identifier not in users:
            users.append(identifier)

    return update_runtime_config(config_path, mutate)


def remove_monitored_user(config_path: str, user: str) -> Dict[str, Any]:
    identifier = user.strip()

    def mutate(config: Dict[str, Any]) -> None:
        users = config["subscription_monitoring"]["users"]
        if identifier not in users:
            raise ValueError(f"名单中不存在：{identifier}")
        users.remove(identifier)

    return update_runtime_config(config_path, mutate)


def set_threshold(config_path: str, key: str, value: int | str) -> Dict[str, Any]:
    if key not in THRESHOLD_SPECS:
        raise ValueError(f"不支持的阈值：{key}")
    label, minimum, maximum = THRESHOLD_SPECS[key]
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label}必须是整数") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{label}范围为 {minimum} 到 {maximum}")
    return update_runtime_config(
        config_path,
        lambda config: config["rules"]["thresholds"].update({key: number}),
    )


def set_telegram_option(config_path: str, key: str, value: Any) -> Dict[str, Any]:
    if key == "minimum_severity":
        normalized: Any = str(value).lower()
        if normalized not in {"low", "medium", "high", "critical"}:
            raise ValueError("推送等级只能是 low、medium、high 或 critical")
    elif key == "cooldown_hours":
        try:
            normalized = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("冷却时间必须是数字") from exc
        if not 0 <= normalized <= 8760:
            raise ValueError("冷却时间范围为 0 到 8760 小时")
    elif key == "include_source_ip":
        normalized = bool(value)
    else:
        raise ValueError(f"不支持的 Telegram 参数：{key}")
    return update_runtime_config(
        config_path,
        lambda config: config["telegram"].update({key: normalized}),
    )
