from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict


DEFAULT_CONFIG: Dict[str, Any] = {
    "thresholds": {
        "multi_ip_window_minutes": 60,
        "multi_ip_count": 4,
        "multi_asn_count": 3,
        "failed_login_window_minutes": 10,
        "failed_login_count": 8,
        "impossible_travel_min_km": 500,
        "impossible_travel_kmh": 900,
        "repeat_process_window_minutes": 60,
        "repeat_process_count": 8,
        "network_burst_window_minutes": 10,
        "network_burst_unique_destinations": 20,
        "subscription_window_minutes": 15,
        "subscription_ip_count": 10,
        "subscription_region_count": 3,
        "subscription_city_count": 5,
        "subscription_asn_count": 4,
        "subscription_device_count": 6,
        "subscription_shared_source_user_count": 8,
    },
    "automation_indicators": {
        "browser_automation": [
            "--headless",
            "chromedriver",
            "geckodriver",
            "playwright",
            "puppeteer",
            "selenium",
            "undetected_chromedriver",
        ],
        "account_workflow": [
            "captcha solver",
            "captcha_solver",
            "sms-activate",
            "sms_activate",
            "email verifier",
            "account creator",
        ],
        "bulk_behavior": ["--threads", "--workers", "proxy-list", "proxy_list"],
    },
    "trusted": {"users": [], "ips": [], "asns": []},
}


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | None = None) -> Dict[str, Any]:
    if not path:
        return copy.deepcopy(DEFAULT_CONFIG)
    with Path(path).open("r", encoding="utf-8") as handle:
        override = json.load(handle)
    if not isinstance(override, dict):
        raise ValueError("config root must be a JSON object")
    return _merge(DEFAULT_CONFIG, override)
