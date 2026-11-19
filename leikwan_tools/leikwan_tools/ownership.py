"""Resource ownership manifest, managed rule registry, symlink-safe paths, and coordinated install/uninstall."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_COORDINATED_LOCK_FILE,
    DEFAULT_RULES_DIR,
    DEFAULT_STATE_DIR,
    FIXED_SYSTEMD_UNIT_TEMPLATE,
    INSTALL_LIB_DIR,
    INSTALL_MANIFEST_PATH,
    INSTALL_ENV_PATH,
    MANAGED_MARKER,
    MANAGED_REALM_BIN,
    __version__,
)
from .config import ConfigError, GlobalConfig, RULE_NAME_RE, load_global_config
from .system import (
    FileLock,
    PreflightError,
    atomic_write_text,
    run_cmd,
    systemd_daemon_reload,
    systemd_disable,
    systemd_is_active,
    systemd_is_enabled,
    systemd_reset_failed,
    systemd_show,
    systemd_stop,
    unit_name_for_rule,
)

TEMPLATE_UNIT_PATH = f"/etc/systemd/system/{FIXED_SYSTEMD_UNIT_TEMPLATE}"
BIN_LAUNCHER_PATH = "/usr/local/bin/leikwan_tools"
SHORTCUT_PATH = "/usr/local/bin/lqtool"


class OwnershipError(RuntimeError):
    """Raised when resource ownership checks fail or refuse unsafe operations."""


def validate_rule_name(name: str) -> str:
    """Validate rule name against strict allowlist before using it in paths or systemd unit names."""
    if not isinstance(name, str) or not RULE_NAME_RE.match(name):
        raise ConfigError(f"rule.name 非法: {name!r} (仅支持字母数字开头及 ._-，长度 1-63)")
    return name


def ensure_safe_subpath(root_dir: Path, target_path: Path) -> Path:
    """Verify target_path resides inside root_dir with no symlinks in relative components."""
    root_real = Path(os.path.realpath(str(root_dir)))
    try:
        rel = target_path.relative_to(root_dir)
    except ValueError as exc:
        raise OwnershipError(f"路径越界 ({target_path} 不在受管目录 {root_dir} 内)") from exc

    cur = root_dir
    for part in rel.parts:
        cur = cur / part
        if cur.is_symlink():
            raise OwnershipError(f"拒绝操作符号链接路径: {cur}")

    target_real = Path(os.path.realpath(str(target_path)))
    try:
        target_real.relative_to(root_real)
    except ValueError as exc:
        raise OwnershipError(f"规范化路径越界: {target_real} 不在 {root_real} 内") from exc
    return target_path


def load_install_manifest(manifest_path: str = INSTALL_MANIFEST_PATH) -> Optional[Dict[str, Any]]:
    """Load install-manifest.json if present and valid."""
    p = Path(manifest_path)
    if not p.is_file() or p.is_symlink():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def resolve_default_config_path(manifest_path: str = INSTALL_MANIFEST_PATH) -> str:
    """Resolve active config.toml path: LEIKWAN_TOOLS_CONFIG -> install manifest -> default."""
    env_cfg = os.environ.get("LEIKWAN_TOOLS_CONFIG", "").strip()
    if env_cfg:
        return env_cfg
    manifest = load_install_manifest(manifest_path)
    if manifest:
        cfg_file = str(manifest.get("config_file", "")).strip()
        if cfg_file:
            return cfg_file
    return DEFAULT_CONFIG_PATH


def resolve_lock_file(
    global_cfg: Optional[GlobalConfig] = None,
    manifest: Optional[Dict[str, Any]] = None,
) -> str:
    """Coordinate lock path across install, uninstall, and rule write operations."""
    if global_cfg is not None and global_cfg.tool.lock_file:
        # Honor non-default lock_file (e.g. isolated unit tests), otherwise prefer manifest/coordinated lock.
        if global_cfg.tool.lock_file != DEFAULT_COORDINATED_LOCK_FILE:
            return global_cfg.tool.lock_file
    if manifest is None:
        manifest = load_install_manifest()
    if manifest:
        mlock = str(manifest.get("lock_file", "")).strip()
        if mlock:
            return mlock
    return DEFAULT_COORDINATED_LOCK_FILE


def verify_template_unit_owned(unit_path: str = TEMPLATE_UNIT_PATH) -> Tuple[bool, str]:
    """Check that the systemd template unit exists, is not a symlink, and carries our ownership marker."""
    p = Path(unit_path)
    if not p.exists():
        return False, f"systemd 模板单元不存在: {unit_path}"
    if p.is_symlink() or not p.is_file():
        return False, f"systemd 模板单元异常（非普通文件或为符号链接）: {unit_path}"
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"无法读取 systemd 模板单元 ({unit_path}): {exc}"
    if MANAGED_MARKER not in content:
        return False, f"systemd 模板单元缺少归属标记 ({MANAGED_MARKER}): {unit_path}"
    return True, ""


def verify_legacy_template_owned(unit_path: str = TEMPLATE_UNIT_PATH) -> Tuple[bool, str]:
    """Recognize the previous release template for an in-place upgrade."""
    p = Path(unit_path)
    if not p.exists() or p.is_symlink() or not p.is_file():
        return False, f"旧版 systemd 模板单元不存在或不是普通文件: {unit_path}"
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"无法读取旧版 systemd 模板单元 ({unit_path}): {exc}"
    required = (
        "[Unit]",
        "Description=leikwan_tools Realm IPv4 TCP Relay (%i)",
        "[Service]",
        "ExecStart=/usr/local/lib/leikwan_tools/realm-exec.sh %i",
    )
    if MANAGED_MARKER not in content and all(token in content for token in required):
        return True, "legacy-template"
    return False, f"旧版 systemd 模板单元内容不匹配: {unit_path}"


def verify_launcher_owned(bin_path: str = BIN_LAUNCHER_PATH) -> Tuple[bool, str]:
    """Check whether CLI launcher belongs to leikwan_tools."""
    p = Path(bin_path)
    if not p.exists():
        return False, f"CLI 入口不存在: {bin_path}"
    if p.is_symlink() or not p.is_file():
        return False, f"CLI 入口非普通受管文件: {bin_path}"
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"无法读取 CLI 入口 ({bin_path}): {exc}"
    if bin_path == SHORTCUT_PATH:
        owned = MANAGED_MARKER in content.splitlines()
    else:
        owned = MANAGED_MARKER in content or "leikwan_tools.cli" in content
    if owned:
        return True, ""
    return False, f"CLI 入口缺少归属标记: {bin_path}"


def is_standalone_unmanaged_unit(unit_name: str, template_path: str = TEMPLATE_UNIT_PATH) -> Tuple[bool, str]:
    """Detect whether unit_name refers to a standalone or foreign systemd unit not managed via our template."""
    for base in (
        Path("/etc/systemd/system"),
        Path("/run/systemd/system"),
        Path("/lib/systemd/system"),
        Path("/usr/lib/systemd/system"),
    ):
        cand = base / unit_name
        if cand.exists():
            if cand.is_symlink():
                target = os.path.realpath(str(cand))
                if target != os.path.realpath(template_path):
                    return True, f"存在指向非本工具模板的单元符号链接: {cand} -> {target}"
            elif cand.is_file():
                try:
                    txt = cand.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    txt = ""
                if MANAGED_MARKER not in txt:
                    return True, f"存在非本工具创建的独立 systemd 单元文件: {cand}"

    try:
        props = systemd_show(unit_name)
    except Exception:
        return False, ""

    frag = props.get("FragmentPath", "").strip()
    if frag:
        frag_name = Path(frag).name
        if frag_name != FIXED_SYSTEMD_UNIT_TEMPLATE and Path(frag).is_file():
            try:
                txt = Path(frag).read_text(encoding="utf-8", errors="replace")
            except OSError:
                txt = ""
            if MANAGED_MARKER not in txt:
                return True, f"systemd 加载了外部单元文件 ({frag})"
    return False, ""


def registry_path_for_state_dir(state_dir: str) -> Path:
    return Path(state_dir) / "managed-rules.json"


def load_managed_rules_registry(state_dir: str) -> Optional[Dict[str, Any]]:
    """Return parsed managed-rules.json dict, or None if missing."""
    reg_path = registry_path_for_state_dir(state_dir)
    if not reg_path.exists():
        return None
    if reg_path.is_symlink() or not reg_path.is_file():
        raise OwnershipError(f"受管规则清单损坏或为符号链接: {reg_path}")
    try:
        data = json.loads(reg_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise OwnershipError(f"受管规则清单格式无效: {reg_path}")
        rules = data.setdefault("rules", {})
        if not isinstance(rules, dict):
            raise OwnershipError(f"受管规则清单 rules 字段无效: {reg_path}")
        return data
    except (OSError, json.JSONDecodeError) as exc:
        raise OwnershipError(f"无法读取受管规则清单 ({reg_path}): {exc}") from exc


def save_managed_rules_registry(state_dir: str, registry: Dict[str, Any]) -> None:
    """Atomically write managed-rules.json."""
    reg_path = registry_path_for_state_dir(state_dir)
    ensure_safe_subpath(Path(state_dir), reg_path)
    payload = {
        "schema_version": 1,
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "rules": registry.get("rules", {}),
    }
    atomic_write_text(reg_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n", mode=0o644)


def register_managed_rule(
    state_dir: str,
    rules_dir: str,
    rule_name: str,
    unit_name: str,
) -> None:
    """Record a managed rule and its exact 4 owned file paths in managed-rules.json."""
    validate_rule_name(rule_name)
    reg = load_managed_rules_registry(state_dir) or {"schema_version": 1, "rules": {}}
    s_root = Path(state_dir)
    r_root = Path(rules_dir)
    reg["rules"][rule_name] = {
        "rule_name": rule_name,
        "unit_name": unit_name,
        "files": {
            "stored_rule": str(ensure_safe_subpath(r_root, r_root / f"{rule_name}.toml")),
            "realm_toml": str(ensure_safe_subpath(s_root, s_root / "realm" / f"{rule_name}.toml")),
            "realm_env": str(ensure_safe_subpath(s_root, s_root / "realm" / f"{rule_name}.env")),
            "state_json": str(ensure_safe_subpath(s_root, s_root / "state" / f"{rule_name}.json")),
        },
        "registered_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    save_managed_rules_registry(state_dir, reg)


def unregister_managed_rule(state_dir: str, rule_name: str) -> None:
    """Remove a rule from managed-rules.json if present."""
    reg = load_managed_rules_registry(state_dir)
    if reg is None:
        return
    if rule_name in reg.get("rules", {}):
        del reg["rules"][rule_name]
        save_managed_rules_registry(state_dir, reg)


def check_conservative_legacy_rule(
    rules_dir: str,
    state_dir: str,
    rule_name: str,
    unit_template: str = FIXED_SYSTEMD_UNIT_TEMPLATE,
) -> Tuple[bool, str]:
    """Conservatively verify ownership for pre-manifest/legacy rules without guessing by name."""
    validate_rule_name(rule_name)
    unit_name = unit_name_for_rule(unit_template, rule_name)
    unmanaged, reason = is_standalone_unmanaged_unit(unit_name)
    if unmanaged:
        return False, reason

    r_root = Path(rules_dir)
    s_root = Path(state_dir)
    stored_rule = r_root / f"{rule_name}.toml"
    realm_toml = s_root / "realm" / f"{rule_name}.toml"
    realm_env = s_root / "realm" / f"{rule_name}.env"
    state_json = s_root / "state" / f"{rule_name}.json"

    try:
        for parent, child in (
            (r_root, stored_rule),
            (s_root, realm_toml),
            (s_root, realm_env),
            (s_root, state_json),
        ):
            ensure_safe_subpath(parent, child)
    except OwnershipError as exc:
        return False, str(exc)

    if not (stored_rule.is_file() and realm_toml.is_file() and state_json.is_file()):
        return False, "缺少完整的旧版规则成套运行文件，无法确认归属"
    if realm_env.exists():
        try:
            if not realm_env.read_text(encoding="utf-8", errors="replace").startswith("# Generated by leikwan_tools"):
                return False, f"Realm 环境文件缺少受管标识头 ({realm_env})"
        except OSError as exc:
            return False, f"无法读取 Realm 环境文件 ({realm_env}): {exc}"

    rule_hdr = f"# Managed by leikwan_tools (rule: {rule_name})"
    realm_hdr = f"# Generated by leikwan_tools for rule: {rule_name}"
    try:
        if not stored_rule.read_text(encoding="utf-8", errors="replace").startswith(rule_hdr):
            return False, f"规则文件缺少受管标识头 ({stored_rule})"
        if not realm_toml.read_text(encoding="utf-8", errors="replace").startswith(realm_hdr):
            return False, f"Realm 运行配置缺少受管标识头 ({realm_toml})"
        st = json.loads(state_json.read_text(encoding="utf-8"))
        if not isinstance(st, dict) or st.get("rule_name") != rule_name or st.get("unit_name") != unit_name:
            return False, f"状态文件归属字段不匹配 ({state_json})"
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"读取旧版规则文件失败: {exc}"

    return True, "legacy-verified"


def check_rule_ownership(
    rules_dir: str,
    state_dir: str,
    rule_name: str,
    unit_template: str = FIXED_SYSTEMD_UNIT_TEMPLATE,
) -> Tuple[str, str]:
    """Return ('manifest' | 'legacy' | 'unowned', detail) for rule_name."""
    validate_rule_name(rule_name)
    unit_name = unit_name_for_rule(unit_template, rule_name)
    unmanaged, reason = is_standalone_unmanaged_unit(unit_name)
    if unmanaged:
        return "unowned", reason

    reg = load_managed_rules_registry(state_dir)
    if reg is not None and rule_name in reg.get("rules", {}):
        entry = reg["rules"][rule_name]
        if isinstance(entry, dict) and entry.get("unit_name") == unit_name:
            return "manifest", "registered"
        return "unowned", f"规则清单记录与单元名不匹配 ({rule_name})"

    legacy_ok, legacy_detail = check_conservative_legacy_rule(
        rules_dir=rules_dir,
        state_dir=state_dir,
        rule_name=rule_name,
        unit_template=unit_template,
    )
    if legacy_ok:
        return "legacy", legacy_detail
    return "unowned", legacy_detail


def assert_rule_slot_available_for_create(
    rules_dir: str,
    state_dir: str,
    rule_name: str,
    unit_template: str = FIXED_SYSTEMD_UNIT_TEMPLATE,
) -> None:
    """Refuse to create or overwrite a rule name if an unmanaged systemd unit/service already occupies it."""
    validate_rule_name(rule_name)
    unit_name = unit_name_for_rule(unit_template, rule_name)
    unmanaged, reason = is_standalone_unmanaged_unit(unit_name)
    if unmanaged:
        raise OwnershipError(f"拒绝创建规则 {rule_name!r}: {reason}")

    stored_rule = Path(rules_dir) / f"{rule_name}.toml"
    if not stored_rule.exists():
        active = systemd_is_active(unit_name)
        enabled = systemd_is_enabled(unit_name)
        if active or enabled:
            raise OwnershipError(
                f"拒绝接管非本工具管理的现有 systemd 服务 {unit_name} "
                f"(active={active}, enabled={enabled})"
            )


def safe_unlink_owned_file(root_dir: Path, target_path: Path) -> bool:
    """Safely remove a single non-symlink file inside root_dir; never removes directories or symlinks."""
    if not target_path.exists() and not target_path.is_symlink():
        return False
    ensure_safe_subpath(root_dir, target_path)
    if target_path.is_dir():
        return False
    target_path.unlink()
    return True


def remove_dir_if_empty(dir_path: Path) -> bool:
    """Remove directory ONLY if completely empty; preserves any unrelated files in shared directories."""
    if not dir_path.is_dir() or dir_path.is_symlink():
        return False
    try:
        dir_path.rmdir()
        return True
    except OSError:
        return False


def _active_unmanaged_template_users(owned_units: set) -> List[str]:
    """Check for any loaded/enabled leikwan_tools-realm@* units NOT in owned_units."""
    found: List[str] = []
    res_units = run_cmd(["systemctl", "list-units", "--all", "--no-legend", "--plain", "leikwan_tools-realm@*.service"])
    res_files = run_cmd(["systemctl", "list-unit-files", "--no-legend", "leikwan_tools-realm@*.service"])
    candidates = set()
    for out in (res_units.stdout if res_units.returncode == 0 else "", res_files.stdout if res_files.returncode == 0 else ""):
        for line in out.splitlines():
            tok = line.strip().split(None, 1)[0] if line.strip() else ""
            if tok.startswith("leikwan_tools-realm@") and tok != FIXED_SYSTEMD_UNIT_TEMPLATE and tok.endswith(".service"):
                candidates.add(tok)

    for unit in sorted(candidates):
        if unit in owned_units:
            continue
        unmanaged_standalone, _ = is_standalone_unmanaged_unit(unit)
        if unmanaged_standalone:
            # Standalone unit files do not depend on our @.service template.
            continue
        if systemd_is_active(unit) or systemd_is_enabled(unit):
            found.append(unit)
    return found


def write_install_artifacts(
    install_lib_dir: str,
    config_dir: str,
    state_dir: str,
    config_file: str,
    lock_file: str,
    realm_bin_path: str,
    realm_managed_install: bool,
    example_files: List[str],
    created_config_file: bool,
) -> Dict[str, Any]:
    """Write install.env and install-manifest.json atomically and adopt legacy rules if present."""
    lib_dir = Path(os.path.realpath(install_lib_dir))
    cfg_dir = Path(os.path.realpath(config_dir))
    st_dir = Path(os.path.realpath(state_dir))
    norm_example_files = [os.path.realpath(x) for x in example_files]

    install_env_content = "\n".join(
        [
            "# Managed-By: leikwan_tools",
            f"LEIKWAN_TOOLS_CONFIG={os.path.realpath(config_file)}",
            f"LEIKWAN_TOOLS_CONFIG_DIR={os.path.realpath(str(cfg_dir))}",
            f"LEIKWAN_TOOLS_STATE_DIR={os.path.realpath(str(st_dir))}",
            f"LEIKWAN_TOOLS_LOCK_FILE={lock_file}",
            "",
        ]
    )
    atomic_write_text(lib_dir / "install.env", install_env_content, mode=0o644)

    # Preserve created_config_file=True across upgrades if previously recorded in manifest.
    prev_manifest = load_install_manifest(str(lib_dir / "install-manifest.json"))
    if prev_manifest and prev_manifest.get("config_file") == os.path.realpath(config_file):
        created_config_file = bool(prev_manifest.get("created_config_file", created_config_file))
        previous_examples = [
            os.path.realpath(str(item))
            for item in (prev_manifest.get("example_files") or [])
            if str(item).strip()
        ]
        norm_example_files = sorted(set(previous_examples + norm_example_files))

    manifest: Dict[str, Any] = {
        "schema_version": 1,
        "tool_version": __version__,
        "managed_marker": MANAGED_MARKER,
        "installed_at_utc": datetime.now(timezone.utc).isoformat(),
        "install_lib_dir": os.path.realpath(str(lib_dir)),
        "launcher_path": BIN_LAUNCHER_PATH,
        "shortcut_path": SHORTCUT_PATH,
        "systemd_template_path": TEMPLATE_UNIT_PATH,
        "systemd_template_unit": FIXED_SYSTEMD_UNIT_TEMPLATE,
        "config_dir": os.path.realpath(str(cfg_dir)),
        "rules_dir": os.path.realpath(str(cfg_dir / "rules.d")),
        "examples_dir": os.path.realpath(str(cfg_dir / "examples")),
        "config_file": os.path.realpath(config_file),
        "created_config_file": created_config_file,
        "state_dir": os.path.realpath(str(st_dir)),
        "lock_file": lock_file,
        "example_files": norm_example_files,
        "lib_files": [
            str(lib_dir / "install.env"),
            str(lib_dir / "install-manifest.json"),
            str(lib_dir / "realm-exec.sh"),
            str(lib_dir / "realm-preflight.sh"),
        ],
        "realm": {
            "managed_install": realm_managed_install,
            "binary_path": realm_bin_path,
        },
    }
    atomic_write_text(
        lib_dir / "install-manifest.json",
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        mode=0o644,
    )

    # Ensure managed-rules.json exists and adopt conservatively verified legacy rules if present.
    reg = load_managed_rules_registry(str(st_dir)) or {"schema_version": 1, "rules": {}}
    rules_dir = cfg_dir / "rules.d"
    if rules_dir.is_dir():
        for cand in sorted(rules_dir.glob("*.toml")):
            rname = cand.stem
            if rname in reg["rules"]:
                continue
            try:
                ok, _ = check_conservative_legacy_rule(str(rules_dir), str(st_dir), rname)
                if ok:
                    register_managed_rule(
                        str(st_dir),
                        str(rules_dir),
                        rname,
                        unit_name_for_rule(FIXED_SYSTEMD_UNIT_TEMPLATE, rname),
                    )
                    reg = load_managed_rules_registry(str(st_dir)) or reg
            except ConfigError:
                continue
    if not registry_path_for_state_dir(str(st_dir)).exists():
        save_managed_rules_registry(str(st_dir), reg)
    return manifest


def uninstall_tool(
    purge: bool = False,
    config_dir_arg: str = "",
    state_dir_arg: str = "",
    install_lib_dir: str = INSTALL_LIB_DIR,
    manifest_path: str = INSTALL_MANIFEST_PATH,
    lock_timeout: float = 15.0,
) -> Dict[str, Any]:
    """Coordinated, ownership-verified uninstall touching ONLY leikwan_tools owned resources."""
    manifest = load_install_manifest(manifest_path)

    if manifest is not None:
        m_cfg_dir = os.path.realpath(str(manifest["config_dir"]))
        m_st_dir = os.path.realpath(str(manifest["state_dir"]))
        if config_dir_arg and os.path.realpath(config_dir_arg) != m_cfg_dir:
            raise OwnershipError(
                f"指定的 --config-dir ({config_dir_arg}) 与安装清单记录 ({m_cfg_dir}) 不一致，拒绝清理未知目录"
            )
        if state_dir_arg and os.path.realpath(state_dir_arg) != m_st_dir:
            raise OwnershipError(
                f"指定的 --state-dir ({state_dir_arg}) 与安装清单记录 ({m_st_dir}) 不一致，拒绝清理未知目录"
            )
        cfg_dir = Path(m_cfg_dir)
        rules_dir = Path(os.path.realpath(str(manifest["rules_dir"])))
        st_dir = Path(m_st_dir)
        lock_file = resolve_lock_file(manifest=manifest)
        mode = "manifest"
    else:
        for flag, raw_dir in (("--config-dir", config_dir_arg), ("--state-dir", state_dir_arg)):
            if raw_dir and Path(raw_dir).is_symlink():
                raise OwnershipError(f"拒绝操作符号链接目录 ({flag}={raw_dir})")
        cfg_dir = Path(os.path.realpath(config_dir_arg or "/etc/leikwan_tools"))
        rules_dir = cfg_dir / "rules.d"
        st_dir = Path(os.path.realpath(state_dir_arg or DEFAULT_STATE_DIR))
        lock_file = DEFAULT_COORDINATED_LOCK_FILE
        mode = "legacy-conservative"

    removed_files: List[str] = []
    removed_rules: List[str] = []
    skipped_items: List[str] = []

    with FileLock(lock_file, timeout=lock_timeout):
        owned_units = set()
        rules_to_remove: Dict[str, Dict[str, Path]] = {}

        if mode == "manifest":
            reg = load_managed_rules_registry(str(st_dir)) or {"rules": {}}
            for rname, entry in sorted((reg.get("rules") or {}).items()):
                validate_rule_name(rname)
                unit_name = unit_name_for_rule(FIXED_SYSTEMD_UNIT_TEMPLATE, rname)
                unmanaged, reason = is_standalone_unmanaged_unit(unit_name)
                if unmanaged:
                    skipped_items.append(f"跳过非受管服务 {unit_name}: {reason}")
                    continue
                files_map = entry.get("files") or {}
                rules_to_remove[rname] = {
                    "stored_rule": Path(files_map.get("stored_rule", str(rules_dir / f"{rname}.toml"))),
                    "realm_toml": Path(files_map.get("realm_toml", str(st_dir / "realm" / f"{rname}.toml"))),
                    "realm_env": Path(files_map.get("realm_env", str(st_dir / "realm" / f"{rname}.env"))),
                    "state_json": Path(files_map.get("state_json", str(st_dir / "state" / f"{rname}.json"))),
                }

        # Also conservatively adopt any legacy-verified rules inside rules_dir not yet in registry.
        if rules_dir.is_dir() and not rules_dir.is_symlink():
            for cand in sorted(rules_dir.glob("*.toml")):
                rname = cand.stem
                if rname in rules_to_remove:
                    continue
                try:
                    ok, reason = check_conservative_legacy_rule(str(rules_dir), str(st_dir), rname)
                except ConfigError as exc:
                    skipped_items.append(f"跳过非法规则文件 {cand}: {exc}")
                    continue
                if ok:
                    rules_to_remove[rname] = {
                        "stored_rule": rules_dir / f"{rname}.toml",
                        "realm_toml": st_dir / "realm" / f"{rname}.toml",
                        "realm_env": st_dir / "realm" / f"{rname}.env",
                        "state_json": st_dir / "state" / f"{rname}.json",
                    }
                else:
                    skipped_items.append(f"保留未证明归属的配置文件 {cand}: {reason}")

        for rname, fpaths in rules_to_remove.items():
            unit_name = unit_name_for_rule(FIXED_SYSTEMD_UNIT_TEMPLATE, rname)
            owned_units.add(unit_name)
            systemd_disable(unit_name, now=True)
            systemd_stop(unit_name)
            systemd_reset_failed(unit_name)
            for key, p in fpaths.items():
                root = rules_dir if key == "stored_rule" else st_dir
                try:
                    if safe_unlink_owned_file(root, p):
                        removed_files.append(str(p))
                except OwnershipError as exc:
                    skipped_items.append(f"跳过越界或符号链接文件 {p}: {exc}")
            removed_rules.append(rname)

        # Remove owned state metadata files item-by-item (NEVER rm -rf st_dir).
        reg_p = registry_path_for_state_dir(str(st_dir))
        try:
            if safe_unlink_owned_file(st_dir, reg_p):
                removed_files.append(str(reg_p))
        except OwnershipError as exc:
            skipped_items.append(str(exc))

        src_rec = st_dir / "realm-source.json"
        if src_rec.exists() and not src_rec.is_symlink() and src_rec.is_file():
            try:
                rec_data = json.loads(src_rec.read_text(encoding="utf-8"))
                rec_mode = str(rec_data.get("mode", ""))
                if rec_mode.startswith("installed-") or rec_mode.startswith("reused-"):
                    if safe_unlink_owned_file(st_dir, src_rec):
                        removed_files.append(str(src_rec))
                else:
                    skipped_items.append(f"保留非本工具格式的 {src_rec}")
            except (OSError, json.JSONDecodeError, OwnershipError) as exc:
                skipped_items.append(f"保留 {src_rec}: {exc}")

        # Remove owned Realm binary ONLY if recorded as managed_install by leikwan_tools.
        if manifest is not None:
            realm_meta = manifest.get("realm") or {}
            if realm_meta.get("managed_install") is True and realm_meta.get("binary_path"):
                rbin_raw = Path(str(realm_meta["binary_path"]))
                lib_root = Path(os.path.realpath(str(manifest.get("install_lib_dir", install_lib_dir))))
                try:
                    if rbin_raw.is_symlink():
                        raise OwnershipError(f"拒绝删除符号链接 Realm 二进制: {rbin_raw}")
                    rbin = Path(os.path.realpath(str(rbin_raw)))
                    if safe_unlink_owned_file(lib_root, rbin):
                        removed_files.append(str(rbin))
                except OwnershipError as exc:
                    skipped_items.append(f"保留 Realm 二进制 {rbin_raw}: {exc}")
            elif realm_meta.get("binary_path"):
                skipped_items.append(f"保留复用的外部 Realm 二进制: {realm_meta['binary_path']}")
        else:
            # Conservative legacy check for managed binary under /usr/local/lib/leikwan_tools/bin/realm
            legacy_bin = Path(MANAGED_REALM_BIN)
            if legacy_bin.is_file() and not legacy_bin.is_symlink():
                try:
                    ensure_safe_subpath(Path(install_lib_dir), legacy_bin)
                    legacy_bin.unlink()
                    removed_files.append(str(legacy_bin))
                except OwnershipError as exc:
                    skipped_items.append(str(exc))

        # Remove systemd template unit ONLY if owned and no external unmanaged instances depend on it.
        tpl_ok, tpl_reason = verify_template_unit_owned(TEMPLATE_UNIT_PATH)
        if tpl_ok:
            external_users = _active_unmanaged_template_users(owned_units)
            if external_users:
                skipped_items.append(
                    f"保留模板单元 {TEMPLATE_UNIT_PATH}，因仍有非受管实例依赖: {', '.join(external_users)}"
                )
            else:
                Path(TEMPLATE_UNIT_PATH).unlink()
                removed_files.append(TEMPLATE_UNIT_PATH)
                systemd_daemon_reload()
        elif Path(TEMPLATE_UNIT_PATH).exists():
            skipped_items.append(f"保留非本工具模板单元 {TEMPLATE_UNIT_PATH}: {tpl_reason}")

        for launcher_path in (BIN_LAUNCHER_PATH, SHORTCUT_PATH):
            launcher = Path(launcher_path)
            if launcher.exists() or launcher.is_symlink():
                bin_ok, bin_reason = verify_launcher_owned(launcher_path)
                if bin_ok:
                    launcher.unlink()
                    removed_files.append(launcher_path)
                else:
                    skipped_items.append(f"保留外部 CLI {launcher_path}: {bin_reason}")

        # Remove our own files inside install_lib_dir (keeping any foreign files untouched!).
        lib_root = Path(os.path.realpath(install_lib_dir))
        for rel in ("install.env", "install-manifest.json", "realm-exec.sh", "realm-preflight.sh"):
            p = lib_root / rel
            try:
                if safe_unlink_owned_file(lib_root, p):
                    removed_files.append(str(p))
            except OwnershipError as exc:
                skipped_items.append(str(exc))

        pkg_dir = lib_root / "leikwan_tools"
        if pkg_dir.is_dir() and not pkg_dir.is_symlink():
            shutil.rmtree(pkg_dir)
            removed_files.append(str(pkg_dir))

        if purge:
            if manifest is not None:
                ex_dir = Path(os.path.realpath(str(manifest.get("examples_dir", str(cfg_dir / "examples")))))
                for ex in manifest.get("example_files") or []:
                    ex_p = Path(ex)
                    try:
                        if safe_unlink_owned_file(ex_dir, ex_p):
                            removed_files.append(str(ex_p))
                    except OwnershipError as exc:
                        skipped_items.append(str(exc))
                cfg_file = Path(str(manifest["config_file"]))
                should_remove_cfg = bool(manifest.get("created_config_file", False))
                if not should_remove_cfg and cfg_file.is_file() and not cfg_file.is_symlink():
                    try:
                        load_global_config(str(cfg_file))
                        should_remove_cfg = True
                    except Exception:
                        should_remove_cfg = False
                if should_remove_cfg:
                    try:
                        if safe_unlink_owned_file(cfg_dir, cfg_file):
                            removed_files.append(str(cfg_file))
                    except OwnershipError as exc:
                        skipped_items.append(str(exc))
                elif cfg_file.exists():
                    skipped_items.append(f"保留非本工具创建或无法识别的配置文件: {cfg_file}")
            else:
                skipped_items.append(f"旧版保守模式下未删除未知来源配置文件，保留 {cfg_dir}")

        # Clean up empty directories via rmdir ONLY (never rm -rf shared dirs!).
        dirs_to_try = [
            st_dir / "realm",
            st_dir / "state",
            st_dir,
            lib_root / "bin",
            lib_root,
        ]
        if purge:
            dirs_to_try.extend([cfg_dir / "examples", rules_dir, cfg_dir])
        for d in dirs_to_try:
            remove_dir_if_empty(d)

    return {
        "mode": mode,
        "removed_rules": removed_rules,
        "removed_files": removed_files,
        "skipped_items": skipped_items,
    }


def _cli_main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m leikwan_tools.ownership")
    sub = parser.add_subparsers(dest="action", required=True)

    p_lock_run = sub.add_parser("check-install-targets")
    p_lock_run.add_argument("--config-dir", required=True)
    p_lock_run.add_argument("--state-dir", required=True)
    p_lock_run.add_argument("--lock-file", default=DEFAULT_COORDINATED_LOCK_FILE)

    p_write = sub.add_parser("write-manifest")
    p_write.add_argument("--install-lib-dir", default=INSTALL_LIB_DIR)
    p_write.add_argument("--config-dir", required=True)
    p_write.add_argument("--state-dir", required=True)
    p_write.add_argument("--config-file", required=True)
    p_write.add_argument("--lock-file", default=DEFAULT_COORDINATED_LOCK_FILE)
    p_write.add_argument("--realm-bin", default="")
    p_write.add_argument("--realm-managed", action="store_true")
    p_write.add_argument("--created-config", action="store_true")
    p_write.add_argument("--example-file", action="append", default=[])

    p_un = sub.add_parser("uninstall")
    p_un.add_argument("--purge", action="store_true")
    p_un.add_argument("--config-dir", default="")
    p_un.add_argument("--state-dir", default="")
    p_un.add_argument("--install-lib-dir", default=INSTALL_LIB_DIR)
    p_un.add_argument("--manifest-path", default=INSTALL_MANIFEST_PATH)
    p_un.add_argument("--lock-timeout", type=float, default=15.0)

    p_wl = sub.add_parser("with-lock")
    p_wl.add_argument("--lock-file", default=DEFAULT_COORDINATED_LOCK_FILE)
    p_wl.add_argument("--lock-timeout", type=float, default=15.0)
    p_wl.add_argument("cmd", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    try:
        if args.action == "with-lock":
            import subprocess

            cmd = list(args.cmd)
            if cmd and cmd[0] == "--":
                cmd = cmd[1:]
            if not cmd:
                raise OwnershipError("with-lock 需要提供待执行命令")
            with FileLock(args.lock_file, timeout=args.lock_timeout):
                proc = subprocess.run(cmd, check=False)
                return proc.returncode
        if args.action == "check-install-targets":
            for launcher_path in (BIN_LAUNCHER_PATH, SHORTCUT_PATH):
                launcher = Path(launcher_path)
                if launcher.exists() or launcher.is_symlink():
                    ok, reason = verify_launcher_owned(launcher_path)
                    if not ok:
                        raise OwnershipError(f"拒绝覆盖非本工具 CLI 入口: {reason}")
            if Path(TEMPLATE_UNIT_PATH).exists() or Path(TEMPLATE_UNIT_PATH).is_symlink():
                ok, reason = verify_template_unit_owned(TEMPLATE_UNIT_PATH)
                if not ok:
                    legacy_ok, legacy_reason = verify_legacy_template_owned(TEMPLATE_UNIT_PATH)
                    if not legacy_ok:
                        raise OwnershipError(f"拒绝覆盖非本工具 systemd 模板: {reason}")
                    print(f"  识别到旧版 leikwan_tools 模板，允许原位迁移: {legacy_reason}")
            cfg_p = Path(args.config_dir)
            st_p = Path(args.state_dir)
            for d in (
                Path(INSTALL_LIB_DIR),
                cfg_p,
                st_p,
                cfg_p / "rules.d",
                cfg_p / "examples",
                cfg_p / "config.toml",
                st_p / "realm",
                st_p / "state",
            ):
                if d.is_symlink():
                    raise OwnershipError(f"拒绝安装到符号链接路径: {d}")
            return 0

        if args.action == "write-manifest":
            with FileLock(args.lock_file, timeout=15.0):
                write_install_artifacts(
                    install_lib_dir=args.install_lib_dir,
                    config_dir=args.config_dir,
                    state_dir=args.state_dir,
                    config_file=args.config_file,
                    lock_file=args.lock_file,
                    realm_bin_path=args.realm_bin,
                    realm_managed_install=args.realm_managed,
                    example_files=args.example_file,
                    created_config_file=args.created_config,
                )
            return 0

        if args.action == "uninstall":
            res = uninstall_tool(
                purge=args.purge,
                config_dir_arg=args.config_dir,
                state_dir_arg=args.state_dir,
                install_lib_dir=args.install_lib_dir,
                manifest_path=args.manifest_path,
                lock_timeout=args.lock_timeout,
            )
            print(f"卸载模式: {res['mode']}")
            if res["removed_rules"]:
                print(f"已清理规则: {', '.join(res['removed_rules'])}")
            for item in res["skipped_items"]:
                print(f"保留/跳过: {item}")
            print("卸载完成：仅清理了 leikwan_tools 自身拥有并验证归属的资源。")
            return 0
    except (OwnershipError, ConfigError, PreflightError, Exception) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
