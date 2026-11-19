"""Realm binary discovery, version compatibility validation, and ownership-safe verified installation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from typing import Any, Dict, List, Optional, Tuple
import urllib.request

from . import (
    ARCH_ALIASES,
    DEFAULT_STATE_DIR,
    INSTALL_MANIFEST_PATH,
    MANAGED_REALM_BIN,
    REALM_MAX_MAJOR,
    REALM_MIN_COMPAT_VERSION,
    REALM_RELEASES,
    REALM_VERIFIED_VERSION,
)

VERSION_RE = re.compile(r"\brealm\s+v?(\d+)\.(\d+)\.(\d+)\b", re.IGNORECASE)


class RealmError(RuntimeError):
    """Raised when Realm binary discovery, verification, or installation fails."""


@dataclass(frozen=True)
class RealmBinaryInfo:
    """Validated Realm binary metadata."""

    path: str
    version_text: str
    version_tuple: Tuple[int, int, int]
    sha256: str
    origin: str  # "managed" | "reused" | "configured"


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def parse_realm_version(output: str) -> Tuple[int, int, int]:
    """Parse version tuple from `realm --version` output."""
    match = VERSION_RE.search(output)
    if not match:
        raise RealmError(f"无法从 Realm 输出解析版本号: {output.strip()!r}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def inspect_realm_binary(path: str, origin: str = "reused") -> RealmBinaryInfo:
    """Validate that a Realm binary is executable and supports v2.6+ TOML, --through, and --interface."""
    bin_path = Path(path)
    if not bin_path.is_file():
        raise RealmError(f"Realm 二进制不存在: {path}")
    if not os.access(bin_path, os.X_OK):
        raise RealmError(f"Realm 二进制不可执行: {path}")

    try:
        ver_res = subprocess.run(
            [str(bin_path), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except OSError as exc:
        raise RealmError(f"无法执行 Realm ({path}): {exc}") from exc

    ver_out = (ver_res.stdout or "") + (ver_res.stderr or "")
    if ver_res.returncode != 0:
        raise RealmError(f"执行 {path} --version 失败 (exit={ver_res.returncode}): {ver_out.strip()}")

    version_tuple = parse_realm_version(ver_out)
    if version_tuple[0] != REALM_MAX_MAJOR or version_tuple < REALM_MIN_COMPAT_VERSION:
        min_str = ".".join(map(str, REALM_MIN_COMPAT_VERSION))
        raise RealmError(
            f"Realm 版本不兼容: {path} 为 {version_tuple[0]}.{version_tuple[1]}.{version_tuple[2]}，"
            f"要求 {min_str} ~ 2.x (已验证 v{REALM_VERIFIED_VERSION})"
        )

    help_res = subprocess.run(
        [str(bin_path), "--help"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    help_out = (help_res.stdout or "") + (help_res.stderr or "")
    if (
        help_res.returncode != 0
        or "--config" not in help_out
        or "--through" not in help_out
        or "--interface" not in help_out
    ):
        raise RealmError(f"Realm 二进制缺少必需参数 (--config / --through / --interface): {path}")

    return RealmBinaryInfo(
        path=str(bin_path),
        version_text=".".join(map(str, version_tuple)),
        version_tuple=version_tuple,
        sha256=sha256_file(bin_path),
        origin=origin,
    )


def discover_realm_binary(configured_path: str = "", managed_bin: str = MANAGED_REALM_BIN) -> RealmBinaryInfo:
    """Find a compatible Realm binary. Strictly validates explicit configured_path if provided."""
    if configured_path:
        return inspect_realm_binary(configured_path, origin="configured")

    candidates: List[Tuple[str, str]] = []
    if managed_bin:
        candidates.append((managed_bin, "managed"))

    which_bin = shutil.which("realm")
    if which_bin:
        candidates.append((which_bin, "reused"))

    for fallback in (
        "/usr/local/bin/realm",
        "/usr/bin/realm",
        "/root/realm/realm",
        "/opt/realm/realm",
        "/etc/realm/realm",
    ):
        candidates.append((fallback, "reused"))

    seen = set()
    errors: List[str] = []
    for cand_path, origin in candidates:
        resolved = os.path.abspath(cand_path)
        if resolved in seen:
            continue
        seen.add(resolved)
        if not Path(cand_path).exists():
            continue
        try:
            return inspect_realm_binary(cand_path, origin=origin)
        except RealmError as exc:
            errors.append(str(exc))

    detail = "；".join(errors) if errors else "未在系统路径中找到 realm 二进制"
    raise RealmError(
        f"未找到兼容的 Realm (要求 >= {'.'.join(map(str, REALM_MIN_COMPAT_VERSION))} 且主版本为 2): {detail}"
    )


def get_release_spec(arch: Optional[str] = None) -> Tuple[str, Dict[str, str]]:
    """Return canonical architecture name and pinned Realm v2.9.6 release metadata."""
    raw_arch = (arch or platform.machine()).strip().lower()
    canon_arch = ARCH_ALIASES.get(raw_arch)
    if not canon_arch or canon_arch not in REALM_RELEASES:
        raise RealmError(f"当前架构暂未内置校验摘要: {raw_arch!r} (支持: {', '.join(REALM_RELEASES)})")
    return canon_arch, REALM_RELEASES[canon_arch]


def _is_owned_realm_target(target: Path, state_dir: str, manifest_path: str = INSTALL_MANIFEST_PATH) -> bool:
    """Return True only if target can be safely overwritten as a tool-owned Realm binary."""
    if target.is_symlink():
        return False
    if not target.exists():
        return True

    real_target = os.path.realpath(str(target))
    if real_target == os.path.realpath(MANAGED_REALM_BIN):
        return True

    mpath = Path(manifest_path)
    if mpath.is_file() and not mpath.is_symlink():
        try:
            manifest = json.loads(mpath.read_text(encoding="utf-8"))
            realm_meta = manifest.get("realm") or {}
            if realm_meta.get("managed_install") is True:
                rec_path = realm_meta.get("binary_path", "")
                if rec_path and os.path.realpath(rec_path) == real_target:
                    return True
        except (OSError, json.JSONDecodeError):
            pass

    src_rec = Path(state_dir) / "realm-source.json"
    if src_rec.is_file() and not src_rec.is_symlink():
        try:
            data = json.loads(src_rec.read_text(encoding="utf-8"))
            mode = str(data.get("mode", ""))
            rec_path = str(data.get("binary_path", ""))
            if mode.startswith("installed-") and rec_path and os.path.realpath(rec_path) == real_target:
                return True
        except (OSError, json.JSONDecodeError):
            pass

    return False


def _record_realm_source(state_dir: str, payload: Dict[str, Any]) -> None:
    """Persist Realm source/verification metadata in leikwan_tools state dir."""
    state_root = Path(state_dir)
    state_root.mkdir(parents=True, exist_ok=True)
    record_path = state_root / "realm-source.json"
    record_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def install_realm_binary(
    target_path: str = MANAGED_REALM_BIN,
    tarball_path: Optional[str] = None,
    arch: Optional[str] = None,
    state_dir: str = DEFAULT_STATE_DIR,
    manifest_path: str = INSTALL_MANIFEST_PATH,
) -> RealmBinaryInfo:
    """Install verified official Realm binary strictly into an owned target path without overwriting foreign binaries."""
    target = Path(target_path)
    if target.is_symlink():
        raise RealmError(f"拒绝写入符号链接目标路径: {target_path}")
    if target.exists() and not _is_owned_realm_target(target, state_dir=state_dir, manifest_path=manifest_path):
        raise RealmError(
            f"目标路径已存在非本工具安装的二进制文件 ({target_path})，拒绝覆盖；"
            f"请安装到默认受管路径 {MANAGED_REALM_BIN} 或通过配置复用已有二进制。"
        )
    if target.parent.is_symlink():
        raise RealmError(f"拒绝写入符号链接父目录: {target.parent}")

    canon_arch, spec = get_release_spec(arch)
    expected_sha = spec["sha256"]
    download_url = spec["url"]

    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="liqun-realm-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        if tarball_path:
            archive_path = Path(tarball_path)
            if not archive_path.is_file():
                raise RealmError(f"指定的 Realm 安装包不存在: {tarball_path}")
            source_mode = "tarball"
        else:
            archive_path = tmp_path / spec["asset"]
            source_mode = "download"
            try:
                req = urllib.request.Request(
                    download_url,
                    headers={"User-Agent": "leikwan_tools/1.0"},
                )
                with urllib.request.urlopen(req, timeout=60) as resp, archive_path.open("wb") as out_fh:
                    shutil.copyfileobj(resp, out_fh)
            except Exception as exc:
                raise RealmError(f"下载官方 Realm 失败 ({download_url}): {exc}") from exc

        actual_sha = sha256_file(archive_path)
        if actual_sha.lower() != expected_sha.lower():
            raise RealmError(
                f"Realm 安装包 SHA-256 校验失败! 预期={expected_sha}, 实际={actual_sha} "
                f"(文件: {archive_path})"
            )

        extract_dir = tmp_path / "extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        extracted_bin: Optional[Path] = None
        try:
            with tarfile.open(archive_path, "r:gz") as tf:
                for member in tf.getmembers():
                    if member.isfile() and Path(member.name).name == "realm":
                        src_fh = tf.extractfile(member)
                        if src_fh is None:
                            continue
                        extracted_bin = extract_dir / "realm"
                        with src_fh, extracted_bin.open("wb") as dst_fh:
                            shutil.copyfileobj(src_fh, dst_fh)
                        break
        except tarfile.TarError as exc:
            raise RealmError(f"解压 Realm 安装包失败: {exc}") from exc

        if extracted_bin is None or not extracted_bin.is_file():
            raise RealmError("安装包中未找到 realm 可执行文件")

        os.chmod(extracted_bin, 0o755)
        tmp_target = target.with_name(f".{target.name}.tmp.{os.getpid()}")
        try:
            shutil.copy2(extracted_bin, tmp_target)
            os.chmod(tmp_target, 0o755)
            info = inspect_realm_binary(str(tmp_target), origin="managed")
            os.replace(tmp_target, target)
        finally:
            if tmp_target.exists():
                tmp_target.unlink(missing_ok=True)

    final_info = inspect_realm_binary(str(target), origin="managed")
    _record_realm_source(
        state_dir,
        {
            "mode": f"installed-{source_mode}",
            "upstream_repo": "https://github.com/zhboner/realm",
            "version": REALM_VERIFIED_VERSION,
            "arch": canon_arch,
            "asset": spec["asset"],
            "upstream_url": download_url,
            "archive_sha256": expected_sha,
            "binary_path": final_info.path,
            "binary_sha256": final_info.sha256,
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        },
    )
    return final_info
