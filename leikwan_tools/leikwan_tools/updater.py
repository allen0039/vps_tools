"""Self-update helpers for checking and pulling leikwan_tools from GitHub or Gitee."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

from . import INSTALL_MANIFEST_PATH, __version__
from .ownership import BIN_LAUNCHER_PATH, ensure_safe_subpath, load_install_manifest

UPDATE_REPO = "allen0039/vps_tools"
UPDATE_BRANCH = "main"
UPDATE_SUBDIR = "leikwan_tools"
DEFAULT_UPDATE_CHANNEL = "github"

UPDATE_CHANNELS: Dict[str, Dict[str, str]] = {
    "github": {
        "label": "GitHub",
        "commit_api": "https://api.github.com/repos/{repo}/commits/{branch}",
        "tree_api": "https://api.github.com/repos/{repo}/git/trees/{tree_sha}",
        "raw_base": "https://raw.githubusercontent.com/{repo}",
    },
    "gitee": {
        "label": "Gitee",
        "commit_api": "https://gitee.com/api/v5/repos/{repo}/branches/{branch}",
        "tree_api": "https://gitee.com/api/v5/repos/{repo}/git/trees/{tree_sha}",
        "raw_base": "https://gitee.com/{repo}/raw",
    },
}

ALLOWED_TOP_FILES = frozenset({"install.sh", "uninstall.sh", "README.md"})
ALLOWED_SUBDIRS = frozenset({"bin", "examples", "systemd", "leikwan_tools"})
REQUIRED_UPDATE_FILES = (
    "install.sh",
    "bin/leikwan_tools",
    "leikwan_tools/__init__.py",
    "leikwan_tools/cli.py",
    "systemd/leikwan_tools-realm@.service",
)
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
NUMERIC_VER_RE = re.compile(r"^v?(\d+(?:\.\d+)*)$", re.IGNORECASE)


class UpdateError(RuntimeError):
    """Raised when checking, downloading, verifying, or installing an update fails."""


@dataclass(frozen=True)
class UpdateCheckInfo:
    """Metadata returned when checking the remote repository for updates."""

    channel: str
    channel_label: str
    repo: str
    branch: str
    current_version: str
    remote_version: str
    commit_sha: str
    short_sha: str
    tree_sha: str
    commit_message: str
    status: str
    update_available: bool


@dataclass(frozen=True)
class UpdateResult:
    """Result returned after installing an update from the repository."""

    channel: str
    channel_label: str
    repo: str
    branch: str
    commit_sha: str
    short_sha: str
    previous_version: str
    remote_version: str
    installed_version: str
    files_updated: int
    install_args: List[str]
    version_changed: bool


def _require_channel(channel: str) -> Dict[str, str]:
    spec = UPDATE_CHANNELS.get(channel)
    if spec is None:
        raise UpdateError(f"不支持的更新渠道: {channel!r}（仅支持 github 或 gitee）")
    return spec


def _other_channel(channel: str) -> str:
    return "gitee" if channel == "github" else "github"


def _with_nonce(url: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}leikwan_refresh={secrets.token_hex(8)}"


def _http_get_bytes(url: str, timeout: float = 20.0, accept: str = "*/*", *, channel: str = "") -> bytes:
    alt_hint = f"（可尝试切换渠道 --channel {_other_channel(channel)}）" if channel in UPDATE_CHANNELS else ""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"leikwan_tools/{__version__}",
            "Accept": accept,
            "Cache-Control": "no-cache",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise UpdateError(f"请求更新资源失败 (HTTP {exc.code}): {url}{alt_hint}") from exc
    except urllib.error.URLError as exc:
        raise UpdateError(f"无法连接更新服务器 ({exc.reason}): {url}{alt_hint}") from exc
    except (TimeoutError, OSError) as exc:
        raise UpdateError(f"下载更新资源超时或网络异常 ({exc}): {url}{alt_hint}") from exc


def _http_get_json(url: str, timeout: float = 20.0, *, channel: str = "") -> Dict[str, Any]:
    raw = _http_get_bytes(url, timeout=timeout, accept="application/json", channel=channel)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError(f"更新源返回的 JSON 元数据无效: {exc}") from exc
    if not isinstance(data, dict):
        raise UpdateError("更新源返回的 JSON 元数据格式异常")
    return data


def _parse_commit_metadata(data: Dict[str, Any]) -> Tuple[str, str, str]:
    """Parse commit_sha, tree_sha, and single-line commit message from GitHub or Gitee JSON."""
    commit_sha = ""
    inner: Dict[str, Any] = {}

    if isinstance(data.get("sha"), str):
        commit_sha = data["sha"].strip().lower()
        if isinstance(data.get("commit"), dict):
            inner = data["commit"]
    elif isinstance(data.get("commit"), dict):
        top_commit = data["commit"]
        if isinstance(top_commit.get("sha"), str):
            commit_sha = top_commit["sha"].strip().lower()
        if isinstance(top_commit.get("commit"), dict):
            inner = top_commit["commit"]
        else:
            inner = top_commit

    if not SHA40_RE.match(commit_sha):
        raise UpdateError("更新渠道未返回有效的 40 位提交编号 (SHA)")

    tree_sha = ""
    tree_obj = inner.get("tree")
    if isinstance(tree_obj, dict) and isinstance(tree_obj.get("sha"), str):
        cand_tree = tree_obj["sha"].strip().lower()
        if SHA40_RE.match(cand_tree):
            tree_sha = cand_tree
    if not tree_sha:
        tree_sha = commit_sha

    raw_msg = inner.get("message") if isinstance(inner.get("message"), str) else ""
    first_line = ""
    for line in raw_msg.splitlines():
        stripped = line.strip()
        if stripped:
            first_line = stripped
            break
    if len(first_line) > 120:
        first_line = first_line[:117] + "..."
    return commit_sha, tree_sha, first_line


def _extract_version_from_init(source_text: str) -> str:
    """Safely extract string literal __version__ from leikwan_tools/__init__.py via AST."""
    try:
        tree = ast.parse(source_text)
    except SyntaxError as exc:
        raise UpdateError(f"仓库 __init__.py 语法无效: {exc}") from exc

    for node in tree.body:
        value_node = None
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets):
                value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "__version__":
                value_node = node.value
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            ver = value_node.value.strip()
            if ver:
                return ver

    raise UpdateError("仓库 leikwan_tools/__init__.py 中未找到有效的 __version__ 字符串")


def _compare_versions(current: str, remote: str) -> Tuple[str, bool]:
    m_cur = NUMERIC_VER_RE.match(current.strip())
    m_rem = NUMERIC_VER_RE.match(remote.strip())
    if not m_cur or not m_rem:
        cur_norm = current.strip().lstrip("vV")
        rem_norm = remote.strip().lstrip("vV")
        return "unknown", cur_norm != rem_norm

    cur_parts = [int(p) for p in m_cur.group(1).split(".")]
    rem_parts = [int(p) for p in m_rem.group(1).split(".")]
    max_len = max(len(cur_parts), len(rem_parts))
    cur_parts.extend([0] * (max_len - len(cur_parts)))
    rem_parts.extend([0] * (max_len - len(rem_parts)))

    if rem_parts > cur_parts:
        return "upgrade", True
    if rem_parts == cur_parts:
        return "same", False
    return "ahead", False


def _validate_rel_path(rel_path: str) -> PurePosixPath:
    if not rel_path or rel_path.startswith("/") or "\\" in rel_path:
        raise UpdateError(f"检测到非法仓库文件路径: {rel_path!r}")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in rel_path):
        raise UpdateError(f"检测到包含控制字符的路径: {rel_path!r}")
    pure = PurePosixPath(rel_path)
    if pure.is_absolute() or not pure.parts:
        raise UpdateError(f"检测到非法仓库文件路径: {rel_path!r}")
    for part in pure.parts:
        if part in ("", ".", ".."):
            raise UpdateError(f"检测到越界路径片段: {rel_path!r}")
    return pure


def _filter_update_tree_paths(
    entries: List[Dict[str, Any]],
    *,
    prefix: str = f"{UPDATE_SUBDIR}/",
) -> List[Tuple[str, str]]:
    """Filter git tree entries down to safe, allowed runtime/installer files for leikwan_tools."""
    selected: Dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw_path = entry.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            continue
        if prefix:
            if not raw_path.startswith(prefix):
                continue
            rel = raw_path[len(prefix):]
        else:
            rel = raw_path

        pure = _validate_rel_path(rel)
        parts = pure.parts
        if entry.get("type") != "blob":
            continue
        mode = str(entry.get("mode", "100644"))
        if mode == "120000":
            continue
        if any(part == "__pycache__" or part.startswith(".") for part in parts):
            continue
        if pure.name.endswith((".pyc", ".pyo")):
            continue

        if len(parts) == 1:
            if parts[0] not in ALLOWED_TOP_FILES:
                continue
        elif parts[0] not in ALLOWED_SUBDIRS:
            continue

        selected[rel] = mode

    return sorted(selected.items(), key=lambda item: item[0])


def _discover_remote_files(
    channel: str,
    tree_sha: str,
    *,
    repo: str = UPDATE_REPO,
    timeout: float = 20.0,
) -> List[Tuple[str, str]]:
    spec = _require_channel(channel)
    root_url = _with_nonce(spec["tree_api"].format(repo=repo, tree_sha=tree_sha) + "?recursive=1")
    root_data = _http_get_json(root_url, timeout=timeout, channel=channel)
    entries = root_data.get("tree")
    if not isinstance(entries, list):
        raise UpdateError("仓库目录树返回格式异常")

    files = _filter_update_tree_paths(entries, prefix=f"{UPDATE_SUBDIR}/")
    if root_data.get("truncated") or not files:
        shallow_url = _with_nonce(spec["tree_api"].format(repo=repo, tree_sha=tree_sha))
        shallow_data = _http_get_json(shallow_url, timeout=timeout, channel=channel)
        shallow_entries = shallow_data.get("tree")
        if not isinstance(shallow_entries, list):
            raise UpdateError("仓库根目录树返回格式异常")
        subdir_sha = ""
        for item in shallow_entries:
            if (
                isinstance(item, dict)
                and item.get("path") == UPDATE_SUBDIR
                and item.get("type") == "tree"
                and isinstance(item.get("sha"), str)
            ):
                cand = item["sha"].strip().lower()
                if SHA40_RE.match(cand):
                    subdir_sha = cand
                    break
        if not subdir_sha:
            raise UpdateError(f"仓库提交中未找到 {UPDATE_SUBDIR} 目录")
        sub_url = _with_nonce(spec["tree_api"].format(repo=repo, tree_sha=subdir_sha) + "?recursive=1")
        sub_data = _http_get_json(sub_url, timeout=timeout, channel=channel)
        sub_entries = sub_data.get("tree")
        if not isinstance(sub_entries, list):
            raise UpdateError(f"仓库 {UPDATE_SUBDIR} 子目录树返回格式异常")
        if sub_data.get("truncated"):
            raise UpdateError(f"仓库 {UPDATE_SUBDIR} 文件列表被截断，无法安全拉取完整更新")
        files = _filter_update_tree_paths(sub_entries, prefix="")

    found_paths = {rel for rel, _ in files}
    missing = [req for req in REQUIRED_UPDATE_FILES if req not in found_paths]
    if missing:
        raise UpdateError(f"仓库更新包缺少必要文件: {', '.join(missing)}")
    return files


def _validate_staged_files(stage_dir: Path, rel_paths: List[str]) -> None:
    """Run syntax and basic structural checks on all downloaded files before invoking install.sh."""
    for rel in rel_paths:
        pure = _validate_rel_path(rel)
        target = ensure_safe_subpath(stage_dir, stage_dir.joinpath(*pure.parts))
        if target.is_symlink() or not target.is_file():
            raise UpdateError(f"暂存文件异常（非普通文件）: {rel}")
        if target.stat().st_size == 0:
            raise UpdateError(f"下载的更新文件为空: {rel}")

        if rel.endswith(".py") or rel == "bin/leikwan_tools":
            try:
                text = target.read_text(encoding="utf-8")
                ast.parse(text)
            except (UnicodeDecodeError, SyntaxError) as exc:
                raise UpdateError(f"Python 文件校验失败 ({rel}): {exc}") from exc
            if rel == "bin/leikwan_tools" and not text.startswith("#!/usr/bin/env python3"):
                raise UpdateError(f"启动脚本头异常: {rel}")
        elif rel.endswith(".sh"):
            try:
                text = target.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                raise UpdateError(f"Shell 脚本解码失败 ({rel}): {exc}") from exc
            if not text.startswith("#!/usr/bin/env bash"):
                raise UpdateError(f"Shell 脚本缺少 bash shebang: {rel}")
            proc = subprocess.run(
                ["bash", "-n", str(target)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode != 0:
                detail = proc.stderr.strip() or proc.stdout.strip() or "syntax error"
                raise UpdateError(f"Shell 语法校验失败 ({rel}): {detail}")
        elif rel.endswith(".service"):
            try:
                text = target.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                raise UpdateError(f"systemd 单元文件解码失败 ({rel}): {exc}") from exc
            if "[Unit]" not in text or "[Service]" not in text:
                raise UpdateError(f"systemd 单元文件格式异常 ({rel})")


def _build_install_args(manifest: Optional[Dict[str, Any]]) -> List[str]:
    """Preserve previously installed config_dir, state_dir, and Realm strategy during in-place update."""
    if not manifest:
        return []
    args: List[str] = []
    config_dir = str(manifest.get("config_dir", "")).strip()
    state_dir = str(manifest.get("state_dir", "")).strip()
    if config_dir:
        args.extend(["--config-dir", config_dir])
    if state_dir:
        args.extend(["--state-dir", state_dir])

    realm_meta = manifest.get("realm")
    if isinstance(realm_meta, dict):
        binary_path = str(realm_meta.get("binary_path", "")).strip()
        managed_install = bool(realm_meta.get("managed_install", False))
        if not binary_path:
            args.append("--skip-realm-install")
        elif not managed_install and Path(binary_path).is_file():
            args.extend(["--realm-bin", binary_path])
    return args


def check_for_update(
    channel: str = DEFAULT_UPDATE_CHANNEL,
    *,
    repo: str = UPDATE_REPO,
    branch: str = UPDATE_BRANCH,
    timeout: float = 20.0,
    current_version: str = __version__,
) -> UpdateCheckInfo:
    """Query GitHub or Gitee for the latest commit and version of leikwan_tools."""
    spec = _require_channel(channel)
    commit_url = _with_nonce(spec["commit_api"].format(repo=repo, branch=branch))
    commit_data = _http_get_json(commit_url, timeout=timeout, channel=channel)
    commit_sha, tree_sha, commit_message = _parse_commit_metadata(commit_data)

    init_url = _with_nonce(
        f"{spec['raw_base'].format(repo=repo)}/{commit_sha}/{UPDATE_SUBDIR}/leikwan_tools/__init__.py"
    )
    init_bytes = _http_get_bytes(init_url, timeout=timeout, channel=channel)
    try:
        init_text = init_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UpdateError(f"仓库 __init__.py 编码无效: {exc}") from exc
    remote_version = _extract_version_from_init(init_text)
    status, update_available = _compare_versions(current_version, remote_version)

    return UpdateCheckInfo(
        channel=channel,
        channel_label=spec["label"],
        repo=repo,
        branch=branch,
        current_version=current_version,
        remote_version=remote_version,
        commit_sha=commit_sha,
        short_sha=commit_sha[:7],
        tree_sha=tree_sha,
        commit_message=commit_message,
        status=status,
        update_available=update_available,
    )


def _read_installed_version(launcher_path: str) -> str:
    proc = subprocess.run(
        [launcher_path, "--version"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
        raise UpdateError(f"安装脚本已执行，但校验新版本失败 ({launcher_path}): {detail}")
    out = proc.stdout.strip() or proc.stderr.strip()
    if not out:
        raise UpdateError(f"安装脚本已执行，但 {launcher_path} --version 无输出")
    return out.split()[-1].lstrip("vV")


def perform_update(
    channel: str = DEFAULT_UPDATE_CHANNEL,
    *,
    repo: str = UPDATE_REPO,
    branch: str = UPDATE_BRANCH,
    timeout: float = 20.0,
    prechecked: Optional[UpdateCheckInfo] = None,
    manifest_path: str = INSTALL_MANIFEST_PATH,
    launcher_path: str = BIN_LAUNCHER_PATH,
    current_version: str = __version__,
) -> UpdateResult:
    """Download, verify, and install the latest leikwan_tools release in place."""
    if platform.system() != "Linux":
        raise UpdateError("仅支持在 Linux 环境下执行原地更新")
    if os.geteuid() != 0:
        raise UpdateError("更新工具需要 root 权限，请使用 sudo lqtool 或 sudo leikwan_tools update")

    spec = _require_channel(channel)
    if (
        prechecked is not None
        and prechecked.channel == channel
        and prechecked.repo == repo
        and prechecked.branch == branch
    ):
        info = prechecked
    else:
        info = check_for_update(
            channel=channel,
            repo=repo,
            branch=branch,
            timeout=timeout,
            current_version=current_version,
        )

    files = _discover_remote_files(channel, info.tree_sha, repo=repo, timeout=timeout)
    raw_base = spec["raw_base"].format(repo=repo)

    with tempfile.TemporaryDirectory(prefix="leikwan-tools-update-") as tmp_dir:
        stage_dir = Path(tmp_dir)
        rel_paths: List[str] = []
        for rel, mode in files:
            pure = _validate_rel_path(rel)
            dst = ensure_safe_subpath(stage_dir, stage_dir.joinpath(*pure.parts))
            dst.parent.mkdir(parents=True, exist_ok=True)
            file_url = _with_nonce(f"{raw_base}/{info.commit_sha}/{UPDATE_SUBDIR}/{rel}")
            content = _http_get_bytes(file_url, timeout=timeout, channel=channel)
            dst.write_bytes(content)
            exec_mode = 0o755 if (mode == "100755" or rel.endswith(".sh") or rel.startswith("bin/")) else 0o644
            os.chmod(dst, exec_mode)
            rel_paths.append(rel)

        _validate_staged_files(stage_dir, rel_paths)

        manifest = load_install_manifest(manifest_path)
        install_args = _build_install_args(manifest)

        # Do not acquire /run/leikwan_tools.lock here: install.sh acquires it via ownership.with_lock.
        proc = subprocess.run(
            ["bash", str(stage_dir / "install.sh"), *install_args],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if proc.returncode != 0:
            lines = (proc.stderr + "\n" + proc.stdout).strip().splitlines()
            tail = "\n".join(lines[-8:]) if lines else f"exit {proc.returncode}"
            raise UpdateError(f"执行更新安装失败（现有配置和运行中转发未删改）:\n{tail}")

    installed_version = _read_installed_version(launcher_path)
    return UpdateResult(
        channel=info.channel,
        channel_label=info.channel_label,
        repo=info.repo,
        branch=info.branch,
        commit_sha=info.commit_sha,
        short_sha=info.short_sha,
        previous_version=current_version,
        remote_version=info.remote_version,
        installed_version=installed_version,
        files_updated=len(rel_paths),
        install_args=install_args,
        version_changed=(installed_version != current_version),
    )
