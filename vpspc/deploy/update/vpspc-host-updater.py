#!/usr/bin/env python3
"""Restricted root helper for VPSPC controller maintenance.

The Web, Telegram bot, and maintenance service never receive a shell, a
filesystem path, or a download URL from this helper.  They can only submit a
short, HMAC-authenticated request over the root-owned Unix socket.  Artifact
selection has already happened in the unprivileged coordinator; this process
only opens a named artifact from its fixed local cache and verifies it again.

Task 10 deliberately implements native controller updates and the *planning*
phase of controller removal.  Docker actions and the irreversible removal
executor are added by later tasks, rather than exposing broad privileged
operations early.
"""

from __future__ import annotations

import argparse
import compileall
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
from typing import Any, Callable, Dict, Mapping, MutableMapping, Optional, Sequence, Tuple, Union


# The installed helper is intentionally outside the application tree it may
# replace.  These locations are installation constants, not API parameters.
INSTALL_ROOT = Path("/opt/vps-audit")
CONFIG_PATH = Path("/etc/vps-audit/config.json")
CACHE_ROOT = Path("/var/lib/vps-audit/maintenance/artifacts")
# A sibling of the native install tree guarantees rename(2) stays atomic even
# when /var/lib is mounted on a different filesystem.
WORK_ROOT = Path("/opt/.vps-audit-update")
OWNERSHIP_PATH = Path("/etc/vps-audit/ownership.json")
UPDATER_KEY_PATH = Path("/etc/vps-audit/updater.key")
SOCKET_PATH = Path("/run/vpspc/updater.sock")

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_ARCHIVE_MEMBERS = 2048
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MIN_FREE_BYTES = 32 * 1024 * 1024
REQUEST_WINDOW_SECONDS = 60
MAX_RECENT_NONCES = 4096

VPSPC_UNITS = (
    "vps-audit.service",
    "vps-audit.timer",
    "vps-audit-bot.service",
    "vps-audit-node-receiver.service",
    "vps-audit-web.service",
    "vps-audit-maintenance.service",
)

ALLOWED_ACTION_FIELDS = {
    "native-update": frozenset({"action", "job_id", "artifact_id", "version", "sha256"}),
    "controller-destroy": frozenset({"action", "job_id", "confirmation_id"}),
}

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{7,63}$")
_ARTIFACT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_RELEASE_VERSION = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[a-f0-9]{32,128}$")


def _add_installed_project_to_path() -> None:
    """Allow the standalone installed helper to load VPSPC ownership checks."""
    for candidate in (INSTALL_ROOT, INSTALL_ROOT / "manager"):
        if (candidate / "vps_audit").is_dir() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))


_add_installed_project_to_path()
from vps_audit.maintenance.ownership import (  # noqa: E402
    DEFAULT_ALLOWED_ROOTS,
    OwnershipManifest,
    build_removal_plan,
)


class UpdateError(RuntimeError):
    """A safe, operational error exposed to the local maintenance client."""


@dataclass(frozen=True)
class NativePaths:
    """Fixed host paths supplied only by the installer or unit tests."""

    install_root: Path = INSTALL_ROOT
    config_path: Path = CONFIG_PATH
    cache_root: Path = CACHE_ROOT
    work_root: Path = WORK_ROOT
    ownership_manifest: Path = OWNERSHIP_PATH
    allowed_roots: Tuple[Path, ...] = DEFAULT_ALLOWED_ROOTS
    enabled_units: Tuple[str, ...] = ()


class SubprocessRunner:
    """Run a fixed argv sequence without ever invoking a shell."""

    def run(self, command: Sequence[str], check: bool = True) -> int:
        result = subprocess.run(list(command), check=False, close_fds=True)
        if check and result.returncode != 0:
            raise UpdateError("required VPSPC service command failed")
        return int(result.returncode)

    def is_enabled(self, unit: str) -> bool:
        return self.run(("systemctl", "is-enabled", "--quiet", unit), check=False) == 0


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return the only JSON representation covered by the HMAC."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_envelope(
    key: Union[str, bytes],
    method: str,
    path: str,
    timestamp: int,
    nonce: str,
    body: Mapping[str, Any],
) -> str:
    secret = key.encode("utf-8") if isinstance(key, str) else key
    material = b"\n".join(
        (
            method.encode("ascii"),
            path.encode("ascii"),
            str(timestamp).encode("ascii"),
            nonce.encode("ascii"),
            canonical_json(body),
        )
    )
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def validate_request(payload: Mapping[str, Any]) -> str:
    """Validate the fixed body schema before dispatching any action."""
    if not isinstance(payload, Mapping):
        raise ValueError("unsupported request fields")
    action = payload.get("action")
    if not isinstance(action, str):
        raise ValueError("unsupported request fields")
    allowed = ALLOWED_ACTION_FIELDS.get(action)
    if allowed is None or frozenset(payload) != allowed:
        raise ValueError("unsupported request fields")
    _validated_identifier(payload["job_id"], "job")
    if action == "native-update":
        artifact_id = payload["artifact_id"]
        version = payload["version"]
        digest = payload["sha256"]
        if not isinstance(artifact_id, str) or not _ARTIFACT_ID.fullmatch(artifact_id):
            raise ValueError("invalid artifact identifier")
        if not isinstance(version, str) or not (_RELEASE_VERSION.fullmatch(version) or version == "edge"):
            raise ValueError("invalid release version")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError("invalid artifact checksum")
    else:
        _validated_identifier(payload["confirmation_id"], "confirmation")
    return action


def _validated_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("invalid " + label + " identifier")
    return value


def _clean_error(error: Union[Exception, str]) -> str:
    value = str(error).replace("\r", " ").replace("\n", " ").strip()
    if not value:
        return "maintenance operation failed"
    return value[:240]


def _safe_rmtree(path: Path, parent: Path) -> None:
    """Remove only a work child derived from a validated job identifier."""
    try:
        resolved_parent = parent.resolve(strict=False)
        resolved_path = path.resolve(strict=False)
        resolved_path.relative_to(resolved_parent)
    except (OSError, ValueError) as exc:
        raise UpdateError("unsafe maintenance workspace") from exc
    if resolved_path == resolved_parent:
        raise UpdateError("unsafe maintenance workspace")
    if path.exists() or path.is_symlink():
        shutil.rmtree(path)


class HostUpdater:
    """The privileged side of the small, authenticated maintenance protocol."""

    def __init__(
        self,
        *,
        paths: NativePaths = NativePaths(),
        key_path: Path = UPDATER_KEY_PATH,
        runner: Optional[Any] = None,
        clock: Callable[[], float] = time.time,
        require_root_owned_files: bool = True,
    ):
        self.paths = paths
        self.key_path = Path(key_path)
        self.runner = runner or SubprocessRunner()
        self.clock = clock
        self.require_root_owned_files = require_root_owned_files
        self._nonces: MutableMapping[str, float] = {}
        self._jobs: MutableMapping[str, Dict[str, Any]] = {}

    def handle(self, payload: Mapping[str, Any], **kwargs: Any) -> Dict[str, Any]:
        """Handle a validated action directly; used by the socket dispatcher/tests."""
        try:
            action = validate_request(payload)
            if action == "native-update":
                return self.native_update(payload, **kwargs)
            if action == "controller-destroy":
                return self.controller_destroy(payload)
            raise ValueError("unsupported request fields")
        except (OSError, ValueError, UpdateError, tarfile.TarError) as exc:
            return {"status": "error", "error": _clean_error(exc)}

    def handle_envelope(self, envelope: Mapping[str, Any], **kwargs: Any) -> Dict[str, Any]:
        """Verify transport metadata and dispatch one fixed protocol endpoint."""
        try:
            method, path, body = self._authenticate_envelope(envelope)
            if method == "GET":
                job_id = _job_id_from_path(path)
                return self.job_status(job_id)
            expected_path = {
                "native-update": "/v1/native-update",
                "controller-destroy": "/v1/controller-destroy",
            }
            action = validate_request(body)
            if method != "POST" or path != expected_path.get(action):
                raise ValueError("unsupported request endpoint")
            return self.handle(body, **kwargs)
        except (OSError, ValueError, UpdateError, tarfile.TarError) as exc:
            return {"status": "error", "error": _clean_error(exc)}

    def native_update(
        self,
        request: Mapping[str, Any],
        *,
        healthcheck: Optional[Callable[[Path], bool]] = None,
    ) -> Dict[str, Any]:
        """Stage a fixed cached archive, atomically switch it, then roll back on failure."""
        validate_request(request)
        job_id = str(request["job_id"])
        result: Dict[str, Any]
        try:
            artifact = self._artifact_path(str(request["artifact_id"]))
            self._verify_artifact(artifact, str(request["sha256"]))
            self._preflight_native(artifact)
        except (OSError, ValueError, UpdateError, tarfile.TarError) as exc:
            result = {"status": "failed", "stage": "preflight", "error": _clean_error(exc)}
            self._record_job(job_id, result)
            return result

        self.paths.work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.paths.work_root, 0o700)
        except OSError as exc:
            result = {"status": "failed", "stage": "workspace", "error": _clean_error(exc)}
            self._record_job(job_id, result)
            return result

        staging = self.paths.work_root / (job_id + ".staging")
        backup = self.paths.work_root / (job_id + ".backup")
        failed = self.paths.work_root / (job_id + ".failed")
        units = self._managed_units()
        moved_old_tree = False
        switched_tree = False
        try:
            self._prepare_staging(staging, artifact)
            self._stop_units(units)
            os.replace(self.paths.install_root, backup)
            moved_old_tree = True
            os.replace(staging, self.paths.install_root)
            switched_tree = True
            self._start_units(units)
            healthy = healthcheck(self.paths.install_root) if healthcheck else self._native_healthcheck(units)
            if not healthy:
                raise UpdateError("native health check failed")
            _safe_rmtree(backup, self.paths.work_root)
            result = {"status": "success", "version": str(request["version"])}
        except (OSError, ValueError, UpdateError, tarfile.TarError) as exc:
            if moved_old_tree:
                try:
                    self._restore_native_tree(backup, failed, switched_tree, units)
                    result = {
                        "status": "rolled_back",
                        "stage": "activation",
                        "error": _clean_error(exc),
                    }
                except (OSError, UpdateError) as rollback_error:
                    result = {
                        "status": "failed",
                        "stage": "rollback",
                        "error": _clean_error(rollback_error),
                    }
            else:
                result = {"status": "failed", "stage": "staging", "error": _clean_error(exc)}
        finally:
            for workspace in (staging, backup, failed):
                try:
                    _safe_rmtree(workspace, self.paths.work_root)
                except (OSError, UpdateError):
                    # An inaccessible residue is safer than widening cleanup.
                    pass
        self._record_job(job_id, result)
        return result

    def controller_destroy(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """Return a fail-closed removal plan.  This method never deletes anything."""
        validate_request(request)
        job_id = str(request["job_id"])
        confirmation_id = _validated_identifier(request["confirmation_id"], "confirmation")
        try:
            manifest = OwnershipManifest.load(
                self.paths.ownership_manifest,
                require_root_owner=self.require_root_owned_files,
            )
            plan = build_removal_plan(manifest, allowed_roots=self.paths.allowed_roots)
            result = {
                "status": "planned",
                "confirmation_id": confirmation_id,
                "removal_plan": plan.to_dict(),
            }
        except (OSError, ValueError) as exc:
            result = {"status": "failed", "stage": "removal_preflight", "error": _clean_error(exc)}
        self._record_job(job_id, result)
        return result

    def job_status(self, job_id: str) -> Dict[str, Any]:
        identifier = _validated_identifier(job_id, "job")
        current = self._jobs.get(identifier)
        if current is None:
            return {"status": "unknown", "job_id": identifier}
        return {"job_id": identifier, **current}

    def _authenticate_envelope(self, envelope: Mapping[str, Any]) -> Tuple[str, str, Mapping[str, Any]]:
        expected = frozenset({"method", "path", "timestamp", "nonce", "body", "signature"})
        if not isinstance(envelope, Mapping) or frozenset(envelope) != expected:
            raise ValueError("unsupported request envelope")
        method = envelope["method"]
        path = envelope["path"]
        timestamp = envelope["timestamp"]
        nonce = envelope["nonce"]
        body = envelope["body"]
        signature = envelope["signature"]
        if method not in {"GET", "POST"} or not isinstance(path, str) or not isinstance(body, Mapping):
            raise ValueError("unsupported request envelope")
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            raise ValueError("invalid request timestamp")
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            raise ValueError("invalid request nonce")
        if not isinstance(signature, str) or not _SHA256.fullmatch(signature):
            raise ValueError("invalid request signature")
        now = int(self.clock())
        if abs(now - timestamp) > REQUEST_WINDOW_SECONDS:
            raise ValueError("request timestamp is outside the replay window")
        key = self._load_key()
        expected_signature = sign_envelope(key, method, path, timestamp, nonce, body)
        if not hmac.compare_digest(expected_signature, signature):
            raise ValueError("invalid request signature")
        self._consume_nonce(nonce, float(now))
        if method == "GET":
            if body or _job_id_from_path(path) is None:
                raise ValueError("unsupported request endpoint")
        elif path not in {"/v1/native-update", "/v1/controller-destroy"}:
            raise ValueError("unsupported request endpoint")
        return method, path, body

    def _load_key(self) -> bytes:
        try:
            descriptor = os.open(self.key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o600:
                raise ValueError("updater key must be a regular file with mode 0600")
            if self.require_root_owned_files and (status.st_uid != 0 or status.st_gid != 0):
                raise ValueError("updater key must be owned by root:root")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                key = handle.read(513).strip()
        except OSError as exc:
            raise ValueError("updater key is unavailable") from exc
        finally:
            if "descriptor" in locals() and descriptor >= 0:
                os.close(descriptor)
        if not 16 <= len(key) <= 512:
            raise ValueError("updater key is invalid")
        return key

    def _consume_nonce(self, nonce: str, now: float) -> None:
        oldest = now - REQUEST_WINDOW_SECONDS
        self._nonces = {value: seen for value, seen in self._nonces.items() if seen >= oldest}
        if nonce in self._nonces:
            raise ValueError("request nonce has already been used")
        if len(self._nonces) >= MAX_RECENT_NONCES:
            raise ValueError("too many recent maintenance requests")
        self._nonces[nonce] = now

    def _artifact_path(self, artifact_id: str) -> Path:
        if not _ARTIFACT_ID.fullmatch(artifact_id):
            raise UpdateError("invalid artifact identifier")
        candidate = self.paths.cache_root / (artifact_id + ".tar.gz")
        try:
            root = self.paths.cache_root.resolve(strict=True)
            target = candidate.resolve(strict=True)
            target.relative_to(root)
            status = target.lstat()
        except (OSError, ValueError) as exc:
            raise UpdateError("cached update artifact is unavailable") from exc
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise UpdateError("cached update artifact is unsafe")
        return target

    def _verify_artifact(self, artifact: Path, expected: str) -> None:
        digest = hashlib.sha256()
        try:
            with artifact.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
        except OSError as exc:
            raise UpdateError("cached update artifact is unavailable") from exc
        if not hmac.compare_digest(digest.hexdigest(), expected):
            raise UpdateError("cached update artifact checksum mismatch")

    def _preflight_native(self, artifact: Path) -> None:
        root = self.paths.install_root
        try:
            status = root.lstat()
        except OSError as exc:
            raise UpdateError("native VPSPC installation is unavailable") from exc
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise UpdateError("native VPSPC installation is unsafe")
        self._read_config()
        self._ensure_same_filesystem(root, self.paths.work_root)
        try:
            required = max(MIN_FREE_BYTES, artifact.stat().st_size * 2 + _tree_size(root))
            free = shutil.disk_usage(root.parent).free
        except OSError as exc:
            raise UpdateError("cannot check native update disk space") from exc
        if free < required:
            raise UpdateError("insufficient disk space for native update")

    def _ensure_same_filesystem(self, install_root: Path, work_root: Path) -> None:
        parent = work_root.parent
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.stat(install_root).st_dev != os.stat(parent).st_dev:
                raise UpdateError("native update workspace must share the install filesystem")
        except OSError as exc:
            raise UpdateError("native update workspace is unavailable") from exc

    def _read_config(self) -> Mapping[str, Any]:
        try:
            descriptor = os.open(self.paths.config_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode):
                raise ValueError("configuration file is unsafe")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                value = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateError("configuration preflight failed") from exc
        finally:
            if "descriptor" in locals() and descriptor >= 0:
                os.close(descriptor)
        if not isinstance(value, Mapping):
            raise UpdateError("configuration preflight failed")
        return value

    def _prepare_staging(self, staging: Path, artifact: Path) -> None:
        _safe_rmtree(staging, self.paths.work_root)
        _copy_tree(self.paths.install_root, staging)
        _safe_extract_archive(artifact, staging)
        package = staging / "vps_audit"
        if not package.is_dir() or not compileall.compile_dir(str(package), quiet=1, force=True):
            raise UpdateError("staged Python compilation failed")

    def _managed_units(self) -> Tuple[str, ...]:
        """Choose only VPSPC services enabled by this fixed local config."""
        if self.paths.enabled_units:
            units = self.paths.enabled_units
        else:
            config = self._read_config()
            candidates = ["vps-audit.service", "vps-audit.timer", "vps-audit-maintenance.service"]
            telegram = config.get("telegram")
            if isinstance(telegram, Mapping) and telegram.get("bot_management_enabled"):
                candidates.append("vps-audit-bot.service")
            node_reporting = config.get("node_reporting")
            if isinstance(node_reporting, Mapping) and node_reporting.get("mode") == "node_reporting":
                candidates.append("vps-audit-node-receiver.service")
            web = config.get("web")
            if isinstance(web, Mapping) and web.get("enabled"):
                candidates.append("vps-audit-web.service")
            units = tuple(unit for unit in candidates if unit == "vps-audit.service" or self._unit_enabled(unit))
        if not units or any(unit not in VPSPC_UNITS for unit in units):
            raise UpdateError("no valid VPSPC service units are configured")
        return tuple(dict.fromkeys(units))

    def _unit_enabled(self, unit: str) -> bool:
        checker = getattr(self.runner, "is_enabled", None)
        if not callable(checker):
            raise UpdateError("host command runner cannot inspect VPSPC service state")
        try:
            return bool(checker(unit))
        except OSError as exc:
            raise UpdateError("cannot inspect VPSPC service state") from exc

    def _stop_units(self, units: Sequence[str]) -> None:
        for unit in units:
            self._run_systemctl("stop", unit)

    def _start_units(self, units: Sequence[str]) -> None:
        for unit in units:
            self._run_systemctl("start", unit)

    def _run_systemctl(self, verb: str, unit: str) -> None:
        if unit not in VPSPC_UNITS or verb not in {"stop", "start", "is-active"}:
            raise UpdateError("invalid VPSPC service operation")
        self.runner.run(("systemctl", verb, unit), check=True)

    def _native_healthcheck(self, units: Sequence[str]) -> bool:
        """Check running services; the periodic one-shot audit service is excluded."""
        try:
            for unit in units:
                if unit == "vps-audit.service":
                    continue
                self._run_systemctl("is-active", unit)
        except (OSError, UpdateError):
            return False
        return True

    def _restore_native_tree(
        self, backup: Path, failed: Path, switched_tree: bool, units: Sequence[str]
    ) -> None:
        try:
            self._stop_units(units)
        except (OSError, UpdateError):
            pass
        try:
            if switched_tree and self.paths.install_root.exists():
                os.replace(self.paths.install_root, failed)
            if backup.exists():
                os.replace(backup, self.paths.install_root)
            else:
                raise UpdateError("native rollback backup is unavailable")
        except OSError as exc:
            raise UpdateError("native update failed and rollback could not be completed") from exc
        self._start_units(units)

    def _record_job(self, job_id: str, result: Mapping[str, Any]) -> None:
        # This is process-local handoff state only.  The maintenance store owns
        # the durable, 24-hour current-job lifecycle and result consumption.
        self._jobs[job_id] = dict(result)


def _job_id_from_path(path: str) -> Optional[str]:
    match = re.fullmatch(r"/v1/jobs/([a-z][a-z0-9_-]{7,63})", path)
    return match.group(1) if match else None


def _tree_size(root: Path) -> int:
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        for name in list(directories):
            candidate = Path(current) / name
            if candidate.is_symlink():
                # A Python venv normally contains a ``lib64`` link.  Preserve
                # it during the atomic tree copy but never recurse through it.
                directories.remove(name)
        for name in files:
            candidate = Path(current) / name
            try:
                status = candidate.lstat()
            except OSError as exc:
                raise UpdateError("cannot inspect native VPSPC installation") from exc
            if stat.S_ISLNK(status.st_mode):
                continue
            if not stat.S_ISREG(status.st_mode):
                raise UpdateError("native VPSPC installation contains an unsafe entry")
            total += status.st_size
    return total


def _copy_tree(source: Path, destination: Path) -> None:
    """Copy a fully regular source tree to an empty same-filesystem staging dir."""
    try:
        source_status = source.lstat()
    except OSError as exc:
        raise UpdateError("native VPSPC installation is unavailable") from exc
    if stat.S_ISLNK(source_status.st_mode) or not stat.S_ISDIR(source_status.st_mode):
        raise UpdateError("native VPSPC installation is unsafe")
    destination.mkdir(mode=0o700, parents=False)
    for current, directories, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        target_directory = destination / relative
        for directory in list(directories):
            source_directory = current_path / directory
            status = source_directory.lstat()
            target = target_directory / directory
            if stat.S_ISLNK(status.st_mode):
                os.symlink(os.readlink(source_directory), target)
                directories.remove(directory)
                continue
            if not stat.S_ISDIR(status.st_mode):
                raise UpdateError("native VPSPC installation contains an unsafe entry")
            target.mkdir(mode=stat.S_IMODE(status.st_mode) & 0o755)
        for filename in files:
            source_file = current_path / filename
            status = source_file.lstat()
            target_file = target_directory / filename
            if stat.S_ISLNK(status.st_mode):
                os.symlink(os.readlink(source_file), target_file)
                continue
            if not stat.S_ISREG(status.st_mode):
                raise UpdateError("native VPSPC installation contains an unsafe entry")
            shutil.copyfile(source_file, target_file, follow_symlinks=False)
            os.chmod(target_file, stat.S_IMODE(status.st_mode) & 0o755)


def _safe_extract_archive(artifact: Path, destination: Path) -> None:
    """Overlay a regular-file-only release archive without tar path escapes."""
    total = 0
    try:
        archive = tarfile.open(artifact, mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise UpdateError("cached update artifact is not a valid gzip archive") from exc
    with archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise UpdateError("cached update artifact has too many files")
        for member in members:
            relative = _safe_archive_name(member.name)
            total += max(0, int(member.size))
            if total > MAX_ARCHIVE_BYTES:
                raise UpdateError("cached update artifact is too large")
            target = destination / relative
            _assert_stage_target(destination, target)
            if member.isdir():
                if target.exists() and not target.is_dir():
                    raise UpdateError("cached update artifact conflicts with staged files")
                target.mkdir(mode=stat.S_IMODE(member.mode) & 0o755, parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise UpdateError("cached update artifact contains an unsafe entry")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if target.exists():
                target_status = target.lstat()
                if stat.S_ISLNK(target_status.st_mode) or not stat.S_ISREG(target_status.st_mode):
                    raise UpdateError("cached update artifact conflicts with staged files")
            source = archive.extractfile(member)
            if source is None:
                raise UpdateError("cached update artifact cannot be read")
            temporary = target.with_name("." + target.name + ".update-" + secrets.token_hex(8))
            try:
                with source, temporary.open("xb") as handle:
                    remaining = member.size
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            raise UpdateError("cached update artifact is truncated")
                        handle.write(block)
                        remaining -= len(block)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, stat.S_IMODE(member.mode) & 0o755)
                os.replace(temporary, target)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass


def _safe_archive_name(value: str) -> Path:
    candidate = PurePosixPath(value)
    if not value or candidate.is_absolute() or ".." in candidate.parts or "\\" in value:
        raise UpdateError("cached update artifact contains an unsafe path")
    clean = Path(*candidate.parts)
    if clean == Path(".") or clean.name in {"", ".", ".."}:
        raise UpdateError("cached update artifact contains an unsafe path")
    return clean


def _assert_stage_target(root: Path, target: Path) -> None:
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise UpdateError("cached update artifact contains an unsafe path") from exc
    current = target.parent
    while current != root:
        if current.exists() and current.is_symlink():
            raise UpdateError("cached update artifact contains an unsafe path")
        current = current.parent


def _recv_request(connection: socket.socket) -> Mapping[str, Any]:
    chunks = []
    total = 0
    while True:
        chunk = connection.recv(8192)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            raise ValueError("maintenance request is too large")
        chunks.append(chunk)
    if not chunks:
        raise ValueError("maintenance request is empty")
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("maintenance request is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ValueError("maintenance request must be an object")
    return value


def _send_response(connection: socket.socket, response: Mapping[str, Any]) -> None:
    body = canonical_json(response)
    if len(body) > MAX_RESPONSE_BYTES:
        body = canonical_json({"status": "error", "error": "maintenance response is too large"})
    connection.sendall(body)


def serve_socket(listener: socket.socket, helper: HostUpdater) -> None:
    """Serve sequentially: the global maintenance lock permits one job anyway."""
    while True:
        connection, _address = listener.accept()
        with connection:
            try:
                response = helper.handle_envelope(_recv_request(connection))
            except (OSError, ValueError, UpdateError) as exc:
                response = {"status": "error", "error": _clean_error(exc)}
            _send_response(connection, response)


def serve_socket_activated(helper: HostUpdater) -> None:
    listen_fds = os.environ.get("LISTEN_FDS")
    if listen_fds != "1":
        raise UpdateError("systemd socket activation is required")
    listener = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        serve_socket(listener, helper)
    finally:
        listener.close()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vpspc-host-updater")
    parser.add_argument("--socket-activated", action="store_true")
    args = parser.parse_args(argv)
    if not args.socket_activated:
        parser.error("the host updater must be started by its systemd socket unit")
    if os.geteuid() != 0:
        print("vpspc-host-updater: root is required", file=sys.stderr)
        return 1
    try:
        serve_socket_activated(HostUpdater())
    except (OSError, UpdateError, ValueError) as exc:
        print("vpspc-host-updater: " + _clean_error(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
