#!/usr/bin/env python3
# managed-by=vpspc
"""Restricted root helper for VPSPC controller maintenance.

The Web, Telegram bot, and maintenance service never receive a shell, a
filesystem path, or a download URL from this helper.  They can only submit a
short, HMAC-authenticated request over the root-owned Unix socket.  Artifact
selection has already happened in the unprivileged coordinator; this process
only opens a named artifact from its fixed local cache and verifies it again.

The helper owns the last step of controller lifecycle operations. In
particular, it never stops the maintenance coordinator while that coordinator
is still recording an update result, and it only removes runtime-critical
state after its authenticated response has been sent.
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
HELPER_JOB_ROOT = Path("/run/vpspc/updater-jobs")
DOCKER_COMPOSE_PATH = Path("/etc/vps-audit/docker-compose.yml")
DOCKER_ENV_PATH = Path("/etc/vps-audit/docker.env")
DOCKER_METADATA_PATH = Path("/etc/vps-audit/docker-maintenance.json")
DOCKER_IMAGE_REPOSITORY = "ghcr.io/allen0039/vpspc"
DOCKER_PROJECT = "vpspc"

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
    "maintenance-restart": frozenset({"action", "job_id"}),
    "controller-destroy": frozenset({"action", "job_id", "confirmation_id"}),
    "docker-update": frozenset({"action", "job_id", "digest", "version"}),
    "docker-destroy": frozenset({"action", "job_id", "confirmation_id"}),
}

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{7,63}$")
_ARTIFACT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_RELEASE_VERSION = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOCKER_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE = re.compile(r"^[a-f0-9]{32,128}$")


def _add_installed_project_to_path() -> None:
    """Allow the standalone installed helper to load VPSPC ownership checks."""
    helper_root = Path(__file__).resolve().parent
    for candidate in (helper_root, INSTALL_ROOT, INSTALL_ROOT / "manager"):
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
    docker_compose_path: Path = DOCKER_COMPOSE_PATH
    docker_env_path: Path = DOCKER_ENV_PATH
    docker_metadata_path: Path = DOCKER_METADATA_PATH
    helper_job_root: Path = HELPER_JOB_ROOT


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
    elif action in {"controller-destroy", "docker-destroy"}:
        _validated_identifier(payload["confirmation_id"], "confirmation")
    elif action == "maintenance-restart":
        pass
    else:
        digest = payload["digest"]
        version = payload["version"]
        if not isinstance(digest, str) or not _DOCKER_DIGEST.fullmatch(digest):
            raise ValueError("invalid Docker image digest")
        if not isinstance(version, str) or not (_RELEASE_VERSION.fullmatch(version) or version == "edge"):
            raise ValueError("invalid release version")
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
        self._deferred_units: Tuple[str, ...] = ()
        self._deferred_files: Tuple[Path, ...] = ()
        self._deferred_directories: Tuple[Path, ...] = ()
        self._deferred_maintenance_restarts = 0
        self._clear_helper_job_root_after_response = False

    def handle(self, payload: Mapping[str, Any], **kwargs: Any) -> Dict[str, Any]:
        """Handle a validated action directly; used by the socket dispatcher/tests."""
        try:
            action = validate_request(payload)
            if action == "native-update":
                return self.native_update(payload, **kwargs)
            if action == "maintenance-restart":
                return self.maintenance_restart(payload)
            if action == "controller-destroy":
                return self.controller_destroy(payload)
            if action == "docker-update":
                return self.docker_update(payload)
            if action == "docker-destroy":
                return self.docker_destroy(payload)
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
                "maintenance-restart": "/v1/maintenance-restart",
                "controller-destroy": "/v1/controller-destroy",
                "docker-update": "/v1/docker-update",
                "docker-destroy": "/v1/docker-destroy",
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

    def maintenance_restart(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """Restart the native coordinator only after it persisted one update.

        This is a named, authenticated action rather than a generic systemd
        endpoint. It may only follow a successful result from this helper, so
        Web and Telegram cannot use it to restart arbitrary host services.
        """
        validate_request(request)
        job_id = str(request["job_id"])
        current = self.job_status(job_id)
        if current.get("status") != "success":
            raise UpdateError("native controller update is not ready for maintenance restart")
        self._deferred_maintenance_restarts += 1
        return {"status": "accepted", "job_id": job_id}

    def controller_destroy(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """Remove only resources that still match the installed ownership manifest."""
        validate_request(request)
        job_id = str(request["job_id"])
        confirmation_id = _validated_identifier(request["confirmation_id"], "confirmation")
        try:
            plan = self._verified_removal_plan("native")
            removed = self._execute_removal_plan(plan, defer_runtime_state=True)
            result = {
                "status": "success",
                "confirmation_id": confirmation_id,
                "removed_paths_count": removed,
                "safely_retained": list(plan.safely_retained),
            }
        except (OSError, ValueError, UpdateError) as exc:
            self._discard_deferred_cleanup()
            result = {"status": "failed", "stage": "removal_preflight", "error": _clean_error(exc)}
        try:
            self._record_job(job_id, result)
        except UpdateError as exc:
            self._discard_deferred_cleanup()
            result = {"status": "failed", "stage": "result_record", "error": _clean_error(exc)}
        return result

    def docker_update(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """Pin the locally managed Compose stack to one immutable GHCR digest.

        The caller cannot choose a Compose directory, Docker project, service,
        image repository, or command.  The host helper owns that small set of
        metadata, which keeps the Docker socket out of Web and Telegram.
        """
        validate_request(request)
        job_id = str(request["job_id"])
        self._record_job(job_id, {"status": "running", "stage": "activation"})
        previous_env = ""
        changed = False
        try:
            metadata = self._docker_metadata()
            image = self._docker_image_ref(str(request["digest"]))
            previous_env = self._read_regular_text(self.paths.docker_env_path, 32 * 1024)
            old_image = self._docker_env_image(previous_env)
            self._write_docker_env_image(previous_env, image)
            changed = True
            base = self._docker_compose_command(metadata)
            self._run_docker((*base, "pull"))
            self._run_docker((*base, "up", "-d", "--wait", "--remove-orphans", *metadata["services"]))
            if old_image and old_image != image and old_image.startswith(DOCKER_IMAGE_REPOSITORY + "@"):
                self._run_docker(("docker", "image", "rm", old_image), check=False)
            result = {"status": "success", "version": str(request["version"])}
        except (OSError, ValueError, UpdateError) as exc:
            if changed:
                try:
                    self._write_regular_text(self.paths.docker_env_path, previous_env)
                    metadata = self._docker_metadata()
                    self._run_docker((*self._docker_compose_command(metadata), "up", "-d", "--wait", "--remove-orphans", *metadata["services"]))
                    result = {"status": "rolled_back", "stage": "activation", "error": _clean_error(exc)}
                except (OSError, ValueError, UpdateError) as rollback_error:
                    result = {"status": "failed", "stage": "rollback", "error": _clean_error(rollback_error)}
            else:
                result = {"status": "failed", "stage": "preflight", "error": _clean_error(exc)}
        self._record_job(job_id, result)
        return result

    def docker_destroy(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """Tear down only the fixed VPSPC Compose project, then owned files."""
        validate_request(request)
        job_id = str(request["job_id"])
        confirmation_id = _validated_identifier(request["confirmation_id"], "confirmation")
        try:
            metadata = self._docker_metadata()
            plan = self._verified_removal_plan("docker")
            self._run_docker((*self._docker_compose_command(metadata), "down", "--volumes", "--remove-orphans"))
            removed = self._execute_removal_plan(plan, defer_runtime_state=True)
            result = {
                "status": "success",
                "confirmation_id": confirmation_id,
                "removed_paths_count": removed,
                "safely_retained": list(plan.safely_retained),
            }
        except (OSError, ValueError, UpdateError) as exc:
            self._discard_deferred_cleanup()
            result = {"status": "failed", "stage": "removal_preflight", "error": _clean_error(exc)}
        try:
            self._record_job(job_id, result)
        except UpdateError as exc:
            self._discard_deferred_cleanup()
            result = {"status": "failed", "stage": "result_record", "error": _clean_error(exc)}
        return result

    def job_status(self, job_id: str) -> Dict[str, Any]:
        identifier = _validated_identifier(job_id, "job")
        current = self._jobs.get(identifier)
        if current is None:
            current = self._read_persisted_job(identifier)
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
        elif path not in {
            "/v1/native-update",
            "/v1/maintenance-restart",
            "/v1/controller-destroy",
            "/v1/docker-update",
            "/v1/docker-destroy",
        }:
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
            units = tuple(unit for unit in self.paths.enabled_units if unit != "vps-audit-maintenance.service")
        else:
            config = self._read_config()
            # Keep the coordinator alive while it writes the update result to
            # its state file. It is restarted through the fixed deferred
            # action once that write has completed.
            candidates = ["vps-audit.service", "vps-audit.timer"]
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
        if unit not in VPSPC_UNITS or verb not in {"stop", "start", "restart", "is-active"}:
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

    def _verified_removal_plan(self, expected_mode: str):
        manifest = OwnershipManifest.load(
            self.paths.ownership_manifest,
            require_root_owner=self.require_root_owned_files,
        )
        if manifest.install_mode != expected_mode:
            raise UpdateError("ownership manifest installation mode does not match this operation")
        return build_removal_plan(manifest, allowed_roots=self.paths.allowed_roots)

    def _execute_removal_plan(self, plan: Any, *, defer_runtime_state: bool = False) -> int:
        """Execute an already revalidated exact plan without broad cleanup.

        ``RemovalPlan`` is deliberately produced immediately before this call.
        We still refuse symlinks at removal time and only invoke fixed
        ``systemctl`` verbs for the enumerated VPSPC units.  There is no
        recursive command, wildcard, Docker prune, or caller-provided path.
        """
        deferred_units = {
            "vps-audit-maintenance.service",
            "vps-audit-update-helper.service",
            "vps-audit-update-helper.socket",
        }
        immediate_units = [unit for unit in plan.units if unit not in deferred_units]
        final_units = tuple(unit for unit in plan.units if unit in deferred_units)
        deferred_roots = self._runtime_state_roots(plan) if defer_runtime_state else ()
        immediate_files, final_files = self._split_deferred_paths(plan.files, deferred_roots)
        immediate_directories, final_directories = self._split_deferred_paths(plan.directories, deferred_roots)
        for unit in immediate_units:
            if unit not in VPSPC_UNITS and unit != "vps-audit-update-helper.socket":
                raise UpdateError("removal plan names an invalid VPSPC unit")
            self.runner.run(("systemctl", "disable", "--now", unit), check=False)

        removed = 0
        for path in immediate_files:
            target = Path(path)
            try:
                status = target.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
                raise UpdateError("owned resource changed before removal")
            target.unlink()
            removed += 1
        for path in immediate_directories:
            target = Path(path)
            try:
                status = target.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                raise UpdateError("owned resource changed before removal")
            try:
                target.rmdir()
            except OSError as exc:
                raise UpdateError("owned directory changed before removal") from exc
            removed += 1
        for component in plan.components:
            if component != "falco-package":
                raise UpdateError("removal plan names an unsupported component")
            # This package was classified as exclusively VPSPC-owned by the
            # manifest's baseline snapshot.  Do not touch repositories or
            # packages when that proof no longer holds.
            self.runner.run(("apt-get", "purge", "-y", "falco"), check=True)
        self.runner.run(("systemctl", "daemon-reload"), check=False)
        # Do not make the controller unable to report a failure half way
        # through removal. Only after all immediate resources are gone do we
        # arm the state/config and self-service cleanup for post-response work.
        self._deferred_units = final_units
        self._deferred_files = final_files
        self._deferred_directories = final_directories
        self._clear_helper_job_root_after_response = True
        return removed

    def finalize_deferred_cleanup(self) -> None:
        """Run only after the authenticated response has been written."""
        restarts, self._deferred_maintenance_restarts = self._deferred_maintenance_restarts, 0
        for _ in range(restarts):
            self._run_systemctl("restart", "vps-audit-maintenance.service")

        files, self._deferred_files = self._deferred_files, ()
        directories, self._deferred_directories = self._deferred_directories, ()
        units, self._deferred_units = self._deferred_units, ()
        clear_jobs, self._clear_helper_job_root_after_response = self._clear_helper_job_root_after_response, False
        for target in files:
            self._unlink_verified_file(target)
        for target in directories:
            self._rmdir_verified(target)
        if clear_jobs:
            self._clear_helper_job_root()
        for unit in units:
            try:
                self.runner.run(("systemctl", "disable", "--now", unit), check=False)
            except OSError:
                # At this point the remaining process is itself being removed;
                # never widen the operation to recover a systemd error.
                pass

    def _discard_deferred_cleanup(self) -> None:
        self._deferred_files = ()
        self._deferred_directories = ()
        self._deferred_units = ()
        self._clear_helper_job_root_after_response = False

    def _runtime_state_roots(self, plan: Any) -> Tuple[Path, ...]:
        """Return only manifest-planned roots needed for final result delivery."""
        candidates = [self.paths.config_path.parent]
        try:
            config = self._read_config()
            configured_state = config.get("state_dir")
            if isinstance(configured_state, str) and configured_state:
                candidates.append(Path(configured_state))
        except UpdateError:
            # The config directory still keeps the response path alive. The
            # manifest preflight rejects unsafe resources before any removal.
            pass
        plan_directories = {Path(value) for value in plan.directories}
        roots = []
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if resolved in plan_directories:
                roots.append(resolved)
        return tuple(dict.fromkeys(roots))

    @staticmethod
    def _split_deferred_paths(paths: Sequence[Path], roots: Sequence[Path]) -> Tuple[Tuple[Path, ...], Tuple[Path, ...]]:
        immediate = []
        deferred = []
        for raw in paths:
            path = Path(raw)
            if any(path == root or root in path.parents for root in roots):
                deferred.append(path)
            else:
                immediate.append(path)
        return tuple(immediate), tuple(deferred)

    @staticmethod
    def _unlink_verified_file(target: Path) -> None:
        try:
            status = target.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise UpdateError("owned resource changed before final removal")
        target.unlink()

    @staticmethod
    def _rmdir_verified(target: Path) -> None:
        try:
            status = target.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise UpdateError("owned resource changed before final removal")
        try:
            target.rmdir()
        except OSError as exc:
            raise UpdateError("owned directory changed before final removal") from exc

    def _clear_helper_job_root(self) -> None:
        root = self.paths.helper_job_root
        try:
            if not root.exists() and not root.is_symlink():
                return
            _safe_rmtree(root, root.parent)
        except (OSError, UpdateError) as exc:
            raise UpdateError("cannot clear VPSPC maintenance result") from exc

    def _docker_metadata(self) -> Dict[str, Any]:
        raw = self._read_regular_text(self.paths.docker_metadata_path, 16 * 1024)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise UpdateError("Docker maintenance metadata is invalid") from exc
        if not isinstance(value, Mapping) or frozenset(value) != {"schema_version", "project", "services"}:
            raise UpdateError("Docker maintenance metadata is invalid")
        if value.get("schema_version") != 1 or value.get("project") != DOCKER_PROJECT:
            raise UpdateError("Docker maintenance metadata is invalid")
        services = value.get("services")
        if not isinstance(services, list) or not services or len(services) > 8:
            raise UpdateError("Docker maintenance metadata is invalid")
        allowed = {"audit", "web", "bot", "receiver", "maintenance"}
        if any(not isinstance(item, str) or item not in allowed for item in services) or len(set(services)) != len(services):
            raise UpdateError("Docker maintenance metadata is invalid")
        self._read_regular_text(self.paths.docker_compose_path, 512 * 1024)
        return {"services": tuple(services)}

    def _docker_compose_command(self, metadata: Mapping[str, Any]) -> Tuple[str, ...]:
        services = metadata.get("services")
        if not isinstance(services, tuple):
            raise UpdateError("Docker maintenance metadata is invalid")
        return (
            "docker",
            "compose",
            "--project-name",
            DOCKER_PROJECT,
            "--env-file",
            str(self.paths.docker_env_path),
            "--file",
            str(self.paths.docker_compose_path),
        )

    @staticmethod
    def _docker_image_ref(digest: str) -> str:
        if not _DOCKER_DIGEST.fullmatch(digest):
            raise UpdateError("invalid Docker image digest")
        return DOCKER_IMAGE_REPOSITORY + "@" + digest

    @staticmethod
    def _docker_env_image(value: str) -> str:
        matches = [line.split("=", 1)[1] for line in value.splitlines() if line.startswith("AUDIT_IMAGE=")]
        if len(matches) != 1 or not matches[0]:
            raise UpdateError("Docker image environment is invalid")
        return matches[0]

    def _write_docker_env_image(self, previous: str, image: str) -> None:
        self._docker_env_image(previous)
        lines = ["AUDIT_IMAGE=" + image if line.startswith("AUDIT_IMAGE=") else line for line in previous.splitlines()]
        self._write_regular_text(self.paths.docker_env_path, "\n".join(lines) + "\n")

    @staticmethod
    def _read_regular_text(path: Path, maximum: int) -> str:
        target = Path(path)
        try:
            descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_size > maximum:
                raise UpdateError("managed maintenance metadata is unsafe")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                return handle.read()
        except (OSError, UnicodeDecodeError) as exc:
            raise UpdateError("managed maintenance metadata is unavailable") from exc
        finally:
            if "descriptor" in locals() and descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _write_regular_text(path: Path, value: str) -> None:
        target = Path(path)
        try:
            status = target.lstat()
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
                raise UpdateError("managed maintenance metadata is unsafe")
            temporary = target.with_name(target.name + ".tmp." + secrets.token_hex(8))
            with temporary.open("x", encoding="utf-8") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, stat.S_IMODE(status.st_mode))
            os.replace(temporary, target)
        except OSError as exc:
            raise UpdateError("managed maintenance metadata cannot be updated") from exc
        finally:
            try:
                temporary.unlink()  # type: ignore[name-defined]
            except (FileNotFoundError, UnboundLocalError):
                pass

    def _run_docker(self, command: Sequence[str], *, check: bool = True) -> int:
        valid = (
            tuple(command[:2]) in {("docker", "pull"), ("docker", "compose")}
            or tuple(command[:3]) == ("docker", "image", "rm")
        )
        if not valid:
            raise UpdateError("invalid Docker maintenance command")
        try:
            return int(self.runner.run(tuple(command), check=check))
        except OSError as exc:
            raise UpdateError("Docker maintenance command failed") from exc

    def _record_job(self, job_id: str, result: Mapping[str, Any]) -> None:
        # Docker can restart the requesting maintenance container during the
        # Compose activation.  Keep a tiny root-only result on the host so the
        # replacement container observes the completed job instead of issuing
        # the update again.  This is not an audit history and is pruned by age.
        saved = dict(result)
        self._jobs[job_id] = saved
        root = self.paths.helper_job_root
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(root, 0o700)
            target = root / (job_id + ".json")
            temporary = target.with_name(target.name + ".tmp." + secrets.token_hex(8))
            with temporary.open("x", encoding="utf-8") as handle:
                json.dump(saved, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
            self._purge_persisted_jobs(root)
        except OSError as exc:
            raise UpdateError("cannot persist maintenance result") from exc
        finally:
            try:
                temporary.unlink()  # type: ignore[name-defined]
            except (FileNotFoundError, UnboundLocalError):
                pass

    def _read_persisted_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        root = self.paths.helper_job_root
        target = root / (job_id + ".json")
        try:
            root_status = root.lstat()
            target_status = target.lstat()
            if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
                raise UpdateError("maintenance result store is unsafe")
            if not stat.S_ISREG(target_status.st_mode) or stat.S_ISLNK(target_status.st_mode) or target_status.st_size > 64 * 1024:
                raise UpdateError("maintenance result is unsafe")
            value = json.loads(target.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateError("maintenance result is unavailable") from exc
        if not isinstance(value, dict) or not isinstance(value.get("status"), str):
            raise UpdateError("maintenance result is invalid")
        return value

    @staticmethod
    def _purge_persisted_jobs(root: Path) -> None:
        cutoff = time.time() - 24 * 60 * 60
        for candidate in root.glob("job_*.json"):
            try:
                status = candidate.lstat()
                if stat.S_ISREG(status.st_mode) and not stat.S_ISLNK(status.st_mode) and status.st_mtime < cutoff:
                    candidate.unlink()
            except OSError:
                # A stale file is safer than broad cleanup under /run.
                continue


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
        raw_names = [_safe_archive_name(member.name) for member in members]
        bundled_root = all(name.parts and name.parts[0] == "vpspc" for name in raw_names)
        for member in members:
            relative = _safe_archive_name(member.name)
            if bundled_root:
                if len(relative.parts) == 1:
                    if not member.isdir():
                        raise UpdateError("cached update artifact has an invalid package root")
                    continue
                relative = Path(*relative.parts[1:])
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
            try:
                _send_response(connection, response)
            finally:
                # A full controller destroy may include this helper's own
                # socket unit, and Docker will stop the requesting container.
                # Run the fixed final cleanup even when that peer has already
                # gone away; no arbitrary cleanup is scheduled here.
                helper.finalize_deferred_cleanup()


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
