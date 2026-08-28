"""Strict VPSPC ownership manifests and non-mutating removal preflight.

The installer is the only writer of ``ownership.json``.  This module treats
that file as a root-owned trust boundary and deliberately fails closed: a
resource is planned only after its manifest entry, location, marker and
fingerprint all agree.  It never removes files itself.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


MANIFEST_SCHEMA_VERSION = 1
MANAGED_DATA_MARKER = ".vps-audit-managed"
MANAGED_SOURCE_MARKER = ".vpspc-source-managed"
MANAGED_DIRECTORY_MARKER = ".vpspc-managed"
FALCO_LOG_MARKER = ".vps-audit-falco-managed"
VPSPC_FILE_MARKER = "managed-by=vpspc"
FALCO_FILE_MARKER = "managed-by=vps-audit"

DEFAULT_ALLOWED_ROOTS = (
    Path("/opt/vps-audit"),
    Path("/opt/vps-audit-src"),
    Path("/etc/vps-audit"),
    Path("/var/lib/vps-audit"),
    Path("/var/log/vps-audit"),
    Path("/etc/falco"),
    Path("/etc/falcoctl"),
    Path("/etc/systemd/system"),
    Path("/etc/systemd/system/falco-modern-bpf.service.d"),
    Path("/etc/logrotate.d"),
    Path("/etc/apt/sources.list.d"),
    Path("/usr/share/keyrings"),
    Path("/usr/local/bin"),
    Path("/usr/local/lib/vpspc-updater"),
)
DEFAULT_FALCO_SNAPSHOT_ROOTS = (
    Path("/etc/falco"),
    Path("/etc/falcoctl"),
    Path("/etc/systemd/system/falco-modern-bpf.service.d"),
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_KEYS = frozenset({"schema_version", "install_mode", "resources"})
_RESOURCE_KEYS = frozenset({"kind", "path", "marker", "fingerprint"})
_INSTALL_MODES = frozenset({"native", "docker"})
_DIRECTORY_KINDS = frozenset(
    {
        "application",
        "source",
        "config",
        "managed_data",
        "managed_directory",
        "state",
        "report",
        "archive",
        "log_directory",
        "falco_log_directory",
    }
)
_FILE_KINDS = frozenset(
    {
        "managed_file",
        "systemd_unit",
        "cli",
        "falco_rule",
        "falco_override",
        "falco_logrotate",
        "falco_repository",
        "falco_repository_key",
    }
)
_FALCO_KINDS = frozenset(
    {
        "falco_package",
        "falco_rule",
        "falco_override",
        "falco_logrotate",
        "falco_log_directory",
        "falco_repository",
        "falco_repository_key",
    }
)
_ALLOWED_KINDS = _DIRECTORY_KINDS | _FILE_KINDS | _FALCO_KINDS
_FALCO_COMPONENT_MARKERS = frozenset(
    {
        "package",
        "rule",
        "service-override",
        "logrotate",
        "log-directory",
        "repository",
        "repository-key",
        "falcoctl-mask",
    }
)
_RESERVED_PATHS = frozenset(
    {
        Path("/"),
        Path("/root"),
        Path("/home"),
        Path("/etc"),
        Path("/opt"),
        Path("/var"),
        Path("/var/lib"),
        Path("/var/log"),
        Path("/usr"),
        Path("/usr/local"),
        Path("/etc/systemd"),
        Path("/etc/systemd/system"),
    }
)
_THIRD_PARTY_COMPONENTS = frozenset(
    {"xray", "xrayagent", "sing-box", "v2board", "miaomiaowux"}
)
_VPSPC_UNITS = frozenset(
    {
        "vps-audit.service",
        "vps-audit.timer",
        "vps-audit-bot.service",
        "vps-audit-node-receiver.service",
        "vps-audit-web.service",
        "vps-audit-maintenance.service",
        "vps-audit-update-helper.service",
        "vps-audit-update-helper.socket",
    }
)


class FalcoOwnership(str, Enum):
    """Whether a VPSPC-installed Falco package remains exclusively owned."""

    EXCLUSIVE = "exclusive"
    SHARED = "shared"


@dataclass(frozen=True)
class OwnedResource:
    """One installer-created resource and its immutable ownership evidence."""

    kind: str
    path: str
    marker: str
    fingerprint: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "OwnedResource":
        if not isinstance(raw, Mapping):
            raise ValueError("resource must be an object")
        if frozenset(raw) != _RESOURCE_KEYS:
            raise ValueError("resource fields are invalid")
        kind = _required_string(raw["kind"], "resource kind", 64)
        path = _validated_path(raw["path"])
        marker = _required_string(raw["marker"], "resource marker", 96)
        fingerprint = _required_string(raw["fingerprint"], "resource fingerprint", 64)
        resource = cls(kind=kind, path=str(path), marker=marker, fingerprint=fingerprint)
        resource.validate()
        return resource

    def to_dict(self) -> Dict[str, str]:
        return {
            "kind": self.kind,
            "path": self.path,
            "marker": self.marker,
            "fingerprint": self.fingerprint,
        }

    def validate(self) -> None:
        if self.kind not in _ALLOWED_KINDS:
            raise ValueError("unsafe or unowned resource kind")
        path = _validated_path(self.path)
        if not _SHA256.fullmatch(self.fingerprint):
            raise ValueError("resource fingerprint must be a lowercase SHA-256")
        if self.kind in {"managed_data", "managed_directory", "state", "report", "archive", "log_directory"}:
            if self.marker not in {MANAGED_DATA_MARKER, MANAGED_DIRECTORY_MARKER}:
                raise ValueError("unsafe or unowned directory marker")
        elif self.kind in {"application", "config"}:
            if self.marker != MANAGED_DIRECTORY_MARKER:
                raise ValueError("unsafe or unowned application marker")
        elif self.kind == "source":
            if self.marker != MANAGED_SOURCE_MARKER:
                raise ValueError("unsafe or unowned source marker")
        elif self.kind == "falco_log_directory":
            if self.marker != FALCO_LOG_MARKER:
                raise ValueError("unsafe or unowned Falco log marker")
        elif self.kind == "falco_package":
            if self.marker not in _FALCO_COMPONENT_MARKERS:
                raise ValueError("unsafe or unowned Falco component marker")
        elif self.kind in _FALCO_KINDS:
            if self.marker != FALCO_FILE_MARKER:
                raise ValueError("unsafe or unowned Falco file marker")
        elif self.kind in _FILE_KINDS:
            if self.marker != VPSPC_FILE_MARKER:
                raise ValueError("unsafe or unowned file marker")

        # A manifest is never allowed to name known third-party node products.
        if any(part.lower() in _THIRD_PARTY_COMPONENTS for part in path.parts):
            raise ValueError("unsafe or unowned third-party path")


@dataclass(frozen=True)
class OwnershipManifest:
    """The root-owned manifest emitted by the VPSPC installer."""

    schema_version: int
    install_mode: str
    resources: Tuple[OwnedResource, ...]

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "OwnershipManifest":
        if not isinstance(raw, Mapping):
            raise ValueError("ownership manifest must be an object")
        if frozenset(raw) != _MANIFEST_KEYS:
            raise ValueError("ownership manifest fields are invalid")
        if raw["schema_version"] != MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported ownership manifest schema")
        install_mode = _required_string(raw["install_mode"], "install mode", 16)
        if install_mode not in _INSTALL_MODES:
            raise ValueError("unsupported install mode")
        resources_raw = raw["resources"]
        if not isinstance(resources_raw, list) or len(resources_raw) > 128:
            raise ValueError("resources must be a bounded array")
        resources = tuple(OwnedResource.from_dict(value) for value in resources_raw)
        manifest = cls(
            schema_version=MANIFEST_SCHEMA_VERSION,
            install_mode=install_mode,
            resources=resources,
        )
        manifest.validate()
        return manifest

    @classmethod
    def load(cls, path: Path, *, require_root_owner: bool = True) -> "OwnershipManifest":
        """Load a private manifest without following a symlink.

        ``require_root_owner=False`` exists only for non-root unit tests.  The
        installer and host helper must use the secure default.
        """
        manifest_path = Path(path)
        try:
            descriptor = os.open(
                manifest_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as exc:
            raise ValueError("ownership manifest is unavailable") from exc
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode):
                raise ValueError("ownership manifest must be a regular file")
            if stat.S_IMODE(status.st_mode) != 0o600:
                raise ValueError("ownership manifest must have mode 0600")
            if require_root_owner and (status.st_uid != 0 or status.st_gid != 0):
                raise ValueError("ownership manifest must be owned by root:root")
            if status.st_size > 128 * 1024:
                raise ValueError("ownership manifest is too large")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                raw = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("ownership manifest is invalid JSON") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return cls.from_dict(raw)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "install_mode": self.install_mode,
            "resources": [resource.to_dict() for resource in self.resources],
        }

    def validate(self) -> None:
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported ownership manifest schema")
        if self.install_mode not in _INSTALL_MODES:
            raise ValueError("unsupported install mode")
        if not isinstance(self.resources, tuple) or len(self.resources) > 128:
            raise ValueError("resources must be a bounded tuple")
        seen_paths = set()
        for resource in self.resources:
            if not isinstance(resource, OwnedResource):
                raise ValueError("ownership manifest has an invalid resource")
            resource.validate()
            path = str(_validated_path(resource.path))
            if path in seen_paths:
                raise ValueError("ownership manifest has duplicate resource paths")
            seen_paths.add(path)


@dataclass(frozen=True)
class RemovalPlan:
    """A non-mutating, exact resource list for the privileged remover."""

    files: Tuple[Path, ...]
    directories: Tuple[Path, ...]
    units: Tuple[str, ...]
    components: Tuple[str, ...]
    safely_retained: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "files": [str(value) for value in self.files],
            "directories": [str(value) for value in self.directories],
            "units": list(self.units),
            "components": list(self.components),
            "safely_retained": list(self.safely_retained),
        }


def file_fingerprint(path: Path) -> str:
    """Return the SHA-256 of one regular, non-symlink file."""
    target = Path(path)
    digest = hashlib.sha256()
    try:
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            os.close(descriptor)
            raise ValueError("unsafe or unowned path")
        with os.fdopen(descriptor, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ValueError("unsafe or unowned path") from exc
    return digest.hexdigest()


def validate_owned_directory(path: Path, marker: str, allowed_roots: Sequence[Path]) -> Path:
    """Validate a marked VPSPC directory and return its resolved path.

    ``allowed_roots`` comes from installer-validated config, never from the
    Web/Bot API.  Passing a broad system root is refused even in tests.
    """
    target = _resolve_existing(path)
    _ensure_allowed(target, _normalized_allowed_roots(allowed_roots))
    marker_path = target / marker
    _validate_regular_file(marker_path)
    if not _valid_directory_marker(marker, _read_small_text(marker_path)):
        raise ValueError("unsafe or unowned path")
    return target


def classify_falco_ownership(
    resource: OwnedResource,
    *,
    allowed_roots: Sequence[Path] = DEFAULT_ALLOWED_ROOTS,
    snapshot_roots: Sequence[Path] = DEFAULT_FALCO_SNAPSHOT_ROOTS,
    ignored_paths: Sequence[Path] = (),
) -> FalcoOwnership:
    """Classify a managed Falco package without ever treating ambiguity as owned.

    The package resource names the VPSPC ``managed`` directory.  Its marker is
    the existing component file (usually ``package``), while its fingerprint
    is the SHA-256 of ``baseline.sha256``.  Files added after that baseline by
    another tool make Falco shared and preserve the package.
    """
    resource.validate()
    if resource.kind != "falco_package":
        raise ValueError("Falco classification requires a falco_package resource")
    roots = _normalized_allowed_roots(allowed_roots)
    managed_dir = _resolve_existing(Path(resource.path))
    _ensure_allowed(managed_dir, roots)
    if (
        tuple(roots) == _normalized_allowed_roots(DEFAULT_ALLOWED_ROOTS)
        and managed_dir != Path("/etc/vps-audit/managed")
    ):
        raise ValueError("unsafe or unowned path")
    marker_path = managed_dir / resource.marker
    _validate_regular_file(marker_path)
    if _read_small_text(marker_path).strip() != FALCO_FILE_MARKER:
        raise ValueError("unsafe or unowned path")
    baseline = managed_dir / "baseline.sha256"
    _validate_regular_file(baseline)
    if file_fingerprint(baseline) != resource.fingerprint:
        raise ValueError("unsafe or unowned path")

    try:
        expected = _parse_falco_snapshot(baseline, snapshot_roots)
        current = _falco_snapshot(snapshot_roots, ignored_paths)
    except ValueError:
        return FalcoOwnership.SHARED
    return FalcoOwnership.EXCLUSIVE if expected == current else FalcoOwnership.SHARED


def build_removal_plan(
    manifest: OwnershipManifest,
    *,
    allowed_roots: Sequence[Path] = DEFAULT_ALLOWED_ROOTS,
    falco_snapshot_roots: Sequence[Path] = DEFAULT_FALCO_SNAPSHOT_ROOTS,
) -> RemovalPlan:
    """Preflight every resource and produce an exact plan without deleting it."""
    manifest.validate()
    roots = _normalized_allowed_roots(allowed_roots)
    file_paths = set()
    directory_paths = set()
    units = set()
    components = set()
    retained = set()
    falco_packages = []
    falco_owned_files = []

    # All non-package resources are fully preflighted before any package can be
    # classified.  A malformed resource therefore yields no partial plan.
    for resource in manifest.resources:
        if resource.kind == "falco_package":
            falco_packages.append(resource)
            continue
        target = _preflight_resource(resource, roots)
        if resource.kind in _DIRECTORY_KINDS:
            files, directories = _collect_tree(target)
            file_paths.update(files)
            directory_paths.update(directories)
        else:
            file_paths.add(target)
            if resource.kind == "systemd_unit":
                units.add(target.name)
        if resource.kind in _FALCO_KINDS:
            falco_owned_files.append(target)

    for resource in falco_packages:
        classification = classify_falco_ownership(
            resource,
            allowed_roots=roots,
            snapshot_roots=falco_snapshot_roots,
            ignored_paths=tuple(falco_owned_files),
        )
        if classification is FalcoOwnership.EXCLUSIVE:
            components.add("falco-package")
        else:
            retained.add("falco shared or externally changed")

    # Remove nested directories before their parents.  The future executor must
    # revalidate each path immediately before acting on this immutable plan.
    return RemovalPlan(
        files=tuple(sorted(file_paths, key=lambda value: str(value))),
        directories=tuple(sorted(directory_paths, key=lambda value: (-len(value.parts), str(value)))),
        units=tuple(sorted(units)),
        components=tuple(sorted(components)),
        safely_retained=tuple(sorted(retained)),
    )


def write_removal_plan(path: Path, plan: RemovalPlan) -> None:
    """Atomically write a private plan for the installer/host helper."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=destination.name + ".tmp.", dir=str(destination.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(plan.to_dict(), handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _required_string(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(label + " must be a non-empty string")
    if value != value.strip() or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(label + " contains invalid whitespace")
    return value


def _validated_path(value: Any) -> Path:
    raw = _required_string(value, "resource path", 1024)
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe or unowned path")
    normalized = Path(os.path.normpath(str(path)))
    if normalized in _RESERVED_PATHS or any(parent in _RESERVED_PATHS for parent in (normalized,)):
        raise ValueError("unsafe or unowned path")
    if any(part.lower() in _THIRD_PARTY_COMPONENTS for part in normalized.parts):
        raise ValueError("unsafe or unowned third-party path")
    return normalized


def _normalized_allowed_roots(values: Sequence[Path]) -> Tuple[Path, ...]:
    roots = []
    for value in values:
        raw = _required_string(str(value), "allowed root", 1024)
        path = Path(os.path.normpath(raw))
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("unsafe or unowned allowed root")
        if path in _RESERVED_PATHS and path not in DEFAULT_ALLOWED_ROOTS:
            raise ValueError("unsafe or unowned allowed root")
        if any(part.lower() in _THIRD_PARTY_COMPONENTS for part in path.parts):
            raise ValueError("unsafe or unowned allowed root")
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            # Standard roots may not exist before a component is installed; a
            # missing target will still fail when a resource is preflighted.
            resolved = path.resolve(strict=False)
        roots.append(resolved)
    if not roots:
        raise ValueError("unsafe or unowned allowed root")
    return tuple(dict.fromkeys(roots))


def _ensure_allowed(path: Path, allowed_roots: Sequence[Path]) -> None:
    if path in _RESERVED_PATHS or path == Path("/") or Path("/root") in path.parents or Path("/home") in path.parents:
        raise ValueError("unsafe or unowned path")
    if not any(path == root or root in path.parents for root in allowed_roots):
        raise ValueError("unsafe or unowned path")


def _resolve_existing(path: Path) -> Path:
    raw = _validated_path(str(path))
    try:
        status = raw.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise ValueError("unsafe or unowned path")
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise ValueError("unsafe or unowned path") from exc
    if resolved in _RESERVED_PATHS:
        raise ValueError("unsafe or unowned path")
    return resolved


def _validate_regular_file(path: Path) -> None:
    try:
        status = path.lstat()
    except OSError as exc:
        raise ValueError("unsafe or unowned path") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise ValueError("unsafe or unowned path")


def _read_small_text(path: Path) -> str:
    _validate_regular_file(path)
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = handle.read(4097)
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("unsafe or unowned path") from exc
    if len(value) > 4096:
        raise ValueError("unsafe or unowned path")
    return value


def _valid_directory_marker(marker: str, value: str) -> bool:
    if marker not in {MANAGED_DATA_MARKER, MANAGED_SOURCE_MARKER, MANAGED_DIRECTORY_MARKER, FALCO_LOG_MARKER}:
        return False
    # Current installer markers are empty; the next installer revision writes
    # the explicit value.  Both remain tied to the manifest fingerprint.
    return value in {"", VPSPC_FILE_MARKER + "\n", VPSPC_FILE_MARKER}


def _preflight_resource(resource: OwnedResource, allowed_roots: Sequence[Path]) -> Path:
    resource.validate()
    target = _resolve_existing(Path(resource.path))
    _ensure_allowed(target, allowed_roots)
    _validate_kind_location(resource.kind, target, allowed_roots)
    if resource.kind in _DIRECTORY_KINDS:
        try:
            target_status = target.lstat()
        except OSError as exc:
            raise ValueError("unsafe or unowned path") from exc
        if not stat.S_ISDIR(target_status.st_mode):
            raise ValueError("unsafe or unowned path")
        marker_path = target / resource.marker
        _validate_regular_file(marker_path)
        marker_value = _read_small_text(marker_path)
        if not _valid_directory_marker(resource.marker, marker_value):
            raise ValueError("unsafe or unowned path")
        if file_fingerprint(marker_path) != resource.fingerprint:
            raise ValueError("unsafe or unowned path")
        return target

    _validate_regular_file(target)
    value = _read_small_text(target)
    if resource.marker not in value:
        raise ValueError("unsafe or unowned path")
    if file_fingerprint(target) != resource.fingerprint:
        raise ValueError("unsafe or unowned path")
    return target


def _collect_tree(root: Path) -> Tuple[Tuple[Path, ...], Tuple[Path, ...]]:
    files = []
    directories = []

    def collect(directory: Path) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda value: value.name)
        except OSError as exc:
            raise ValueError("unsafe or unowned path") from exc
        for entry in entries:
            try:
                status = entry.lstat()
            except OSError as exc:
                raise ValueError("unsafe or unowned path") from exc
            if stat.S_ISLNK(status.st_mode):
                raise ValueError("unsafe or unowned path")
            if stat.S_ISDIR(status.st_mode):
                collect(entry)
                directories.append(entry)
            elif stat.S_ISREG(status.st_mode):
                files.append(entry)
            else:
                raise ValueError("unsafe or unowned path")

    collect(root)
    directories.append(root)
    return tuple(files), tuple(directories)


def _parse_falco_snapshot(path: Path, snapshot_roots: Sequence[Path]) -> Tuple[Tuple[str, str], ...]:
    roots = _normalized_allowed_roots(snapshot_roots)
    values = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("invalid Falco baseline") from exc
    for line in lines:
        try:
            digest, raw_path = line.split("  ", 1)
        except ValueError as exc:
            raise ValueError("invalid Falco baseline") from exc
        if not _SHA256.fullmatch(digest):
            raise ValueError("invalid Falco baseline")
        target = _resolve_existing(Path(raw_path))
        _ensure_allowed(target, roots)
        if not any(target == root or root in target.parents for root in roots):
            raise ValueError("invalid Falco baseline")
        values.append((digest, str(target)))
    if values != sorted(values, key=lambda value: value[1]) or len(values) != len(set(values)):
        raise ValueError("invalid Falco baseline")
    return tuple(values)


def _falco_snapshot(
    snapshot_roots: Sequence[Path], ignored_paths: Sequence[Path]
) -> Tuple[Tuple[str, str], ...]:
    roots = _normalized_allowed_roots(snapshot_roots)
    ignored = {str(_resolve_existing(Path(path))) for path in ignored_paths if Path(path).exists()}
    values = []
    found_root = False
    for root in roots:
        if not root.is_dir():
            continue
        found_root = True
        for files, _directories in (_collect_tree(root),):
            for path in files:
                if str(path) not in ignored:
                    values.append((file_fingerprint(path), str(path)))
    if not found_root:
        raise ValueError("Falco snapshot roots are unavailable")
    return tuple(sorted(values, key=lambda value: value[1]))


def _validate_kind_location(kind: str, target: Path, allowed_roots: Sequence[Path]) -> None:
    """Apply exact production paths without making temporary tests impractical."""
    if kind == "application" and target != Path("/opt/vps-audit"):
        raise ValueError("unsafe or unowned path")
    if kind == "source" and target != Path("/opt/vps-audit-src"):
        raise ValueError("unsafe or unowned path")
    if kind == "config" and target != Path("/etc/vps-audit"):
        raise ValueError("unsafe or unowned path")
    if kind == "log_directory" and target != Path("/var/log/vps-audit"):
        raise ValueError("unsafe or unowned path")
    if kind == "systemd_unit" and (
        target.parent != Path("/etc/systemd/system") or target.name not in _VPSPC_UNITS
    ):
        raise ValueError("unsafe or unowned path")
    if kind == "cli" and target != Path("/usr/local/bin/vpspc"):
        raise ValueError("unsafe or unowned path")
    if tuple(allowed_roots) != _normalized_allowed_roots(DEFAULT_ALLOWED_ROOTS):
        return
    fixed_falco_paths = {
        "falco_rule": Path("/etc/falco/rules.d/vps-audit-rules.yaml"),
        "falco_override": Path("/etc/systemd/system/falco-modern-bpf.service.d/vps-audit.conf"),
        "falco_logrotate": Path("/etc/logrotate.d/vps-audit-falco"),
        "falco_log_directory": Path("/var/log/vps-audit"),
        "falco_repository": Path("/etc/apt/sources.list.d/falcosecurity.list"),
        "falco_repository_key": Path("/usr/share/keyrings/falco-archive-keyring.gpg"),
    }
    if kind in fixed_falco_paths and target != fixed_falco_paths[kind]:
        raise ValueError("unsafe or unowned path")


def _parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a verified VPSPC removal plan")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allowed-root", action="append", type=Path, default=[])
    parser.add_argument("--falco-snapshot-root", action="append", type=Path, default=[])
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_arguments(argv)
    manifest = OwnershipManifest.load(args.manifest)
    roots = tuple(args.allowed_root) or DEFAULT_ALLOWED_ROOTS
    falco_roots = tuple(args.falco_snapshot_root) or DEFAULT_FALCO_SNAPSHOT_ROOTS
    plan = build_removal_plan(manifest, allowed_roots=roots, falco_snapshot_roots=falco_roots)
    write_removal_plan(args.output, plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
