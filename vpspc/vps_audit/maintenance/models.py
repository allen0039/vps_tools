"""Immutable, validated value types for managed maintenance operations.

The release manifest is a trust boundary.  This module intentionally accepts
only the schema emitted by the VPSPC release builder; source-host restrictions
and download validation are applied by the release client in a later layer.
"""

from dataclasses import dataclass
import re
from typing import Any, Mapping, Optional, Tuple
from urllib.parse import urlsplit


RELEASE_VERSION = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
_PACKAGE_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_MANIFEST_KEYS = frozenset({
    "schema_version",
    "version",
    "channel",
    "source_revision",
    "controller_protocol",
    "node_protocol",
    "config_schema_min",
    "config_schema_max",
    "controller_upgrade_from",
    "controller_downgrade_from",
    "node_upgrade_from",
    "node_downgrade_from",
    "artifacts",
    "docker_digest",
})
_ARTIFACT_KEYS = frozenset({"name", "url", "sha256", "size"})
_ARTIFACT_COMPONENTS = frozenset({"controller", "node"})
_MAX_ARTIFACT_SIZE = 2 * 1024 * 1024 * 1024


class CompatibilityError(ValueError):
    """A compatibility preflight failure that is safe to present to operators."""

    stage = "compatibility_preflight"

    def __init__(self, reason: str):
        super().__init__("incompatible: " + reason)


def parse_release_version(value: str) -> Tuple[int, int, int]:
    """Parse only immutable GitHub Release-style ``vMAJOR.MINOR.PATCH`` tags."""
    if not isinstance(value, str):
        raise ValueError("release version must use vMAJOR.MINOR.PATCH")
    match = RELEASE_VERSION.fullmatch(value.strip())
    if not match:
        raise ValueError("release version must use vMAJOR.MINOR.PATCH")
    return tuple(int(part) for part in match.groups())


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(label + " must be an object")
    if not all(isinstance(key, str) for key in value):
        raise ValueError(label + " keys must be strings")
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset, label: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise ValueError(label + " fields are invalid: " + "; ".join(details))


def _require_string(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(label + " must be a non-empty string")
    if value != value.strip() or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(label + " contains invalid whitespace")
    return value


def _require_positive_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(label + " must be an integer in range")
    return value


def _parse_manifest_version(value: Any, label: str) -> str:
    version = _require_string(value, label, 32)
    parse_release_version(version)
    return version


@dataclass(frozen=True)
class ArtifactSpec:
    """One named, checksummed, size-bounded release artifact."""

    name: str
    url: str
    sha256: str
    size: int

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], label: str) -> "ArtifactSpec":
        value = _require_mapping(raw, label)
        _require_exact_keys(value, _ARTIFACT_KEYS, label)

        name = _require_string(value["name"], label + ".name", 128)
        if not _ARTIFACT_NAME.fullmatch(name):
            raise ValueError(label + ".name must be a simple artifact filename")

        url = _require_string(value["url"], label + ".url", 2048)
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise ValueError(label + ".url must be an HTTPS URL without credentials or fragments")

        sha256 = _require_string(value["sha256"], label + ".sha256", 64)
        if not _SHA256.fullmatch(sha256):
            raise ValueError(label + ".sha256 must be 64 lowercase hexadecimal characters")

        size = _require_positive_int(value["size"], label + ".size", _MAX_ARTIFACT_SIZE)
        return cls(name=name, url=url, sha256=sha256, size=size)


@dataclass(frozen=True)
class ReleaseManifest:
    """Validated immutable metadata for one stable or edge VPSPC release."""

    schema_version: int
    version: str
    channel: str
    source_revision: str
    controller_protocol: int
    node_protocol: int
    config_schema_min: int
    config_schema_max: int
    controller_upgrade_from: str
    controller_downgrade_from: str
    node_upgrade_from: str
    node_downgrade_from: str
    controller: ArtifactSpec
    node: ArtifactSpec
    docker_digest: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ReleaseManifest":
        value = _require_mapping(raw, "release manifest")
        _require_exact_keys(value, _MANIFEST_KEYS, "release manifest")

        schema_version = _require_positive_int(value["schema_version"], "schema_version", 1)
        if schema_version != 1:
            raise ValueError("unsupported release manifest schema")

        channel = _require_string(value["channel"], "channel", 16)
        if channel not in {"stable", "edge"}:
            raise ValueError("channel must be stable or edge")

        version = _require_string(value["version"], "version", 32)
        if channel == "stable":
            parse_release_version(version)
        elif version != "edge":
            raise ValueError("edge release version must be edge")

        source_revision = _require_string(value["source_revision"], "source_revision", 40)
        if not _SOURCE_REVISION.fullmatch(source_revision):
            raise ValueError("source_revision must be a 40-character lowercase Git revision")

        controller_protocol = _require_positive_int(
            value["controller_protocol"], "controller_protocol", 2 ** 31 - 1
        )
        node_protocol = _require_positive_int(
            value["node_protocol"], "node_protocol", 2 ** 31 - 1
        )
        config_schema_min = _require_positive_int(
            value["config_schema_min"], "config_schema_min", 2 ** 31 - 1
        )
        config_schema_max = _require_positive_int(
            value["config_schema_max"], "config_schema_max", 2 ** 31 - 1
        )
        if config_schema_min > config_schema_max:
            raise ValueError("config schema minimum cannot exceed maximum")

        controller_upgrade_from = _parse_manifest_version(
            value["controller_upgrade_from"], "controller_upgrade_from"
        )
        controller_downgrade_from = _parse_manifest_version(
            value["controller_downgrade_from"], "controller_downgrade_from"
        )
        node_upgrade_from = _parse_manifest_version(value["node_upgrade_from"], "node_upgrade_from")
        node_downgrade_from = _parse_manifest_version(
            value["node_downgrade_from"], "node_downgrade_from"
        )

        artifacts = _require_mapping(value["artifacts"], "artifacts")
        _require_exact_keys(artifacts, _ARTIFACT_COMPONENTS, "artifacts")
        controller = ArtifactSpec.from_dict(artifacts["controller"], "artifacts.controller")
        node = ArtifactSpec.from_dict(artifacts["node"], "artifacts.node")

        docker_digest = _require_string(value["docker_digest"], "docker_digest", 71)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", docker_digest):
            raise ValueError("docker_digest must be an immutable sha256 digest")

        return cls(
            schema_version=schema_version,
            version=version,
            channel=channel,
            source_revision=source_revision,
            controller_protocol=controller_protocol,
            node_protocol=node_protocol,
            config_schema_min=config_schema_min,
            config_schema_max=config_schema_max,
            controller_upgrade_from=controller_upgrade_from,
            controller_downgrade_from=controller_downgrade_from,
            node_upgrade_from=node_upgrade_from,
            node_downgrade_from=node_downgrade_from,
            controller=controller,
            node=node,
            docker_digest=docker_digest,
        )


@dataclass(frozen=True)
class VersionCatalog:
    """Cached version choices shown to the administrator."""

    checked_at: str
    stable: Optional[ReleaseManifest]
    edge: Optional[ReleaseManifest]
    releases: Tuple[ReleaseManifest, ...]
    error: str = ""


@dataclass(frozen=True)
class NodeTask:
    """A short-lived, node-owned update or destroy command."""

    task_id: str
    job_id: str
    node_id: str
    node_name: str
    kind: str
    status: str
    created_at: str
    expires_at: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class MaintenanceJob:
    """The single in-progress maintenance operation and its transient result."""

    id: str
    kind: str
    status: str
    actor: str
    created_at: str
    updated_at: str
    targets: Tuple[str, ...]
    results: Mapping[str, Mapping[str, Any]]
    manifest: Optional[ReleaseManifest]


def _current_version(value: Any) -> Tuple[int, int, int]:
    if not isinstance(value, str):
        raise ValueError("current version is not a semantic version")
    candidate = value.strip()
    if _PACKAGE_VERSION.fullmatch(candidate):
        candidate = "v" + candidate
    return parse_release_version(candidate)


def _incompatible(reason: str) -> None:
    raise CompatibilityError(reason)


def validate_compatibility(
    manifest: ReleaseManifest,
    component: str,
    current_version: str,
    current_protocol: int,
    config_schema: int,
    direction: str,
) -> None:
    """Reject an unsafe update before any production file can be written.

    A release can only operate on the declared protocol and configuration
    schema.  Its component-specific source-version floor protects both
    upgrades and downgrades from unsupported jumps.
    """
    if component not in {"controller", "node"}:
        _incompatible("unknown component")
    if direction not in {"upgrade", "downgrade"}:
        _incompatible("unknown update direction")
    if isinstance(current_protocol, bool) or not isinstance(current_protocol, int):
        _incompatible("current protocol is invalid")
    if isinstance(config_schema, bool) or not isinstance(config_schema, int):
        _incompatible("current configuration schema is invalid")

    expected_protocol = (
        manifest.controller_protocol if component == "controller" else manifest.node_protocol
    )
    if current_protocol != expected_protocol:
        _incompatible("component protocol does not match the target release")
    if not manifest.config_schema_min <= config_schema <= manifest.config_schema_max:
        _incompatible("configuration schema is outside the target release range")

    try:
        current = _current_version(current_version)
    except ValueError:
        _incompatible("current version is not a supported release version")

    minimum_text = getattr(manifest, component + "_" + direction + "_from")
    minimum = parse_release_version(minimum_text)
    if current < minimum:
        _incompatible("current version is below the supported source-version floor")

    if manifest.channel == "edge":
        if direction != "upgrade":
            _incompatible("edge releases cannot be selected for downgrade")
        return

    target = parse_release_version(manifest.version)
    if direction == "upgrade" and target <= current:
        _incompatible("target release is not newer than the current version")
    if direction == "downgrade" and target >= current:
        _incompatible("target release is not older than the current version")
