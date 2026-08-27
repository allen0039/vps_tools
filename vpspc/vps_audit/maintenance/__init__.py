"""Domain types shared by VPSPC managed update and removal workflows."""

from .models import (
    ArtifactSpec,
    CompatibilityError,
    MaintenanceJob,
    NodeTask,
    ReleaseManifest,
    VersionCatalog,
    parse_release_version,
    validate_compatibility,
)

__all__ = [
    "ArtifactSpec",
    "CompatibilityError",
    "MaintenanceJob",
    "NodeTask",
    "ReleaseManifest",
    "VersionCatalog",
    "parse_release_version",
    "validate_compatibility",
]
