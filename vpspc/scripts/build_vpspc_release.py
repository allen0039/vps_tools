#!/usr/bin/env python3
"""Build reproducible, checksummed VPSPC release artifacts.

This script intentionally has a small trust surface: it packages only files
tracked by Git and allowed by ``INCLUDED``.  It never copies local state,
runtime configuration, logs, or Docker secrets into a release artifact.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Iterable, List, Optional, Sequence


SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from vps_audit.maintenance.models import ReleaseManifest, parse_release_version


REPOSITORY = "allen0039/vps_tools"
RELEASE_DOWNLOAD_ROOT = "https://github.com/" + REPOSITORY + "/releases/download"
INCLUDED = (
    "vps_audit",
    "deploy",
    "docker",
    "install.sh",
    "remote-install.sh",
    "compose.yml",
    "Dockerfile",
    "pyproject.toml",
    "setup.py",
    "README.md",
)
SECRET_DIRECTORIES = frozenset({"secrets", "secret", "state", "logs", "__pycache__"})
MAX_FILE_BYTES = 64 * 1024 * 1024
CONTROLLER_PROTOCOL = 1
NODE_PROTOCOL = 1
CONFIG_SCHEMA_MIN = 1
CONFIG_SCHEMA_MAX = 1
CONTROLLER_UPGRADE_FROM = "v0.1.0"
CONTROLLER_DOWNGRADE_FROM = "v999.0.0"
NODE_UPGRADE_FROM = "v0.1.0"
NODE_DOWNGRADE_FROM = "v999.0.0"


@dataclass(frozen=True)
class BuildResult:
    """File paths emitted by one successful release build."""

    controller: Path
    node: Path
    manifest: Path
    checksums: Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_source_revision(value: str) -> str:
    if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("revision must be a 40-character lowercase Git commit SHA")
    return value


def _require_docker_digest(value: str) -> str:
    prefix = "sha256:"
    if not value.startswith(prefix) or len(value) != len(prefix) + 64:
        raise ValueError("docker digest must use sha256:<64 lowercase hexadecimal characters>")
    if any(char not in "0123456789abcdef" for char in value[len(prefix):]):
        raise ValueError("docker digest must use sha256:<64 lowercase hexadecimal characters>")
    return value


def _release_tag(channel: str, version: str) -> str:
    if channel == "stable":
        parse_release_version(version)
        return version
    if channel == "edge" and version == "edge":
        return "edge"
    raise ValueError("stable builds require vMAJOR.MINOR.PATCH; edge builds require version edge")


def _tracked_paths(source: Path) -> List[PurePosixPath]:
    """Return Git-tracked relative file names, never a filesystem walk."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(source), "ls-files", "-z"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("release source must be a readable Git working tree") from exc

    paths = []
    for raw in completed.stdout.decode("utf-8", errors="strict").split("\0"):
        if raw:
            paths.append(_safe_relative_path(raw))
    return sorted(paths, key=lambda item: item.as_posix())


def _safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("tracked release path is unsafe")
    return path


def _is_included(path: PurePosixPath) -> bool:
    rendered = path.as_posix()
    for entry in INCLUDED:
        if rendered == entry or rendered.startswith(entry + "/"):
            return True
    return False


def _is_secret_path(path: PurePosixPath) -> bool:
    parts = path.parts
    if any(part.lower() in SECRET_DIRECTORIES for part in parts):
        return True
    filename = parts[-1].lower()
    return filename == ".env"


def _collect_release_files(source: Path) -> List[PurePosixPath]:
    """Validate and return the exact whitelisted files included in the bundle."""
    selected: List[PurePosixPath] = []
    for relative in _tracked_paths(source):
        if not _is_included(relative):
            continue
        if _is_secret_path(relative):
            # The repository keeps this sentinel so fresh Docker deployments
            # create the directory.  It is never a release payload.
            if relative == PurePosixPath("docker/secrets/.gitkeep"):
                continue
            raise ValueError("tracked release path is inside a secret or runtime directory")

        candidate = source.joinpath(*relative.parts)
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise ValueError("tracked release file is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("tracked release file is not a regular file")
        if metadata.st_size > MAX_FILE_BYTES:
            raise ValueError("tracked release file exceeds the maximum allowed size")
        selected.append(relative)

    if not selected:
        raise ValueError("release source contains no whitelisted tracked files")
    node_path = PurePosixPath("deploy/node/vpspc-node.py")
    if node_path not in selected:
        raise ValueError("release source is missing deploy/node/vpspc-node.py")
    return selected


def _normalized_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Erase host-specific metadata while retaining the tracked executable bit."""
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    info.mode = 0o755 if info.mode & 0o111 else 0o644
    return info


def _build_controller_bundle(source: Path, destination: Path, files: Iterable[PurePosixPath]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for relative in files:
                    source_file = source.joinpath(*relative.parts)
                    info = archive.gettarinfo(str(source_file), arcname="vpspc/" + relative.as_posix())
                    if not info.isreg():
                        raise ValueError("release archive member is not a regular file")
                    with source_file.open("rb") as handle:
                        archive.addfile(_normalized_tarinfo(info), handle)


def _atomic_write_bytes(path: Path, payload: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _artifact_metadata(path: Path, release_tag: str) -> dict:
    return {
        "name": path.name,
        "url": RELEASE_DOWNLOAD_ROOT + "/" + release_tag + "/" + path.name,
        "sha256": _sha256(path),
        "size": path.stat().st_size,
    }


def _write_checksums(paths: Sequence[Path], destination: Path) -> None:
    rows = ["{}  {}\n".format(_sha256(path), path.name) for path in sorted(paths, key=lambda item: item.name)]
    _atomic_write_bytes(destination, "".join(rows).encode("ascii"))


def build_release(
    source: Path,
    output: Path,
    *,
    version: str,
    revision: str,
    channel: str,
    docker_digest: str,
) -> BuildResult:
    """Build controller/node artifacts and a parser-validated manifest.

    ``source`` must be the VPSPC directory inside a Git working tree.  The
    function deliberately does not accept artifact URLs, refs, or image tags;
    those values are derived from the immutable release channel/version.
    """
    source = source.resolve()
    output = output.resolve()
    release_tag = _release_tag(channel, version)
    revision = _require_source_revision(revision)
    docker_digest = _require_docker_digest(docker_digest)
    files = _collect_release_files(source)

    controller = output / ("vpspc-controller-" + release_tag + ".tar.gz")
    node = output / ("vpspc-node-" + release_tag + ".py")
    manifest_path = output / "manifest.json"
    checksums = output / "SHA256SUMS"

    _build_controller_bundle(source, controller, files)
    node_source = source / "deploy/node/vpspc-node.py"
    _atomic_write_bytes(node, node_source.read_bytes(), mode=0o644)

    manifest = {
        "schema_version": 1,
        "version": version,
        "channel": channel,
        "source_revision": revision,
        "controller_protocol": CONTROLLER_PROTOCOL,
        "node_protocol": NODE_PROTOCOL,
        "config_schema_min": CONFIG_SCHEMA_MIN,
        "config_schema_max": CONFIG_SCHEMA_MAX,
        "controller_upgrade_from": CONTROLLER_UPGRADE_FROM,
        "controller_downgrade_from": CONTROLLER_DOWNGRADE_FROM,
        "node_upgrade_from": NODE_UPGRADE_FROM,
        "node_downgrade_from": NODE_DOWNGRADE_FROM,
        "artifacts": {
            "controller": _artifact_metadata(controller, release_tag),
            "node": _artifact_metadata(node, release_tag),
        },
        "docker_digest": docker_digest,
    }
    # The same parser used by the controller is the builder's final gate.
    ReleaseManifest.from_dict(manifest)
    _atomic_write_bytes(
        manifest_path,
        (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    _write_checksums((controller, node, manifest_path), checksums)
    return BuildResult(controller=controller, node=node, manifest=manifest_path, checksums=checksums)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build reproducible VPSPC release artifacts")
    parser.add_argument("--source", type=Path, default=SCRIPT_ROOT, help="VPSPC Git working tree")
    parser.add_argument("--output", type=Path, required=True, help="empty or existing release output directory")
    parser.add_argument("--channel", choices=("stable", "edge"), required=True)
    parser.add_argument("--version", help="vMAJOR.MINOR.PATCH for stable; edge for testing channel")
    parser.add_argument("--revision", required=True, help="40-character lowercase Git commit SHA")
    parser.add_argument("--docker-digest", required=True, help="immutable pushed image digest")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    version = args.version or ("edge" if args.channel == "edge" else None)
    if version is None:
        _parser().error("--version is required for stable releases")
    try:
        result = build_release(
            args.source,
            args.output,
            version=version,
            revision=args.revision,
            channel=args.channel,
            docker_digest=args.docker_digest,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("release build failed: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps({
        "controller": str(result.controller),
        "node": str(result.node),
        "manifest": str(result.manifest),
        "checksums": str(result.checksums),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
