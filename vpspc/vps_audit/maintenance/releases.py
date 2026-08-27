"""Fetch, verify, and cache only immutable VPSPC release artifacts.

The maintenance coordinator never accepts a URL, branch name, or commit from
Telegram or the Web UI.  This module is the narrow trust boundary between the
controller and the fixed GitHub Release repository.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple
from urllib.parse import unquote, urlsplit

from .models import ArtifactSpec, ReleaseManifest, VersionCatalog, parse_release_version


REPOSITORY = "allen0039/vps_tools"
API_ROOT = "https://api.github.com/repos/" + REPOSITORY
GHCR_IMAGE = "ghcr.io/allen0039/vpspc"

API_HOST = "api.github.com"
DOWNLOAD_HOSTS = frozenset({"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"})
DOWNLOAD_PREFIX = "/" + REPOSITORY + "/releases/download/"

DEFAULT_TIMEOUT_SECONDS = 20
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_TAR_MEMBERS = 10_000
_ARTIFACT_ID = re.compile(r"^sha256-[a-f0-9]{64}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class ReleaseSourceError(RuntimeError):
    """A recoverable failure while reading the managed release source."""

    def __init__(self, message: str, *, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


def _utc_iso(value: Optional[datetime] = None) -> str:
    current = value or datetime.now(timezone.utc)
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _url_parts(value: str) -> Any:
    if not isinstance(value, str) or not value:
        raise ValueError("release URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("release URL is invalid") from exc
    if parsed.scheme != "https" or not parsed.hostname or port not in {None, 443}:
        raise ValueError("release URL must use HTTPS")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("release URL must not contain credentials or fragments")
    return parsed


def _validate_api_url(value: str) -> str:
    parsed = _url_parts(value)
    if parsed.hostname != API_HOST or not parsed.path.startswith("/repos/" + REPOSITORY + "/"):
        raise ValueError("release API URL is outside the allowed GitHub repository")
    return value


def _validate_asset_url(value: str) -> str:
    """Validate a manifest URL before issuing a request.

    GitHub redirects browser download URLs to a signed asset host, but the
    initial URL must remain a repository-scoped ``github.com`` URL.  This
    prevents a manifest from naming an unrelated file on an otherwise allowed
    CDN host.
    """

    parsed = _url_parts(value)
    if (
        parsed.hostname != "github.com"
        or not parsed.path.startswith(DOWNLOAD_PREFIX)
        or parsed.query
    ):
        raise ValueError("asset URL is outside the allowed GitHub repository")
    tail = PurePosixPath(unquote(parsed.path[len(DOWNLOAD_PREFIX):]))
    if len(tail.parts) != 2 or any(part in {"", ".", ".."} for part in tail.parts):
        raise ValueError("asset URL is outside the allowed GitHub repository")
    return value


def _validate_download_redirect(value: str) -> str:
    parsed = _url_parts(value)
    if parsed.hostname not in DOWNLOAD_HOSTS:
        raise ValueError("asset URL is outside the allowed GitHub repository")
    if parsed.hostname == "github.com" and not parsed.path.startswith(DOWNLOAD_PREFIX):
        raise ValueError("asset URL is outside the allowed GitHub repository")
    return value


def artifact_id_for(artifact: ArtifactSpec) -> str:
    """Return the non-path artifact ID exposed to node task consumers."""

    if not isinstance(artifact, ArtifactSpec) or not _SHA256.fullmatch(artifact.sha256):
        raise ValueError("artifact must have a valid SHA-256 checksum")
    return "sha256-" + artifact.sha256


def verify_file(path: Path, expected_sha256: str, expected_size: int) -> None:
    """Verify a complete file without trusting its name or filesystem metadata."""

    if not _SHA256.fullmatch(str(expected_sha256)):
        raise ValueError("expected SHA-256 is invalid")
    if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0:
        raise ValueError("expected artifact size is invalid")
    candidate = Path(path)
    try:
        actual_size = candidate.stat().st_size
    except OSError as exc:
        raise ValueError("artifact file is unavailable") from exc
    if actual_size != expected_size:
        raise ValueError("artifact size does not match manifest")

    digest = hashlib.sha256()
    try:
        with candidate.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ValueError("artifact file is unavailable") from exc
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise ValueError("artifact SHA-256 does not match manifest")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _archive_member_path(root: Path, member: tarfile.TarInfo) -> Path:
    name = member.name
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("unsafe archive member path")
    pure = PurePosixPath(name)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("unsafe archive member path")
    target = root.joinpath(*pure.parts)
    if not _is_within(target, root):
        raise ValueError("unsafe archive member path")
    return target


def safe_extract_tar(
    archive: Path,
    destination: Path,
    *,
    max_bytes: int,
    max_members: int = MAX_TAR_MEMBERS,
) -> Path:
    """Extract only regular files and directories into a new bounded directory.

    The destination is populated in a sibling temporary directory and renamed
    only after every member has passed validation and has been copied.  Existing
    destinations are rejected to prevent an update bundle from overwriting
    unrelated files.
    """

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("archive maximum must be a positive integer")
    if isinstance(max_members, bool) or not isinstance(max_members, int) or max_members < 1:
        raise ValueError("archive member maximum must be a positive integer")

    source = Path(archive)
    target = Path(destination)
    try:
        if not source.is_file() or source.stat().st_size > max_bytes:
            raise ValueError("archive exceeds maximum compressed size")
    except OSError as exc:
        raise ValueError("unsafe archive could not be read") from exc
    if target.exists() or target.is_symlink():
        raise FileExistsError("archive destination already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    parent = target.parent.resolve()
    final_target = parent / target.name
    if not _is_within(final_target, parent):
        raise ValueError("unsafe archive destination")

    temporary = Path(tempfile.mkdtemp(prefix="." + target.name + ".", dir=str(parent)))
    staged = temporary / "payload"
    staged.mkdir(mode=0o700)
    try:
        try:
            with tarfile.open(source, "r:*") as bundle:
                members = bundle.getmembers()
                if len(members) > max_members:
                    raise ValueError("archive exceeds maximum member count")

                paths = []
                total_declared = 0
                seen = set()
                for member in members:
                    if not (member.isdir() or member.isfile()):
                        raise ValueError("unsafe archive member type")
                    member_path = _archive_member_path(staged, member)
                    relative = member_path.relative_to(staged).as_posix()
                    if relative in seen:
                        raise ValueError("unsafe archive duplicate member")
                    seen.add(relative)
                    if member.isfile():
                        if member.size < 0:
                            raise ValueError("unsafe archive member size")
                        total_declared += member.size
                        if total_declared > max_bytes:
                            raise ValueError("archive exceeds maximum expanded size")
                    paths.append((member, member_path))

                total_written = 0
                for member, member_path in paths:
                    if member.isdir():
                        member_path.mkdir(mode=0o755, parents=True, exist_ok=False)
                        continue
                    member_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    input_file = bundle.extractfile(member)
                    if input_file is None:
                        raise ValueError("unsafe archive member cannot be read")
                    member_written = 0
                    with input_file, member_path.open("xb") as output:
                        while True:
                            chunk = input_file.read(1024 * 1024)
                            if not chunk:
                                break
                            member_written += len(chunk)
                            total_written += len(chunk)
                            if total_written > max_bytes or member_written > member.size:
                                raise ValueError("archive exceeds maximum expanded size")
                            output.write(chunk)
                    if member_written != member.size:
                        raise ValueError("unsafe archive member size")
                    os.chmod(member_path, 0o644)
        except ValueError:
            raise
        except (OSError, tarfile.TarError) as exc:
            raise ValueError("unsafe archive could not be read") from exc

        os.replace(staged, final_target)
        os.chmod(final_target, 0o755)
        return target
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


class GitHubReleaseSource:
    """A fixed-source GitHub Release client with an immutable local cache."""

    def __init__(
        self,
        cache_dir: Path,
        *,
        opener: Callable[..., Any] = urllib.request.urlopen,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ):
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds < 1:
            raise ValueError("release timeout must be a positive integer")
        self.cache_dir = Path(cache_dir)
        self.opener = opener
        self.timeout_seconds = timeout_seconds
        self._catalog: Optional[VersionCatalog] = None

    def _cache_root(self) -> Path:
        self.cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.cache_dir.is_dir() or self.cache_dir.is_symlink():
            raise ValueError("managed artifact cache directory is invalid")
        root = self.cache_dir.resolve()
        os.chmod(root, 0o700)
        return root

    @staticmethod
    def _artifact_filename(artifact_id: str) -> str:
        if not _ARTIFACT_ID.fullmatch(artifact_id):
            raise ValueError("artifact ID is invalid")
        return artifact_id + ".bundle"

    def _index_path(self) -> Path:
        return self._cache_root() / "artifacts.json"

    def _load_index(self) -> Dict[str, str]:
        path = self._index_path()
        try:
            with path.open(encoding="utf-8") as handle:
                raw = json.load(handle)
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("managed artifact cache index is invalid") from exc
        if not isinstance(raw, Mapping) or raw.get("schema_version") != 1 or not isinstance(raw.get("artifacts"), Mapping):
            raise ValueError("managed artifact cache index is invalid")
        result: Dict[str, str] = {}
        for artifact_id, filename in raw["artifacts"].items():
            if not isinstance(artifact_id, str) or not isinstance(filename, str):
                raise ValueError("managed artifact cache index is invalid")
            if not _ARTIFACT_ID.fullmatch(artifact_id) or filename != self._artifact_filename(artifact_id):
                raise ValueError("managed artifact cache index is invalid")
            result[artifact_id] = filename
        return result

    def _save_index(self, artifacts: Mapping[str, str]) -> None:
        root = self._cache_root()
        payload = {"schema_version": 1, "artifacts": dict(artifacts)}
        descriptor, temporary_name = tempfile.mkstemp(prefix=".artifacts-", dir=str(root))
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, root / "artifacts.json")
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def cached_artifacts(self) -> Dict[str, str]:
        """Return the validated artifact-ID-to-cache-filename mapping."""

        return dict(self._load_index())

    def artifact_path(self, artifact_id: str) -> Path:
        """Resolve one known artifact ID without accepting caller-provided paths."""

        if not isinstance(artifact_id, str) or not _ARTIFACT_ID.fullmatch(artifact_id):
            raise FileNotFoundError("unknown managed artifact")
        filename = self._load_index().get(artifact_id)
        if filename is None:
            raise FileNotFoundError("unknown managed artifact")
        root = self._cache_root()
        candidate = root / filename
        if not _is_within(candidate, root) or candidate.resolve() != candidate or not candidate.is_file():
            raise FileNotFoundError("unknown managed artifact")
        verify_file(candidate, artifact_id.removeprefix("sha256-"), candidate.stat().st_size)
        return candidate

    def _read_remote(
        self,
        url: str,
        *,
        max_bytes: int,
        initial_validator: Callable[[str], str],
        final_validator: Callable[[str], str],
    ) -> bytes:
        initial_validator(url)
        request = urllib.request.Request(url, headers={"User-Agent": "vpspc-release-client/1"})
        try:
            with self.opener(request, timeout=self.timeout_seconds) as response:
                final_url = response.geturl() if hasattr(response, "geturl") else url
                final_validator(str(final_url))
                chunks = []
                total = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise ReleaseSourceError("managed release response is invalid")
                    total += len(chunk)
                    if total > max_bytes:
                        raise ReleaseSourceError("managed release response exceeds its size limit")
                    chunks.append(chunk)
                return b"".join(chunks)
        except (ValueError, ReleaseSourceError):
            raise
        except urllib.error.HTTPError as exc:
            raise ReleaseSourceError(
                "managed GitHub release source returned an HTTP error", status=exc.code
            ) from None
        except (OSError, urllib.error.URLError, TimeoutError):
            raise ReleaseSourceError("unable to reach the managed GitHub release source") from None

    def _fetch_json(
        self,
        url: str,
        *,
        max_bytes: int,
        initial_validator: Callable[[str], str],
        final_validator: Callable[[str], str],
    ) -> Any:
        payload = self._read_remote(
            url,
            max_bytes=max_bytes,
            initial_validator=initial_validator,
            final_validator=final_validator,
        )
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("managed release metadata is not valid JSON") from None

    @staticmethod
    def _manifest_asset(release: Mapping[str, Any]) -> str:
        assets = release.get("assets")
        if not isinstance(assets, list):
            raise ValueError("GitHub release assets are invalid")
        matches = []
        for asset in assets:
            if isinstance(asset, Mapping) and asset.get("name") == "manifest.json":
                url = asset.get("browser_download_url")
                if isinstance(url, str):
                    matches.append(url)
        if len(matches) != 1:
            raise ValueError("GitHub release must contain exactly one manifest.json asset")
        return _validate_asset_url(matches[0])

    def parse_manifest(self, raw: Mapping[str, Any]) -> ReleaseManifest:
        manifest = ReleaseManifest.from_dict(raw)
        for artifact in (manifest.controller, manifest.node):
            _validate_asset_url(artifact.url)
            path = urlsplit(artifact.url).path
            release_tag, filename = PurePosixPath(unquote(path[len(DOWNLOAD_PREFIX):])).parts
            if release_tag != manifest.version or filename != artifact.name:
                raise ValueError("artifact URL does not match the managed release manifest")
        return manifest

    def _fetch_release_manifest(self, release: Mapping[str, Any], *, channel: str, tag: str) -> ReleaseManifest:
        manifest_url = self._manifest_asset(release)
        raw = self._fetch_json(
            manifest_url,
            max_bytes=MAX_MANIFEST_BYTES,
            initial_validator=_validate_asset_url,
            final_validator=_validate_download_redirect,
        )
        if not isinstance(raw, Mapping):
            raise ValueError("release manifest must be a JSON object")
        manifest = self.parse_manifest(raw)
        if manifest.channel != channel or manifest.version != tag:
            raise ValueError("release manifest does not match its GitHub Release")
        return manifest

    @staticmethod
    def _release_tag(release: Mapping[str, Any]) -> Optional[str]:
        tag = release.get("tag_name")
        return tag if isinstance(tag, str) else None

    def fetch_catalog(self, *, checked_at: Optional[datetime] = None) -> VersionCatalog:
        """Fetch at most ten stable releases plus the fixed ``edge`` prerelease."""

        raw_releases = self._fetch_json(
            API_ROOT + "/releases?per_page=100",
            max_bytes=MAX_CATALOG_BYTES,
            initial_validator=_validate_api_url,
            final_validator=_validate_api_url,
        )
        if not isinstance(raw_releases, list):
            raise ValueError("GitHub releases response must be a list")

        stable_releases = []
        for raw_release in raw_releases:
            if not isinstance(raw_release, Mapping) or raw_release.get("draft") is not False:
                continue
            tag = self._release_tag(raw_release)
            if tag is None:
                continue
            if raw_release.get("prerelease") is True:
                continue
            if raw_release.get("prerelease") is not False:
                continue
            try:
                parsed = parse_release_version(tag)
            except ValueError:
                continue
            stable_releases.append((parsed, tag, raw_release))

        stable_releases.sort(reverse=True)
        stable_manifests = []
        for _parsed, tag, release in stable_releases[:10]:
            stable_manifests.append(self._fetch_release_manifest(release, channel="stable", tag=tag))
        try:
            raw_edge = self._fetch_json(
                API_ROOT + "/releases/tags/edge",
                max_bytes=MAX_CATALOG_BYTES,
                initial_validator=_validate_api_url,
                final_validator=_validate_api_url,
            )
        except ReleaseSourceError as exc:
            if exc.status != 404:
                raise
            raw_edge = None
        edge_manifest = None
        if raw_edge is not None:
            if (
                not isinstance(raw_edge, Mapping)
                or self._release_tag(raw_edge) != "edge"
                or raw_edge.get("draft") is not False
                or raw_edge.get("prerelease") is not True
            ):
                raise ValueError("GitHub edge release metadata is invalid")
            edge_manifest = self._fetch_release_manifest(raw_edge, channel="edge", tag="edge")
        catalog = VersionCatalog(
            checked_at=_utc_iso(checked_at),
            stable=stable_manifests[0] if stable_manifests else None,
            edge=edge_manifest,
            releases=tuple(stable_manifests),
        )
        self._catalog = catalog
        return catalog

    def resolve(self, channel: str, version: Optional[str]) -> ReleaseManifest:
        """Resolve only stable/latest, edge/latest, or a listed stable Release."""

        if channel not in {"stable", "edge"}:
            raise ValueError("release channel must be stable or edge")
        if version is not None and not isinstance(version, str):
            raise ValueError("release version is invalid")
        catalog = self._catalog or self.fetch_catalog()
        if channel == "edge":
            if version not in {None, "edge"}:
                raise ValueError("edge updates do not accept a release version")
            if catalog.edge is None:
                raise ValueError("no managed edge release is available")
            return catalog.edge

        if version is None:
            if catalog.stable is None:
                raise ValueError("no managed stable release is available")
            return catalog.stable
        parse_release_version(version)
        for manifest in catalog.releases:
            if manifest.version == version:
                return manifest
        raise ValueError("requested release is not in the managed catalog")

    def _cache_candidate(self, artifact_id: str) -> Path:
        root = self._cache_root()
        candidate = root / self._artifact_filename(artifact_id)
        if not _is_within(candidate, root):
            raise ValueError("managed artifact cache path is invalid")
        return candidate

    def _drop_cache_entry(self, artifact_id: str) -> None:
        index = self._load_index()
        if artifact_id in index:
            del index[artifact_id]
            self._save_index(index)

    def download(self, artifact: ArtifactSpec) -> Path:
        """Download, verify and atomically cache one artifact by its SHA-256 ID."""

        if not isinstance(artifact, ArtifactSpec):
            raise ValueError("release artifact is invalid")
        _validate_asset_url(artifact.url)
        artifact_id = artifact_id_for(artifact)
        candidate = self._cache_candidate(artifact_id)
        if candidate.is_file() and not candidate.is_symlink():
            try:
                verify_file(candidate, artifact.sha256, artifact.size)
                index = self._load_index()
                if index.get(artifact_id) != candidate.name:
                    index[artifact_id] = candidate.name
                    self._save_index(index)
                return candidate
            except ValueError:
                candidate.unlink(missing_ok=True)
                self._drop_cache_entry(artifact_id)

        root = self._cache_root()
        descriptor, temporary_name = tempfile.mkstemp(prefix=".download-", dir=str(root))
        temporary = Path(temporary_name)
        try:
            request = urllib.request.Request(artifact.url, headers={"User-Agent": "vpspc-release-client/1"})
            try:
                with self.opener(request, timeout=self.timeout_seconds) as response, os.fdopen(descriptor, "wb") as output:
                    descriptor = -1
                    final_url = response.geturl() if hasattr(response, "geturl") else artifact.url
                    _validate_download_redirect(str(final_url))
                    total = 0
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        if not isinstance(chunk, bytes):
                            raise ReleaseSourceError("managed artifact response is invalid")
                        total += len(chunk)
                        if total > artifact.size:
                            raise ValueError("artifact size does not match manifest")
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            except (ValueError, ReleaseSourceError):
                raise
            except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
                raise ReleaseSourceError("unable to download the managed release artifact") from None
            verify_file(temporary, artifact.sha256, artifact.size)
            os.chmod(temporary, 0o600)
            os.replace(temporary, candidate)
            index = self._load_index()
            index[artifact_id] = candidate.name
            self._save_index(index)
            return candidate
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


__all__ = [
    "API_ROOT",
    "DEFAULT_TIMEOUT_SECONDS",
    "DOWNLOAD_HOSTS",
    "GHCR_IMAGE",
    "GitHubReleaseSource",
    "REPOSITORY",
    "ReleaseSourceError",
    "artifact_id_for",
    "safe_extract_tar",
    "verify_file",
]
