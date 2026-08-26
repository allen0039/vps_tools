from __future__ import annotations

import argparse
import os
import re
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Callable, Dict


DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"
EDITIONS = ("GeoLite2-City", "GeoLite2-ASN")
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_DATABASE_BYTES = 512 * 1024 * 1024
METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class DownloadError(RuntimeError):
    """A sanitized GeoLite2 download or validation failure."""


def _validate_license_key(value: str) -> str:
    key = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", key):
        raise DownloadError("MaxMind License Key 格式无效")
    return key


def _download_archive(
    edition: str,
    license_key: str,
    destination: Path,
    opener: Callable[..., object],
) -> None:
    query = urllib.parse.urlencode(
        {
            "edition_id": edition,
            "license_key": license_key,
            "suffix": "tar.gz",
        }
    )
    request = urllib.request.Request(
        f"{DOWNLOAD_URL}?{query}",
        headers={"User-Agent": "vps-user-audit/0.3.2"},
    )
    try:
        with opener(request, timeout=120) as response, destination.open("xb") as output:
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise DownloadError(f"{edition} 下载文件超过安全大小限制")
                output.write(chunk)
    except DownloadError:
        raise
    except Exception:
        raise DownloadError(f"{edition} 官方下载失败，请检查网络和 License Key") from None


def _extract_database(archive: Path, edition: str, destination: Path) -> None:
    filename = f"{edition}.mmdb"
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            matches = [
                member
                for member in bundle.getmembers()
                if member.isfile() and PurePosixPath(member.name).name == filename
            ]
            if len(matches) != 1:
                raise DownloadError(f"{edition} 压缩包未包含唯一的 {filename}")
            source = bundle.extractfile(matches[0])
            if source is None:
                raise DownloadError(f"{edition} 数据库无法读取")
            with source, destination.open("xb") as output:
                total = 0
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DATABASE_BYTES:
                        raise DownloadError(f"{edition} 数据库超过安全大小限制")
                    output.write(chunk)
    except DownloadError:
        raise
    except (OSError, tarfile.TarError):
        raise DownloadError(f"{edition} 压缩包损坏或格式无效") from None

    size = destination.stat().st_size
    if size <= len(METADATA_MARKER):
        raise DownloadError(f"{edition} 数据库大小异常")
    with destination.open("rb") as handle:
        handle.seek(max(0, size - 131_072))
        if METADATA_MARKER not in handle.read():
            raise DownloadError(f"{edition} 数据库缺少 MaxMind 元数据标记")
    destination.chmod(0o600)


def download_databases(
    license_key: str,
    destination: Path,
    opener: Callable[..., object] = urllib.request.urlopen,
) -> Dict[str, Path]:
    key = _validate_license_key(license_key)
    destination.mkdir(parents=True, exist_ok=True)
    destination.chmod(0o700)
    staged: Dict[str, Path] = {}
    with tempfile.TemporaryDirectory(prefix=".maxmind-", dir=destination) as temporary:
        staging = Path(temporary)
        for edition in EDITIONS:
            archive = staging / f"{edition}.tar.gz"
            database = staging / f"{edition}.mmdb"
            _download_archive(edition, key, archive, opener)
            _extract_database(archive, edition, database)
            staged[edition] = database
        installed = {}
        for edition in EDITIONS:
            target = destination / f"{edition}.mmdb"
            os.replace(staged[edition], target)
            target.chmod(0o600)
            installed[edition] = target
    return installed


def main() -> int:
    parser = argparse.ArgumentParser(description="Securely download official MaxMind GeoLite2 databases")
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()
    license_key = sys.stdin.read().strip()
    try:
        installed = download_databases(license_key, Path(args.destination))
    except DownloadError as exc:
        print(f"GeoIP 安装失败: {exc}", file=sys.stderr)
        return 1
    finally:
        license_key = ""
    for edition in EDITIONS:
        print(installed[edition])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
