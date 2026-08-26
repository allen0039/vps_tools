import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vps_audit.maxmind_install import (
    DownloadError,
    EDITIONS,
    METADATA_MARKER,
    download_databases,
)


def database_archive(edition: str) -> bytes:
    output = io.BytesIO()
    payload = b"fixture-database\n" + METADATA_MARKER + b"\nmetadata"
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        info = tarfile.TarInfo(f"{edition}_20260826/{edition}.mmdb")
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    return output.getvalue()


class MaxMindInstallTests(unittest.TestCase):
    def test_downloads_both_databases_with_private_permissions(self):
        requested = []

        def opener(request, timeout):
            requested.append((request.full_url, timeout))
            edition = next(item for item in EDITIONS if f"edition_id={item}" in request.full_url)
            return io.BytesIO(database_archive(edition))

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "geoip"
            installed = download_databases("test_license_123", destination, opener=opener)
            self.assertEqual(set(installed), set(EDITIONS))
            self.assertEqual(len(requested), 2)
            for edition, path in installed.items():
                self.assertEqual(path, destination / f"{edition}.mmdb")
                self.assertTrue(path.is_file())
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertIn(METADATA_MARKER, path.read_bytes())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)

    def test_failure_preserves_existing_databases_and_hides_key(self):
        secret = "private_license_123"

        def opener(request, timeout):
            if "GeoLite2-ASN" in request.full_url:
                raise OSError(f"failed URL containing {secret}")
            return io.BytesIO(database_archive("GeoLite2-City"))

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "geoip"
            destination.mkdir()
            originals = {}
            for edition in EDITIONS:
                path = destination / f"{edition}.mmdb"
                path.write_bytes(f"old-{edition}".encode())
                originals[edition] = path.read_bytes()
            with self.assertRaises(DownloadError) as raised:
                download_databases(secret, destination, opener=opener)
            self.assertNotIn(secret, str(raised.exception))
            for edition in EDITIONS:
                self.assertEqual((destination / f"{edition}.mmdb").read_bytes(), originals[edition])
            self.assertFalse(any(item.name.startswith(".maxmind-") for item in destination.iterdir()))

    def test_rejects_invalid_license_key_before_network_access(self):
        called = False

        def opener(request, timeout):
            nonlocal called
            called = True
            return io.BytesIO()

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(DownloadError):
                download_databases("bad key", Path(temporary), opener=opener)
        self.assertFalse(called)

    def test_rejects_oversized_expanded_database(self):
        def opener(request, timeout):
            edition = next(item for item in EDITIONS if f"edition_id={item}" in request.full_url)
            return io.BytesIO(database_archive(edition))

        with tempfile.TemporaryDirectory() as temporary:
            with patch("vps_audit.maxmind_install.MAX_DATABASE_BYTES", 16):
                with self.assertRaises(DownloadError):
                    download_databases("test_license_123", Path(temporary), opener=opener)


if __name__ == "__main__":
    unittest.main()
