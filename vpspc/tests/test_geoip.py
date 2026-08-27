import unittest
from types import SimpleNamespace

from vps_audit.geoip import GeoIPEnricher


class FakeAsnReader:
    def __init__(self):
        self.calls = 0

    def asn(self, _source_ip):
        self.calls += 1
        return SimpleNamespace(
            autonomous_system_number=64500,
            autonomous_system_organization="Example ASN",
        )


class GeoIPTests(unittest.TestCase):
    def test_repeated_ip_is_cached_within_one_enricher(self):
        reader = FakeAsnReader()
        enricher = GeoIPEnricher.__new__(GeoIPEnricher)
        enricher._readers = {"asn_db": reader}
        enricher._cache = {}
        first = enricher.enrich("198.51.100.9")
        second = enricher.enrich("198.51.100.9")
        self.assertEqual(first, second)
        self.assertEqual(reader.calls, 1)


if __name__ == "__main__":
    unittest.main()
