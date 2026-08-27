from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from typing import Any, Dict


class GeoIPEnricher:
    def __init__(self, config: Dict[str, Any]):
        self._stack = ExitStack()
        self._readers: Dict[str, Any] = {}
        self._cache: Dict[str, Dict[str, Any]] = {}
        paths = config.get("geoip", {})
        configured = {key: value for key, value in paths.items() if key.endswith("_db") and value}
        if not configured:
            return
        try:
            import geoip2.database
        except ImportError as exc:
            raise RuntimeError("GeoIP databases are configured but the geoip2 package is not installed") from exc
        for key, value in configured.items():
            path = Path(str(value))
            if not path.is_file():
                raise RuntimeError(f"GeoIP database not found: {path}")
            self._readers[key] = self._stack.enter_context(geoip2.database.Reader(str(path)))

    def close(self) -> None:
        self._stack.close()

    def enrich(self, source_ip: str) -> Dict[str, Any]:
        if source_ip in self._cache:
            return dict(self._cache[source_ip])
        result: Dict[str, Any] = {}
        try:
            if "city_db" in self._readers:
                city = self._readers["city_db"].city(source_ip)
                result.update({
                    "city": city.city.name,
                    "region": city.subdivisions.most_specific.name,
                    "country": city.country.iso_code,
                    "lat": city.location.latitude,
                    "lon": city.location.longitude,
                })
            if "asn_db" in self._readers:
                asn = self._readers["asn_db"].asn(source_ip)
                result.update({"asn": asn.autonomous_system_number, "isp": asn.autonomous_system_organization})
            if "connection_type_db" in self._readers:
                connection = self._readers["connection_type_db"].connection_type(source_ip)
                result["network_type"] = connection.connection_type
            if "anonymous_ip_db" in self._readers:
                anonymous = self._readers["anonymous_ip_db"].anonymous_ip(source_ip)
                if anonymous.is_tor_exit_node:
                    result["network_type"] = "tor"
                elif anonymous.is_anonymous_vpn:
                    result["network_type"] = "vpn"
                elif anonymous.is_hosting_provider:
                    result["network_type"] = "hosting"
        except Exception as exc:  # Database address misses differ across geoip2 versions.
            if exc.__class__.__name__ != "AddressNotFoundError":
                raise
        normalized = {key: value for key, value in result.items() if value is not None}
        self._cache[source_ip] = normalized
        return dict(normalized)

    def __enter__(self) -> "GeoIPEnricher":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
