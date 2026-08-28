import re
from pathlib import Path

from setuptools import find_packages, setup


PACKAGE_INIT = Path(__file__).parent / "vps_audit" / "__init__.py"
VERSION_MATCH = re.search(
    r"^__version__\s*=\s*['\"]([^'\"]+)['\"]",
    PACKAGE_INIT.read_text(encoding="utf-8"),
    re.MULTILINE,
)
if VERSION_MATCH is None:
    raise RuntimeError("Unable to find vps_audit.__version__")
VERSION = VERSION_MATCH.group(1)


setup(
    name="vps-user-audit",
    version=VERSION,
    description="Evidence-first VPS user behavior audit",
    packages=find_packages(include=["vps_audit", "vps_audit.*"]),
    python_requires=">=3.9",
    extras_require={"geoip": ["geoip2>=4,<6"]},
    entry_points={"console_scripts": [
        "vps-audit=vps_audit.cli:main",
        "vps-audit-runner=vps_audit.runtime:main",
        "vps-audit-bot=vps_audit.bot:main",
        "vpspc=vps_audit.management:main",
        "vps-audit-nodes=vps_audit.node_reporting:main",
        "vps-audit-web=vps_audit.web:main",
        "vps-audit-maintenance=vps_audit.maintenance.service:main",
    ]},
)
