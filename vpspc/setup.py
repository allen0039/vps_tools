from setuptools import find_packages, setup


setup(
    name="vps-user-audit",
    version="0.4.1",
    description="Evidence-first VPS user behavior audit",
    packages=find_packages(include=["vps_audit", "vps_audit.*"]),
    python_requires=">=3.9",
    extras_require={"geoip": ["geoip2>=4,<6"]},
    entry_points={"console_scripts": [
        "vps-audit=vps_audit.cli:main",
        "vps-audit-runner=vps_audit.runtime:main",
        "vps-audit-bot=vps_audit.bot:main",
        "vpspc=vps_audit.management:main",
    ]},
)
