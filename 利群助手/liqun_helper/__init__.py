"""独立「利群助手」(liqun-helper) 核心包。"""

__version__ = "0.1.1"

INSTALL_LIB_DIR = "/usr/local/lib/liqun-helper"
INSTALL_MANIFEST_PATH = "/usr/local/lib/liqun-helper/install-manifest.json"
INSTALL_ENV_PATH = "/usr/local/lib/liqun-helper/install.env"
MANAGED_MARKER = "# Managed-By: liqun-helper"

DEFAULT_CONFIG_PATH = "/etc/liqun-helper/config.toml"
DEFAULT_RULES_DIR = "/etc/liqun-helper/rules.d"
DEFAULT_STATE_DIR = "/var/lib/liqun-helper"
DEFAULT_COORDINATED_LOCK_FILE = "/run/liqun-helper.lock"
DEFAULT_LOCK_FILE = DEFAULT_COORDINATED_LOCK_FILE
FIXED_SYSTEMD_UNIT_TEMPLATE = "liqun-helper-realm@.service"
DEFAULT_SYSTEMD_UNIT_TEMPLATE = FIXED_SYSTEMD_UNIT_TEMPLATE
DEFAULT_STARTUP_ROUTE_WAIT_SECONDS = 45
DEFAULT_INGRESS_DOMAIN = "paid-v4.bgp1.leikwanhost.com"
MANAGED_REALM_BIN = "/usr/local/lib/liqun-helper/bin/realm"

REALM_VERIFIED_VERSION = "2.9.6"
REALM_MIN_COMPAT_VERSION = (2, 6, 0)
REALM_MAX_MAJOR = 2

REALM_RELEASES = {
    "x86_64": {
        "asset": "realm-x86_64-unknown-linux-musl.tar.gz",
        "url": "https://github.com/zhboner/realm/releases/download/v2.9.6/realm-x86_64-unknown-linux-musl.tar.gz",
        "sha256": "b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65",
    },
    "aarch64": {
        "asset": "realm-aarch64-unknown-linux-musl.tar.gz",
        "url": "https://github.com/zhboner/realm/releases/download/v2.9.6/realm-aarch64-unknown-linux-musl.tar.gz",
        "sha256": "f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488",
    },
}

ARCH_ALIASES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}
