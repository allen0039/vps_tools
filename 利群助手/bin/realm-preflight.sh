#!/usr/bin/env bash
# Managed-By: liqun-helper
set -euo pipefail

INSTANCE="${1:-}"
if [[ -z "${INSTANCE}" ]]; then
    echo "Usage: $0 <rule-instance-name>" >&2
    exit 2
fi

if [[ ! "${INSTANCE}" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$ ]]; then
    echo "Invalid instance name: ${INSTANCE}" >&2
    exit 2
fi

INSTALL_ENV="/usr/local/lib/liqun-helper/install.env"
CONFIG_FILE="${LIQUN_HELPER_CONFIG:-/etc/liqun-helper/config.toml}"
if [[ -f "${INSTALL_ENV}" && ! -L "${INSTALL_ENV}" ]]; then
    while IFS='=' read -r k v; do
        if [[ "${k}" == "LIQUN_HELPER_CONFIG" && -n "${v}" ]]; then
            CONFIG_FILE="${v}"
        fi
    done < "${INSTALL_ENV}"
fi

exec /usr/local/bin/liqun-helper --config "${CONFIG_FILE}" _verify-startup "${INSTANCE}"
