#!/usr/bin/env bash
# Managed-By: leikwan_tools
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

INSTALL_ENV="/usr/local/lib/leikwan_tools/install.env"
CONFIG_FILE="${LEIKWAN_TOOLS_CONFIG:-/etc/leikwan_tools/config.toml}"
if [[ -f "${INSTALL_ENV}" && ! -L "${INSTALL_ENV}" ]]; then
    while IFS='=' read -r k v; do
        if [[ "${k}" == "LEIKWAN_TOOLS_CONFIG" && -n "${v}" ]]; then
            CONFIG_FILE="${v}"
        fi
    done < "${INSTALL_ENV}"
fi

exec /usr/local/bin/leikwan_tools --config "${CONFIG_FILE}" _verify-startup "${INSTANCE}"
