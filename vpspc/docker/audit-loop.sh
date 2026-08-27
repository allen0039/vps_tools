#!/bin/sh
set -eu
config=${VPS_AUDIT_CONFIG:-/etc/vps-audit/config.json}
interval=${AUDIT_INTERVAL_SECONDS:-300}
while :; do
  /usr/local/bin/vps-audit-runner --config "$config" run || true
  sleep "$interval"
done
