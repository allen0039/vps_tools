#!/bin/sh
set -eu
config=${VPS_AUDIT_CONFIG:-/etc/vps-audit/config.json}
interval=${AUDIT_INTERVAL_SECONDS:-300}
case "$interval" in
  ''|*[!0-9]*) echo "AUDIT_INTERVAL_SECONDS must be a positive integer" >&2; exit 2 ;;
esac
[ "$interval" -gt 0 ] || { echo "AUDIT_INTERVAL_SECONDS must be positive" >&2; exit 2; }

failures=0
trap 'exit 0' INT TERM
while :; do
  if /usr/local/bin/vps-audit-runner --config "$config" run; then
    failures=0
  else
    failures=$((failures + 1))
    echo "vpspc audit cycle failed ($failures consecutive failures)" >&2
    # Restarting the container is more observable than hiding a persistent
    # configuration or collector failure forever.
    [ "$failures" -lt 3 ] || exit 1
  fi
  sleep "$interval"
done
