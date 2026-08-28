#!/bin/sh
set -eu

# Compose `command` values are appended to ENTRYPOINT.  Execute them instead of
# silently starting the audit loop for every service profile.
if [ "$#" -eq 0 ]; then
  set -- /opt/vps-audit/docker/audit-loop.sh
fi

exec "$@"
