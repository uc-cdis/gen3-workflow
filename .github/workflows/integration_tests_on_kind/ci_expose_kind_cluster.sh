#!/usr/bin/env bash
set -Eeuo pipefail

# Expose the Kind cluster at http://localhost:8000
kubectl port-forward -n "${NAMESPACE}" service/revproxy-service 8000:80 &

# This ensures the port-forward command keeps running after the script exits, so the cluster
# stays accessible
disown $!

# Wait until the port is actually accepting connections
timeout 30 bash -c 'until nc -z localhost 8000; do sleep 0.5; done'

echo "DEBUG: hitting $HOSTNAME_PROTOCOL://$HOSTNAME/user/_status"
RESPONSE=$(curl -w "%{http_code}" "$HOSTNAME_PROTOCOL://$HOSTNAME/user/_status")
echo RESPONSE: $RESPONSE
