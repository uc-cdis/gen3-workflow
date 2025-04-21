#!/usr/bin/env bash
set -e

# Common setup for both tests and running the service
# Used in run.sh and test.sh

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "/src/gen3-workflow-config.yaml" ]; then
  PROMETHEUS_MULTIPROC_DIR=$(grep 'PROMETHEUS_MULTIPROC_DIR:' /src/gen3-workflow-config.yaml | awk -F': ' '{print $2}' | tr -d '"')
else
  PROMETHEUS_MULTIPROC_DIR=""
fi
# Source the environment variables from the metrics setup script
source "${CURRENT_DIR}/setup_prometheus.sh" $PROMETHEUS_MULTIPROC_DIR

echo "installing dependencies with 'poetry install -vv'..."
poetry install -vv
poetry env info
