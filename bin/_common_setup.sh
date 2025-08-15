#!/usr/bin/env bash
set -e

# Common setup for both tests and running the service
# Used in run.sh and test.sh

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "/src/gen3-workflow-config.yaml" ]; then
  # For multi-worker Gunicorn setups; requires PROMETHEUS_MULTIPROC_DIR to be set before startup,
  # here we assume the config file is mounted at /src via cloud-automation.
  PROMETHEUS_MULTIPROC_DIR=$(grep 'PROMETHEUS_MULTIPROC_DIR:' /src/gen3-workflow-config.yaml | awk -F': ' '{print $2}' | tr -d '"')
else
  PROMETHEUS_MULTIPROC_DIR=""
fi
# Source the environment variables from the metrics setup script
source "${CURRENT_DIR}/setup_prometheus.sh" $PROMETHEUS_MULTIPROC_DIR

echo "installing dependencies with 'poetry install -vv'..."
poetry install -vv
poetry env info
