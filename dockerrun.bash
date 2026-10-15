#!/bin/bash
set -e

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Sets up PROMETHEUS_MULTIPROC_DIR, which has to exist before the app starts
source "${CURRENT_DIR}/bin/_common_setup.sh"

# One worker per container: this is an ASGI app, so concurrency comes from the event loop and
# scale comes from replicas, not from workers.
#
# --host is not configurable: uvicorn defaults to 127.0.0.1, and anything other than 0.0.0.0
# here leaves the container listening where nothing can reach it.
#
# `exec` so uvicorn is PID 1 and gets SIGTERM directly: otherwise the container is killed
# outright, cutting in-flight requests and skipping the FastAPI lifespan shutdown.
exec uvicorn gen3workflow.app:app \
  --host 0.0.0.0 \
  --port "${UVICORN_PORT:-8000}" \
  --timeout-graceful-shutdown "${UVICORN_TIMEOUT_GRACEFUL_SHUTDOWN:-90}"
