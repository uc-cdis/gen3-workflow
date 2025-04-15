#!/usr/bin/env bash
set -e

# Mostly simulates the production run of the app as described in the Dockerfile.
# Uses Gunicorn, multiple Uvicorn workers
# Small config overrides for local dev, like hot reload  when the code is modified and logs to stdout

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo $CURRENT_DIR
export ENV="production"

if [ -f "${CURRENT_DIR}/.env" ]; then
  echo "Loading environment variables from ${CURRENT_DIR}/.env"
  source "${CURRENT_DIR}/.env"
else
  echo "No .env file found in ${CURRENT_DIR}. Using default environment variables."
fi

source "${CURRENT_DIR}/bin/_common_setup.sh"

poetry run gunicorn \
  gen3workflow.app:app \
  -k uvicorn.workers.UvicornWorker \
  -c gunicorn.conf.py \
  --reload \
  --access-logfile - \
  --error-logfile -
