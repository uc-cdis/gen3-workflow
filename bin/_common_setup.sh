#!/usr/bin/env bash
set -e

# Common setup for both tests and running the service
# Used in run.sh and test.sh

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the environment variables from the metrics setup script
# source "${CURRENT_DIR}/setup_prometheus"

echo "installing dependencies with 'poetry install -vv'..."
poetry install -vv
poetry env info
echo "ensuring db exists"

# Get the username, password, host, port, and database name
db_settings=$(poetry run python $CURRENT_DIR/../gen3workflow/config.py | tail -1)
if [ -z "${db_settings}" ]; then
    echo "'gen3workflow/config.py' did not return DB settings"
    exit 1
fi
db_settings_array=($db_settings)
HOST=${db_settings_array[0]}
PORT=${db_settings_array[1]}
USER=${db_settings_array[2]}
PASSWORD=${db_settings_array[3]}
DB_NAME=${db_settings_array[4]}

if [ -z "${HOST}" ] || [ -z "${PORT}" ] || [ -z "${USER}" ] || [ -z "${PASSWORD}" ] || [ -z "${DB_NAME}" ]; then
    echo "Failed to extract one or more components from DB settings"
    exit 1
fi

echo "Extracted database name: ${DB_NAME}"
echo "Extracted username: ${USER}"

# Check if the database exists
# Use the full connection string to connect directly
if [ "$( PGPASSWORD="${PASSWORD}" psql -h "${HOST}" -p "${PORT}" -U "${USER}" -d postgres -XtAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" )" = '1' ]
then
    echo "Database ${DB_NAME} already exists."
else
    echo "Database ${DB_NAME} does not exist. Creating it..."
    # Connect to the default postgres database to create the new database
    PGPASSWORD="${PASSWORD}" psql -h "${HOST}" -p "${PORT}" -U "${USER}" -d postgres -c "CREATE DATABASE \"${DB_NAME}\";"
fi

echo "running db migration with 'poetry run alembic upgrade head'..."
poetry run alembic upgrade head
