#!/usr/bin/env bash

poetry run pytest -vv --cov=gen3workflow --cov-report term-missing:skip-covered --cov-report xml tests
