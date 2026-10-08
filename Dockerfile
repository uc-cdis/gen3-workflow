ARG AZLINUX_BASE_VERSION=3.13-pythonpoetry

# Base stage with python-poetry-base
FROM quay.io/cdis/amazonlinux-base:${AZLINUX_BASE_VERSION} AS base

ENV appname=gen3workflow

# Tooling and environment only: no application sources here, so a source-only change cannot
# invalidate the dependency layer in `builder`. poetry and the empty /venv it installs into
# both come from the base image.
WORKDIR /${appname}

RUN chown -R gen3:gen3 /${appname}

# Builder stage
FROM base AS builder

# copy ONLY the poetry artifacts, so that a change to the source code does not invalidate the
# cached dependency install below
COPY --chown=gen3:gen3 poetry.lock pyproject.toml /${appname}/

# --no-root because the app itself is installed further down, once its sources are in
RUN poetry install -vv --without dev --no-interaction --no-root

# copy the source code only after installing the dependencies
COPY --chown=gen3:gen3 . /${appname}

# Run poetry again so the app itself gets installed too
RUN poetry install --without dev --no-interaction

# Creating the runtime image
FROM base

# poetry installs the app as an editable package, so /venv holds a .pth pointing back at this
# source tree: both are needed at runtime.
COPY --from=builder /venv /venv
COPY --from=builder /${appname} /${appname}

WORKDIR /${appname}

# The base image already selects the non-root gen3 user, so USER is left alone everywhere.
CMD ["/bin/bash", "-c", "/${appname}/dockerrun.bash"]
