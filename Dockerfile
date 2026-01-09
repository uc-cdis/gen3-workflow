ARG AZLINUX_BASE_VERSION=3.13-pythonnginx

# Base stage
FROM quay.io/cdis/amazonlinux-base:${AZLINUX_BASE_VERSION} AS base

ENV appname=gen3workflow

WORKDIR /${appname}

RUN chown -R gen3:gen3 /${appname}

# Builder stage
FROM base AS builder

# copy ONLY poetry artifact, install the dependencies but not the app;
# this will make sure that the dependencies are cached
COPY poetry.lock pyproject.toml /${appname}/
RUN poetry install -vv --no-root --only main --no-interaction

COPY --chown=gen3:gen3 . /${appname}

# install the app
RUN poetry install --without dev --no-interaction

# Final stage
FROM base

COPY --from=builder /${appname} /${appname}

# switch to root user to install vim
USER root

RUN dnf -y install vim

# Switch to non-root user 'gen3' for the serving process
USER gen3

WORKDIR /${appname}

RUN chmod 755 bin/run.sh

CMD ["bash", "bin/run.sh"]
