ARG PYTHON_BASE_VERSION=3.13-pythonpoetry

FROM quay.io/cdis/amazonlinux-base:${PYTHON_BASE_VERSION} AS builder
USER root
RUN dnf install -y --nodocs --setopt=install_weak_deps=False \
        gcc rust cargo openssl-devel libffi-devel \
    && dnf clean all \
    && /venv/bin/python -m pip uninstall -y pipx argcomplete userpath filelock platformdirs
USER gen3
WORKDIR /gen3workflow

COPY --chown=gen3:gen3 poetry.lock pyproject.toml ./
# The published cryptography wheel bundles its own OpenSSL.
RUN POETRY_INSTALLER_NO_BINARY=cryptography \
    poetry install --without dev --no-interaction --no-root

COPY --chown=gen3:gen3 gen3workflow ./gen3workflow
COPY --chown=gen3:gen3 NOTICE README.md ./
RUN poetry install --without dev --no-interaction

FROM quay.io/cdis/amazonlinux-base:${PYTHON_BASE_VERSION} AS runtime
USER root
RUN dnf update -y openssl openssl-libs \
    && dnf swap -y openssl-fips-provider-latest openssl-fips-provider-certified \
    && dnf clean all \
    && rm -rf /var/cache/dnf /var/cache/yum /venv

COPY --from=builder --chown=0:0 /venv /venv
COPY --from=builder --chown=0:0 /gen3workflow /gen3workflow
RUN ldd "$(/venv/bin/python -c 'from cryptography.hazmat.bindings import _rust; print(_rust.__file__)')" | grep -q 'libcrypto.so' \
    && /venv/bin/python -c 'import ssl; from cryptography.hazmat.bindings.openssl.binding import Binding; b = Binding(); assert b.ffi.string(b.lib.OpenSSL_version(0)).decode() == ssl.OPENSSL_VERSION, "cryptography and Python use different OpenSSL versions"' \
    && rm -rf /venv/lib/python3.13/site-packages/pip \
        /venv/lib/python3.13/site-packages/pip-*.dist-info \
    && find /venv/bin -mindepth 1 -maxdepth 1 ! -name 'python*' -delete \
    && chmod -R go-w /venv /gen3workflow \
    && mkdir -p /src /gen3-workflow /var/tmp/prometheus_metrics \
    && chown gen3:gen3 /var/tmp/prometheus_metrics \
    && rm -rf /home/gen3/.cache /home/gen3/.local /home/gen3/.bash* \
        /usr/include/python3.13* /usr/lib64/python3.9 /usr/lib/python3.9 \
        /usr/lib64/python3.13/ensurepip /usr/share/python-wheels \
        /usr/share/python3-wheels /usr/share/python3.13-wheels \
        /usr/lib/rpm /usr/share/git-core /usr/lib64/security/pam_filter/upperLOWER \
        /usr/libexec /usr/local/bin /usr/local/sbin \
    && chown root:root /home/gen3 \
    && chmod 755 /home/gen3 \
    && find /usr/sbin -mindepth 1 -maxdepth 1 -delete \
    && find /usr/bin -mindepth 1 -maxdepth 1 ! -name python3.13 -delete

FROM scratch
COPY --from=runtime / /

ENV PATH=/venv/bin:/usr/bin \
    VIRTUAL_ENV=/venv \
    HOME=/home/gen3 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONIOENCODING=UTF-8
WORKDIR /gen3workflow
USER 1000:1000
CMD ["/venv/bin/python", "-m", "gen3workflow.start"]
