FROM docker.io/library/python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=UTC

WORKDIR /opt/ahr-idps

COPY pipeline/requirements.txt /tmp/requirements.txt
RUN python -m pip install --requirement /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt

COPY collector ./collector
COPY normalizer ./normalizer
COPY ahr_common ./ahr_common
COPY pipeline/config.yml ./pipeline/config.yml

# Services select their own module and numeric user in Compose. The collector
# runs with no Linux capabilities but needs uid 0 to read Wazuh's 0640 logs;
# the normalizer runs as an unprivileged numeric uid.
