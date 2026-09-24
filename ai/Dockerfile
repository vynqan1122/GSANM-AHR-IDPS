FROM docker.io/library/python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=180 \
    TZ=UTC

WORKDIR /opt/ahr-idps

COPY ai/requirements.txt /tmp/ai-requirements.txt
RUN grep -v '^xgboost==' /tmp/ai-requirements.txt > /tmp/ai-base-requirements.txt \
    && python -m pip install --retries 8 --timeout 180 --requirement /tmp/ai-base-requirements.txt \
    && python -m pip install --retries 8 --timeout 180 --no-deps "$(grep '^xgboost==' /tmp/ai-requirements.txt)" \
    && rm -f /tmp/ai-requirements.txt /tmp/ai-base-requirements.txt

COPY ai ./ai
COPY correlation ./correlation
COPY feature_engine ./feature_engine
COPY rule_engine ./rule_engine
COPY response ./response
