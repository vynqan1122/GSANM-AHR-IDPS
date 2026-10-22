FROM docker.io/library/python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=UTC

WORKDIR /opt/ahr-idps

COPY backend/requirements.txt /tmp/backend-requirements.txt
RUN python -m pip install --requirement /tmp/backend-requirements.txt \
    && rm -f /tmp/backend-requirements.txt

COPY backend ./backend
COPY correlation ./correlation
COPY feature_engine ./feature_engine
COPY dataset_collection ./dataset_collection
COPY dashboard/dist ./dashboard/dist
