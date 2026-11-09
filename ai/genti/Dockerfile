FROM docker.io/library/python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HOME=/tmp/hf
WORKDIR /opt/ahr-idps
RUN pip install --no-cache-dir torch==2.8.0 --index-url https://download.pytorch.org/whl/cpu
COPY ai/genti/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY ai/genti ./ai/genti
USER 65532:65532
CMD ["uvicorn", "ai.genti.serve:app", "--host", "0.0.0.0", "--port", "8090"]
