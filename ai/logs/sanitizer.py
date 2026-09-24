from __future__ import annotations

import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\b")
PID_RE = re.compile(r"\b(?:pid|ppid|proc.pid|process.pid)[=: ]+(\d+)\b", re.IGNORECASE)
CONTAINER_RE = re.compile(r"\b[0-9a-f]{12,64}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:sha256:)?[0-9a-f]{64}\b", re.IGNORECASE)
PORT_RE = re.compile(r"\bport[=: ]+\d{1,5}\b", re.IGNORECASE)


def sanitize_text(value: str) -> str:
    text = TIME_RE.sub("<TIME>", value)
    text = UUID_RE.sub("<UUID>", text)
    text = HASH_RE.sub("<HASH>", text)
    text = IP_RE.sub("<IP>", text)
    text = PID_RE.sub(lambda match: match.group(0).replace(match.group(1), "<PID>"), text)
    text = PORT_RE.sub("port=<PORT>", text)
    text = CONTAINER_RE.sub("<CONTAINER_ID>", text)
    return " ".join(text.split())
