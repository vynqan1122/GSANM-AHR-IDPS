"""Minimal structured JSON logging without leaking exception arguments."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "service": self.service,
            "level": record.levelname,
            "event": record.getMessage(),
        }
        for field in ("trace_id", "event_id", "incident_id", "scenario_id"):
            value = getattr(record, field, None)
            if value is not None:
                document[field] = str(value)
        if record.exc_info and record.exc_info[0]:
            document["exception_type"] = record.exc_info[0].__name__
        return json.dumps(document, ensure_ascii=False, separators=(",", ":"))


def configure_logging(service: str, level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter(service))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

