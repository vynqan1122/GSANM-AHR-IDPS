from __future__ import annotations

import re
from typing import Any


HEXISH = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)
NUMBER = re.compile(r"\b\d+\b")


def generalize_uri(uri: str) -> str:
    value = uri.split("?", 1)[0]
    value = HEXISH.sub("*", value)
    value = NUMBER.sub("*", value)
    return value or "/"


def http_method(events: list[dict[str, Any]]) -> str:
    methods = [str((event.get("http") or {}).get("method") or "GET").upper() for event in events]
    return max(set(methods), key=methods.count) if methods else "GET"


def abstract_pattern(events: list[dict[str, Any]]) -> dict[str, Any]:
    first = events[0]
    http = first.get("http") if isinstance(first.get("http"), dict) else {}
    process = first.get("process") if isinstance(first.get("process"), dict) else {}
    container = first.get("container") if isinstance(first.get("container"), dict) else {}
    uris = [generalize_uri(str((event.get("http") or {}).get("uri") or (event.get("http") or {}).get("url") or "")) for event in events]
    uri_pattern = max(set(uris), key=uris.count) if uris else ""
    pattern_type = "network" if http or first.get("source") in {"nginx", "suricata"} else "host"
    if process or first.get("source") == "falco":
        pattern_type = "runtime"
    if first.get("source") == "wazuh":
        pattern_type = "host"
    return {
        "type": pattern_type,
        "source": first.get("source"),
        "event_type": first.get("event_type"),
        "http_method": http_method(events),
        "uri_pattern": uri_pattern,
        "protocol": first.get("protocol"),
        "dst_port_class": "web" if int(first.get("dst_port") or 0) in {80, 443, 8080} else "other",
        "container_role": container.get("name") or "",
        "process_family": process.get("name") or process.get("command_line") or "",
        "support_examples": [event["event_id"] for event in events[:5]],
    }


def contains_sample_specific_artifact(content: str, examples: list[dict[str, Any]]) -> bool:
    for event in examples:
        for key in ("src_ip", "event_id", "source_event_id"):
            value = event.get(key)
            if value and str(value) in content:
                return True
        process = event.get("process") if isinstance(event.get("process"), dict) else {}
        pid = process.get("pid")
        if pid and str(pid) in content:
            return True
    return False

