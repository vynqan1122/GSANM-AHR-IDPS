from __future__ import annotations

from typing import Any


def select_engine(pattern: dict[str, Any]) -> str:
    if pattern.get("type") == "network":
        return "suricata"
    if pattern.get("type") == "runtime":
        return "falco"
    return "wazuh"

