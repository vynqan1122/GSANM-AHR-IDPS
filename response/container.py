from __future__ import annotations

import re
from dataclasses import dataclass, asdict


SAFE_CONTAINER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
PROTECTED_NAMES = {"postgres", "redis", "mariadb"}


@dataclass(frozen=True, slots=True)
class IsolationPlan:
    container: str
    action: str
    disconnect_networks: list[str]
    preserve_networks: list[str]
    deletes_container: bool
    deletes_volumes: bool
    deletes_logs: bool
    applied: bool

    def to_json(self) -> dict[str, object]:
        return asdict(self)


def safe_isolation_plan(container_name: str, *, apply: bool = False) -> IsolationPlan:
    if not SAFE_CONTAINER.fullmatch(container_name):
        raise ValueError(f"unsafe container name: {container_name}")
    short = container_name.split("-")[-1]
    if short in PROTECTED_NAMES:
        raise ValueError(f"refusing to isolate protected data service: {container_name}")
    return IsolationPlan(
        container=container_name,
        action="disconnect_application_network",
        disconnect_networks=["dvwa_front"],
        preserve_networks=["data", "forensics"],
        deletes_container=False,
        deletes_volumes=False,
        deletes_logs=False,
        applied=apply,
    )

