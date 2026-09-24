"""Source-specific adapters into :class:`normalizer.schemas.SecurityEvent`."""

from __future__ import annotations

from collections.abc import Callable

from normalizer.schemas import RawEnvelope, SecurityEvent

from .docker import map_docker
from .falco import map_falco
from .nginx import map_nginx
from .suricata import map_suricata
from .system import map_system
from .wazuh import map_wazuh

Mapper = Callable[[RawEnvelope], SecurityEvent]

MAPPERS: dict[str, Mapper] = {
    "suricata": map_suricata,
    "falco": map_falco,
    "wazuh": map_wazuh,
    "nginx": map_nginx,
    "docker": map_docker,
    "docker_events": map_docker,
    "system": map_system,
}


def normalize(envelope: RawEnvelope) -> SecurityEvent:
    try:
        mapper = MAPPERS[envelope.source.lower()]
    except KeyError as exc:
        raise ValueError(f"unsupported event source: {envelope.source}") from exc
    return mapper(envelope)


__all__ = ["normalize"]
