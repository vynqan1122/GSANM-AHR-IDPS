"""Concrete collectors for AHR-IDPS sensor and platform telemetry."""

from .falco import parse_falco
from .nginx import parse_nginx
from .suricata import parse_suricata
from .wazuh import parse_wazuh

__all__ = ["parse_falco", "parse_nginx", "parse_suricata", "parse_wazuh"]

