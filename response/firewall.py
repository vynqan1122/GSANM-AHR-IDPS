from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True, slots=True)
class FirewallBlock:
    target_ip: str
    tag: str
    expires_at: datetime
    rollback_token: str
    applied: bool
    implementation: str

    def to_json(self) -> dict[str, object]:
        data = asdict(self)
        data["expires_at"] = self.expires_at.isoformat().replace("+00:00", "Z")
        return data


def is_lab_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local)


def temporary_lab_block(target_ip: str, *, incident_id: str, ttl_seconds: int = 900, apply: bool = False) -> FirewallBlock:
    if not is_lab_ip(target_ip):
        raise ValueError(f"refusing to block non-lab IP address: {target_ip}")
    ttl = max(60, min(int(ttl_seconds), 3600))
    expires = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    tag = f"AHR-IDPS:{incident_id}:{target_ip}"
    token = hashlib.sha256(f"{tag}:{expires.timestamp()}".encode()).hexdigest()
    return FirewallBlock(
        target_ip=target_ip,
        tag=tag,
        expires_at=expires,
        rollback_token=token,
        applied=apply,
        implementation="lab-audit-wrapper" if apply else "dry-run-lab-audit-wrapper",
    )

