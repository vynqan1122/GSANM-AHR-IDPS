from __future__ import annotations

from typing import Any


VALID_STATES = {"candidate", "validating", "shadow", "active", "rejected", "disabled"}


def require_valid_state(status: str) -> str:
    normalized = status.lower()
    if normalized not in VALID_STATES:
        raise ValueError(f"invalid rule state: {status}")
    return normalized


async def promote_active(connection: Any, rule_id: str, *, approved: bool = False) -> None:
    if not approved:
        raise PermissionError("manual approval is required to promote a shadow rule to active")
    row = await connection.fetchrow("SELECT status FROM ahr.rules WHERE rule_id = $1", rule_id)
    if not row:
        raise RuntimeError(f"rule not found: {rule_id}")
    if row["status"] != "shadow":
        raise RuntimeError("only SHADOW rules can be promoted to ACTIVE")
    await connection.execute("UPDATE ahr.rules SET status = 'active', updated_at = now() WHERE rule_id = $1", rule_id)


async def reject_rule(connection: Any, rule_id: str, reason: str = "manual") -> None:
    await connection.execute(
        "UPDATE ahr.rules SET status = 'rejected', disabled_reason = $2, updated_at = now() WHERE rule_id = $1",
        rule_id,
        reason,
    )


async def disable_rule(connection: Any, rule_id: str, reason: str = "manual") -> None:
    await connection.execute(
        "UPDATE ahr.rules SET status = 'disabled', disabled_reason = $2, updated_at = now() WHERE rule_id = $1",
        rule_id,
        reason,
    )
