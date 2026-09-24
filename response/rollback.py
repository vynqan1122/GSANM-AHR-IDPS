from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def rollback_record(response: dict[str, Any]) -> dict[str, Any]:
    action = response.get("action") or response.get("action_type")
    rollback_data = response.get("rollback_data") if isinstance(response.get("rollback_data"), dict) else {}
    return {
        "response_id": response.get("response_id"),
        "action": action,
        "target": response.get("target"),
        "rollback_status": "rolled_back",
        "rolled_back_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "rollback_data": rollback_data,
        "destructive": False,
    }

