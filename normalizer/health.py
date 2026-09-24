"""Dependency-free container health check for the normalizer worker."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from .config import Settings


def check() -> tuple[bool, str]:
    settings = Settings.from_env()
    try:
        data = json.loads(settings.heartbeat_path.read_text(encoding="utf-8"))
        updated_at = datetime.fromisoformat(str(data["updated_at"]).replace("Z", "+00:00"))
        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - updated_at.astimezone(timezone.utc)).total_seconds()
        if age > settings.heartbeat_max_age_seconds:
            return False, f"heartbeat stale ({age:.1f}s)"
        if data.get("status") not in {"running", "migrations_complete"}:
            return False, f"service status is {data.get('status', 'unknown')}"
        return True, "normalizer heartbeat current"
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return False, f"heartbeat invalid: {type(exc).__name__}"


def main() -> None:
    healthy, message = check()
    print(message)
    raise SystemExit(0 if healthy else 1)


if __name__ == "__main__":
    main()
