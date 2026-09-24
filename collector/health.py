"""Small file-based health registry and container healthcheck CLI."""

from __future__ import annotations

import argparse
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class HealthRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._started_at = utc_now()
        self._sources: dict[str, dict[str, Any]] = {}
        self._heartbeat_at = self._started_at

    def update(self, source: str, status: str, **details: Any) -> None:
        with self._lock:
            previous = self._sources.get(source, {})
            self._sources[source] = {
                **previous,
                **details,
                "status": status,
                "updated_at": utc_now(),
            }
            self._write_locked()

    def increment(self, source: str, counter: str, amount: int = 1, **details: Any) -> None:
        with self._lock:
            previous = self._sources.get(source, {})
            value = int(previous.get(counter, 0)) + amount
            self._sources[source] = {
                **previous,
                **details,
                counter: value,
                "updated_at": utc_now(),
            }
            self._write_locked()

    def heartbeat(self) -> None:
        with self._lock:
            self._heartbeat_at = utc_now()
            self._write_locked()

    def _write_locked(self) -> None:
        document = {
            "service": "collector",
            "status": "running",
            "started_at": self._started_at,
            "heartbeat_at": self._heartbeat_at,
            "sources": self._sources,
        }
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        os.replace(temporary, self.path)


def check_health(path: Path, max_age_seconds: float) -> tuple[bool, str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        heartbeat = datetime.fromisoformat(str(document["heartbeat_at"]).replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return False, f"collector health unavailable: {exc}"
    age = (datetime.now(UTC) - heartbeat.astimezone(UTC)).total_seconds()
    if age > max_age_seconds:
        return False, f"collector heartbeat is stale ({age:.1f}s)"
    return True, "collector heartbeat is current"


def check_redis() -> tuple[bool, str]:
    try:
        from redis import Redis

        redis_url = os.environ.get("REDIS_URL")
        password = os.environ.get("REDIS_PASSWORD") or None
        if redis_url:
            client = Redis.from_url(
                redis_url,
                password=password,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
        else:
            client = Redis(
                host=os.environ.get("REDIS_HOST", "redis"),
                port=int(os.environ.get("REDIS_PORT", "6379")),
                password=password,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
        healthy = bool(client.ping())
        client.close()
        return (healthy, "Redis PING succeeded" if healthy else "Redis PING returned false")
    except Exception as exc:  # redis-py exceptions differ across releases
        return False, f"Redis unavailable: {type(exc).__name__}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check AHR-IDPS collector heartbeat")
    parser.add_argument(
        "--path",
        type=Path,
        default=Path(
            os.environ.get(
                "COLLECTOR_HEARTBEAT_PATH",
                os.environ.get("COLLECTOR_HEALTH_PATH", "/var/lib/ahr-idps/collector/health.json"),
            )
        ),
    )
    parser.add_argument("--max-age", type=float, default=30.0)
    parser.add_argument("--skip-redis", action="store_true", help="Only for isolated file-heartbeat diagnostics")
    args = parser.parse_args()
    healthy, message = check_health(args.path, args.max_age)
    if not healthy:
        print(message)
        return 1
    if not args.skip_redis:
        redis_healthy, redis_message = check_redis()
        if not redis_healthy:
            print(redis_message)
            return 1
        message = f"{message}; {redis_message}"
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
