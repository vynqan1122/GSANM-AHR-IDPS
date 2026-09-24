"""AHR-IDPS collector service entry point."""

from __future__ import annotations

import asyncio
import logging
import signal

from ahr_common.logging import configure_logging

from .base import JsonlFileCollector, RedisPublisher
from .checkpoint import CheckpointStore, DeadLetterStore
from .collectors import parse_falco, parse_nginx, parse_suricata, parse_wazuh
from .collectors.docker_events import DockerEventsCollector
from .collectors.system import SystemCollector
from .config import CollectorConfig
from .health import HealthRegistry

LOGGER = logging.getLogger(__name__)


async def heartbeat(health: HealthRegistry, stop: asyncio.Event, interval: float) -> None:
    while not stop.is_set():
        health.heartbeat()
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            pass


async def run(config: CollectorConfig) -> None:
    try:
        from redis.asyncio import Redis
    except ImportError as exc:  # pragma: no cover - packaging failure path
        raise RuntimeError("redis package is required to run the collector") from exc

    health = HealthRegistry(config.health_path)
    checkpoints = CheckpointStore(config.checkpoint_path)
    dead_letters = DeadLetterStore(config.dead_letter_path)
    redis_client = Redis.from_url(
        config.redis_url,
        password=config.redis_password,
        decode_responses=True,
        health_check_interval=15,
        socket_connect_timeout=5,
        socket_timeout=10,
    )
    publisher = RedisPublisher(
        redis_client,
        stream=config.raw_stream,
        maxlen=config.stream_maxlen,
        dedupe_ttl_seconds=config.dedupe_ttl_seconds,
        retry_initial_seconds=config.redis_retry_initial_seconds,
        retry_max_seconds=config.redis_retry_max_seconds,
        health=health,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows unit/dev execution
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))

    parsers = {
        "suricata": parse_suricata,
        "falco": parse_falco,
        "wazuh": parse_wazuh,
        "nginx": parse_nginx,
    }
    tasks: list[asyncio.Task[None]] = []
    for source in config.file_sources:
        if not source.enabled:
            health.update(source.name, "disabled", path=str(source.path))
            continue
        collector = JsonlFileCollector(
            source=source.name,
            path=source.path,
            parser=parsers[source.name],
            checkpoints=checkpoints,
            dead_letters=dead_letters,
            publisher=publisher,
            health=health,
            max_line_bytes=config.max_line_bytes,
            poll_interval_seconds=config.poll_interval_seconds,
            start_at_end_for_new_files=config.start_at_end_for_new_files,
        )
        tasks.append(asyncio.create_task(collector.run(stop), name=f"collector-{source.name}"))

    if config.docker_events_enabled:
        docker = DockerEventsCollector(
            socket_path=config.docker_socket,
            api_version=config.docker_api_version,
            checkpoints=checkpoints,
            publisher=publisher,
            health=health,
        )
        tasks.append(asyncio.create_task(docker.run(stop), name="collector-docker"))
    else:
        health.update("docker", "disabled")
    if config.system_metrics_enabled:
        system = SystemCollector(publisher, health, config.system_interval_seconds)
        tasks.append(asyncio.create_task(system.run(stop), name="collector-system"))
    else:
        health.update("system", "disabled")
    tasks.append(
        asyncio.create_task(heartbeat(health, stop, config.heartbeat_interval_seconds), name="collector-heartbeat")
    )

    LOGGER.info("collector started with %d data source tasks", len(tasks) - 1)
    try:
        await stop.wait()
    finally:
        stop.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await redis_client.aclose()
        checkpoints.close()


def main() -> int:
    configure_logging("collector")
    config = CollectorConfig.from_env()
    asyncio.run(run(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
