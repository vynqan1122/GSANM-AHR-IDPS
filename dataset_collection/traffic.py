"""Benign and controlled DVWA scenario traffic."""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass

import httpx


HOST_HEADERS = {"Host": "dvwa.local", "Connection": "close"}


@dataclass(frozen=True, slots=True)
class RequestSpec:
    method: str
    path: str
    params: dict[str, str] | None = None
    data: dict[str, str] | None = None


BENIGN_FLOW = (
    RequestSpec("GET", "/"),
    RequestSpec("GET", "/login.php"),
    RequestSpec("GET", "/setup.php"),
    RequestSpec("GET", "/security.php"),
    RequestSpec("GET", "/instructions.php"),
    RequestSpec("GET", "/about.php"),
    RequestSpec("GET", "/vulnerabilities/brute/", {"username": "guest", "password": "guest", "Login": "Login"}),
    RequestSpec("GET", "/logout.php"),
)


CONTROLLED_SCENARIOS: dict[str, tuple[RequestSpec, ...]] = {
    "sql_injection": (
        RequestSpec("GET", "/vulnerabilities/sqli/", {"id": "1'", "Submit": "Submit"}),
        RequestSpec("GET", "/vulnerabilities/sqli/", {"id": "1 OR 1=1", "Submit": "Submit"}),
    ),
    "xss": (
        RequestSpec("GET", "/vulnerabilities/xss_r/", {"name": "<script>alert(1)</script>"}),
    ),
    "command_injection": (
        RequestSpec("GET", "/vulnerabilities/exec/", {"ip": "127.0.0.1; id", "Submit": "Submit"}),
    ),
    "file_inclusion": (
        RequestSpec("GET", "/vulnerabilities/fi/", {"page": "../../etc/passwd"}),
    ),
    "brute_force": (
        RequestSpec("GET", "/vulnerabilities/brute/", {"username": "admin", "password": "wrong1", "Login": "Login"}),
        RequestSpec("GET", "/vulnerabilities/brute/", {"username": "admin", "password": "wrong2", "Login": "Login"}),
        RequestSpec("GET", "/vulnerabilities/brute/", {"username": "admin", "password": "wrong3", "Login": "Login"}),
    ),
    "file_upload": (
        RequestSpec("GET", "/vulnerabilities/upload/"),
    ),
    "scanner_pattern": tuple(
        RequestSpec("GET", path)
        for path in ("/phpinfo.php", "/admin/", "/.env", "/server-status", "/robots.txt")
    ),
}


async def run_specs(
    target: str,
    specs: tuple[RequestSpec, ...],
    *,
    scenario_id: str,
    repeat: int,
    fast: bool,
) -> int:
    count = 0
    timeout = httpx.Timeout(10.0)
    async with httpx.AsyncClient(base_url=target, timeout=timeout, follow_redirects=True) as client:
        for _ in range(max(1, repeat)):
            for spec in specs:
                params = dict(spec.params or {})
                params["ahr_scenario"] = scenario_id
                if spec.method == "GET":
                    response = await client.get(
                        spec.path,
                        params=params,
                        headers=HOST_HEADERS,
                    )
                else:
                    response = await client.post(
                        spec.path,
                        params=params,
                        data=spec.data or {},
                        headers=HOST_HEADERS,
                    )
                if response.status_code >= 500:
                    raise RuntimeError(f"lab target returned HTTP {response.status_code}")
                count += 1
                if not fast:
                    await asyncio.sleep(random.uniform(0.15, 0.75))
    return count
