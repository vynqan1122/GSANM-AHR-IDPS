"""Run authorized, local-only DVWA monitoring scenarios.

The script logs into the lab DVWA first, then sends low-volume requests that
exercise the existing AHR-IDPS sensors. It refuses non-loopback targets and
never performs persistence, exfiltration, reverse shells, or destructive writes.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx


@dataclass(frozen=True)
class Scenario:
    name: str
    method: str
    path: str
    params: dict[str, str]


SCENARIOS = {
    "baseline": (
        Scenario("home", "GET", "/", {}),
        Scenario("login_page", "GET", "/login.php", {}),
        Scenario("instructions", "GET", "/instructions.php", {}),
    ),
    "web_injection": (
        Scenario("sql_injection_signal", "GET", "/vulnerabilities/sqli/", {"id": "1 OR 1=1", "Submit": "Submit"}),
        Scenario("reflected_xss_signal", "GET", "/vulnerabilities/xss_r/", {"name": "<script>alert(1)</script>"}),
        Scenario("command_injection_signal", "GET", "/vulnerabilities/exec/", {"ip": "127.0.0.1; id", "Submit": "Submit"}),
        Scenario("file_inclusion_signal", "GET", "/vulnerabilities/fi/", {"page": "../../etc/passwd"}),
    ),
    "auth_abuse": (
        Scenario("scanner_env_probe", "GET", "/.env", {}),
        Scenario("brute_force_signal_1", "GET", "/vulnerabilities/brute/", {"username": "admin", "password": "wrong-lab-1", "Login": "Login"}),
        Scenario("brute_force_signal_2", "GET", "/vulnerabilities/brute/", {"username": "admin", "password": "wrong-lab-2", "Login": "Login"}),
        Scenario("brute_force_signal_3", "GET", "/vulnerabilities/brute/", {"username": "admin", "password": "wrong-lab-3", "Login": "Login"}),
    ),
}


def local_target(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise SystemExit("ABORT: target must be http://127.0.0.1 or http://localhost")
    return value.rstrip("/")


def token(html: str) -> str:
    match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", html)
    if not match:
        raise RuntimeError("DVWA login token was not found")
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Authorized local DVWA monitoring scenarios")
    parser.add_argument("--target", default="http://127.0.0.1:8080")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="password")
    parser.add_argument("--scenario-id", default=f"authorized_{int(time.time())}")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="baseline")
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--no-attack", action="store_true", help="Only verify login and benign landing pages")
    args = parser.parse_args()
    base = local_target(args.target)
    headers = {"Host": "dvwa.local", "Connection": "close"}

    with httpx.Client(base_url=base, headers=headers, follow_redirects=True, timeout=15.0) as client:
        login_page = client.get("/login.php")
        login_page.raise_for_status()
        response = client.post(
            "/login.php",
            data={"username": args.username, "password": args.password, "Login": "Login", "user_token": token(login_page.text)},
        )
        response.raise_for_status()
        if "Login failed" in response.text or "login.php" in str(response.url):
            raise SystemExit("ABORT: DVWA login failed")

        landing = client.get("/")
        landing.raise_for_status()
        print(f"LOGIN PASS scenario_id={args.scenario_id} status={landing.status_code}")

        if args.no_attack:
            return

        for scenario in SCENARIOS[args.scenario]:
            params = dict(scenario.params)
            params["ahr_scenario"] = f"{args.scenario_id}_{scenario.name}"
            result = client.request(scenario.method, scenario.path, params=params)
            if result.status_code >= 500:
                raise SystemExit(f"ABORT: {scenario.name} returned HTTP {result.status_code}")
            print(f"SCENARIO {scenario.name} status={result.status_code}")
            time.sleep(max(0.0, args.delay))

        print(f"COMPLETE scenario={args.scenario}: inspect /dashboard/#live, /dashboard/#alerts and /dashboard/#incidents")


if __name__ == "__main__":
    try:
        main()
    except (httpx.HTTPError, RuntimeError) as exc:
        print(f"ABORT: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
