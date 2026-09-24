from __future__ import annotations

from typing import Any


def render(pattern: dict[str, Any], sid: int) -> str:
    method = str(pattern.get("http_method") or "GET")
    uri = str(pattern.get("uri_pattern") or "/")
    msg = f"AHR generated repeated HTTP behavior {method} {uri}"
    return (
        f'alert http any any -> any any (msg:"{msg}"; '
        f'flow:to_server,established; http.method; content:"{method}"; '
        f'http.uri; content:"{uri}"; startswith; '
        f'classtype:web-application-attack; sid:{sid}; rev:1;)'
    )

