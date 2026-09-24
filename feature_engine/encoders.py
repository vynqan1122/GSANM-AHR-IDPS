from __future__ import annotations


def port_class(port: int | None) -> float:
    if port is None:
        return 0.0
    if port in {80, 443, 8080, 8000}:
        return 1.0
    if port < 1024:
        return 2.0
    return 3.0


def protocol_flags(protocol: str | None) -> tuple[float, float, float]:
    value = (protocol or "").lower()
    return (
        1.0 if value in {"tcp", "http"} else 0.0,
        1.0 if value == "udp" else 0.0,
        1.0 if value == "http" else 0.0,
    )
