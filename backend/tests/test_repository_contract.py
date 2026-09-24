from __future__ import annotations

from backend.services.repository import _event_filters, _page


def test_pagination_is_bounded() -> None:
    assert _page(0, 500) == (1, 200, 0)
    assert _page(3, 25) == (3, 25, 50)


def test_event_filters_include_required_fields() -> None:
    clauses, params = _event_filters(
        {
            "source": "suricata",
            "severity": 7,
            "event_type": "alert",
            "src_ip": "127.0.0.1",
            "container": "dvwa",
        }
    )
    joined = " ".join(clauses)
    assert "source = :source" in joined
    assert "severity >= :severity" in joined
    assert "event_type = :event_type" in joined
    assert "src_ip = :src_ip" in joined
    assert "container ->> 'name' ILIKE :container" in joined
    assert params["container"] == "%dvwa%"
