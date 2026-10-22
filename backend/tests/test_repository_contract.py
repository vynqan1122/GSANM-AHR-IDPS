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


def test_activity_status_does_not_treat_old_data_as_current_health():
    from datetime import datetime, timedelta, timezone
    from backend.services.activity import activity_status
    now=datetime(2026,10,22,tzinfo=timezone.utc)
    assert activity_status(now-timedelta(seconds=20),now)=='reporting'
    assert activity_status(now-timedelta(minutes=10),now)=='stale'
    assert activity_status(now+timedelta(minutes=5),now)=='stale'
    assert activity_status(None,now)=='unknown'


def test_numeric_database_metrics_serialize_as_numbers():
    from decimal import Decimal
    from backend.services.repository import _jsonable
    data=_jsonable({'flows_per_sec':Decimal('3.400000'), 'bytes_per_sec':Decimal('0E-20')})
    assert data=={'flows_per_sec':3.4,'bytes_per_sec':0.0}
    assert isinstance(data['flows_per_sec'],float)
