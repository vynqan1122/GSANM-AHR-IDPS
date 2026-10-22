"""Fresh ingestion proves observed activity, not Docker process health."""
from datetime import datetime, timezone


def activity_status(last_ingestion, now=None):
    if not isinstance(last_ingestion, datetime):
        return 'unknown'
    if last_ingestion.tzinfo is None:
        last_ingestion = last_ingestion.replace(tzinfo=timezone.utc)
    age = ((now or datetime.now(timezone.utc)) - last_ingestion).total_seconds()
    return 'reporting' if -30 <= age <= 120 else 'stale'
