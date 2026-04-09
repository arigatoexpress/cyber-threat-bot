from __future__ import annotations

from datetime import datetime, timezone

from .models import ThreatRecord


def record_priority(record: ThreatRecord, *, now: datetime | None = None) -> float:
    current_time = now or datetime.now(timezone.utc)
    score = 0.0
    if record.exploited:
        score += 5.0
    if record.score is not None:
        score += min(record.score, 10.0) / 2.0
    if record.published_at is not None:
        age_days = max((current_time - record.published_at).total_seconds() / 86400, 0.0)
        score += max(0.0, 3.0 - min(age_days, 9.0) / 3.0)
    if "rce" in record.tags:
        score += 1.5
    return round(score, 2)
