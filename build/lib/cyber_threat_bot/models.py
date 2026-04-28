from __future__ import annotations

from dataclasses import field, dataclass
from datetime import datetime, timezone
from typing import Any


def ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return ensure_utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class Evidence:
    label: str
    url: str
    published_at: datetime | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "url": self.url,
            "published_at": isoformat(self.published_at),
            "note": self.note,
        }


@dataclass(slots=True)
class ThreatRecord:
    source: str
    source_type: str
    canonical_id: str
    title: str
    url: str
    published_at: datetime | None
    summary: str
    score: float | None = None
    exploited: bool = False
    tags: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "source_type": self.source_type,
            "canonical_id": self.canonical_id,
            "title": self.title,
            "url": self.url,
            "published_at": isoformat(self.published_at),
            "summary": self.summary,
            "score": self.score,
            "exploited": self.exploited,
            "tags": self.tags,
            "evidence": [item.to_dict() for item in self.evidence],
            "metadata": self.metadata,
        }

