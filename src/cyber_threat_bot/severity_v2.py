"""Composite "actionability" score for ranking CVEs operators must address now.

The legacy ``scoring.record_priority`` is kept for backward compatibility
with the briefs / render layer; this module produces a richer 0-100 score
that combines four signals:

  * **KEV listing**          — +50 if CISA KEV says it's actively exploited
  * **CVSS strength**        — +30 * CVSS / 10
  * **EPSS percentile**      — +20 * EPSS percentile in [0, 1]
  * **Disclosure freshness** — +10 if disclosed in last 7 days

The bands map roughly to the operator response:

  >= 70  CRITICAL_NOW    drop everything; KEV-listed or near-KEV
  50-69  HIGH            this cycle; chunky CVSS or near-KEV
  25-49  MEDIUM          next sprint
  <25    WATCH           track in case EPSS / KEV catches up

Numbers add up. Worst-case (KEV + CVSS 10 + EPSS 1.0 + fresh) = 110, but
we clamp to 100 so the upper band is unambiguous.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

KEV_BONUS = 50.0
CVSS_WEIGHT = 30.0
EPSS_WEIGHT = 20.0
FRESHNESS_BONUS = 10.0
FRESHNESS_WINDOW_DAYS = 7

TIER_CRITICAL = "CRITICAL_NOW"
TIER_HIGH = "HIGH"
TIER_MEDIUM = "MEDIUM"
TIER_WATCH = "WATCH"

TIER_THRESHOLDS = (
    (70.0, TIER_CRITICAL),
    (50.0, TIER_HIGH),
    (25.0, TIER_MEDIUM),
)


def _record_get(record: Any, key: str, default=None):
    if isinstance(record, dict):
        return record.get(key, default)
    return getattr(record, key, default)


def _is_kev(record: Any) -> bool:
    if _record_get(record, "exploited"):
        return True
    sources = _record_get(record, "sources", []) or []
    if any("kev" in str(s).lower() for s in sources):
        return True
    primary = str(_record_get(record, "source", "") or "").lower()
    return "kev" in primary


def _cvss(record: Any) -> float | None:
    score = _record_get(record, "score")
    if score is None:
        return None
    try:
        return float(score)
    except (TypeError, ValueError):
        return None


def _epss_percentile(record: Any) -> float | None:
    metadata = _record_get(record, "metadata", {}) or {}
    val = metadata.get("epss_percentile")
    if val is None:
        return None
    try:
        f = float(val)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(f, 1.0))


def _published_at(record: Any) -> datetime | None:
    raw = _record_get(record, "published_at")
    if raw is None:
        return None
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw.astimezone(timezone.utc)
    if isinstance(raw, str):
        normalized = raw.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return None


def _is_fresh(record: Any, *, now: datetime | None = None) -> bool:
    published = _published_at(record)
    if published is None:
        return False
    current = now or datetime.now(timezone.utc)
    return (current - published).total_seconds() <= FRESHNESS_WINDOW_DAYS * 86400


def actionability_score(record: Any, *, now: datetime | None = None) -> float:
    """Compute the composite 0-100 actionability score for one record."""
    score = 0.0
    if _is_kev(record):
        score += KEV_BONUS
    cvss = _cvss(record)
    if cvss is not None:
        score += CVSS_WEIGHT * max(0.0, min(cvss, 10.0)) / 10.0
    epss_pct = _epss_percentile(record)
    if epss_pct is not None:
        score += EPSS_WEIGHT * epss_pct
    if _is_fresh(record, now=now):
        score += FRESHNESS_BONUS
    # Clamp so 100 is genuinely the ceiling.
    return round(min(score, 100.0), 2)


def actionability_tier(score: float) -> str:
    for threshold, tier in TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return TIER_WATCH


def annotate_actionability(records, *, now: datetime | None = None):
    """In-place: stamp ``record.metadata['actionability_score'/'_tier']``.

    Works on ThreatRecord instances OR dicts. Returns the same iterable
    (as a list) so callers can chain.
    """
    out = []
    for rec in records:
        score = actionability_score(rec, now=now)
        tier = actionability_tier(score)
        if isinstance(rec, dict):
            meta = rec.setdefault("metadata", {})
            meta["actionability_score"] = score
            meta["actionability_tier"] = tier
        else:
            meta = getattr(rec, "metadata", None)
            if meta is None:
                # Defensive: ThreatRecord always has a metadata dict, but
                # third-party records may not.
                pass
            else:
                meta["actionability_score"] = score
                meta["actionability_tier"] = tier
        out.append(rec)
    return out


def prioritize(records, *, min_tier: str | None = None, now: datetime | None = None) -> list:
    """Return records sorted by actionability descending.

    If ``min_tier`` is provided, only records >= that tier are returned.
    Records are mutated to carry actionability fields (same as
    ``annotate_actionability``).
    """
    annotated = annotate_actionability(list(records), now=now)
    rank = {TIER_CRITICAL: 4, TIER_HIGH: 3, TIER_MEDIUM: 2, TIER_WATCH: 1}
    min_rank = rank.get((min_tier or "").upper(), 0)

    def _score_of(rec):
        if isinstance(rec, dict):
            return rec.get("metadata", {}).get("actionability_score", 0.0)
        return getattr(rec, "metadata", {}).get("actionability_score", 0.0)

    def _tier_of(rec) -> str:
        if isinstance(rec, dict):
            return rec.get("metadata", {}).get("actionability_tier", TIER_WATCH)
        return getattr(rec, "metadata", {}).get("actionability_tier", TIER_WATCH)

    if min_rank > 0:
        annotated = [r for r in annotated if rank.get(_tier_of(r), 0) >= min_rank]
    annotated.sort(key=_score_of, reverse=True)
    return annotated
