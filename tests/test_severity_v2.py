"""Tests for the composite actionability score (Lane 3)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cyber_threat_bot.models import Evidence, ThreatRecord
from cyber_threat_bot.severity_v2 import (
    EPSS_WEIGHT,
    FRESHNESS_BONUS,
    KEV_BONUS,
    TIER_CRITICAL,
    TIER_HIGH,
    TIER_MEDIUM,
    TIER_WATCH,
    actionability_score,
    actionability_tier,
    annotate_actionability,
    prioritize,
)


REF_NOW = datetime(2026, 5, 1, tzinfo=timezone.utc)


def _record(
    cve: str = "CVE-2026-0001",
    *,
    score: float | None = None,
    exploited: bool = False,
    sources: list[str] | None = None,
    epss_percentile: float | None = None,
    published_at: datetime | None = None,
    metadata: dict | None = None,
) -> ThreatRecord:
    md = dict(metadata or {})
    if epss_percentile is not None:
        md["epss_percentile"] = epss_percentile
    rec = ThreatRecord(
        source="nvd",
        source_type="cve",
        canonical_id=cve,
        title=f"{cve}: stub",
        url=f"https://example.invalid/{cve}",
        published_at=published_at,
        summary="stub",
        score=score,
        exploited=exploited,
        evidence=[Evidence(label="ref", url="https://example.invalid/ref")],
        metadata=md,
    )
    if sources is not None:
        rec.sources = sources
    return rec


# ---------------------------------------------------------------------------
# actionability_score
# ---------------------------------------------------------------------------

def test_score_kev_only():
    rec = _record(exploited=True)
    assert actionability_score(rec, now=REF_NOW) == KEV_BONUS


def test_score_cvss_only():
    rec = _record(score=10.0)
    # 30 * 10 / 10 = 30
    assert actionability_score(rec, now=REF_NOW) == 30.0


def test_score_epss_only():
    rec = _record(epss_percentile=1.0)
    assert actionability_score(rec, now=REF_NOW) == EPSS_WEIGHT


def test_score_freshness_only():
    rec = _record(published_at=REF_NOW - timedelta(days=2))
    assert actionability_score(rec, now=REF_NOW) == FRESHNESS_BONUS


def test_score_old_record_no_freshness_bonus():
    rec = _record(published_at=REF_NOW - timedelta(days=30))
    assert actionability_score(rec, now=REF_NOW) == 0.0


def test_score_full_stack_clamps_to_100():
    rec = _record(
        exploited=True,
        score=10.0,
        epss_percentile=1.0,
        published_at=REF_NOW - timedelta(days=1),
    )
    # raw 50 + 30 + 20 + 10 = 110; clamps to 100.
    assert actionability_score(rec, now=REF_NOW) == 100.0


def test_score_kev_via_sources_field():
    """A record promoted from CISA KEV via merge has sources=['cisa-kev'] but
    may not have ``exploited=True`` if it's a side feed."""
    rec = _record(sources=["cisa-kev"])
    assert actionability_score(rec, now=REF_NOW) == KEV_BONUS


def test_score_handles_dict_record():
    rec = _record(score=7.5, epss_percentile=0.8).to_dict()
    # 30 * 0.75 + 20 * 0.8 = 22.5 + 16 = 38.5
    assert actionability_score(rec, now=REF_NOW) == 38.5


def test_score_handles_iso_string_published_at():
    rec = _record(score=5.0).to_dict()
    rec["published_at"] = (REF_NOW - timedelta(days=3)).isoformat().replace("+00:00", "Z")
    # 30 * 0.5 + freshness 10 = 25
    assert actionability_score(rec, now=REF_NOW) == 25.0


def test_score_clamps_out_of_range_cvss():
    # An ill-formed upstream might produce >10 or <0.
    rec = _record(score=15.0)
    assert actionability_score(rec, now=REF_NOW) == 30.0
    rec = _record(score=-5.0)
    assert actionability_score(rec, now=REF_NOW) == 0.0


# ---------------------------------------------------------------------------
# actionability_tier
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "score,expected",
    [
        (100, TIER_CRITICAL),
        (75, TIER_CRITICAL),
        (70, TIER_CRITICAL),
        (69.99, TIER_HIGH),
        (50, TIER_HIGH),
        (49.99, TIER_MEDIUM),
        (25, TIER_MEDIUM),
        (24.99, TIER_WATCH),
        (0, TIER_WATCH),
    ],
)
def test_tier_thresholds(score, expected):
    assert actionability_tier(score) == expected


# ---------------------------------------------------------------------------
# annotate / prioritize
# ---------------------------------------------------------------------------

def test_annotate_stamps_metadata_on_threat_record():
    rec = _record(score=10.0, exploited=True, epss_percentile=1.0, published_at=REF_NOW)
    annotate_actionability([rec], now=REF_NOW)
    assert rec.metadata["actionability_score"] == 100.0
    assert rec.metadata["actionability_tier"] == TIER_CRITICAL


def test_annotate_stamps_metadata_on_dict():
    d = _record(score=5.0).to_dict()
    annotate_actionability([d], now=REF_NOW)
    assert d["metadata"]["actionability_score"] == 15.0
    assert d["metadata"]["actionability_tier"] == TIER_WATCH


def test_prioritize_orders_descending_and_filters():
    recs = [
        _record("CVE-A", exploited=True, score=10.0, epss_percentile=1.0, published_at=REF_NOW),  # 100 CRITICAL
        _record("CVE-B", score=8.0, epss_percentile=0.5),                                          # 24+10=34 MEDIUM
        _record("CVE-C", score=2.0),                                                               # 6 WATCH
        _record("CVE-D", exploited=True, score=4.0),                                               # 50+12=62 HIGH
    ]
    out = prioritize(recs, now=REF_NOW)
    ids = [r.canonical_id for r in out]
    assert ids == ["CVE-A", "CVE-D", "CVE-B", "CVE-C"]

    only_high = prioritize(recs, min_tier="HIGH", now=REF_NOW)
    assert [r.canonical_id for r in only_high] == ["CVE-A", "CVE-D"]

    only_critical = prioritize(recs, min_tier="CRITICAL_NOW", now=REF_NOW)
    assert [r.canonical_id for r in only_critical] == ["CVE-A"]


def test_prioritize_works_on_dict_inputs():
    recs = [_record("CVE-A", score=9.0).to_dict(), _record("CVE-B", score=2.0).to_dict()]
    out = prioritize(recs, now=REF_NOW)
    assert out[0]["canonical_id"] == "CVE-A"
