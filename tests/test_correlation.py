"""Tests for cross-source dedup, confidence scoring, and CVE clustering."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cyber_threat_bot.correlation import (
    annotate_confidence,
    compute_confidence,
    correlate_records,
)
from cyber_threat_bot.models import Evidence, ThreatRecord
from cyber_threat_bot.sources import merge_records


def _record(
    canonical_id: str,
    *,
    source: str = "nvd",
    score: float | None = None,
    tags: list[str] | None = None,
    metadata: dict | None = None,
    title: str | None = None,
    summary: str = "stub",
) -> ThreatRecord:
    return ThreatRecord(
        source=source,
        source_type="cve",
        canonical_id=canonical_id,
        title=title or f"{canonical_id}: stub",
        url=f"https://example.invalid/{canonical_id}",
        published_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        summary=summary,
        score=score,
        tags=tags or [],
        evidence=[Evidence(label="ref", url=f"https://example.invalid/ref/{canonical_id}")],
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# compute_confidence
# ---------------------------------------------------------------------------

def test_confidence_single_source_no_cvss_is_low():
    rec = _record("CVE-2026-0001")
    rec.sources = ["nvd"]
    # 0.4 * (1/3) + 0.6 * 0 = 0.133
    assert compute_confidence(rec) == pytest.approx(0.133, abs=1e-3)


def test_confidence_three_sources_caps_agreement():
    rec = _record("CVE-2026-0001")
    rec.sources = ["nvd", "cisa-kev", "darkreading"]
    # 0.4 * 1.0 + 0.6 * 0 = 0.4
    assert compute_confidence(rec) == pytest.approx(0.4, abs=1e-3)


def test_confidence_high_cvss_dominates():
    rec = _record("CVE-2026-0001", score=9.8)
    rec.sources = ["nvd"]
    # 0.4 * (1/3) + 0.6 * 0.98 = 0.133 + 0.588 = 0.721
    assert compute_confidence(rec) == pytest.approx(0.721, abs=1e-3)


def test_confidence_perfect_score():
    rec = _record("CVE-2026-0001", score=10.0)
    rec.sources = ["nvd", "cisa-kev", "darkreading", "fourth"]
    # 0.4 * 1.0 + 0.6 * 1.0 = 1.0
    assert compute_confidence(rec) == 1.0


def test_confidence_clamps_negative_score():
    rec = _record("CVE-2026-0001", score=-1.0)
    rec.sources = ["nvd"]
    # cvss factor 0; agreement 1/3
    assert compute_confidence(rec) == pytest.approx(0.133, abs=1e-3)


def test_confidence_falls_back_to_metadata_source_set():
    rec = _record("CVE-2026-0001", score=5.0)
    rec.metadata["source_set"] = ["nvd", "cisa-kev"]
    # 0.4 * (2/3) + 0.6 * 0.5 = 0.267 + 0.3 = 0.567
    assert compute_confidence(rec) == pytest.approx(0.567, abs=1e-3)


# ---------------------------------------------------------------------------
# annotate_confidence
# ---------------------------------------------------------------------------

def test_annotate_confidence_promotes_source_set_and_stamps_score():
    rec = _record("CVE-2026-0001", score=7.5)
    rec.metadata["source_set"] = ["nvd", "cisa-kev"]
    annotate_confidence([rec])
    assert rec.sources == ["nvd", "cisa-kev"]
    assert rec.confidence is not None
    assert 0.0 < rec.confidence <= 1.0


def test_annotate_confidence_falls_back_to_primary_source():
    rec = _record("CVE-2026-0001", source="nvd")
    annotate_confidence([rec])
    assert rec.sources == ["nvd"]


# ---------------------------------------------------------------------------
# merge_records still works after model change (regression)
# ---------------------------------------------------------------------------

def test_merge_records_dedupes_same_cve_across_sources():
    a = _record("CVE-2026-0001", source="nvd", score=7.0)
    b = _record("CVE-2026-0001", source="cisa-kev", score=None)
    b.exploited = True
    merged = merge_records([a, b])
    assert len(merged) == 1
    rec = merged[0]
    # source_set carries both, primary source becomes the joined string.
    assert "nvd" in rec.metadata["source_set"]
    assert "cisa-kev" in rec.metadata["source_set"]
    assert rec.exploited is True
    assert rec.score == 7.0


# ---------------------------------------------------------------------------
# correlate_records
# ---------------------------------------------------------------------------

def test_correlate_groups_by_cwe():
    recs = [
        _record("CVE-2026-A", tags=["CWE-79", "xss"]),
        _record("CVE-2026-B", tags=["CWE-79", "xss"]),
        _record("CVE-2026-C", tags=["CWE-89"]),
    ]
    out = correlate_records(recs)
    # CWE-79 has 2 members -> kept; CWE-89 only 1 -> dropped.
    assert "CWE-79" in out["cwe"]
    assert sorted(out["cwe"]["CWE-79"]) == ["CVE-2026-A", "CVE-2026-B"]
    assert "CWE-89" not in out["cwe"]


def test_correlate_groups_by_vendor_and_product():
    recs = [
        _record("CVE-2026-A", metadata={"vendor_project": "Linux", "product": "Kernel"}),
        _record("CVE-2026-B", metadata={"vendor_project": "Linux", "product": "Kernel"}),
        _record("CVE-2026-C", metadata={"vendor_project": "Microsoft"}),
    ]
    out = correlate_records(recs)
    assert out["vendor"]["linux"] == ["CVE-2026-A", "CVE-2026-B"]
    assert out["product"]["kernel"] == ["CVE-2026-A", "CVE-2026-B"]
    # Microsoft singleton: dropped.
    assert "microsoft" not in out["vendor"]


def test_correlate_drops_generic_tag_keys():
    recs = [
        _record("CVE-2026-A", tags=["kev", "rce"]),
        _record("CVE-2026-B", tags=["kev", "rce"]),
    ]
    out = correlate_records(recs)
    # 'kev' is generic and excluded; 'rce' is a real category.
    assert "kev" not in out["tag"]
    assert "rce" in out["tag"]


def test_correlate_min_group_size():
    recs = [
        _record(f"CVE-2026-{i}", tags=["CWE-79"]) for i in range(3)
    ]
    out = correlate_records(recs, min_group_size=3)
    assert "CWE-79" in out["cwe"]
    out2 = correlate_records(recs[:2], min_group_size=3)
    assert "CWE-79" not in out2["cwe"]  # only 2 < min_group_size=3


def test_correlate_works_on_dict_records():
    """End-to-end: cached snapshot is dicts (post to_dict). Correlation must work on them."""
    recs = [
        _record("CVE-2026-A", tags=["CWE-79"]).to_dict(),
        _record("CVE-2026-B", tags=["CWE-79"]).to_dict(),
    ]
    out = correlate_records(recs)
    assert "CWE-79" in out["cwe"]


def test_correlate_orders_by_descending_size():
    recs = [
        _record("CVE-A", tags=["CWE-1"]),
        _record("CVE-B", tags=["CWE-1"]),
        _record("CVE-C", tags=["CWE-2"]),
        _record("CVE-D", tags=["CWE-2"]),
        _record("CVE-E", tags=["CWE-2"]),
    ]
    out = correlate_records(recs)
    keys = list(out["cwe"].keys())
    assert keys[0] == "CWE-2"  # 3 members
    assert keys[1] == "CWE-1"  # 2 members
