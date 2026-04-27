"""Edge-case tests for severity / classification helpers.

Covers boundary behavior for:
- ``_extract_cvss`` (empty metrics, missing keys, malformed types, version ordering)
- ``_extract_cwes`` (empty weaknesses, missing description, dedup, mixed-case preservation)
- ``_keyword_tags`` (case-insensitivity, multi-match, empty input)
- ``clean_text`` (``None``, empty, HTML entities, whitespace collapsing)
- ``record_priority`` (missing score, missing timestamp, exploited+rce stacking)
- ``parse_nvd`` (empty payload, malformed CVE entries, missing severity, missing CWE)

All inputs are constructed in-memory; no real network calls are made.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cyber_threat_bot.models import ThreatRecord
from cyber_threat_bot.scoring import record_priority
from cyber_threat_bot.sources import (
    _extract_cvss,
    _extract_cwes,
    _keyword_tags,
    clean_text,
    parse_nvd,
)


# ---------------------------------------------------------------------------
# _extract_cvss
# ---------------------------------------------------------------------------


def test_extract_cvss_empty_metrics_returns_none_pair():
    assert _extract_cvss({}) == (None, None)


def test_extract_cvss_all_keys_empty_lists_returns_none_pair():
    metrics = {
        "cvssMetricV40": [],
        "cvssMetricV31": [],
        "cvssMetricV30": [],
        "cvssMetricV2": [],
    }
    assert _extract_cvss(metrics) == (None, None)


def test_extract_cvss_unknown_keys_only_returns_none_pair():
    metrics = {"someOtherMetric": [{"cvssData": {"baseScore": 9.9}}]}
    assert _extract_cvss(metrics) == (None, None)


def test_extract_cvss_prefers_v40_over_lower_versions():
    metrics = {
        "cvssMetricV40": [{"cvssData": {"baseScore": 9.5, "vectorString": "CVSS:4.0/x"}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "vectorString": "CVSS:3.1/x"}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 6.0, "vectorString": "AV:N"}}],
    }
    assert _extract_cvss(metrics) == (9.5, "CVSS:4.0/x")


def test_extract_cvss_falls_back_to_v2_when_higher_versions_missing():
    metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L"}}]}
    assert _extract_cvss(metrics) == (5.0, "AV:N/AC:L")


def test_extract_cvss_missing_cvss_data_returns_none_pair_for_that_entry():
    """Empty cvssData dict yields (None, None) — no KeyError."""
    metrics = {"cvssMetricV31": [{}]}
    assert _extract_cvss(metrics) == (None, None)


def test_extract_cvss_partial_cvss_data_only_score():
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}
    score, vector = _extract_cvss(metrics)
    assert score == 7.5
    assert vector is None


def test_extract_cvss_partial_cvss_data_only_vector():
    metrics = {"cvssMetricV31": [{"cvssData": {"vectorString": "CVSS:3.1/AV:N"}}]}
    score, vector = _extract_cvss(metrics)
    assert score is None
    assert vector == "CVSS:3.1/AV:N"


def test_extract_cvss_zero_score_is_preserved_not_treated_as_missing():
    """Score of 0.0 (informational) must be returned, not collapsed to None."""
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 0.0, "vectorString": "x"}}]}
    score, _ = _extract_cvss(metrics)
    assert score == 0.0


def test_extract_cvss_coerces_numeric_string_score():
    """A numeric string baseScore (e.g. NVD returning ``"9.8"``) is coerced
    to ``float`` to match the function's declared return type.
    """
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": "9.8", "vectorString": "x"}}]}
    score, vector = _extract_cvss(metrics)
    assert score == 9.8
    assert isinstance(score, float)
    assert vector == "x"


def test_extract_cvss_drops_non_numeric_string_score():
    """A non-numeric baseScore returns ``None`` (and logs) rather than
    silently bleeding the bad value to downstream consumers.
    """
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": "garbage", "vectorString": "x"}}]}
    score, vector = _extract_cvss(metrics)
    assert score is None
    # Vector is preserved so callers can still surface partial info.
    assert vector == "x"


def test_extract_cvss_none_in_candidate_list_position_treated_as_empty():
    """A ``None`` value for a metric key (instead of a list) is treated as empty."""
    metrics = {"cvssMetricV31": None, "cvssMetricV30": [{"cvssData": {"baseScore": 4.0}}]}
    score, _ = _extract_cvss(metrics)
    assert score == 4.0


# ---------------------------------------------------------------------------
# _extract_cwes
# ---------------------------------------------------------------------------


def test_extract_cwes_empty_cve_returns_empty_list():
    assert _extract_cwes({}) == []


def test_extract_cwes_no_weaknesses_key_returns_empty_list():
    assert _extract_cwes({"id": "CVE-2026-0001"}) == []


def test_extract_cwes_weakness_without_description_returns_empty_list():
    assert _extract_cwes({"weaknesses": [{}]}) == []


def test_extract_cwes_dedupes_repeated_values():
    cve = {
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-79"}]},
            {"description": [{"lang": "en", "value": "CWE-79"}]},
            {"description": [{"lang": "en", "value": "CWE-89"}]},
        ]
    }
    assert _extract_cwes(cve) == ["CWE-79", "CWE-89"]


def test_extract_cwes_preserves_mixed_case_input():
    """clean_text only normalizes whitespace — case is preserved as-is."""
    cve = {"weaknesses": [{"description": [{"lang": "en", "value": "cwe-352"}]}]}
    assert _extract_cwes(cve) == ["cwe-352"]


def test_extract_cwes_collapses_internal_whitespace():
    cve = {
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-79  \n  Cross-site Scripting"}]}
        ]
    }
    assert _extract_cwes(cve) == ["CWE-79 Cross-site Scripting"]


def test_extract_cwes_skips_blank_descriptions():
    cve = {
        "weaknesses": [
            {"description": [{"lang": "en", "value": ""}]},
            {"description": [{"lang": "en", "value": "   "}]},
            {"description": [{"lang": "en", "value": "CWE-22"}]},
        ]
    }
    assert _extract_cwes(cve) == ["CWE-22"]


# ---------------------------------------------------------------------------
# _keyword_tags
# ---------------------------------------------------------------------------


def test_keyword_tags_empty_string_returns_empty_list():
    assert _keyword_tags("") == []


def test_keyword_tags_no_match_returns_empty_list():
    assert _keyword_tags("a benign report about gardening tools") == []


def test_keyword_tags_is_case_insensitive():
    tags = _keyword_tags("Remote Code Execution via UNSAFE deserialization")
    assert "rce" in tags
    assert "deserialization" in tags


def test_keyword_tags_returns_multiple_categories_when_present():
    tags = _keyword_tags(
        "SQL injection plus path traversal (../) plus prompt injection in an LLM agent"
    )
    assert "injection" in tags
    assert "path-traversal" in tags
    assert "ai" in tags


def test_keyword_tags_is_deterministic_in_order():
    """Same input always returns the same ordered list (dict insertion order)."""
    text = "Remote code execution via authentication bypass"
    assert _keyword_tags(text) == _keyword_tags(text)


# ---------------------------------------------------------------------------
# clean_text
# ---------------------------------------------------------------------------


def test_clean_text_none_returns_empty_string():
    assert clean_text(None) == ""


def test_clean_text_empty_string_returns_empty_string():
    assert clean_text("") == ""


def test_clean_text_whitespace_only_returns_empty_string():
    assert clean_text("   \n\t  ") == ""


def test_clean_text_collapses_internal_whitespace():
    assert clean_text("foo   bar\n\tbaz") == "foo bar baz"


def test_clean_text_unescapes_html_entities():
    assert clean_text("AT&amp;T &lt;script&gt;") == "AT&T <script>"


# ---------------------------------------------------------------------------
# record_priority
# ---------------------------------------------------------------------------


def _baseline_record(**overrides) -> ThreatRecord:
    base = dict(
        source="nvd",
        source_type="cve",
        canonical_id="CVE-2026-0001",
        title="Example",
        url="https://example.invalid/CVE-2026-0001",
        published_at=None,
        summary="example",
        score=None,
        exploited=False,
        tags=[],
    )
    base.update(overrides)
    return ThreatRecord(**base)


def test_record_priority_zero_when_all_signals_missing():
    record = _baseline_record()
    assert record_priority(record) == 0.0


def test_record_priority_exploited_alone_yields_five():
    record = _baseline_record(exploited=True)
    assert record_priority(record) == 5.0


def test_record_priority_caps_score_contribution_at_five():
    """``score`` contribution is ``min(score, 10) / 2`` — capped at 5.0."""
    record = _baseline_record(score=999.0)
    assert record_priority(record) == 5.0


def test_record_priority_clamps_negative_score_at_zero():
    """A bogus negative score (e.g. from a corrupted feed) does not pull the
    priority below zero. The score component is clamped at the [0, 10] range.
    """
    record = _baseline_record(score=-2.0)
    assert record_priority(record) == 0.0


def test_record_priority_freshness_decays_to_zero_after_nine_days():
    now = datetime(2026, 4, 27, tzinfo=timezone.utc)
    record = _baseline_record(published_at=now - timedelta(days=20))
    assert record_priority(record, now=now) == 0.0


def test_record_priority_freshness_full_three_for_just_published():
    now = datetime(2026, 4, 27, tzinfo=timezone.utc)
    record = _baseline_record(published_at=now)
    assert record_priority(record, now=now) == 3.0


def test_record_priority_future_published_at_clamped_to_zero_age():
    """A published_at in the future shouldn't subtract from priority."""
    now = datetime(2026, 4, 27, tzinfo=timezone.utc)
    record = _baseline_record(published_at=now + timedelta(days=5))
    assert record_priority(record, now=now) == 3.0


def test_record_priority_rce_tag_adds_one_and_a_half():
    record = _baseline_record(tags=["rce"])
    assert record_priority(record) == 1.5


def test_record_priority_stacks_all_signals():
    now = datetime(2026, 4, 27, tzinfo=timezone.utc)
    record = _baseline_record(
        exploited=True,
        score=10.0,
        published_at=now,
        tags=["rce"],
    )
    # exploited(5) + score-cap(5) + freshness(3) + rce(1.5) == 14.5
    assert record_priority(record, now=now) == 14.5


# ---------------------------------------------------------------------------
# parse_nvd boundary cases
# ---------------------------------------------------------------------------


def test_parse_nvd_empty_payload_returns_empty_list():
    assert parse_nvd({}) == []


def test_parse_nvd_payload_with_empty_vulnerabilities_returns_empty_list():
    assert parse_nvd({"vulnerabilities": []}) == []


def test_parse_nvd_missing_severity_yields_none_score():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1111",
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Example with no CVSS metrics."}],
                    "metrics": {},
                }
            }
        ]
    }
    records = parse_nvd(payload)
    assert len(records) == 1
    assert records[0].score is None
    assert records[0].metadata["cvss_vector"] is None


def test_parse_nvd_missing_cwe_yields_empty_weaknesses():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-2222",
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Example without weaknesses."}],
                    "metrics": {},
                }
            }
        ]
    }
    records = parse_nvd(payload)
    assert records[0].metadata["weaknesses"] == []


def test_parse_nvd_missing_english_description_falls_back_to_first_value():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-3333",
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [
                        {"lang": "es", "value": "Descripcion en espanol."},
                        {"lang": "fr", "value": "Description en francais."},
                    ],
                    "metrics": {},
                }
            }
        ]
    }
    records = parse_nvd(payload)
    # _english_description falls back to the first available value.
    assert records[0].summary == "Descripcion en espanol."


def test_parse_nvd_no_descriptions_yields_empty_summary_but_does_not_crash():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-4444",
                    "published": "2026-04-08T12:00:00.000",
                    "metrics": {},
                }
            }
        ]
    }
    records = parse_nvd(payload)
    assert records[0].summary == ""
    # Title is still constructed from the CVE id.
    assert records[0].title.startswith("CVE-2026-4444")


def test_parse_nvd_respects_limit():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": f"CVE-2026-{1000 + i}",
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "metrics": {},
                }
            }
            for i in range(5)
        ]
    }
    records = parse_nvd(payload, limit=2)
    assert len(records) == 2


@pytest.mark.parametrize(
    "raw_id,expected_id",
    [
        ("CVE-2026-9999", "CVE-2026-9999"),
        ("cve-2026-9999", "CVE-2026-9999"),  # lowercase normalized to upper
        ("CVE-1999-0001", "CVE-1999-0001"),  # 4-digit suffix
        ("CVE-2026-1234567", "CVE-2026-1234567"),  # 7-digit suffix accepted
    ],
)
def test_parse_nvd_normalizes_well_formed_cve_id(raw_id: str, expected_id: str):
    """Valid CVE IDs are uppercased and preserved; suffix length is not capped."""
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": raw_id,
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "metrics": {},
                }
            }
        ]
    }
    records = parse_nvd(payload)
    assert records[0].canonical_id == expected_id
    assert expected_id in records[0].url


@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "not-a-cve",
        "CVE-",
        "CVE-2026",
        "CVE-2026-",
        "CVE-2026-XXX",
        "CVE-2026-123",  # suffix shorter than the documented 4-digit minimum
        "GHSA-xxxx-yyyy-zzzz",  # GitHub Security Advisory format, not CVE
    ],
)
def test_parse_nvd_drops_malformed_cve_id(bad_id: str):
    """Malformed CVE IDs are logged and dropped rather than silently
    propagating bad identifiers to downstream consumers.
    """
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": bad_id,
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "metrics": {},
                }
            }
        ]
    }
    records = parse_nvd(payload)
    assert records == []
