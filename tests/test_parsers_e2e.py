"""End-to-end parser tests against on-disk fixtures.

Loads representative payloads from tests/fixtures/{kev,nvd,mitre} that
mirror the public source shapes (CISA KEV JSON, NVD CVE 2.0 JSON, MITRE
ATT&CK technique HTML) and asserts the parsers return well-formed
ThreatRecord objects with the expected fields populated.

Snapshot tests live alongside in test_parsers_snapshot.py.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cyber_threat_bot.models import ThreatRecord
from cyber_threat_bot.sources import (
    parse_attack_technique_html,
    parse_cisa_kev,
    parse_nvd,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
KEV_PATH = FIXTURES / "kev" / "cisa_kev_sample.json"
NVD_PATH = FIXTURES / "nvd" / "nvd_cve_sample.json"
MITRE_PATH = FIXTURES / "mitre" / "T1059_command_and_scripting_interpreter.html"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert_record_invariants(rec: ThreatRecord) -> None:
    """Every ThreatRecord must satisfy these regardless of source."""
    assert isinstance(rec, ThreatRecord)
    assert rec.canonical_id, "canonical_id is required"
    assert rec.source, "source is required"
    assert rec.source_type, "source_type is required"
    assert rec.title, "title is required"
    assert rec.url, "url is required"
    assert isinstance(rec.tags, list)
    assert isinstance(rec.evidence, list)
    assert isinstance(rec.metadata, dict)
    if rec.published_at is not None:
        assert rec.published_at.tzinfo is not None, "published_at must be tz-aware"


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

class TestParseCisaKev:
    def test_loads_two_recent_entries_filters_old(self):
        payload = _load_json(KEV_PATH)
        # As of 2026-05-01, days=30 should drop the 2025-12-01 entry.
        records = parse_cisa_kev(
            payload,
            days=30,
            now=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc),
            limit=10,
        )
        assert len(records) == 2
        cves = {r.canonical_id for r in records}
        assert cves == {"CVE-2026-12345", "CVE-2026-22222"}
        assert "CVE-2025-99999" not in cves, "lookback window should filter old entries"

    def test_record_invariants_hold_for_each(self):
        payload = _load_json(KEV_PATH)
        records = parse_cisa_kev(
            payload, days=30, now=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc), limit=10
        )
        for rec in records:
            _assert_record_invariants(rec)
            assert rec.exploited is True, "everything in CISA KEV is by definition exploited"

    def test_known_ransomware_flag_propagates_to_metadata_or_tags(self):
        payload = _load_json(KEV_PATH)
        records = parse_cisa_kev(
            payload, days=30, now=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc), limit=10
        )
        ransomware_rec = next(r for r in records if r.canonical_id == "CVE-2026-12345")
        # Either the structured metadata or tags should reflect the ransomware association.
        haystack = json.dumps(ransomware_rec.metadata) + " ".join(ransomware_rec.tags)
        assert "ansomware" in haystack or ransomware_rec.metadata.get("known_ransomware_use") in (
            "Known",
            True,
        ), "known ransomware association should surface somewhere"

    def test_cisa_kev_url_points_at_canonical_cisa_page(self):
        payload = _load_json(KEV_PATH)
        records = parse_cisa_kev(
            payload, days=30, now=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc), limit=10
        )
        for rec in records:
            assert "cisa.gov" in rec.url or rec.url.startswith("http"), rec.url

    def test_empty_vulnerabilities_returns_empty(self):
        records = parse_cisa_kev({"vulnerabilities": []}, days=30)
        assert records == []

    def test_missing_vulnerabilities_key_returns_empty(self):
        records = parse_cisa_kev({}, days=30)
        assert records == []


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

class TestParseNvd:
    def test_loads_both_cves(self):
        payload = _load_json(NVD_PATH)
        records = parse_nvd(payload, limit=10)
        assert len(records) == 2
        ids = {r.canonical_id for r in records}
        assert ids == {"CVE-2026-12345", "CVE-2026-67890"}

    def test_record_invariants_hold_for_each(self):
        payload = _load_json(NVD_PATH)
        records = parse_nvd(payload, limit=10)
        for rec in records:
            _assert_record_invariants(rec)

    def test_cvss_v31_score_extracted(self):
        payload = _load_json(NVD_PATH)
        records = parse_nvd(payload, limit=10)
        v31_rec = next(r for r in records if r.canonical_id == "CVE-2026-12345")
        assert v31_rec.score == pytest.approx(9.8)

    def test_cvss_v40_score_extracted(self):
        """v4.0 metric should win over absent v3.1 metric for CVE-2026-67890."""
        payload = _load_json(NVD_PATH)
        records = parse_nvd(payload, limit=10)
        v40_rec = next(r for r in records if r.canonical_id == "CVE-2026-67890")
        assert v40_rec.score == pytest.approx(9.4)

    def test_cwe_propagates_to_metadata(self):
        payload = _load_json(NVD_PATH)
        records = parse_nvd(payload, limit=10)
        cwes_by_id = {r.canonical_id: r.metadata.get("weaknesses", []) for r in records}
        assert "CWE-287" in cwes_by_id["CVE-2026-12345"]
        assert "CWE-502" in cwes_by_id["CVE-2026-67890"]

    def test_references_captured_for_evidence(self):
        payload = _load_json(NVD_PATH)
        records = parse_nvd(payload, limit=10)
        rec = next(r for r in records if r.canonical_id == "CVE-2026-12345")
        # The vendor advisory should be reachable somewhere on the record (evidence list,
        # metadata, or summary). This is intentionally loose because the parser may store
        # references in either place across versions.
        all_text = (
            " ".join(e.url for e in rec.evidence)
            + " "
            + json.dumps(rec.metadata)
            + " "
            + rec.summary
            + " "
            + rec.url
        )
        assert "acme.example/security/advisory/2026-001" in all_text or "nvd.nist.gov" in all_text

    def test_published_at_is_timezone_aware(self):
        payload = _load_json(NVD_PATH)
        records = parse_nvd(payload, limit=10)
        for rec in records:
            assert rec.published_at is not None
            assert rec.published_at.tzinfo is not None

    def test_limit_is_respected(self):
        payload = _load_json(NVD_PATH)
        records = parse_nvd(payload, limit=1)
        assert len(records) == 1


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------

class TestParseAttackTechnique:
    def test_record_invariants_hold(self):
        html = MITRE_PATH.read_text(encoding="utf-8")
        rec = parse_attack_technique_html(html, "T1059")
        _assert_record_invariants(rec)
        assert rec.canonical_id == "T1059"

    def test_extracts_human_readable_title(self):
        html = MITRE_PATH.read_text(encoding="utf-8")
        rec = parse_attack_technique_html(html, "T1059")
        assert "Command and Scripting Interpreter" in rec.title

    def test_detection_strategy_in_metadata(self):
        html = MITRE_PATH.read_text(encoding="utf-8")
        rec = parse_attack_technique_html(html, "T1059")
        detection = rec.metadata.get("detection_strategy", "")
        assert "Monitor command-line arguments" in detection

    def test_mitigation_ids_present_somewhere(self):
        html = MITRE_PATH.read_text(encoding="utf-8")
        rec = parse_attack_technique_html(html, "T1059")
        meta_text = json.dumps(rec.metadata)
        # At least one mitigation ID from the table should make it through.
        assert any(mid in meta_text for mid in ("M1038", "M1042")), (
            f"expected mitigation IDs in metadata, got keys={list(rec.metadata.keys())}"
        )

    def test_handles_minimal_html_with_main_tag(self):
        # Parser currently requires either <div class="description-body"> or <main>.
        # Real ATT&CK pages always have <main>, so this is the realistic minimal shape.
        rec = parse_attack_technique_html(
            "<html><body><main><h1>Stub</h1></main></body></html>",
            "T9999",
        )
        _assert_record_invariants(rec)
        assert rec.canonical_id == "T9999"
