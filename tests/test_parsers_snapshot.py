"""Snapshot tests for the parsers.

These freeze the canonical_id / source / score / exploited fields produced
from each fixture to JSON files under tests/fixtures/snapshots/. If the
parser changes the shape of its output, the test fails and prints both
the expected and actual snapshot so the reviewer can decide whether the
new shape is intentional.

Update snapshots intentionally with::

    UPDATE_SNAPSHOTS=1 pytest tests/test_parsers_snapshot.py

Snapshots only capture stable, structured fields — never free-form summary
text or library-version-dependent ordering. This keeps them useful as a
regression net without becoming a maintenance burden.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from cyber_threat_bot.sources import (
    parse_attack_technique_html,
    parse_cisa_kev,
    parse_nvd,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SNAPSHOTS = FIXTURES / "snapshots"
KEV_PATH = FIXTURES / "kev" / "cisa_kev_sample.json"
NVD_PATH = FIXTURES / "nvd" / "nvd_cve_sample.json"
MITRE_PATH = FIXTURES / "mitre" / "T1059_command_and_scripting_interpreter.html"

UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"


def _stable_record(rec: Any) -> dict:
    """Project a ThreatRecord onto its stable fields for snapshotting."""
    return {
        "source": rec.source,
        "source_type": rec.source_type,
        "canonical_id": rec.canonical_id,
        "score": rec.score,
        "exploited": rec.exploited,
        "weaknesses": sorted(rec.metadata.get("weaknesses", []) or []),
        # We deliberately don't snapshot title/summary/url — those depend on
        # upstream wording that can change without a parser bug.
    }


def _assert_snapshot(name: str, actual: list[dict] | dict) -> None:
    path = SNAPSHOTS / f"{name}.json"
    actual_text = json.dumps(actual, indent=2, sort_keys=True) + "\n"

    if UPDATE or not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual_text, encoding="utf-8")
        if not UPDATE:
            pytest.skip(f"created initial snapshot at {path}")
        return

    expected_text = path.read_text(encoding="utf-8")
    if actual_text != expected_text:
        diff_msg = (
            f"\nSnapshot mismatch for {name}.\n"
            f"---- expected ({path}) ----\n{expected_text}\n"
            f"---- actual ----\n{actual_text}\n"
            "Re-run with UPDATE_SNAPSHOTS=1 if the new shape is intentional."
        )
        raise AssertionError(diff_msg)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_kev_snapshot():
    payload = json.loads(KEV_PATH.read_text(encoding="utf-8"))
    records = parse_cisa_kev(
        payload,
        days=30,
        now=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc),
        limit=10,
    )
    actual = sorted([_stable_record(r) for r in records], key=lambda d: d["canonical_id"])
    _assert_snapshot("kev_recent", actual)


def test_nvd_snapshot():
    payload = json.loads(NVD_PATH.read_text(encoding="utf-8"))
    records = parse_nvd(payload, limit=10)
    actual = sorted([_stable_record(r) for r in records], key=lambda d: d["canonical_id"])
    _assert_snapshot("nvd_recent", actual)


def test_mitre_snapshot():
    html = MITRE_PATH.read_text(encoding="utf-8")
    rec = parse_attack_technique_html(html, "T1059")
    actual = {
        "canonical_id": rec.canonical_id,
        "source": rec.source,
        "source_type": rec.source_type,
        # Stable structural fact: "Monitor command-line" must appear in detection_strategy.
        "detection_substring_present": "Monitor command-line" in rec.metadata.get("detection_strategy", ""),
    }
    _assert_snapshot("mitre_T1059", actual)
