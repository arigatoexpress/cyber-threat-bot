"""Tests for the EPSS lookup client.

Real FIRST.org responses are fixtured under tests/fixtures/epss/. The
HTTP layer is monkeypatched so these tests never hit the network.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from cyber_threat_bot import epss as epss_client
from cyber_threat_bot.models import Evidence, ThreatRecord


FIXTURES = Path(__file__).parent / "fixtures" / "epss"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Each test gets its own fresh cache directory."""
    cache = tmp_path / "epss"
    monkeypatch.setenv("EPSS_CACHE_DIR", str(cache))
    yield cache


@pytest.fixture
def fake_http(monkeypatch):
    """Replace _http_get_json with a fake that records calls and returns
    pre-loaded fixtures. Yields the call list so tests can assert on it.
    """
    calls: list[tuple[str, dict]] = []
    queue: list[dict] = []

    def _fake(url: str, params: dict):
        calls.append((url, dict(params)))
        if not queue:
            raise AssertionError(f"unexpected EPSS call: url={url} params={params}")
        return queue.pop(0)

    monkeypatch.setattr(epss_client, "_http_get_json", _fake)
    return calls, queue


# ---------------------------------------------------------------------------
# parse_response
# ---------------------------------------------------------------------------

def test_parse_response_two_cves():
    payload = _load("two_cves.json")
    out = epss_client._parse_response(payload)
    assert "CVE-2024-3400" in out
    assert "CVE-2023-44487" in out
    assert 0.0 <= out["CVE-2024-3400"].score <= 1.0
    assert 0.0 <= out["CVE-2024-3400"].percentile <= 1.0
    assert pytest.approx(out["CVE-2024-3400"].score, abs=1e-6) == 0.94323
    assert pytest.approx(out["CVE-2024-3400"].percentile, abs=1e-6) == 0.99953


def test_parse_response_missing_cve_returns_empty():
    payload = _load("missing_cve.json")
    out = epss_client._parse_response(payload)
    assert out == {}


def test_parse_response_clamps_out_of_range():
    payload = {
        "data": [
            {"cve": "CVE-2024-9999", "epss": "1.5", "percentile": "-0.2"},
        ]
    }
    out = epss_client._parse_response(payload)
    assert out["CVE-2024-9999"].score == 1.0
    assert out["CVE-2024-9999"].percentile == 0.0


def test_parse_response_drops_non_numeric():
    payload = {
        "data": [
            {"cve": "CVE-2024-1234", "epss": "n/a", "percentile": "0.5"},
        ]
    }
    out = epss_client._parse_response(payload)
    assert out == {}


def test_parse_response_drops_invalid_cve_id():
    payload = {"data": [{"cve": "not-a-cve", "epss": "0.1", "percentile": "0.5"}]}
    assert epss_client._parse_response(payload) == {}


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------

def test_lookup_returns_result_for_known_cve(fake_http):
    calls, queue = fake_http
    queue.append(_load("two_cves.json"))
    result = epss_client.lookup("CVE-2024-3400")
    assert result is not None
    assert result.cve == "CVE-2024-3400"
    assert result.score > 0.9
    assert result.percentile > 0.9
    assert calls and calls[0][0] == epss_client.EPSS_API_URL


def test_lookup_returns_none_for_missing_cve(fake_http):
    _, queue = fake_http
    queue.append(_load("missing_cve.json"))
    assert epss_client.lookup("CVE-9999-99999") is None


def test_lookup_rejects_malformed_id():
    assert epss_client.lookup("not-a-cve") is None
    assert epss_client.lookup("") is None
    assert epss_client.lookup(None) is None  # type: ignore[arg-type]


def test_lookup_uses_cache_on_second_call(fake_http):
    calls, queue = fake_http
    queue.append(_load("two_cves.json"))
    a = epss_client.lookup("CVE-2024-3400")
    b = epss_client.lookup("CVE-2024-3400")
    assert a == b
    assert len(calls) == 1, "second lookup must hit the on-disk cache"


def test_lookup_negative_cache_skips_repeat_call(fake_http):
    calls, queue = fake_http
    queue.append(_load("missing_cve.json"))
    assert epss_client.lookup("CVE-9999-99999") is None
    # Second call should not enqueue another request.
    assert epss_client.lookup("CVE-9999-99999") is None
    assert len(calls) == 1


def test_lookup_cache_expires_after_ttl(fake_http, monkeypatch, isolated_cache):
    monkeypatch.setenv("EPSS_TTL_SECONDS", "1")
    calls, queue = fake_http
    queue.append(_load("two_cves.json"))
    queue.append(_load("two_cves.json"))
    epss_client.lookup("CVE-2024-3400")
    # Backdate the cache file so it's stale.
    cache_file = isolated_cache / "CVE-2024-3400.json"
    old_time = time.time() - 3600
    os.utime(cache_file, (old_time, old_time))
    epss_client.lookup("CVE-2024-3400")
    assert len(calls) == 2


def test_lookup_degrades_to_none_on_http_failure(monkeypatch):
    def _fail(url, params):
        raise RuntimeError("simulated outage")

    monkeypatch.setattr(epss_client, "_http_get_json", _fail)
    assert epss_client.lookup("CVE-2024-3400") is None


# ---------------------------------------------------------------------------
# lookup_many
# ---------------------------------------------------------------------------

def test_lookup_many_batched_call(fake_http):
    calls, queue = fake_http
    queue.append(_load("two_cves.json"))
    out = epss_client.lookup_many(["CVE-2024-3400", "CVE-2023-44487"])
    assert "CVE-2024-3400" in out and "CVE-2023-44487" in out
    # Single batched call.
    assert len(calls) == 1
    assert "CVE-2024-3400" in calls[0][1]["cve"]


def test_lookup_many_skips_invalid_ids(fake_http):
    calls, queue = fake_http
    queue.append(_load("two_cves.json"))
    out = epss_client.lookup_many(["junk", "", "CVE-2024-3400"])
    assert "CVE-2024-3400" in out
    assert calls[0][1]["cve"] == "CVE-2024-3400"


def test_lookup_many_uses_cache(fake_http):
    calls, queue = fake_http
    queue.append(_load("two_cves.json"))
    epss_client.lookup_many(["CVE-2024-3400", "CVE-2023-44487"])
    epss_client.lookup_many(["CVE-2024-3400", "CVE-2023-44487"])
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# annotate_records
# ---------------------------------------------------------------------------

def _record(cve: str) -> ThreatRecord:
    return ThreatRecord(
        source="nvd",
        source_type="cve",
        canonical_id=cve,
        title=f"{cve}: stub",
        url=f"https://nvd.nist.gov/vuln/detail/{cve}",
        published_at=None,
        summary="stub",
        evidence=[Evidence(label="ref", url="https://example.invalid")],
    )


def test_annotate_records_stamps_metadata(fake_http):
    _, queue = fake_http
    queue.append(_load("two_cves.json"))
    recs = [_record("CVE-2024-3400"), _record("CVE-2023-44487")]
    epss_client.annotate_records(recs)
    assert recs[0].metadata["epss_score"] > 0.9
    assert recs[0].metadata["epss_percentile"] > 0.9
    assert recs[0].metadata["epss_date"]
    assert recs[1].metadata["epss_score"] > 0.9


def test_annotate_records_marks_missing_as_none(fake_http):
    _, queue = fake_http
    queue.append(_load("missing_cve.json"))
    recs = [_record("CVE-9999-99999")]
    epss_client.annotate_records(recs)
    assert recs[0].metadata["epss_score"] is None
    assert recs[0].metadata["epss_percentile"] is None


def test_annotate_records_skips_non_cve():
    """MITRE technique records (e.g. T1059) should not trigger any HTTP."""
    rec = ThreatRecord(
        source="mitre-attack",
        source_type="technique",
        canonical_id="T1059",
        title="T1059: Command and Scripting Interpreter",
        url="https://attack.mitre.org/techniques/T1059/",
        published_at=None,
        summary="stub",
    )
    # No fake_http fixture means any HTTP call would error with AttributeError;
    # this should pass without ever calling out.
    epss_client.annotate_records([rec])
    assert "epss_score" not in rec.metadata
