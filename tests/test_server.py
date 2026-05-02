"""Tests for the HTTP server in :mod:`cyber_threat_bot.server`.

These exercise the routing layer end-to-end against a real ThreadingHTTPServer
on a local port, with the upstream fetchers stubbed via dependency injection.
No CISA / NVD / MITRE traffic occurs.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

import pytest

from cyber_threat_bot import server as srv
from cyber_threat_bot.models import Evidence, ThreatRecord


def _stub_record(canonical_id: str, source: str = "stub") -> ThreatRecord:
    return ThreatRecord(
        source=source,
        source_type="test",
        canonical_id=canonical_id,
        title=f"stub {canonical_id}",
        url=f"https://example.invalid/{canonical_id}",
        published_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        summary="stub summary",
        evidence=[Evidence(label="ref", url="https://example.invalid/ref")],
    )


@pytest.fixture(autouse=True)
def disable_epss(monkeypatch):
    """Server tests don't need real EPSS lookups; keep them off the network."""
    monkeypatch.setenv("EPSS_DISABLED", "1")


@pytest.fixture
def stub_fetchers():
    return {
        "kev": lambda: [_stub_record("CVE-2026-0001", "CISA KEV")],
        "nvd": lambda: [_stub_record("CVE-2026-0002", "NVD"), _stub_record("CVE-2026-0003", "NVD")],
        "mitre": lambda: [_stub_record("T1059", "MITRE ATT&CK")],
        "all": lambda: [_stub_record("CVE-2026-0001"), _stub_record("T1059")],
    }


@pytest.fixture
def running_server(stub_fetchers):
    """Spin up a real ThreadingHTTPServer on an ephemeral port with stubbed fetchers."""
    # Fresh cache per test so /threats lazy-warm is observable.
    srv.set_cache(srv.ThreatCache())

    # Bind a per-test handler subclass that carries the stubbed fetchers.
    class _Handler(srv.ThreatHandler):
        fetchers = stub_fetchers

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _get(port: int, path: str) -> tuple[int, dict, dict]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode("utf-8"))
        return e.code, dict(e.headers), body


def _post(port: int, path: str) -> tuple[int, dict, dict]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode("utf-8"))
        return e.code, dict(e.headers), body


# ---------------------------------------------------------------------------
# /healthz
# ---------------------------------------------------------------------------

def test_healthz_returns_ok(running_server):
    status, headers, body = _get(running_server, "/healthz/")
    assert status == 200
    assert body["status"] == "ok"
    assert body["schema_version"] == srv.SCHEMA_VERSION
    assert headers.get("Cache-Control") == "no-store"
    assert headers.get("Content-Type", "").startswith("application/json")


def test_healthz_root_alias(running_server):
    status, _, body = _get(running_server, "/")
    assert status == 200
    assert body["status"] == "ok"


def test_healthz_reports_last_refresh_after_refresh(running_server):
    _post(running_server, "/refresh")
    _, _, body = _get(running_server, "/healthz/")
    assert body["last_refresh"] is not None


# ---------------------------------------------------------------------------
# /threats
# ---------------------------------------------------------------------------

def test_threats_lazy_warmup_on_first_request(running_server):
    # Before any /refresh, the cache is cold. /threats should warm itself.
    status, _, body = _get(running_server, "/threats?source=kev")
    assert status == 200
    assert body["source"] == "kev"
    assert body["fetched_at"] is not None
    assert len(body["records"]) == 1
    assert body["records"][0]["canonical_id"] == "CVE-2026-0001"


def test_threats_invalid_source_rejected(running_server):
    status, _, body = _get(running_server, "/threats?source=bogus")
    assert status == 400
    assert "invalid source" in body["error"]
    assert "kev" in body["valid"]


def test_threats_default_source_is_all(running_server):
    status, _, body = _get(running_server, "/threats")
    assert status == 200
    assert body["source"] == "all"


def test_threats_each_supported_source(running_server):
    for source, expected_count in [("kev", 1), ("nvd", 2), ("mitre", 1), ("all", 2)]:
        status, _, body = _get(running_server, f"/threats?source={source}")
        assert status == 200, f"{source} -> {status}"
        assert len(body["records"]) == expected_count, source


# ---------------------------------------------------------------------------
# /refresh
# ---------------------------------------------------------------------------

def test_refresh_returns_counts(running_server):
    status, headers, body = _post(running_server, "/refresh")
    assert status == 200
    assert headers.get("Cache-Control") == "no-store"
    assert body["counts"] == {"kev": 1, "nvd": 2, "mitre": 1, "all": 2}
    assert body["errors"] == {}
    assert body["refreshed_at"] is not None


def test_refresh_is_idempotent(running_server):
    _post(running_server, "/refresh")
    _, _, body1 = _get(running_server, "/threats?source=kev")
    _post(running_server, "/refresh")
    _, _, body2 = _get(running_server, "/threats?source=kev")
    # Same content; just newer fetched_at allowed.
    assert body1["records"] == body2["records"]


def test_refresh_captures_per_source_errors(running_server, stub_fetchers):
    # Replace one fetcher with a raising one mid-flight by replacing the cache.
    cache = srv.ThreatCache()
    failing = {
        "kev": stub_fetchers["kev"],
        "nvd": (lambda: (_ for _ in ()).throw(RuntimeError("nvd outage"))),
        "mitre": stub_fetchers["mitre"],
        "all": stub_fetchers["all"],
    }
    report = cache.refresh_all(failing)
    assert report["counts"]["kev"] == 1
    assert report["counts"]["nvd"] == 0
    assert "RuntimeError: nvd outage" in report["errors"]["nvd"]
    # Successful sources remain populated.
    assert cache.snapshot("kev")["records"]


# ---------------------------------------------------------------------------
# Routing fall-throughs
# ---------------------------------------------------------------------------

def test_unknown_path_returns_404(running_server):
    status, _, body = _get(running_server, "/nope")
    assert status == 404
    assert body["error"] == "not found"


def test_post_to_get_route_returns_404(running_server):
    status, _, _ = _post(running_server, "/threats")
    assert status == 404


# ---------------------------------------------------------------------------
# /threats/correlate (Lane 2)
# ---------------------------------------------------------------------------

def _correlation_record(cve: str, *, tags: list[str] | None = None, metadata: dict | None = None) -> ThreatRecord:
    return ThreatRecord(
        source="nvd",
        source_type="cve",
        canonical_id=cve,
        title=f"{cve}: stub",
        url=f"https://example.invalid/{cve}",
        published_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        summary="stub",
        tags=tags or [],
        metadata=metadata or {},
        evidence=[Evidence(label="ref", url="https://example.invalid/ref")],
    )


@pytest.fixture
def correlation_fetchers():
    return {
        "all": lambda: [
            _correlation_record("CVE-2026-A", tags=["CWE-79", "xss"]),
            _correlation_record("CVE-2026-B", tags=["CWE-79", "xss"]),
            _correlation_record("CVE-2026-C", metadata={"vendor_project": "Linux", "product": "Kernel"}),
            _correlation_record("CVE-2026-D", metadata={"vendor_project": "Linux", "product": "Kernel"}),
        ],
        "kev": lambda: [],
        "nvd": lambda: [],
        "mitre": lambda: [],
    }


@pytest.fixture
def correlation_server(correlation_fetchers):
    srv.set_cache(srv.ThreatCache())

    class _Handler(srv.ThreatHandler):
        fetchers = correlation_fetchers

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_threats_correlate_returns_clusters(correlation_server):
    _post(correlation_server, "/refresh")
    status, _, body = _get(correlation_server, "/threats/correlate")
    assert status == 200
    assert body["min_group_size"] == 2
    assert "CWE-79" in body["clusters"]["cwe"]
    assert sorted(body["clusters"]["cwe"]["CWE-79"]) == ["CVE-2026-A", "CVE-2026-B"]
    assert "linux" in body["clusters"]["vendor"]
    assert "kernel" in body["clusters"]["product"]


def test_threats_correlate_min_group_size_param(correlation_server):
    _post(correlation_server, "/refresh")
    status, _, body = _get(correlation_server, "/threats/correlate?min_group_size=3")
    # No group has 3 members in this fixture.
    assert status == 200
    assert body["clusters"]["cwe"] == {}


def test_threats_correlate_lazy_warmup(correlation_server):
    # Don't /refresh first; the endpoint should warm the cache itself.
    status, _, body = _get(correlation_server, "/threats/correlate")
    assert status == 200
    assert body["fetched_at"] is not None


def test_threats_correlate_invalid_min_group_size(correlation_server):
    status, _, body = _get(correlation_server, "/threats/correlate?min_group_size=abc")
    assert status == 400


def test_threats_correlate_invalid_source(correlation_server):
    status, _, body = _get(correlation_server, "/threats/correlate?source=bogus")
    assert status == 400


# ---------------------------------------------------------------------------
# Confidence + sources fields on /threats records
# ---------------------------------------------------------------------------

def test_threats_records_include_sources_and_confidence(running_server):
    _post(running_server, "/refresh")
    status, _, body = _get(running_server, "/threats?source=kev")
    assert status == 200
    rec = body["records"][0]
    assert "sources" in rec
    assert "confidence" in rec
    assert isinstance(rec["sources"], list)
    assert rec["sources"]  # non-empty
    # confidence should be a float in [0, 1] or None.
    assert rec["confidence"] is None or 0.0 <= rec["confidence"] <= 1.0


def test_schema_version_is_4():
    assert srv.SCHEMA_VERSION == "4"


# ---------------------------------------------------------------------------
# /threats/prioritized (Lane 3)
# ---------------------------------------------------------------------------

def _priority_record(cve: str, *, score: float | None = None, exploited: bool = False) -> ThreatRecord:
    return ThreatRecord(
        source="nvd",
        source_type="cve",
        canonical_id=cve,
        title=f"{cve}: stub",
        url=f"https://example.invalid/{cve}",
        published_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        summary="stub",
        score=score,
        exploited=exploited,
        evidence=[Evidence(label="ref", url="https://example.invalid/ref")],
    )


@pytest.fixture
def priority_fetchers():
    return {
        "all": lambda: [
            _priority_record("CVE-LOW", score=2.0),
            _priority_record("CVE-MED", score=8.0),
            _priority_record("CVE-CRIT", score=10.0, exploited=True),
        ],
        "kev": lambda: [],
        "nvd": lambda: [],
        "mitre": lambda: [],
    }


@pytest.fixture
def priority_server(priority_fetchers):
    srv.set_cache(srv.ThreatCache())

    class _Handler(srv.ThreatHandler):
        fetchers = priority_fetchers

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_prioritized_returns_records_sorted(priority_server):
    _post(priority_server, "/refresh")
    status, _, body = _get(priority_server, "/threats/prioritized")
    assert status == 200
    ids = [r["canonical_id"] for r in body["records"]]
    assert ids[0] == "CVE-CRIT"
    # All records have actionability stamped.
    assert all("actionability_score" in r["metadata"] for r in body["records"])
    assert all("actionability_tier" in r["metadata"] for r in body["records"])


def test_prioritized_filters_by_min_tier(priority_server):
    _post(priority_server, "/refresh")
    status, _, body = _get(priority_server, "/threats/prioritized?min_tier=HIGH")
    assert status == 200
    ids = [r["canonical_id"] for r in body["records"]]
    assert "CVE-CRIT" in ids
    assert "CVE-LOW" not in ids


def test_prioritized_invalid_source(priority_server):
    status, _, _ = _get(priority_server, "/threats/prioritized?source=bogus")
    assert status == 400


def test_prioritized_invalid_limit(priority_server):
    status, _, _ = _get(priority_server, "/threats/prioritized?limit=abc")
    assert status == 400


def test_prioritized_lazy_warmup(priority_server):
    status, _, body = _get(priority_server, "/threats/prioritized")
    assert status == 200
    assert body["fetched_at"] is not None


# ---------------------------------------------------------------------------
# Direct cache unit tests
# ---------------------------------------------------------------------------

def test_cache_snapshot_returns_empty_for_unknown_source():
    cache = srv.ThreatCache()
    snap = cache.snapshot("never-fetched")
    assert snap == {"source": "never-fetched", "records": [], "fetched_at": None}


def test_cache_snapshot_is_defensive_copy():
    cache = srv.ThreatCache()
    cache.refresh_all({"kev": lambda: [_stub_record("CVE-2026-9999")]})
    s1 = cache.snapshot("kev")
    s1["records"].clear()
    s2 = cache.snapshot("kev")
    assert len(s2["records"]) == 1, "snapshot must not let callers mutate the cache"


def test_cache_concurrent_refresh_is_safe():
    """Concurrent /refresh calls must not corrupt state."""
    cache = srv.ThreatCache()
    fetchers = {"kev": lambda: [_stub_record(f"CVE-2026-{i:04d}") for i in range(5)]}

    errors = []

    def worker():
        try:
            cache.refresh_all(fetchers)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    snap = cache.snapshot("kev")
    assert len(snap["records"]) == 5
