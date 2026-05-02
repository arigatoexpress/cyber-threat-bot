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
