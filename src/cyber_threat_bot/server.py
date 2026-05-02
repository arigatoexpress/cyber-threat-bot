"""Lightweight HTTP server for cyber-threat-bot.

Designed for Cloud Run: stdlib-only (no fastapi runtime dependency), single
process, JSON in / JSON out. The endpoints are intentionally narrow:

* ``GET /healthz/``           -> ``{"status": "ok", ...}`` for Cloud Run probes
* ``GET /threats?source=...`` -> latest cached threats (kev | nvd | mitre)
* ``POST /refresh``           -> refetch all sources, idempotent

The cache is in-memory and lazily warmed on the first ``/threats`` request,
so cold starts on Cloud Run don't block on three upstream HTTP calls.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from . import epss as epss_client
from . import webhook as webhook_notifier
from .correlation import annotate_confidence, correlate_records
from .severity_v2 import annotate_actionability, prioritize
from .sources import (
    collect_latest_records,
    fetch_attack_technique,
    fetch_cisa_kev,
    fetch_nvd_recent,
)

log = logging.getLogger(__name__)

VALID_SOURCES = {"kev", "nvd", "mitre", "all"}
DEFAULT_MITRE_TECHNIQUE = "T1059"  # Command and Scripting Interpreter — common warm-up
SCHEMA_VERSION = "5"  # added: webhook notifier in /refresh post-processing


# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------

class ThreatCache:
    """Thread-safe cache holding the latest fetch per source.

    Refresh is idempotent: ``refresh_all()`` recomputes every entry; concurrent
    callers serialize on the same lock so we never fan out duplicate upstream
    requests.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, Any]] = {}
        self._last_refresh: datetime | None = None

    def snapshot(self, source: str) -> dict[str, Any]:
        with self._lock:
            payload = self._data.get(source)
            if payload is None:
                return {"source": source, "records": [], "fetched_at": None}
            # Defensive copy so callers cannot mutate cache state.
            return json.loads(json.dumps(payload))

    def last_refresh(self) -> datetime | None:
        with self._lock:
            return self._last_refresh

    def refresh_all(self, fetchers: dict[str, Callable[[], list[Any]]] | None = None) -> dict[str, Any]:
        """Refetch every source. Returns a small status report.

        ``fetchers`` is injectable for tests so the server can be exercised
        without hitting CISA / NVD / MITRE.
        """
        if fetchers is None:
            fetchers = _default_fetchers()

        results: dict[str, Any] = {}
        errors: dict[str, str] = {}
        with self._lock:
            for name, fn in fetchers.items():
                try:
                    records = fn()
                    # Best-effort EPSS enrichment — never fail refresh on it.
                    try:
                        epss_client.annotate_records(records)
                    except Exception as enrich_exc:  # noqa: BLE001
                        log.warning("EPSS annotation failed for source=%s err=%s", name, enrich_exc)
                    # Stamp top-level sources[] + confidence on every record.
                    try:
                        annotate_confidence(records)
                    except Exception as enrich_exc:  # noqa: BLE001
                        log.warning("confidence annotation failed for source=%s err=%s", name, enrich_exc)
                    # Stamp actionability_score / _tier (Lane 3).
                    try:
                        annotate_actionability(records)
                    except Exception as enrich_exc:  # noqa: BLE001
                        log.warning("actionability annotation failed for source=%s err=%s", name, enrich_exc)
                    self._data[name] = {
                        "source": name,
                        "fetched_at": _now_iso(),
                        "records": [_to_dict(rec) for rec in records],
                    }
                    results[name] = len(records)
                except Exception as exc:  # noqa: BLE001 — surface upstream failure shape
                    log.warning("refresh failed for source=%s err=%s", name, exc)
                    errors[name] = f"{type(exc).__name__}: {exc}"
                    results[name] = 0
            self._last_refresh = datetime.now(timezone.utc)
            # Webhook notification for newly-actionable records. Best-effort:
            # any failure logs but never poisons the refresh report. Uses the
            # 'all' snapshot since that's the deduped/correlated view.
            webhook_report: dict[str, Any] = {"enabled": False}
            try:
                all_snapshot = self._data.get("all", {})
                webhook_report = webhook_notifier.notify_actionable(
                    all_snapshot.get("records") or []
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("webhook delivery encountered an error: %s", exc)

            return {
                "refreshed_at": _now_iso(),
                "counts": results,
                "errors": errors,
                "webhook": webhook_report,
            }


def _default_fetchers() -> dict[str, Callable[[], list[Any]]]:
    return {
        "kev": lambda: fetch_cisa_kev(days=30, limit=20),
        "nvd": lambda: fetch_nvd_recent(days=7, limit=20),
        "mitre": lambda: [fetch_attack_technique(DEFAULT_MITRE_TECHNIQUE)],
        "all": lambda: collect_latest_records(days=7, per_source=8),
    }


def _to_dict(rec: Any) -> dict[str, Any]:
    if hasattr(rec, "to_dict"):
        return rec.to_dict()
    if isinstance(rec, dict):
        return rec
    return {"value": str(rec)}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# Module-level singleton; tests can replace with their own instance via
# ``set_cache``.
_CACHE = ThreatCache()


def get_cache() -> ThreatCache:
    return _CACHE


def set_cache(cache: ThreatCache) -> None:
    global _CACHE
    _CACHE = cache


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class ThreatHandler(BaseHTTPRequestHandler):
    # Inject in tests so we don't hit CISA/NVD/MITRE.
    fetchers: dict[str, Callable[[], list[Any]]] | None = None

    server_version = "cyber-threat-bot-server/1.0"

    # Quiet the default stderr access log so Cloud Run logs stay clean.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 — base class signature
        log.info("%s - %s", self.address_string(), format % args)

    # ---- routing -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 — base class signature
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"

        if path in ("/", "/healthz", "/health"):
            return self._healthz()
        if path == "/threats":
            return self._threats(parse_qs(url.query))
        if path == "/threats/correlate":
            return self._threats_correlate(parse_qs(url.query))
        if path == "/threats/prioritized":
            return self._threats_prioritized(parse_qs(url.query))
        return self._not_found()

    def do_POST(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        if path == "/refresh":
            return self._refresh()
        return self._not_found()

    # ---- handlers ----------------------------------------------------------

    def _healthz(self) -> None:
        last = get_cache().last_refresh()
        self._json(
            200,
            {
                "status": "ok",
                "schema_version": SCHEMA_VERSION,
                "last_refresh": last.replace(microsecond=0).isoformat().replace("+00:00", "Z") if last else None,
            },
            cache_control="no-store",
        )

    def _threats(self, query: dict[str, list[str]]) -> None:
        source = (query.get("source", ["all"])[0] or "all").lower()
        if source not in VALID_SOURCES:
            return self._json(400, {"error": f"invalid source: {source}", "valid": sorted(VALID_SOURCES)})

        cache = get_cache()
        snapshot = cache.snapshot(source)
        # Lazy warm-up: if the cache has never been populated, do a refresh now.
        if snapshot.get("fetched_at") is None:
            cache.refresh_all(self.fetchers)
            snapshot = cache.snapshot(source)
        self._json(200, snapshot)

    def _threats_correlate(self, query: dict[str, list[str]]) -> None:
        """Group the cached ``all`` records by shared CWE / vendor / product / tag.

        Optional query params:
          ``min_group_size``  default 2 — drop singleton clusters smaller than this
          ``source``          default "all" — which cache snapshot to correlate

        Response shape::

            {
              "fetched_at": "...",
              "min_group_size": 2,
              "clusters": {"cwe": {...}, "vendor": {...}, "product": {...}, "tag": {...}}
            }
        """
        try:
            min_size = int((query.get("min_group_size", ["2"])[0] or "2"))
        except (TypeError, ValueError):
            return self._json(400, {"error": "min_group_size must be int"})
        if min_size < 2:
            min_size = 2

        source = (query.get("source", ["all"])[0] or "all").lower()
        if source not in VALID_SOURCES:
            return self._json(400, {"error": f"invalid source: {source}", "valid": sorted(VALID_SOURCES)})

        cache = get_cache()
        snapshot = cache.snapshot(source)
        # Lazy warm-up — same semantics as /threats.
        if snapshot.get("fetched_at") is None:
            cache.refresh_all(self.fetchers)
            snapshot = cache.snapshot(source)

        clusters = correlate_records(snapshot.get("records", []), min_group_size=min_size)
        self._json(
            200,
            {
                "source": source,
                "fetched_at": snapshot.get("fetched_at"),
                "min_group_size": min_size,
                "clusters": clusters,
            },
        )

    def _threats_prioritized(self, query: dict[str, list[str]]) -> None:
        """Records sorted by actionability score, optionally filtered by tier.

        Optional query params:
          ``min_tier``  one of CRITICAL_NOW / HIGH / MEDIUM / WATCH (case-insensitive)
          ``source``    default "all"
          ``limit``     default 50, capped at 200
        """
        source = (query.get("source", ["all"])[0] or "all").lower()
        if source not in VALID_SOURCES:
            return self._json(400, {"error": f"invalid source: {source}", "valid": sorted(VALID_SOURCES)})

        min_tier = (query.get("min_tier", [""])[0] or "").upper() or None

        try:
            limit = int((query.get("limit", ["50"])[0] or "50"))
        except (TypeError, ValueError):
            return self._json(400, {"error": "limit must be int"})
        limit = max(1, min(limit, 200))

        cache = get_cache()
        snapshot = cache.snapshot(source)
        if snapshot.get("fetched_at") is None:
            cache.refresh_all(self.fetchers)
            snapshot = cache.snapshot(source)

        ranked = prioritize(list(snapshot.get("records") or []), min_tier=min_tier)
        self._json(
            200,
            {
                "source": source,
                "fetched_at": snapshot.get("fetched_at"),
                "min_tier": min_tier,
                "count": len(ranked),
                "records": ranked[:limit],
            },
        )

    def _refresh(self) -> None:
        report = get_cache().refresh_all(self.fetchers)
        self._json(200, report, cache_control="no-store")

    def _not_found(self) -> None:
        self._json(404, {"error": "not found", "path": self.path})

    # ---- response helper ---------------------------------------------------

    def _json(self, status: int, payload: dict[str, Any], *, cache_control: str | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cache_control:
            self.send_header("Cache-Control", cache_control)
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def make_server(host: str = "0.0.0.0", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), ThreatHandler)


def main(argv: list[str] | None = None) -> int:
    """Module entrypoint for ``python -m cyber_threat_bot.server``.

    PORT and HOST honored from the environment for Cloud Run compatibility.
    """
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    server = make_server(host=host, port=port)
    log.info("cyber-threat-bot HTTP server listening on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
        server.shutdown()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
