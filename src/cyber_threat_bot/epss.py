"""EPSS (Exploit Prediction Scoring System) lookup client.

EPSS is FIRST.org's machine-learning model that estimates the probability
a CVE will be exploited in the wild within the next 30 days. It returns
two numbers per CVE:

* ``epss``       — raw probability in [0, 1]
* ``percentile`` — relative rank vs. all scored CVEs, also in [0, 1]

The public API is unauthenticated, rate-friendly, and supports bulk
lookups via comma-separated ``cve=`` query strings:

    https://api.first.org/data/v1/epss?cve=CVE-2024-3400,CVE-2023-44487

Design notes
------------
* Cloud Run instances are ephemeral, but the local filesystem at /tmp
  is fast and persists for the lifetime of the instance. We cache there
  with a 24h TTL so repeated /threats requests within a single instance
  lifetime don't re-pound EPSS.
* Outbound HTTP uses ``httpx`` with a 5s timeout and a single retry on
  network / 5xx errors, per project convention.
* Missing CVEs (not yet scored, e.g. very fresh disclosures) return
  ``None`` rather than raising; callers fold them into records as
  ``epss_score=None``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import httpx
except ImportError:  # pragma: no cover - defensive; httpx is a hard dep
    httpx = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_TTL_SECONDS = 24 * 3600
DEFAULT_CACHE_DIR = "/tmp/cyber-threat-bot/epss"
USER_AGENT = "cyber-threat-bot/0.2 (+https://github.com/arigatoexpress/cyber-threat-bot)"
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# EPSS lets you query many CVEs at once; cap to keep URLs sane.
_BULK_BATCH_SIZE = 50


@dataclass(slots=True, frozen=True)
class EpssResult:
    """One row of EPSS data for a single CVE."""

    cve: str
    score: float
    percentile: float
    date: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "epss_score": self.score,
            "epss_percentile": self.percentile,
            "epss_date": self.date,
        }


def _cache_dir() -> Path:
    return Path(os.environ.get("EPSS_CACHE_DIR", DEFAULT_CACHE_DIR))


def _cache_path(cve: str) -> Path:
    # Sanitize: only keep CVE-YYYY-NNNN shape; refuse anything else.
    if not _CVE_ID_RE.match(cve):
        raise ValueError(f"refusing to cache non-CVE id: {cve!r}")
    return _cache_dir() / f"{cve.upper()}.json"


def _ttl_seconds() -> int:
    raw = os.environ.get("EPSS_TTL_SECONDS")
    if not raw:
        return DEFAULT_TTL_SECONDS
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TTL_SECONDS
    return value if value > 0 else DEFAULT_TTL_SECONDS


def _read_cache(cve: str, *, now: float | None = None) -> EpssResult | None:
    """Return cached result if present AND fresh, else None."""
    try:
        path = _cache_path(cve)
    except ValueError:
        return None
    if not path.exists():
        return None
    age = (now or time.time()) - path.stat().st_mtime
    if age > _ttl_seconds():
        return None
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("missing"):
        # Negative cache: we know EPSS does not score this CVE.
        return None
    return EpssResult(
        cve=payload["cve"],
        score=float(payload["score"]),
        percentile=float(payload["percentile"]),
        date=payload.get("date"),
    )


def _is_negative_cached(cve: str, *, now: float | None = None) -> bool:
    """True if we have a fresh negative-cache entry (CVE not in EPSS)."""
    try:
        path = _cache_path(cve)
    except ValueError:
        return False
    if not path.exists():
        return False
    age = (now or time.time()) - path.stat().st_mtime
    if age > _ttl_seconds():
        return False
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    return bool(isinstance(payload, dict) and payload.get("missing"))


def _write_cache(cve: str, result: EpssResult | None) -> None:
    try:
        path = _cache_path(cve)
    except ValueError:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if result is None:
            payload = {"cve": cve.upper(), "missing": True}
        else:
            payload = {
                "cve": result.cve,
                "score": result.score,
                "percentile": result.percentile,
                "date": result.date,
            }
        path.write_text(json.dumps(payload))
    except OSError as exc:  # pragma: no cover - non-fatal
        log.debug("EPSS cache write failed for %s: %s", cve, exc)


def _parse_response(payload: dict[str, Any]) -> dict[str, EpssResult]:
    out: dict[str, EpssResult] = {}
    for row in payload.get("data") or []:
        cve_id = (row.get("cve") or "").upper()
        if not _CVE_ID_RE.match(cve_id):
            continue
        try:
            score = float(row.get("epss"))
            percentile = float(row.get("percentile"))
        except (TypeError, ValueError):
            log.warning("EPSS row dropped — non-numeric score/percentile: %r", row)
            continue
        # Clamp into [0, 1] defensively in case upstream returns a string
        # representation that float()s into a slightly-out-of-range value.
        score = max(0.0, min(score, 1.0))
        percentile = max(0.0, min(percentile, 1.0))
        out[cve_id] = EpssResult(
            cve=cve_id,
            score=score,
            percentile=percentile,
            date=row.get("date"),
        )
    return out


def _http_get_json(url: str, params: dict[str, Any]) -> dict[str, Any]:
    """GET ``url`` with httpx, 5s timeout, single retry on transport / 5xx."""
    if httpx is None:  # pragma: no cover
        raise RuntimeError("httpx not installed; EPSS client unavailable")
    last_exc: Exception | None = None
    for attempt in range(2):  # initial + 1 retry
        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS, headers={"User-Agent": USER_AGENT}) as client:
                resp = client.get(url, params=params)
            if 500 <= resp.status_code < 600:
                raise httpx.HTTPStatusError(
                    f"EPSS server error: {resp.status_code}", request=resp.request, response=resp
                )
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            last_exc = exc
            log.debug("EPSS request failed attempt=%d err=%s", attempt, exc)
            continue
    raise RuntimeError(f"EPSS request failed after retry: {last_exc}") from last_exc


def _disabled() -> bool:
    """Check the kill-switch env var. Tests + ops can disable EPSS at runtime."""
    return os.environ.get("EPSS_DISABLED", "").strip().lower() in {"1", "true", "yes"}


def lookup(cve_id: str) -> EpssResult | None:
    """Return EPSS data for a single CVE, using the on-disk TTL cache.

    Returns ``None`` when:
      * the input is not a valid CVE id
      * EPSS has no record for the CVE
      * the upstream call fails (after one retry) — we degrade gracefully
        rather than fail the whole /refresh cycle.
      * the kill switch ``EPSS_DISABLED=1`` is set.
    """
    if _disabled():
        return None
    if not cve_id or not _CVE_ID_RE.match(cve_id):
        return None
    cve_id = cve_id.upper()
    cached = _read_cache(cve_id)
    if cached is not None:
        return cached
    if _is_negative_cached(cve_id):
        return None
    try:
        payload = _http_get_json(EPSS_API_URL, {"cve": cve_id})
    except Exception as exc:  # noqa: BLE001 — degrade gracefully
        log.warning("EPSS lookup failed for %s: %s", cve_id, exc)
        return None
    parsed = _parse_response(payload)
    result = parsed.get(cve_id)
    _write_cache(cve_id, result)
    return result


def lookup_many(cve_ids: Iterable[str]) -> dict[str, EpssResult]:
    """Bulk EPSS lookup. Cache-first, then a single batched API call.

    Returns a dict keyed by upper-cased CVE id. CVEs missing from EPSS
    or failed by the upstream are simply absent from the dict; callers
    decide whether to treat that as ``None`` or skip.
    """
    if _disabled():
        return {}
    ids = [c.upper() for c in cve_ids if c and _CVE_ID_RE.match(c)]
    out: dict[str, EpssResult] = {}
    misses: list[str] = []
    for cve in dict.fromkeys(ids):  # preserve order, dedupe
        cached = _read_cache(cve)
        if cached is not None:
            out[cve] = cached
            continue
        if _is_negative_cached(cve):
            continue  # known-not-scored, skip
        misses.append(cve)

    for batch_start in range(0, len(misses), _BULK_BATCH_SIZE):
        batch = misses[batch_start : batch_start + _BULK_BATCH_SIZE]
        try:
            payload = _http_get_json(EPSS_API_URL, {"cve": ",".join(batch)})
        except Exception as exc:  # noqa: BLE001
            log.warning("EPSS bulk lookup failed for %d ids: %s", len(batch), exc)
            continue
        parsed = _parse_response(payload)
        for cve in batch:
            result = parsed.get(cve)
            _write_cache(cve, result)
            if result is not None:
                out[cve] = result
    return out


def annotate_records(records: list) -> list:
    """In-place: stamp ``metadata['epss_score']`` and ``['epss_percentile']``.

    Operates on :class:`cyber_threat_bot.models.ThreatRecord` instances or
    anything else exposing ``.canonical_id`` and ``.metadata``. Only CVE
    canonical ids are looked up; non-CVE records (MITRE techniques, news
    items) are skipped silently.
    """
    cve_ids = [
        getattr(rec, "canonical_id", "")
        for rec in records
        if _CVE_ID_RE.match(getattr(rec, "canonical_id", "") or "")
    ]
    if not cve_ids:
        return records
    results = lookup_many(cve_ids)
    for rec in records:
        cve = (getattr(rec, "canonical_id", "") or "").upper()
        if not _CVE_ID_RE.match(cve):
            continue
        meta = getattr(rec, "metadata", None)
        if meta is None:
            continue
        result = results.get(cve)
        if result is None:
            meta.setdefault("epss_score", None)
            meta.setdefault("epss_percentile", None)
            meta.setdefault("epss_date", None)
        else:
            meta["epss_score"] = result.score
            meta["epss_percentile"] = result.percentile
            meta["epss_date"] = result.date
    return records
