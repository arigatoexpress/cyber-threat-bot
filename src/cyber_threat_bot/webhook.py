"""HMAC-signed webhook delivery for HIGH / CRITICAL_NOW threats.

Operators tell us where to send notifications via two env vars:

  WEBHOOK_URL       full URL to POST to (Slack, PagerDuty, Sapphire control-plane, etc.)
  WEBHOOK_SECRET    shared secret used to compute HMAC-SHA256 over the body

Each call to ``notify_actionable`` walks the latest ``/refresh`` records,
filters to those at or above the configured minimum tier (default HIGH),
and POSTs a one-record-per-CVE payload. We dedupe across calls using a
JSONL file at ``$WEBHOOK_IDEMPOTENCY_PATH`` (default ``/tmp/cyber-threat-bot/webhook.jsonl``)
so the same CVE-tier pair is never sent twice unless the tier escalates
(e.g. MEDIUM -> CRITICAL_NOW after EPSS catches up).

Network calls use httpx with a 5s timeout and a single retry on transport
or 5xx. Failures are logged but never raised — webhook delivery must
never block a /refresh cycle.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Iterable

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

from .severity_v2 import (
    TIER_CRITICAL,
    TIER_HIGH,
    TIER_MEDIUM,
    TIER_WATCH,
)

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MIN_TIER = TIER_HIGH
DEFAULT_IDEMPOTENCY_PATH = "/tmp/cyber-threat-bot/webhook.jsonl"
USER_AGENT = "cyber-threat-bot/0.2 (+https://github.com/arigatoexpress/cyber-threat-bot)"
SIGNATURE_HEADER = "X-CyberThreatBot-Signature"
TIMESTAMP_HEADER = "X-CyberThreatBot-Timestamp"

_TIER_RANK = {
    TIER_WATCH: 1,
    TIER_MEDIUM: 2,
    TIER_HIGH: 3,
    TIER_CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def webhook_url() -> str | None:
    return (os.environ.get("WEBHOOK_URL") or "").strip() or None


def webhook_secret() -> str | None:
    return (os.environ.get("WEBHOOK_SECRET") or "").strip() or None


def min_tier() -> str:
    raw = (os.environ.get("WEBHOOK_MIN_TIER") or DEFAULT_MIN_TIER).upper()
    return raw if raw in _TIER_RANK else DEFAULT_MIN_TIER


def idempotency_path() -> Path:
    return Path(os.environ.get("WEBHOOK_IDEMPOTENCY_PATH") or DEFAULT_IDEMPOTENCY_PATH)


def is_enabled() -> bool:
    return webhook_url() is not None


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def _idempotency_key(cve: str, tier: str) -> str:
    return f"{cve.upper()}|{tier.upper()}"


def _load_sent_keys(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        out: set[str] = set()
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            cve = obj.get("cve")
            tier = obj.get("tier")
            if cve and tier:
                out.add(_idempotency_key(cve, tier))
        return out
    except OSError as exc:  # pragma: no cover
        log.debug("idempotency load failed: %s", exc)
        return set()


def _append_sent(path: Path, cve: str, tier: str, sent_at: float) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            fh.write(json.dumps({"cve": cve, "tier": tier, "sent_at": sent_at}) + "\n")
    except OSError as exc:  # pragma: no cover
        log.warning("idempotency append failed: %s", exc)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def sign_body(body: bytes, secret: str, *, timestamp: str | None = None) -> tuple[str, str]:
    """Compute (timestamp, hex-encoded signature) for a request body.

    Signs ``f"{timestamp}.{body}"`` so a leaked signature can't be replayed
    (timestamp drift checks live on the receiver).
    """
    ts = timestamp or str(int(time.time()))
    payload = ts.encode("ascii") + b"." + body
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256)
    return ts, digest.hexdigest()


# ---------------------------------------------------------------------------
# Record extraction
# ---------------------------------------------------------------------------


def _record_get(record: Any, key: str, default=None):
    if isinstance(record, dict):
        return record.get(key, default)
    return getattr(record, key, default)


def _build_payload(record: Any) -> dict[str, Any]:
    metadata = _record_get(record, "metadata", {}) or {}
    return {
        "cve": _record_get(record, "canonical_id", ""),
        "title": _record_get(record, "title", ""),
        "score": metadata.get("actionability_score"),
        "tier": metadata.get("actionability_tier"),
        "cvss": _record_get(record, "score"),
        "epss_score": metadata.get("epss_score"),
        "epss_percentile": metadata.get("epss_percentile"),
        "exploited": bool(_record_get(record, "exploited", False)),
        "sources": list(_record_get(record, "sources", []) or []),
        "link": _record_get(record, "url", ""),
        "published_at": _record_get(record, "published_at"),
    }


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


def _post(url: str, body: bytes, headers: dict[str, str]) -> int:
    """POST with httpx, 5s timeout, single retry on transport / 5xx.

    Returns the final HTTP status code, or 0 on transport failure.
    """
    if httpx is None:  # pragma: no cover
        log.warning("httpx not installed; webhook disabled")
        return 0
    last_exc: Exception | None = None
    last_status = 0
    for attempt in range(2):
        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS) as client:
                resp = client.post(url, content=body, headers=headers)
            last_status = resp.status_code
            if 500 <= resp.status_code < 600:
                last_exc = httpx.HTTPStatusError(
                    f"webhook server error {resp.status_code}", request=resp.request, response=resp
                )
                continue
            return resp.status_code
        except httpx.HTTPError as exc:
            last_exc = exc
            log.debug("webhook attempt=%d failed: %s", attempt, exc)
            continue
    log.warning("webhook delivery failed after retry: %s", last_exc)
    return last_status


def deliver_one(payload: dict[str, Any], *, url: str, secret: str) -> int:
    """POST a single payload. Used by ``notify_actionable``; exposed for tests."""
    body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    ts, sig = sign_body(body, secret)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        SIGNATURE_HEADER: f"sha256={sig}",
        TIMESTAMP_HEADER: ts,
    }
    return _post(url, body, headers)


def notify_actionable(records: Iterable[Any], *, min_tier_override: str | None = None) -> dict[str, Any]:
    """Walk records, send a webhook for each new HIGH+/CRITICAL.

    Returns a small report::

        {
          "delivered": int,
          "skipped_idempotent": int,
          "skipped_below_tier": int,
          "errors": int,
          "enabled": bool,
        }

    Skips silently if ``WEBHOOK_URL`` is not set. ``WEBHOOK_SECRET`` is
    required when URL is set; otherwise the call is treated as misconfigured
    and skipped (logged at warning).
    """
    report = {
        "delivered": 0,
        "skipped_idempotent": 0,
        "skipped_below_tier": 0,
        "errors": 0,
        "enabled": False,
    }
    url = webhook_url()
    if not url:
        return report
    secret = webhook_secret()
    if not secret:
        log.warning("WEBHOOK_URL set but WEBHOOK_SECRET missing — skipping notifications")
        return report
    report["enabled"] = True

    threshold = _TIER_RANK[(min_tier_override or min_tier()).upper()] if (
        (min_tier_override or min_tier()).upper() in _TIER_RANK
    ) else _TIER_RANK[DEFAULT_MIN_TIER]

    path = idempotency_path()
    sent = _load_sent_keys(path)

    for rec in records:
        cve = (_record_get(rec, "canonical_id", "") or "").upper()
        if not cve.startswith("CVE-"):
            continue
        metadata = _record_get(rec, "metadata", {}) or {}
        tier = (metadata.get("actionability_tier") or "").upper()
        if not tier:
            report["skipped_below_tier"] += 1
            continue
        if _TIER_RANK.get(tier, 0) < threshold:
            report["skipped_below_tier"] += 1
            continue
        key = _idempotency_key(cve, tier)
        if key in sent:
            report["skipped_idempotent"] += 1
            continue
        payload = _build_payload(rec)
        status = deliver_one(payload, url=url, secret=secret)
        if 200 <= status < 300:
            sent.add(key)
            _append_sent(path, cve, tier, time.time())
            report["delivered"] += 1
        else:
            report["errors"] += 1
    return report
