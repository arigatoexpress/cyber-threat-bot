"""Tests for the HMAC-signed webhook notifier (Lane 4)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from cyber_threat_bot import webhook as wh
from cyber_threat_bot.models import Evidence, ThreatRecord


@pytest.fixture(autouse=True)
def isolated_idempotency(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBHOOK_IDEMPOTENCY_PATH", str(tmp_path / "webhook.jsonl"))
    yield


def _record(cve: str, *, tier: str, score: float = 80.0, cvss: float | None = 9.5) -> ThreatRecord:
    rec = ThreatRecord(
        source="nvd",
        source_type="cve",
        canonical_id=cve,
        title=f"{cve}: stub",
        url=f"https://example.invalid/{cve}",
        published_at=None,
        summary="stub",
        score=cvss,
        evidence=[Evidence(label="ref", url="https://example.invalid")],
    )
    rec.metadata.update({
        "actionability_score": score,
        "actionability_tier": tier,
        "epss_score": 0.5,
        "epss_percentile": 0.9,
    })
    rec.sources = ["nvd", "cisa-kev"]
    return rec


# ---------------------------------------------------------------------------
# sign_body
# ---------------------------------------------------------------------------

def test_sign_body_deterministic_for_same_timestamp():
    body = b'{"cve":"CVE-2026-A"}'
    secret = "topsecret"
    ts1, sig1 = wh.sign_body(body, secret, timestamp="1234567890")
    ts2, sig2 = wh.sign_body(body, secret, timestamp="1234567890")
    assert ts1 == ts2 == "1234567890"
    assert sig1 == sig2


def test_sign_body_signature_matches_manual_hmac():
    body = b'{"cve":"CVE-2026-A"}'
    secret = "topsecret"
    ts, sig = wh.sign_body(body, secret, timestamp="1700000000")
    expected = hmac.new(
        secret.encode("utf-8"),
        b"1700000000." + body,
        hashlib.sha256,
    ).hexdigest()
    assert sig == expected


def test_sign_body_uses_current_time_when_omitted():
    before = int(time.time())
    ts, _ = wh.sign_body(b"x", "secret")
    after = int(time.time())
    assert before <= int(ts) <= after


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def test_is_enabled_false_when_no_url(monkeypatch):
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    assert wh.is_enabled() is False


def test_is_enabled_true_when_url_set(monkeypatch):
    monkeypatch.setenv("WEBHOOK_URL", "https://example.invalid/wh")
    assert wh.is_enabled() is True


def test_min_tier_default_high(monkeypatch):
    monkeypatch.delenv("WEBHOOK_MIN_TIER", raising=False)
    assert wh.min_tier() == wh.TIER_HIGH


def test_min_tier_invalid_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("WEBHOOK_MIN_TIER", "BOGUS")
    assert wh.min_tier() == wh.DEFAULT_MIN_TIER


# ---------------------------------------------------------------------------
# notify_actionable: skip paths
# ---------------------------------------------------------------------------

def test_notify_skips_when_url_unset(monkeypatch):
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    report = wh.notify_actionable([_record("CVE-2026-A", tier=wh.TIER_CRITICAL)])
    assert report == {
        "delivered": 0,
        "skipped_idempotent": 0,
        "skipped_below_tier": 0,
        "errors": 0,
        "enabled": False,
    }


def test_notify_skips_when_secret_missing(monkeypatch):
    monkeypatch.setenv("WEBHOOK_URL", "https://example.invalid/wh")
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    report = wh.notify_actionable([_record("CVE-2026-A", tier=wh.TIER_CRITICAL)])
    assert report["enabled"] is False
    assert report["delivered"] == 0


# ---------------------------------------------------------------------------
# notify_actionable: tier filtering
# ---------------------------------------------------------------------------

@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("WEBHOOK_URL", "https://example.invalid/wh")
    monkeypatch.setenv("WEBHOOK_SECRET", "topsecret")


@pytest.fixture
def captured_posts(monkeypatch):
    """Replace _post with a recorder that returns a configurable status."""
    posts: list[dict] = []
    status_holder = {"value": 200}

    def _fake_post(url, body, headers):
        posts.append({"url": url, "body": body, "headers": dict(headers)})
        return status_holder["value"]

    monkeypatch.setattr(wh, "_post", _fake_post)
    return posts, status_holder


def test_notify_filters_below_min_tier(configured, captured_posts):
    posts, _ = captured_posts
    records = [
        _record("CVE-A", tier=wh.TIER_WATCH, score=10),
        _record("CVE-B", tier=wh.TIER_MEDIUM, score=30),
        _record("CVE-C", tier=wh.TIER_HIGH, score=60),
        _record("CVE-D", tier=wh.TIER_CRITICAL, score=90),
    ]
    report = wh.notify_actionable(records)
    # Default min_tier=HIGH -> CVE-C and CVE-D pass.
    assert report["delivered"] == 2
    assert report["skipped_below_tier"] == 2
    sent_cves = sorted(json.loads(p["body"])["cve"] for p in posts)
    assert sent_cves == ["CVE-C", "CVE-D"]


def test_notify_min_tier_override(configured, captured_posts):
    posts, _ = captured_posts
    records = [_record("CVE-C", tier=wh.TIER_HIGH), _record("CVE-D", tier=wh.TIER_CRITICAL)]
    report = wh.notify_actionable(records, min_tier_override="CRITICAL_NOW")
    assert report["delivered"] == 1
    assert json.loads(posts[0]["body"])["cve"] == "CVE-D"


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

def test_notify_idempotent_across_calls(configured, captured_posts):
    posts, _ = captured_posts
    rec = _record("CVE-A", tier=wh.TIER_CRITICAL)
    wh.notify_actionable([rec])
    report = wh.notify_actionable([rec])
    assert report["delivered"] == 0
    assert report["skipped_idempotent"] == 1
    # Only one POST happened.
    assert len(posts) == 1


def test_notify_resends_when_tier_escalates(configured, captured_posts):
    posts, _ = captured_posts
    rec_high = _record("CVE-A", tier=wh.TIER_HIGH)
    rec_crit = _record("CVE-A", tier=wh.TIER_CRITICAL)
    wh.notify_actionable([rec_high])
    report = wh.notify_actionable([rec_crit])
    # Different tier -> different idempotency key -> redelivered.
    assert report["delivered"] == 1
    assert len(posts) == 2


# ---------------------------------------------------------------------------
# HMAC signing on the wire
# ---------------------------------------------------------------------------

def test_post_carries_valid_hmac_signature(configured, captured_posts):
    posts, _ = captured_posts
    rec = _record("CVE-A", tier=wh.TIER_CRITICAL)
    wh.notify_actionable([rec])
    p = posts[0]
    sig_header = p["headers"][wh.SIGNATURE_HEADER]
    ts_header = p["headers"][wh.TIMESTAMP_HEADER]
    assert sig_header.startswith("sha256=")
    expected = hmac.new(
        b"topsecret",
        ts_header.encode("ascii") + b"." + p["body"],
        hashlib.sha256,
    ).hexdigest()
    assert sig_header == f"sha256={expected}"


def test_payload_shape_includes_required_fields(configured, captured_posts):
    posts, _ = captured_posts
    rec = _record("CVE-A", tier=wh.TIER_CRITICAL)
    wh.notify_actionable([rec])
    body = json.loads(posts[0]["body"])
    for key in ("cve", "score", "tier", "link", "sources"):
        assert key in body
    assert body["cve"] == "CVE-A"
    assert body["tier"] == wh.TIER_CRITICAL
    assert body["sources"] == ["nvd", "cisa-kev"]


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------

def test_notify_records_errors_when_post_fails(configured, captured_posts):
    posts, status_holder = captured_posts
    status_holder["value"] = 500
    rec = _record("CVE-A", tier=wh.TIER_CRITICAL)
    report = wh.notify_actionable([rec])
    assert report["errors"] == 1
    assert report["delivered"] == 0


def test_notify_failed_delivery_is_not_marked_idempotent(configured, captured_posts):
    posts, status_holder = captured_posts
    status_holder["value"] = 500
    rec = _record("CVE-A", tier=wh.TIER_CRITICAL)
    wh.notify_actionable([rec])
    # Server recovers; we should retry next cycle.
    status_holder["value"] = 200
    report = wh.notify_actionable([rec])
    assert report["delivered"] == 1


# ---------------------------------------------------------------------------
# dict input compatibility
# ---------------------------------------------------------------------------

def test_notify_accepts_dict_records(configured, captured_posts):
    posts, _ = captured_posts
    rec = _record("CVE-A", tier=wh.TIER_CRITICAL).to_dict()
    report = wh.notify_actionable([rec])
    assert report["delivered"] == 1


def test_notify_skips_non_cve_canonical_ids(configured, captured_posts):
    posts, _ = captured_posts
    rec = ThreatRecord(
        source="mitre-attack",
        source_type="technique",
        canonical_id="T1059",
        title="T1059",
        url="https://example.invalid",
        published_at=None,
        summary="",
    )
    rec.metadata["actionability_tier"] = wh.TIER_CRITICAL
    report = wh.notify_actionable([rec])
    assert report["delivered"] == 0
    assert len(posts) == 0
