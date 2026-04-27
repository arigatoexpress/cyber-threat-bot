"""Tests for per-request timeouts and session-level retries in sources.py.

All tests mock the network — no real HTTP calls are made.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from cyber_threat_bot import sources


@pytest.fixture(autouse=True)
def _clear_timeout_env(monkeypatch):
    """Ensure tests don't inherit a stray CYBER_THREAT_BOT_TIMEOUT override."""
    monkeypatch.delenv("CYBER_THREAT_BOT_TIMEOUT", raising=False)


def test_default_timeout_is_thirty_seconds():
    assert sources._request_timeout() == 30.0


def test_timeout_overridable_via_env(monkeypatch):
    monkeypatch.setenv("CYBER_THREAT_BOT_TIMEOUT", "12")
    assert sources._request_timeout() == 12.0


def test_timeout_env_invalid_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("CYBER_THREAT_BOT_TIMEOUT", "not-a-number")
    assert sources._request_timeout() == 30.0


def test_timeout_env_non_positive_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("CYBER_THREAT_BOT_TIMEOUT", "0")
    assert sources._request_timeout() == 30.0
    monkeypatch.setenv("CYBER_THREAT_BOT_TIMEOUT", "-5")
    assert sources._request_timeout() == 30.0


def test_request_json_passes_timeout_to_session(monkeypatch):
    fake_response = MagicMock()
    fake_response.json.return_value = {"ok": True}
    fake_response.raise_for_status.return_value = None
    fake_session = MagicMock()
    fake_session.get.return_value = fake_response

    monkeypatch.setattr(sources, "SESSION", fake_session)
    monkeypatch.setenv("CYBER_THREAT_BOT_TIMEOUT", "7")

    result = sources._request_json("https://example.invalid/data", params={"a": "b"})

    assert result == {"ok": True}
    fake_session.get.assert_called_once_with(
        "https://example.invalid/data", params={"a": "b"}, timeout=7.0
    )
    fake_response.raise_for_status.assert_called_once()


def test_request_text_passes_timeout_to_session(monkeypatch):
    fake_response = MagicMock()
    fake_response.text = "<rss/>"
    fake_response.raise_for_status.return_value = None
    fake_session = MagicMock()
    fake_session.get.return_value = fake_response

    monkeypatch.setattr(sources, "SESSION", fake_session)

    result = sources._request_text("https://example.invalid/feed")

    assert result == "<rss/>"
    fake_session.get.assert_called_once_with(
        "https://example.invalid/feed", timeout=30.0
    )


def test_request_json_stdlib_fallback_uses_timeout(monkeypatch):
    """When requests is unavailable, urlopen must still receive a timeout."""
    monkeypatch.setattr(sources, "SESSION", None)
    captured: dict = {}

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"ok": true}'

    def _fake_urlopen(request, timeout=None):
        captured["timeout"] = timeout
        captured["url"] = request.full_url if hasattr(request, "full_url") else None
        return _FakeResp()

    monkeypatch.setattr(sources, "urlopen", _fake_urlopen)
    monkeypatch.setenv("CYBER_THREAT_BOT_TIMEOUT", "9")

    result = sources._request_json("https://example.invalid/x", params={"q": "1"})
    assert result == {"ok": True}
    assert captured["timeout"] == 9.0


def test_request_text_stdlib_fallback_uses_timeout(monkeypatch):
    monkeypatch.setattr(sources, "SESSION", None)
    captured: dict = {}

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"hello"

    def _fake_urlopen(request, timeout=None):
        captured["timeout"] = timeout
        return _FakeResp()

    monkeypatch.setattr(sources, "urlopen", _fake_urlopen)

    assert sources._request_text("https://example.invalid/y") == "hello"
    assert captured["timeout"] == 30.0


def test_session_mounts_retry_adapter_on_both_schemes():
    session = sources._session()
    assert session is not None, "requests is installed in the test env"

    https_adapter = session.get_adapter("https://example.invalid/")
    http_adapter = session.get_adapter("http://example.invalid/")

    for adapter in (https_adapter, http_adapter):
        retry = adapter.max_retries
        assert retry.total == sources.MAX_RETRIES
        assert retry.connect == sources.MAX_RETRIES
        assert retry.read == sources.MAX_RETRIES
        assert retry.backoff_factor == sources.RETRY_BACKOFF_FACTOR
        # 5xx are retried, 4xx are NOT
        assert 500 in retry.status_forcelist
        assert 502 in retry.status_forcelist
        assert 503 in retry.status_forcelist
        assert 504 in retry.status_forcelist
        assert 400 not in retry.status_forcelist
        assert 401 not in retry.status_forcelist
        assert 403 not in retry.status_forcelist
        assert 404 not in retry.status_forcelist
        assert 429 not in retry.status_forcelist
        # Only safe / idempotent methods are retried.
        assert "GET" in retry.allowed_methods
        assert "POST" not in retry.allowed_methods


def test_session_user_agent_header_set():
    session = sources._session()
    assert session is not None
    assert session.headers.get("User-Agent") == sources.USER_AGENT


def test_session_returns_none_when_requests_missing(monkeypatch):
    monkeypatch.setattr(sources, "requests", None)
    assert sources._session() is None


def test_request_json_does_not_retry_on_4xx(monkeypatch):
    """A 4xx error must surface immediately — retries are 5xx only."""
    import requests as real_requests

    fake_response = MagicMock()
    fake_response.raise_for_status.side_effect = real_requests.HTTPError("404 not found")
    fake_session = MagicMock()
    fake_session.get.return_value = fake_response

    monkeypatch.setattr(sources, "SESSION", fake_session)

    with pytest.raises(real_requests.HTTPError):
        sources._request_json("https://example.invalid/missing")

    # Single GET — no retry loop in the helper itself; retries live in the adapter.
    assert fake_session.get.call_count == 1


def test_session_retry_total_is_three():
    """Bound the retry budget so a slow upstream cannot stall the pipeline."""
    session = sources._session()
    assert session is not None
    retry = session.get_adapter("https://example.invalid/").max_retries
    assert retry.total == 3
