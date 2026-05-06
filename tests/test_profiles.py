"""Tests for src/cyber_threat_bot/profiles.py.

Covers the previously-uncovered branches: load_profile() defaults vs. file
loading, _clean_list whitespace handling, package_sizes int coercion +
fallback, JSON-not-an-object validation error, and to_dict / from_dict
round-tripping.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyber_threat_bot.profiles import (
    DEFAULT_BUYERS,
    DEFAULT_PACKAGE_SIZES,
    DEFAULT_PRIORITY_TAGS,
    DEFAULT_SERVICE_STRENGTHS,
    CustomerProfile,
    _clean_list,
    load_profile,
)


# ---------------------------------------------------------------------------
# _clean_list
# ---------------------------------------------------------------------------


class TestCleanList:
    def test_drops_empty_and_whitespace_only_entries(self) -> None:
        assert _clean_list(["a", "", "  ", "b\n", " c "]) == ["a", "b", "c"]

    def test_handles_none_input(self) -> None:
        assert _clean_list(None) == []

    def test_coerces_non_string_values(self) -> None:
        # 0 is preserved (str(0) == "0", which is truthy after strip)
        assert _clean_list([0, 1, None, "x"]) == ["0", "1", "None", "x"]


# ---------------------------------------------------------------------------
# CustomerProfile.from_dict / to_dict
# ---------------------------------------------------------------------------


class TestCustomerProfileFromDict:
    def test_empty_dict_falls_back_to_all_defaults(self) -> None:
        profile = CustomerProfile.from_dict({})
        assert profile.name == "Threat-Led Revenue Desk"
        assert profile.priority_tags == DEFAULT_PRIORITY_TAGS
        assert profile.buyers == DEFAULT_BUYERS
        assert profile.service_strengths == DEFAULT_SERVICE_STRENGTHS
        assert profile.package_sizes == DEFAULT_PACKAGE_SIZES
        assert profile.currency == "USD"

    def test_package_sizes_coerce_strings_and_ints(self) -> None:
        profile = CustomerProfile.from_dict(
            {"package_sizes": ["1000", 2000, "3000.5"]}
        )
        # "3000.5" fails int() coercion → skipped silently
        assert profile.package_sizes == [1000, 2000]

    def test_package_sizes_all_invalid_falls_back_to_defaults(self) -> None:
        profile = CustomerProfile.from_dict(
            {"package_sizes": ["not-a-number", None, "garbage"]}
        )
        assert profile.package_sizes == DEFAULT_PACKAGE_SIZES

    def test_empty_lists_fall_back_to_defaults(self) -> None:
        profile = CustomerProfile.from_dict(
            {"priority_tags": [], "buyers": [], "service_strengths": []}
        )
        assert profile.priority_tags == DEFAULT_PRIORITY_TAGS
        assert profile.buyers == DEFAULT_BUYERS
        assert profile.service_strengths == DEFAULT_SERVICE_STRENGTHS

    def test_round_trip(self) -> None:
        original = {
            "name": "Acme Cyber",
            "description": "Custom desk",
            "industries": ["finance", "energy"],
            "owned_technologies": ["aws", "azure"],
            "priority_tags": ["zero-day"],
            "priority_keywords": ["ransom"],
            "excluded_keywords": ["physical-security"],
            "buyers": ["CFO"],
            "service_strengths": ["red team"],
            "package_sizes": [5000, 10000],
            "currency": "EUR",
            "lead_goal": "Win retainers.",
        }
        profile = CustomerProfile.from_dict(original)
        assert profile.to_dict() == original


# ---------------------------------------------------------------------------
# load_profile
# ---------------------------------------------------------------------------


class TestLoadProfile:
    def test_no_path_returns_default(self) -> None:
        profile = load_profile(None)
        assert profile.name == "Threat-Led Revenue Desk"

    def test_loads_valid_file(self, tmp_path: Path) -> None:
        target = tmp_path / "profile.json"
        target.write_text(
            json.dumps({"name": "Mining Co", "industries": ["mining"]}),
            encoding="utf-8",
        )
        profile = load_profile(str(target))
        assert profile.name == "Mining Co"
        assert profile.industries == ["mining"]

    def test_rejects_non_object_payload(self, tmp_path: Path) -> None:
        target = tmp_path / "list.json"
        target.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
        with pytest.raises(ValueError, match="must contain a JSON object"):
            load_profile(str(target))
