from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_PRIORITY_TAGS = ["kev", "rce", "auth", "supply-chain", "ai", "path-traversal"]
DEFAULT_BUYERS = ["CISO", "CTO", "VP Engineering"]
DEFAULT_SERVICE_STRENGTHS = [
    "Rapid exposure review",
    "Patch and mitigation verification",
    "Executive-ready threat briefings",
]
DEFAULT_PACKAGE_SIZES = [2500, 7500, 20000]


def _clean_list(values: list[Any] | None) -> list[str]:
    cleaned: list[str] = []
    for value in values or []:
        text = str(value).strip()
        if text:
            cleaned.append(text)
    return cleaned


@dataclass(slots=True)
class CustomerProfile:
    name: str = "Threat-Led Revenue Desk"
    description: str = "Ranks threats by urgency, buyer pain, and sellable delivery scope."
    industries: list[str] = field(default_factory=list)
    owned_technologies: list[str] = field(default_factory=list)
    priority_tags: list[str] = field(default_factory=lambda: list(DEFAULT_PRIORITY_TAGS))
    priority_keywords: list[str] = field(default_factory=list)
    excluded_keywords: list[str] = field(default_factory=list)
    buyers: list[str] = field(default_factory=lambda: list(DEFAULT_BUYERS))
    service_strengths: list[str] = field(default_factory=lambda: list(DEFAULT_SERVICE_STRENGTHS))
    package_sizes: list[int] = field(default_factory=lambda: list(DEFAULT_PACKAGE_SIZES))
    currency: str = "USD"
    lead_goal: str = "Sell high-trust cyber sprints now and convert them into retainers."

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CustomerProfile":
        package_sizes: list[int] = []
        for raw_value in payload.get("package_sizes", DEFAULT_PACKAGE_SIZES):
            try:
                package_sizes.append(int(raw_value))
            except (TypeError, ValueError):
                continue
        if not package_sizes:
            package_sizes = list(DEFAULT_PACKAGE_SIZES)
        return cls(
            name=str(payload.get("name") or "Threat-Led Revenue Desk"),
            description=str(payload.get("description") or "Ranks threats by urgency, buyer pain, and sellable delivery scope."),
            industries=_clean_list(payload.get("industries")),
            owned_technologies=_clean_list(payload.get("owned_technologies")),
            priority_tags=_clean_list(payload.get("priority_tags")) or list(DEFAULT_PRIORITY_TAGS),
            priority_keywords=_clean_list(payload.get("priority_keywords")),
            excluded_keywords=_clean_list(payload.get("excluded_keywords")),
            buyers=_clean_list(payload.get("buyers")) or list(DEFAULT_BUYERS),
            service_strengths=_clean_list(payload.get("service_strengths")) or list(DEFAULT_SERVICE_STRENGTHS),
            package_sizes=package_sizes,
            currency=str(payload.get("currency") or "USD"),
            lead_goal=str(payload.get("lead_goal") or "Sell high-trust cyber sprints now and convert them into retainers."),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "industries": self.industries,
            "owned_technologies": self.owned_technologies,
            "priority_tags": self.priority_tags,
            "priority_keywords": self.priority_keywords,
            "excluded_keywords": self.excluded_keywords,
            "buyers": self.buyers,
            "service_strengths": self.service_strengths,
            "package_sizes": self.package_sizes,
            "currency": self.currency,
            "lead_goal": self.lead_goal,
        }


def load_profile(path: str | None = None) -> CustomerProfile:
    if path is None:
        return CustomerProfile()
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Profile file must contain a JSON object: {path}")
    return CustomerProfile.from_dict(payload)
