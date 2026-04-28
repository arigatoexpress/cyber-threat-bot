from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import ThreatRecord, isoformat
from .profiles import CustomerProfile
from .scoring import record_priority


def _record_text(record: ThreatRecord) -> str:
    metadata_text = " ".join(str(value) for value in record.metadata.values())
    return f"{record.title} {record.summary} {' '.join(record.tags)} {metadata_text}".lower()


def _money(amount: int, currency: str = "USD") -> str:
    if currency.upper() == "USD":
        return f"${amount:,.0f}"
    return f"{currency.upper()} {amount:,.0f}"


def _contains_term(text: str, term: str) -> bool:
    escaped = re.escape(term.lower())
    pattern = re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])")
    return bool(pattern.search(text))


def _best_buyer(record: ThreatRecord, profile: CustomerProfile) -> str:
    tags = set(record.tags)
    if "auth" in tags:
        return "CISO or Head of Identity"
    if "ai" in tags:
        return "CTO or Head of AI Platform"
    if "supply-chain" in tags:
        return "VP Engineering or Platform Security Lead"
    if record.exploited or "rce" in tags:
        return "CISO or VP Engineering"
    return profile.buyers[0]


def _offer_template(record: ThreatRecord) -> tuple[str, list[str]]:
    tags = set(record.tags)
    if "ai" in tags:
        return (
            "Agent Guardrail Assessment",
            [
                "Map trusted instructions, retrieval context, tools, and user input.",
                "Attempt controlled prompt-boundary tests against the exposed workflow.",
                "Deliver remediation steps, safe tool policy, and executive summary.",
            ],
        )
    if "auth" in tags:
        return (
            "Identity Boundary Review",
            [
                "Trace auth flows, token lifetimes, and session transitions.",
                "Validate the patch or mitigation against real boundary cases.",
                "Ship a fix verification memo and customer-safe incident language.",
            ],
        )
    if "supply-chain" in tags:
        return (
            "Supply-Chain Blast Radius Sprint",
            [
                "Inventory affected packages, plugins, or artifacts.",
                "Check provenance, version pinning, and reachable execution paths.",
                "Deliver a prioritized remediation and comms plan.",
            ],
        )
    if "path-traversal" in tags:
        return (
            "External Surface Exposure Sweep",
            [
                "Validate path handling and exposed file-serving routes.",
                "Check patch coverage and compensating controls.",
                "Summarize reachability, blast radius, and next actions.",
            ],
        )
    if record.exploited or "rce" in tags:
        return (
            "48-Hour Exposure & Patch Sprint",
            [
                "Identify exposed instances and reachable attack paths.",
                "Validate the patch, controls, and detection coverage.",
                "Deliver a decision-ready brief for engineering and leadership.",
            ],
        )
    return (
        "Threat-Led Exposure Assessment",
        [
            "Map the issue to owned systems and customer-facing risk.",
            "Validate fix status and likely abuse path.",
            "Package findings into an engineering and executive brief.",
        ],
    )


def _score_record(record: ThreatRecord, profile: CustomerProfile) -> tuple[float, list[str], list[str], list[str]]:
    text = _record_text(record)
    reasons: list[str] = []
    tag_hits = [tag for tag in profile.priority_tags if tag.lower() in record.tags]
    tech_hits = [item for item in profile.owned_technologies if _contains_term(text, item)]
    keyword_hits = [item for item in profile.priority_keywords if _contains_term(text, item)]
    excluded_hits = [item for item in profile.excluded_keywords if _contains_term(text, item)]

    score = record_priority(record)
    if record.exploited:
        reasons.append("Confirmed exploitation")
    if tag_hits:
        score += 1.25 * len(tag_hits)
        reasons.append(f"Matches priority tags: {', '.join(tag_hits)}")
    if tech_hits:
        score += 1.75 * len(tech_hits)
        reasons.append(f"Touches owned technologies: {', '.join(tech_hits)}")
    if keyword_hits:
        score += 0.75 * len(keyword_hits)
        reasons.append(f"Buyer keyword match: {', '.join(keyword_hits)}")
    if excluded_hits:
        score -= 2.5 * len(excluded_hits)
        reasons.append(f"Deprioritized by: {', '.join(excluded_hits)}")

    if not reasons:
        reasons.append("High base urgency from severity, recency, or exploit status.")
    return round(max(score, 0.0), 2), reasons, tag_hits, tech_hits


def _price_anchor(record: ThreatRecord, profile: CustomerProfile, *, tech_hits: list[str]) -> int:
    package_sizes = sorted(profile.package_sizes)
    price = package_sizes[1] if len(package_sizes) > 1 else package_sizes[0]
    if record.exploited:
        price = max(price, package_sizes[-1])
    if "rce" in record.tags:
        price += 5000
    if tech_hits:
        price += 2500
    if any(tag in record.tags for tag in ("auth", "ai", "supply-chain")):
        price += 2500
    return int(round(price / 500.0) * 500)


def _sales_hook(record: ThreatRecord, offer_name: str, buyer: str) -> str:
    urgency = "confirmed exploitation" if record.exploited else "a newly public, operationally relevant issue"
    return (
        f"Use {record.canonical_id} as the reason to sell a fixed-scope {offer_name.lower()} to the {buyer}. "
        f"The hook is {urgency} plus a short turnaround that turns uncertainty into a decision-ready plan."
    )


@dataclass(slots=True)
class RevenueOpportunity:
    record: ThreatRecord
    fit_score: float
    reasons: list[str]
    offer_name: str
    buyer: str
    delivery_plan: list[str]
    price_anchor: int
    sales_hook: str

    def to_dict(self) -> dict[str, object]:
        return {
            "fit_score": self.fit_score,
            "offer_name": self.offer_name,
            "buyer": self.buyer,
            "delivery_plan": self.delivery_plan,
            "price_anchor": self.price_anchor,
            "sales_hook": self.sales_hook,
            "reasons": self.reasons,
            "record": self.record.to_dict(),
        }


def build_revenue_opportunities(
    records: list[ThreatRecord], profile: CustomerProfile, *, limit: int = 5
) -> list[RevenueOpportunity]:
    opportunities: list[RevenueOpportunity] = []
    for record in records:
        fit_score, reasons, _, tech_hits = _score_record(record, profile)
        offer_name, delivery_plan = _offer_template(record)
        buyer = _best_buyer(record, profile)
        opportunities.append(
            RevenueOpportunity(
                record=record,
                fit_score=fit_score,
                reasons=reasons,
                offer_name=offer_name,
                buyer=buyer,
                delivery_plan=delivery_plan,
                price_anchor=_price_anchor(record, profile, tech_hits=tech_hits),
                sales_hook=_sales_hook(record, offer_name, buyer),
            )
        )
    opportunities.sort(key=lambda item: item.fit_score, reverse=True)
    return opportunities[:limit]


def _annual_path(profile: CustomerProfile) -> list[str]:
    package_sizes = sorted(profile.package_sizes)
    pilot = package_sizes[0]
    sprint = package_sizes[1] if len(package_sizes) > 1 else package_sizes[0]
    retainer = package_sizes[-1]
    annual = (12 * pilot) + (12 * sprint) + (4 * 12 * retainer)
    return [
        f"- Sell 12 diagnostic pilots at {_money(pilot, profile.currency)} each to generate fast trust and case studies.",
        f"- Convert 12 of those into fixed-scope sprints at {_money(sprint, profile.currency)} each.",
        f"- Close 4 recurring retainers at {_money(retainer, profile.currency)}/month.",
        f"- Annualized path: {_money(annual, profile.currency)} in booked revenue if you execute the ladder consistently.",
    ]


def render_revenue_markdown(profile: CustomerProfile, opportunities: list[RevenueOpportunity]) -> str:
    lines = [
        f"# Threat Revenue Board: {profile.name}",
        "",
        profile.description,
        "",
        f"Generated at: {isoformat(datetime.now(timezone.utc))}",
        "",
        "## Highest-Leverage Offers",
        "",
    ]
    for index, opportunity in enumerate(opportunities, start=1):
        record = opportunity.record
        lines.extend(
            [
                f"### {index}. {opportunity.offer_name}",
                f"- Trigger threat: `{record.canonical_id}` - {record.title}",
                f"- Best buyer: {opportunity.buyer}",
                f"- Fit score: {opportunity.fit_score}",
                f"- Suggested starting price: {_money(opportunity.price_anchor, profile.currency)}",
                f"- Why this fits: {'; '.join(opportunity.reasons)}",
                f"- Sales hook: {opportunity.sales_hook}",
                "- Delivery plan:",
            ]
        )
        lines.extend(f"  - {item}" for item in opportunity.delivery_plan)
        lines.append(f"- Evidence source: {record.url}")
        lines.append("")

    package_sizes = sorted(profile.package_sizes)
    lines.extend(
        [
            "## Offer Ladder",
            "",
            f"- Pilot: {_money(package_sizes[0], profile.currency)} for a 48-hour diagnostic and leadership memo.",
            f"- Sprint: {_money(package_sizes[1] if len(package_sizes) > 1 else package_sizes[0], profile.currency)} for validation, patch review, and customer-safe writeup.",
            f"- Retainer: {_money(package_sizes[-1], profile.currency)}/month for ongoing monitoring, escalation, and bespoke briefs.",
            "",
            "## Million-Dollar Path",
            "",
        ]
    )
    lines.extend(_annual_path(profile))
    return "\n".join(lines)


def opportunities_to_json(opportunities: list[RevenueOpportunity]) -> str:
    return json.dumps([item.to_dict() for item in opportunities], indent=2)
