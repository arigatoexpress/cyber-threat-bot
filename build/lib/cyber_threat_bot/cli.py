from __future__ import annotations

import argparse
import json
from pathlib import Path

from .briefs import brief_to_json, render_technique_brief_markdown, render_threat_brief_markdown
from .profiles import load_profile
from .render import render_cve_markdown, render_latest_markdown, render_technique_markdown, to_json
from .revenue import build_revenue_opportunities, opportunities_to_json, render_revenue_markdown
from .sources import (
    collect_latest_records,
    fetch_attack_technique,
    fetch_nvd_cve,
    find_cisa_kev_record,
    search_darkreading,
)


def _write_output(content: str, output_path: str | None) -> None:
    if output_path is None:
        print(content)
        return
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"Wrote {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Current-source cybersecurity threat research bot")
    subparsers = parser.add_subparsers(dest="command", required=True)

    latest = subparsers.add_parser("latest", help="Collect and prioritize the latest threat signals")
    latest.add_argument("--days", type=int, default=7, help="Lookback window for current CVE and KEV data")
    latest.add_argument("--per-source", type=int, default=8, help="Items to fetch from each live source")
    latest.add_argument("--format", choices=("markdown", "json"), default="markdown")
    latest.add_argument("--out", help="Optional output path")

    cve = subparsers.add_parser("cve", help="Fetch and render one CVE drill-down starter")
    cve.add_argument("cve_id", help="CVE identifier such as CVE-2026-1340")
    cve.add_argument("--format", choices=("markdown", "json"), default="markdown")
    cve.add_argument("--out", help="Optional output path")

    technique = subparsers.add_parser("technique", help="Fetch one MITRE ATT&CK technique page")
    technique.add_argument("technique_id", help="Technique identifier such as T1059")
    technique.add_argument("--format", choices=("markdown", "json"), default="markdown")
    technique.add_argument("--out", help="Optional output path")

    brief = subparsers.add_parser("brief", help="Produce a substantial threat or technique brief")
    brief.add_argument("target_id", help="CVE-YYYY-NNNN or ATT&CK technique ID such as T1059")
    brief.add_argument("--format", choices=("markdown", "json"), default="markdown")
    brief.add_argument("--out", help="Optional output path")

    offers = subparsers.add_parser("offers", help="Turn current threat intel into sellable service offers")
    offers.add_argument("--days", type=int, default=14, help="Lookback window for live threat collection")
    offers.add_argument("--per-source", type=int, default=10, help="Items to fetch from each live source")
    offers.add_argument("--profile", help="Optional JSON customer or business profile")
    offers.add_argument("--format", choices=("markdown", "json"), default="markdown")
    offers.add_argument("--out", help="Optional output path")

    return parser


def _latest(days: int, per_source: int, output_format: str) -> str:
    merged = collect_latest_records(days=days, per_source=per_source)
    if output_format == "json":
        return to_json(merged)
    return render_latest_markdown(merged)


def _cve(cve_id: str, output_format: str) -> str:
    record = fetch_nvd_cve(cve_id.upper())
    if output_format == "json":
        return to_json([record])
    return render_cve_markdown(record)


def _technique(technique_id: str, output_format: str) -> str:
    record = fetch_attack_technique(technique_id.upper())
    if output_format == "json":
        return to_json([record])
    return render_technique_markdown(record)


def _brief(target_id: str, output_format: str) -> str:
    normalized = target_id.upper()
    if normalized.startswith("CVE-"):
        record = fetch_nvd_cve(normalized)
        supporting = []
        kev_record = find_cisa_kev_record(normalized)
        if kev_record is not None:
            supporting.append(kev_record)
        search_terms = [normalized]
        vendor = record.metadata.get("vendor_project")
        product = record.metadata.get("product")
        if vendor:
            search_terms.append(str(vendor))
        if product:
            search_terms.append(str(product))
        supporting.extend(search_darkreading(search_terms, limit=2))
        if output_format == "json":
            return brief_to_json(record, supporting)
        return render_threat_brief_markdown(record, supporting)
    if normalized.startswith("T"):
        record = fetch_attack_technique(normalized)
        if output_format == "json":
            return json.dumps({"primary": record.to_dict()}, indent=2)
        return render_technique_brief_markdown(record)
    raise ValueError(f"Unsupported brief target: {target_id}")


def _offers(days: int, per_source: int, profile_path: str | None, output_format: str) -> str:
    profile = load_profile(profile_path)
    records = collect_latest_records(days=days, per_source=per_source)
    opportunities = build_revenue_opportunities(records, profile)
    if output_format == "json":
        return opportunities_to_json(opportunities)
    return render_revenue_markdown(profile, opportunities)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "latest":
        content = _latest(args.days, args.per_source, args.format)
    elif args.command == "cve":
        content = _cve(args.cve_id, args.format)
    elif args.command == "technique":
        content = _technique(args.technique_id, args.format)
    elif args.command == "brief":
        content = _brief(args.target_id, args.format)
    elif args.command == "offers":
        content = _offers(args.days, args.per_source, args.profile, args.format)
    else:
        parser.error(f"Unknown command: {args.command}")
        return 2

    _write_output(content, getattr(args, "out", None))
    return 0
