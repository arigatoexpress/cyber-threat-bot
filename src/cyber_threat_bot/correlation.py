"""Cross-source dedup, confidence scoring, and CVE clustering.

After the per-source fetchers run, the same CVE can appear in CISA KEV
(authoritative for "exploited") AND NVD (authoritative for "scored")
AND a Dark Reading post (authoritative for "the press knows about it").
``cyber_threat_bot.sources.merge_records`` already collapses these by
``canonical_id``; this module:

  1. Adds a ``compute_confidence`` helper that produces a [0, 1] score
     combining source agreement and CVSS strength.
  2. Promotes the merge metadata onto top-level ``sources`` so consumers
     don't need to dig into ``metadata['source_set']``.
  3. Provides ``correlate_records`` for grouping CVEs that share a CWE,
     vendor, or product — the basis of the ``/threats/correlate`` endpoint.

Confidence model
----------------
We use a simple, explainable formula:

    confidence = clip(0.4 * source_agreement + 0.6 * cvss_factor, 0, 1)

where:

  * ``source_agreement = min(1.0, distinct_sources / 3)`` — three or more
    independent sources reach the ceiling. CISA + NVD agreeing on the
    same CVE id (sources={"cisa-kev", "nvd"}) counts as ~0.67.
  * ``cvss_factor       = score / 10`` if ``score`` is set, else 0.

We deliberately do NOT bake EPSS into ``confidence``. EPSS measures
"likelihood of exploitation"; confidence here is "likelihood the record
is accurate and material". Both flow into the actionability score in
the ``severity_v2`` module (Lane 3) where they're weighted explicitly.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import ThreatRecord


def _distinct_sources(record: ThreatRecord) -> list[str]:
    """Return the union of ``record.sources`` and ``metadata['source_set']``,
    deduped, in insertion order."""
    seen: list[str] = []
    for src in list(record.sources) + list(record.metadata.get("source_set", []) or []):
        if src and src not in seen:
            seen.append(src)
    if not seen and record.source:
        # Fall back to the record's primary source — for un-merged records
        # we still want a sensible single-element list.
        seen.append(record.source)
    return seen


def compute_confidence(record: ThreatRecord) -> float:
    """Return a [0, 1] confidence score for this record.

    See module docstring for the formula. Pure function so callers can
    re-score after late EPSS / KEV updates without re-walking merge logic.
    """
    sources = _distinct_sources(record)
    source_agreement = min(1.0, len(sources) / 3.0)
    cvss_factor = 0.0
    if record.score is not None:
        cvss_factor = max(0.0, min(record.score, 10.0)) / 10.0
    raw = 0.4 * source_agreement + 0.6 * cvss_factor
    return round(max(0.0, min(raw, 1.0)), 3)


def annotate_confidence(records: Iterable[ThreatRecord]) -> list[ThreatRecord]:
    """In-place: stamp ``record.sources`` and ``record.confidence`` for each."""
    out: list[ThreatRecord] = []
    for rec in records:
        # Promote metadata['source_set'] onto the top-level field. We keep the
        # metadata key for backward compat; consumers can switch over.
        if not rec.sources:
            rec.sources = list(rec.metadata.get("source_set", []) or [])
            if not rec.sources and rec.source:
                rec.sources = [rec.source]
        rec.confidence = compute_confidence(rec)
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Correlation by shared attributes
# ---------------------------------------------------------------------------

# Tags we never want to use as cluster keys — too generic to be meaningful.
_GENERIC_TAGS = {
    "kev",
    "mitre-attack",
    "technique",
    "ai",
}


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def _record_get(record: object, key: str, default=None):
    """Read attr from a ThreatRecord OR a dict snapshot uniformly."""
    if isinstance(record, dict):
        return record.get(key, default)
    return getattr(record, key, default)


def _cwe_keys(record: object) -> list[str]:
    """Extract CWE-id strings (e.g. 'CWE-79') from tags + metadata."""
    out: list[str] = []
    for tag in _record_get(record, "tags", []) or []:
        norm = _normalize(tag)
        if norm.startswith("cwe-") and norm.upper() not in out:
            out.append(norm.upper())
    metadata = _record_get(record, "metadata", {}) or {}
    weaknesses = metadata.get("weaknesses") or []
    for w in weaknesses:
        norm = _normalize(w)
        if norm.startswith("cwe-") and norm.upper() not in out:
            out.append(norm.upper())
    return out


def _vendor_key(record: object) -> str | None:
    metadata = _record_get(record, "metadata", {}) or {}
    vendor = _normalize(metadata.get("vendor_project"))
    return vendor or None


def _product_key(record: object) -> str | None:
    metadata = _record_get(record, "metadata", {}) or {}
    product = _normalize(metadata.get("product"))
    return product or None


def _category_keys(record: object) -> list[str]:
    """Generic category tags that aren't CWE-ids and aren't too generic."""
    out: list[str] = []
    for tag in _record_get(record, "tags", []) or []:
        norm = _normalize(tag)
        if not norm or norm.startswith("cwe-"):
            continue
        if norm in _GENERIC_TAGS:
            continue
        if norm not in out:
            out.append(norm)
    return out


def correlate_records(records: Iterable[object], *, min_group_size: int = 2) -> dict[str, dict[str, list[str]]]:
    """Group CVE records by shared CWE / vendor / product / category.

    Returns a dict like::

        {
          "cwe": {"CWE-79": ["CVE-...", ...], ...},
          "vendor": {"linux": [...], ...},
          "product": {"kernel": [...], ...},
          "tag":    {"rce": [...], ...},
        }

    Only groups with ``min_group_size`` or more members are kept — singleton
    "clusters" are noise. Groups are ordered by descending size.
    """
    by_cwe: dict[str, list[str]] = defaultdict(list)
    by_vendor: dict[str, list[str]] = defaultdict(list)
    by_product: dict[str, list[str]] = defaultdict(list)
    by_tag: dict[str, list[str]] = defaultdict(list)

    record_list = list(records)
    for rec in record_list:
        cve = _record_get(rec, "canonical_id", "") or ""
        if not cve:
            continue
        for cwe in _cwe_keys(rec):
            if cve not in by_cwe[cwe]:
                by_cwe[cwe].append(cve)
        vendor = _vendor_key(rec)
        if vendor and cve not in by_vendor[vendor]:
            by_vendor[vendor].append(cve)
        product = _product_key(rec)
        if product and cve not in by_product[product]:
            by_product[product].append(cve)
        for tag in _category_keys(rec):
            if cve not in by_tag[tag]:
                by_tag[tag].append(cve)

    def _filter_and_sort(buckets: dict[str, list[str]]) -> dict[str, list[str]]:
        kept = {k: v for k, v in buckets.items() if len(v) >= min_group_size}
        return dict(sorted(kept.items(), key=lambda kv: (-len(kv[1]), kv[0])))

    return {
        "cwe": _filter_and_sort(by_cwe),
        "vendor": _filter_and_sort(by_vendor),
        "product": _filter_and_sort(by_product),
        "tag": _filter_and_sort(by_tag),
    }
