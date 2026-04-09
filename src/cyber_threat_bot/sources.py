from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from typing import Any
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET

try:
    import requests
except ImportError:  # pragma: no cover - exercised through stdlib fallback
    requests = None

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - exercised through stdlib fallback
    BeautifulSoup = None

from .models import Evidence, ThreatRecord
from .scoring import record_priority

USER_AGENT = "cyber-threat-bot/0.2 (+https://example.invalid/cyber-threat-bot)"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DARK_READING_RSS_URL = "https://www.darkreading.com/rss.xml"
ATTACK_TECHNIQUE_URL = "https://attack.mitre.org/techniques/{technique_id}/"


def _headers() -> dict[str, str]:
    return {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, application/xml, text/xml, text/html;q=0.9, */*;q=0.8",
    }

def _session() -> Any:
    if requests is None:
        return None
    session = requests.Session()
    session.headers.update(_headers())
    return session


SESSION = _session()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def clean_text(value: str | None) -> str:
    if not value:
        return ""
    return " ".join(unescape(value).split())


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).astimezone(timezone.utc)


def parse_rfc822_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return parsedate_to_datetime(value).astimezone(timezone.utc)


def _request_json(url: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
    if SESSION is not None:
        response = SESSION.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    query = urlencode(params or {})
    request_url = f"{url}?{query}" if query else url
    request = Request(request_url, headers=_headers())
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _request_text(url: str) -> str:
    if SESSION is not None:
        response = SESSION.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    request = Request(url, headers=_headers())
    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def _english_description(values: list[dict[str, Any]]) -> str:
    for item in values:
        if item.get("lang") == "en":
            return clean_text(item.get("value"))
    if values:
        return clean_text(values[0].get("value"))
    return ""


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key) or []
        if not candidates:
            continue
        data = candidates[0].get("cvssData", {})
        score = data.get("baseScore")
        vector = data.get("vectorString")
        return score, vector
    return None, None


def _extract_cwes(cve: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            text = clean_text(desc.get("value"))
            if text and text not in values:
                values.append(text)
    return values


def _extract_references(cve: dict[str, Any], limit: int = 5) -> list[str]:
    refs: list[str] = []
    for entry in cve.get("references", []):
        url = entry.get("url")
        if url and url not in refs:
            refs.append(url)
        if len(refs) >= limit:
            break
    return refs


def _keyword_tags(text: str) -> list[str]:
    lowered = text.lower()
    lookup = {
        "memory-corruption": ("overflow", "memory corruption", "use-after-free", "heap", "out-of-bounds"),
        "injection": ("injection", "sql", "command", "prompt", "template"),
        "auth": ("authentication", "authorization", "bypass", "session", "token"),
        "path-traversal": ("path traversal", "../", "directory traversal"),
        "deserialization": ("deserialization", "serialize", "pickle", "marshal"),
        "rce": ("remote code execution", "arbitrary code", "execute arbitrary", "command execution"),
        "xss": ("cross-site scripting", "xss", "script injection"),
        "supply-chain": ("dependency", "package", "supply chain", "artifact", "plugin"),
        "ai": ("llm", "ai ", "model", "prompt injection", "agent"),
    }
    hits = [label for label, needles in lookup.items() if any(needle in lowered for needle in needles)]
    return hits


def merge_records(records: list[ThreatRecord]) -> list[ThreatRecord]:
    merged: dict[str, ThreatRecord] = {}
    for record in records:
        key = record.canonical_id.lower()
        if key not in merged:
            clone = ThreatRecord(
                source=record.source,
                source_type=record.source_type,
                canonical_id=record.canonical_id,
                title=record.title,
                url=record.url,
                published_at=record.published_at,
                summary=record.summary,
                score=record.score,
                exploited=record.exploited,
                tags=list(record.tags),
                evidence=list(record.evidence),
                metadata=dict(record.metadata),
            )
            clone.metadata["source_set"] = [record.source]
            merged[key] = clone
            continue

        current = merged[key]
        source_set = list(current.metadata.get("source_set", []))
        if record.source not in source_set:
            source_set.append(record.source)
        current.metadata["source_set"] = source_set
        current.source = "+".join(source_set)
        current.exploited = current.exploited or record.exploited
        current.score = max(x for x in (current.score, record.score) if x is not None) if any(
            x is not None for x in (current.score, record.score)
        ) else None
        if (record.published_at or datetime.min.replace(tzinfo=timezone.utc)) > (
            current.published_at or datetime.min.replace(tzinfo=timezone.utc)
        ):
            current.published_at = record.published_at
        current_is_generic = current.title.upper().startswith(current.canonical_id.upper())
        incoming_is_generic = record.title.upper().startswith(record.canonical_id.upper())
        if current_is_generic and not incoming_is_generic:
            current.title = record.title
        elif len(record.title) > len(current.title) and not (not current_is_generic and incoming_is_generic):
            current.title = record.title
        if len(record.summary) > len(current.summary):
            current.summary = record.summary
        for tag in record.tags:
            if tag not in current.tags:
                current.tags.append(tag)
        for item in record.evidence:
            if all(existing.url != item.url for existing in current.evidence):
                current.evidence.append(item)
        for key_name, value in record.metadata.items():
            if key_name == "source_set":
                continue
            if key_name not in current.metadata:
                current.metadata[key_name] = value
    return sorted(merged.values(), key=record_priority, reverse=True)


def parse_cisa_kev(payload: dict[str, Any], *, days: int = 30, now: datetime | None = None, limit: int = 10) -> list[ThreatRecord]:
    now = now or utc_now()
    cutoff = now - timedelta(days=days)
    records: list[ThreatRecord] = []
    for item in payload.get("vulnerabilities", []):
        added = parse_iso_datetime(item.get("dateAdded"))
        if added is None or added < cutoff:
            continue
        cve_id = clean_text(item.get("cveID"))
        vendor = clean_text(item.get("vendorProject"))
        product = clean_text(item.get("product"))
        vuln_name = clean_text(item.get("vulnerabilityName"))
        title = f"{vendor} {product}: {vuln_name}".strip(": ")
        summary_parts = [clean_text(item.get("shortDescription"))]
        due_date = clean_text(item.get("dueDate"))
        if due_date:
            summary_parts.append(f"CISA remediation due date: {due_date}.")
        ransomware = clean_text(item.get("knownRansomwareCampaignUse"))
        if ransomware:
            summary_parts.append(f"Known ransomware campaign use: {ransomware}.")
        summary = " ".join(part for part in summary_parts if part)
        records.append(
            ThreatRecord(
                source="cisa-kev",
                source_type="cve",
                canonical_id=cve_id,
                title=title or cve_id,
                url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
                published_at=added,
                summary=summary,
                exploited=True,
                tags=["kev", vendor.lower(), product.lower()] + _keyword_tags(summary),
                evidence=[
                    Evidence(
                        label="CISA Known Exploited Vulnerabilities",
                        url=CISA_KEV_URL,
                        published_at=added,
                        note=f"{cve_id} catalog entry",
                    )
                ],
                metadata={
                    "vendor_project": vendor,
                    "product": product,
                    "required_action": clean_text(item.get("requiredAction")),
                    "due_date": due_date,
                    "known_ransomware_campaign_use": ransomware,
                },
            )
        )
        if len(records) >= limit:
            break
    return records


def fetch_cisa_kev(*, days: int = 30, limit: int = 10) -> list[ThreatRecord]:
    payload = _request_json(CISA_KEV_URL)
    return parse_cisa_kev(payload, days=days, limit=limit)


def parse_nvd(payload: dict[str, Any], *, limit: int = 10) -> list[ThreatRecord]:
    records: list[ThreatRecord] = []
    for entry in payload.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = clean_text(cve.get("id"))
        published_at = parse_iso_datetime(cve.get("published"))
        summary = _english_description(cve.get("descriptions", []))
        score, vector = _extract_cvss(cve.get("metrics", {}))
        cwes = _extract_cwes(cve)
        title = f"{cve_id}: {summary[:110]}".rstrip()
        refs = _extract_references(cve)
        records.append(
            ThreatRecord(
                source="nvd",
                source_type="cve",
                canonical_id=cve_id,
                title=title,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published_at=published_at,
                summary=summary,
                score=score,
                exploited=False,
                tags=cwes + _keyword_tags(summary),
                evidence=[
                    Evidence(
                        label="NVD CVE API 2.0",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        published_at=published_at,
                    )
                ],
                metadata={
                    "cvss_vector": vector,
                    "weaknesses": cwes,
                    "references": refs,
                    "source_identifier": clean_text(cve.get("sourceIdentifier")),
                    "vuln_status": clean_text(cve.get("vulnStatus")),
                },
            )
        )
        if len(records) >= limit:
            break
    return records


def fetch_nvd_recent(*, days: int = 7, limit: int = 10) -> list[ThreatRecord]:
    now = utc_now()
    start = now - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": max(limit * 5, 50),
        "noRejected": "",
    }
    payload = _request_json(NVD_CVE_API, params=params)
    records = parse_nvd(payload, limit=max(limit * 4, 25))
    records.sort(key=record_priority, reverse=True)
    return records[:limit]


def fetch_nvd_cve(cve_id: str) -> ThreatRecord:
    payload = _request_json(NVD_CVE_API, params={"cveId": cve_id})
    records = parse_nvd(payload, limit=1)
    if not records:
        raise ValueError(f"No NVD record found for {cve_id}")
    record = records[0]
    if record.metadata.get("references") is None:
        record.metadata["references"] = []
    record.metadata["cve_org_url"] = f"https://www.cve.org/CVERecord?id={record.canonical_id}"
    return record


def parse_darkreading_rss(xml_text: str, *, limit: int = 10) -> list[ThreatRecord]:
    root = ET.fromstring(xml_text)
    records: list[ThreatRecord] = []
    channel = root.find("channel")
    if channel is None:
        return records
    for item in channel.findall("item")[:limit]:
        title = clean_text(item.findtext("title"))
        link = clean_text(item.findtext("link"))
        description = clean_text(item.findtext("description"))
        published_at = parse_rfc822_datetime(item.findtext("pubDate"))
        categories = [clean_text(category.text) for category in item.findall("category") if clean_text(category.text)]
        slug = link.rstrip("/").rsplit("/", 1)[-1]
        records.append(
            ThreatRecord(
                source="darkreading",
                source_type="news",
                canonical_id=f"darkreading:{slug}",
                title=title,
                url=link,
                published_at=published_at,
                summary=description,
                tags=categories + _keyword_tags(f"{title} {description}"),
                evidence=[
                    Evidence(
                        label="Dark Reading RSS",
                        url=link,
                        published_at=published_at,
                    )
                ],
                metadata={"categories": categories},
            )
        )
    return records


def fetch_darkreading(*, limit: int = 10) -> list[ThreatRecord]:
    return parse_darkreading_rss(_request_text(DARK_READING_RSS_URL), limit=limit)


def search_darkreading(terms: list[str], *, limit: int = 3) -> list[ThreatRecord]:
    needles = [item.lower() for item in terms if item]
    if not needles:
        return []
    candidates = fetch_darkreading(limit=max(limit * 6, 18))
    matches = [
        record
        for record in candidates
        if any(needle in f"{record.title} {record.summary}".lower() for needle in needles)
    ]
    return matches[:limit]


def _table_after_heading(soup: BeautifulSoup, heading: str, *, limit: int = 5) -> list[str]:
    header = soup.find(lambda tag: tag.name in {"h2", "h3"} and clean_text(tag.get_text()) == heading)
    if header is None:
        return []
    table = header.find_next("table")
    if table is None:
        return []
    rows: list[str] = []
    for row in table.find_all("tr"):
        values = [clean_text(cell.get_text(" ", strip=True)) for cell in row.find_all(["th", "td"])]
        values = [value for value in values if value]
        if values:
            rows.append(" | ".join(values))
        if len(rows) >= limit:
            break
    return rows


def _text_after_heading(soup: BeautifulSoup, heading: str) -> str:
    header = soup.find(lambda tag: tag.name in {"h2", "h3"} and clean_text(tag.get_text()) == heading)
    if header is None:
        return ""
    pieces: list[str] = []
    for sibling in header.find_next_siblings():
        if sibling.name in {"h2", "h3"}:
            break
        text = clean_text(sibling.get_text(" ", strip=True))
        if text:
            pieces.append(text)
        if len(" ".join(pieces)) > 900:
            break
    return " ".join(pieces)


def _strip_html(fragment: str) -> str:
    return clean_text(re.sub(r"<[^>]+>", " ", fragment))


def _fallback_heading_block(html: str, heading: str) -> str:
    pattern = re.compile(
        rf"<h[23][^>]*>\s*{re.escape(heading)}\s*</h[23]>(.*?)(?=<h[23][^>]*>|$)",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(html)
    return match.group(1) if match else ""


def _fallback_table_after_heading(html: str, heading: str, *, limit: int = 5) -> list[str]:
    block = _fallback_heading_block(html, heading)
    if not block:
        return []
    table_match = re.search(r"<table[^>]*>(.*?)</table>", block, re.IGNORECASE | re.DOTALL)
    if table_match is None:
        return []
    rows: list[str] = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", table_match.group(1), re.IGNORECASE | re.DOTALL):
        cells = re.findall(r"<t[hd][^>]*>(.*?)</t[hd]>", row, re.IGNORECASE | re.DOTALL)
        values = [_strip_html(cell) for cell in cells]
        values = [value for value in values if value]
        if values:
            rows.append(" | ".join(values))
        if len(rows) >= limit:
            break
    return rows


def _fallback_text_after_heading(html: str, heading: str) -> str:
    return _strip_html(_fallback_heading_block(html, heading))


def parse_attack_technique_html(html: str, technique_id: str) -> ThreatRecord:
    if BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        name = clean_text((soup.find("h1") or soup.title).get_text())
        description = clean_text((soup.select_one("div.description-body") or soup.find("main")).get_text(" ", strip=True))
        mitigations = _table_after_heading(soup, "Mitigations")
        procedures = _table_after_heading(soup, "Procedure Examples")
        detection = _text_after_heading(soup, "Detection Strategy")
        references = [
            urljoin("https://attack.mitre.org", link.get("href"))
            for link in soup.select("a[href]")
            if "/references/" in link.get("href", "")
        ]
        subtechniques = []
        first_table = soup.find("table")
        if first_table is not None:
            for row in first_table.find_all("tr"):
                values = [clean_text(cell.get_text(" ", strip=True)) for cell in row.find_all("td")]
                if len(values) >= 2 and values[0].startswith(f"{technique_id}."):
                    subtechniques.append(f"{values[0]} {values[1]}")
    else:
        heading_match = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.IGNORECASE | re.DOTALL)
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        name = _strip_html((heading_match or title_match).group(1)) if (heading_match or title_match) else technique_id.upper()
        description_match = re.search(
            r'<div[^>]*class="[^"]*description-body[^"]*"[^>]*>(.*?)</div>',
            html,
            re.IGNORECASE | re.DOTALL,
        )
        if description_match is None:
            description_match = re.search(r"<main[^>]*>(.*?)</main>", html, re.IGNORECASE | re.DOTALL)
        description = _strip_html(description_match.group(1)) if description_match else ""
        mitigations = _fallback_table_after_heading(html, "Mitigations")
        procedures = _fallback_table_after_heading(html, "Procedure Examples")
        detection = _fallback_text_after_heading(html, "Detection Strategy")
        references = [
            urljoin("https://attack.mitre.org", href)
            for href in re.findall(r'href="([^"]+)"', html, re.IGNORECASE)
            if "/references/" in href
        ]
        subtechniques = []
    return ThreatRecord(
        source="mitre-attack",
        source_type="technique",
        canonical_id=technique_id.upper(),
        title=f"{technique_id.upper()}: {name}",
        url=ATTACK_TECHNIQUE_URL.format(technique_id=technique_id.upper()),
        published_at=None,
        summary=description,
        tags=["mitre-attack", "technique"],
        evidence=[
            Evidence(
                label="MITRE ATT&CK technique page",
                url=ATTACK_TECHNIQUE_URL.format(technique_id=technique_id.upper()),
            )
        ],
        metadata={
            "detection_strategy": detection,
            "mitigations": mitigations,
            "procedure_examples": procedures,
            "subtechniques": subtechniques,
            "references": references[:8],
        },
    )


def fetch_attack_technique(technique_id: str) -> ThreatRecord:
    html = _request_text(ATTACK_TECHNIQUE_URL.format(technique_id=technique_id.upper()))
    return parse_attack_technique_html(html, technique_id)


def find_cisa_kev_record(cve_id: str) -> ThreatRecord | None:
    payload = _request_json(CISA_KEV_URL)
    vulnerabilities = payload.get("vulnerabilities", [])
    records = parse_cisa_kev(payload, days=3650, limit=len(vulnerabilities))
    target = cve_id.upper()
    for record in records:
        if record.canonical_id.upper() == target:
            return record
    return None


def collect_latest_records(*, days: int = 7, per_source: int = 8) -> list[ThreatRecord]:
    records: list[ThreatRecord] = []
    cisa_records = fetch_cisa_kev(days=max(days * 4, 30), limit=per_source)
    records.extend(cisa_records)
    for record in cisa_records:
        try:
            records.append(fetch_nvd_cve(record.canonical_id))
        except Exception:
            continue
    records.extend(fetch_nvd_recent(days=days, limit=per_source))
    records.extend(fetch_darkreading(limit=per_source))
    return merge_records(records)
