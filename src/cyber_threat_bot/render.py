from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import ThreatRecord, isoformat
from .scoring import record_priority


def _display_date(value: datetime | None) -> str:
    return isoformat(value) or "unknown"


def _teaching_angles(record: ThreatRecord) -> list[str]:
    text = f"{record.title} {record.summary} {' '.join(record.tags)}".lower()
    patterns = [
        (
            ("memory-corruption", "overflow", "heap", "use-after-free", "out-of-bounds"),
            [
                "Show a tiny memory-layout diagram with length, flags, and attacker-controlled bytes.",
                "Explain how bounds checks fail before any shellcode discussion.",
                "Use endianness and offset math instead of exploit strings.",
            ],
        ),
        (
            ("deserialization", "serialize", "pickle", "marshal"),
            [
                "Draw the serialized object envelope and explain trusted vs untrusted fields.",
                "Show where type confusion or unsafe object construction begins.",
                "Use a synthetic byte stream, not a live gadget chain.",
            ],
        ),
        (
            ("path-traversal", "directory traversal"),
            [
                "Visualize path normalization before and after decoding.",
                "Compare intended root path vs resolved path with a short ASCII diagram.",
                "Use harmless filenames to explain the parser bug.",
            ],
        ),
        (
            ("injection", "sql", "command", "template", "prompt"),
            [
                "Show delimiter boundaries and where trusted instructions mix with attacker input.",
                "Explain tokenizer or parser context changes step by step.",
                "Use benign payload placeholders rather than runnable attack strings.",
            ],
        ),
        (
            ("auth", "session", "token", "bypass"),
            [
                "Draw the request-to-session validation path and the missing check.",
                "Show the token fields or state transitions that matter.",
                "Contrast accepted vs rejected validation flow.",
            ],
        ),
        (
            ("supply-chain", "dependency", "package", "artifact", "plugin", "integrity check", "update payload", "updater"),
            [
                "Map the trust chain from maintainer to build system to runtime.",
                "Show where signatures, manifests, or lockfiles are supposed to be enforced.",
                "Use a package metadata sketch instead of malicious package contents.",
            ],
        ),
        (
            ("prompt injection", "large language model", "llm", "tool schema", "assistant", "agentic"),
            [
                "Separate system rules, tool schema, retrieval context, and untrusted input in a flowchart.",
                "Explain why control-plane text and data-plane text got mixed.",
                "Use a sanitized prompt frame with obvious placeholders.",
            ],
        ),
    ]
    for needles, angles in patterns:
        if any(needle in text for needle in needles):
            return angles
    return [
        "Explain the vulnerable parser or state machine in three steps.",
        "Use a small mermaid diagram for data flow from input to sink.",
        "If bytes matter, show a synthetic structure layout rather than a weaponized payload.",
    ]


def to_json(records: list[ThreatRecord]) -> str:
    return json.dumps([record.to_dict() for record in records], indent=2)


def _timeline(records: list[ThreatRecord]) -> list[str]:
    lines = ["```mermaid", "flowchart TD"]
    for index, record in enumerate(records[:6], start=1):
        label = f"{_display_date(record.published_at)[:10]}\\n{record.canonical_id}\\n{record.source}"
        lines.append(f'  n{index}["{label}"]')
        if index > 1:
            lines.append(f"  n{index - 1} --> n{index}")
    lines.append("```")
    return lines


def render_latest_markdown(records: list[ThreatRecord]) -> str:
    ordered = sorted(records, key=record_priority, reverse=True)
    lines = [
        "# Latest Cyber Threat Pack",
        "",
        f"Generated at: {_display_date(datetime.now(timezone.utc))}",
        "",
        "## Prioritized Queue",
        "",
    ]
    for index, record in enumerate(ordered, start=1):
        source_set = ", ".join(record.metadata.get("source_set", [record.source]))
        lines.extend(
            [
                f"### {index}. {record.title}",
                f"- Canonical ID: `{record.canonical_id}`",
                f"- Sources: {source_set}",
                f"- Latest evidence date: {_display_date(record.published_at)}",
                f"- Priority score: {record_priority(record)}",
                f"- Exploited in the wild: {'yes' if record.exploited else 'not confirmed'}",
            ]
        )
        if record.score is not None:
            lines.append(f"- CVSS base score: {record.score}")
        lines.append(f"- Summary: {record.summary}")
        for angle in _teaching_angles(record):
            lines.append(f"- Teaching angle: {angle}")
        for evidence in record.evidence[:4]:
            published = _display_date(evidence.published_at)
            note = f" - {evidence.note}" if evidence.note else ""
            lines.append(f"- Evidence: [{evidence.label}]({evidence.url}) ({published}){note}")
        lines.append("")

    lines.extend(["## Signal Timeline", ""])
    lines.extend(_timeline(ordered))
    lines.extend(
        [
            "",
            "## Suggested Next Steps",
            "",
            "1. Pick the top one to three items and verify them against primary sources and any vendor advisory.",
            "2. Turn each item into a four-layer explainer: plain English, component internals, low-level structure, and defender takeaways.",
            "3. Label every claim as Confirmed, Inferred, or Unknown before publishing a final brief.",
        ]
    )
    return "\n".join(lines)


def render_cve_markdown(record: ThreatRecord) -> str:
    weaknesses = record.metadata.get("weaknesses") or []
    references = record.metadata.get("references") or []
    vector = record.metadata.get("cvss_vector") or "unknown"
    lines = [
        f"# CVE Deep Dive Starter: {record.canonical_id}",
        "",
        f"- Title: {record.title}",
        f"- NVD detail: [{record.url}]({record.url})",
        f"- CVE.org record: [{record.metadata.get('cve_org_url')}]({record.metadata.get('cve_org_url')})",
        f"- Published: {_display_date(record.published_at)}",
        f"- CVSS: {record.score if record.score is not None else 'unknown'}",
        f"- Vector: `{vector}`",
        f"- Weaknesses: {', '.join(weaknesses) if weaknesses else 'not listed'}",
        "",
        "## Confirmed Facts",
        "",
        f"- {record.summary}",
        "",
        "## Safe Low-Level Teaching Angles",
        "",
    ]
    for angle in _teaching_angles(record):
        lines.append(f"- {angle}")
    lines.extend(
        [
            "",
            "## Illustrative Byte-Level Sketch",
            "",
            "This is a sanitized teaching template. Replace field names with the real parser or protocol only when a public specification or vendor artifact supports it.",
            "",
            "```text",
            "Offset  Size  Field          Example        Why it matters",
            "0x00    2     length         0x0010         Parser trust boundary starts here",
            "0x02    2     flags          0x0001         Changes control flow or validation mode",
            "0x04    N     user_data      41 41 41 41    Attacker-controlled bytes enter here",
            "```",
            "",
            "## Visual Starter",
            "",
            "```mermaid",
            "flowchart LR",
            '  input["Untrusted input"] --> parser["Parser / validator"]',
            '  parser --> state["State transition or memory write"]',
            '  state --> sink["Crash, auth bypass, or code path change"]',
            "```",
            "",
            "## References",
            "",
        ]
    )
    for ref in references[:8]:
        lines.append(f"- {ref}")
    return "\n".join(lines)


def render_technique_markdown(record: ThreatRecord) -> str:
    mitigations = record.metadata.get("mitigations") or []
    procedures = record.metadata.get("procedure_examples") or []
    detection = record.metadata.get("detection_strategy") or "No detection summary captured."
    subtechniques = record.metadata.get("subtechniques") or []
    lines = [
        f"# MITRE ATT&CK Technique: {record.title}",
        "",
        f"- Technique page: [{record.url}]({record.url})",
        "",
        "## MITRE Summary",
        "",
        record.summary,
        "",
        "## Detection Strategy",
        "",
        detection,
        "",
        "## Sub-techniques",
        "",
    ]
    if subtechniques:
        lines.extend(f"- {item}" for item in subtechniques[:10])
    else:
        lines.append("- None captured from the page.")
    lines.extend(["", "## Mitigations", ""])
    if mitigations:
        lines.extend(f"- {item}" for item in mitigations)
    else:
        lines.append("- None captured from the page.")
    lines.extend(["", "## Procedure Examples", ""])
    if procedures:
        lines.extend(f"- {item}" for item in procedures)
    else:
        lines.append("- None captured from the page.")
    lines.extend(
        [
            "",
            "## Visual Starter",
            "",
            "```mermaid",
            "flowchart TD",
            '  access["Initial access or foothold"] --> technique["Technique execution"]',
            '  technique --> objective["Privilege, execution, persistence, or collection"]',
            '  objective --> detection["Detection opportunities"]',
            "```",
        ]
    )
    return "\n".join(lines)
