from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import Evidence, ThreatRecord, isoformat
from .scoring import record_priority


def _display_date(value: datetime | None) -> str:
    return isoformat(value) or "unknown"


def _is_exploited(record: ThreatRecord, supporting: list[ThreatRecord]) -> bool:
    return record.exploited or any(item.exploited for item in supporting)


def _category(record: ThreatRecord) -> str:
    tags = set(record.tags)
    weaknesses = " ".join(record.metadata.get("weaknesses") or []).lower()
    text = f"{record.title} {record.summary} {weaknesses}".lower()
    if "ai" in tags or "prompt injection" in text:
        return "ai"
    if "deserialization" in tags or "cwe-502" in weaknesses:
        return "deserialization"
    if "path-traversal" in tags or "cwe-22" in weaknesses:
        return "path-traversal"
    if "auth" in tags or "cwe-287" in weaknesses or "cwe-285" in weaknesses:
        return "auth"
    if "memory-corruption" in tags or "cwe-787" in weaknesses or "cwe-416" in weaknesses:
        return "memory-corruption"
    if "supply-chain" in tags:
        return "supply-chain"
    if "injection" in tags:
        return "injection"
    return "generic"


def _dedupe_evidence(*record_groups: list[ThreatRecord]) -> list[Evidence]:
    evidence: list[Evidence] = []
    seen_urls: set[str] = set()
    for group in record_groups:
        for record in group:
            for item in record.evidence:
                if item.url in seen_urls:
                    continue
                seen_urls.add(item.url)
                evidence.append(item)
    return evidence


def _snapshot_lines(record: ThreatRecord, supporting: list[ThreatRecord]) -> list[str]:
    dates = [item.published_at for item in [record, *supporting] if item.published_at is not None]
    exploited = _is_exploited(record, supporting)
    date_range = "unknown"
    if dates:
        date_range = f"{_display_date(min(dates))} to {_display_date(max(dates))}"
    confidence = (
        "High confidence. Confirmed claims come from official source material."
        if exploited or record.source == "mitre-attack"
        else "Moderate-to-high confidence. Confirmed claims come from NVD or MITRE; the mechanism section includes labeled inferences."
    )
    return [
        "## 1. Threat Snapshot",
        "",
        f"- What happened: {record.title}",
        f"- Why it matters now: {'Confirmed exploitation increases operational urgency.' if exploited else 'Public disclosure and severity indicate immediate triage value.'}",
        f"- Exact date or date range: {date_range}",
        f"- One-line confidence statement: {confidence}",
    ]


def _evidence_lines(record: ThreatRecord, supporting: list[ThreatRecord]) -> list[str]:
    lines = ["## 2. Evidence", ""]
    evidence = _dedupe_evidence([record], supporting)
    if not evidence:
        lines.append(f"- {record.source}: {record.url}")
        return lines
    for item in evidence[:8]:
        note = f" - {item.note}" if item.note else ""
        lines.append(f"- {item.label} with URL: {item.url} ({_display_date(item.published_at)}){note}")
    if record.metadata.get("cve_org_url"):
        lines.append(f"- CVE Program record with URL: {record.metadata['cve_org_url']}")
    return lines


def _simple_explanation(record: ThreatRecord, supporting: list[ThreatRecord]) -> str:
    exploited = _is_exploited(record, supporting)
    urgency = (
        "Because there is evidence of exploitation, defenders should treat this as active-response work."
        if exploited
        else "Even without confirmed exploitation, the public disclosure and severity are enough to justify quick validation."
    )
    return (
        f"{record.summary} {urgency} Start by checking whether the affected product, parser, or trust boundary exists in your environment. "
        "Then confirm patch status, exposed attack surface, and whether compensating controls already block the path."
    )


def _deep_breakdown_lines(record: ThreatRecord) -> list[str]:
    category = _category(record)
    lookup = {
        "ai": [
            "- Trust boundary: untrusted content crosses from data-plane text into control-plane instructions or tool arguments.",
            "- Vulnerable component: the agent orchestration layer or prompt assembly step.",
            "- State transition or parser failure: the system incorrectly treats attacker-controlled text as instructions with authority.",
            "- Why the bug matters: tool access, retrieval context, or downstream automations may execute under the wrong trust model.",
        ],
        "auth": [
            "- Trust boundary: the request crosses into a session, token, or authorization decision point.",
            "- Vulnerable component: auth middleware, token validation, or state synchronization logic.",
            "- State transition or parser failure: validation returns an unsafe accept decision before the necessary identity checks complete.",
            "- Why the bug matters: attackers can reach privileged code paths or actions without the intended authorization gate.",
        ],
        "deserialization": [
            "- Trust boundary: serialized bytes or objects cross from untrusted input into trusted reconstruction logic.",
            "- Vulnerable component: an object loader, parser, or framework-level deserializer.",
            "- State transition or parser failure: the implementation reconstructs attacker-controlled structure before validating type or capability boundaries.",
            "- Why the bug matters: unsafe object creation can redirect control flow or activate dangerous code paths.",
        ],
        "injection": [
            "- Trust boundary: user-controlled text is mixed into a command, query, template, or execution context.",
            "- Vulnerable component: the tokenizer, interpreter, or templating engine.",
            "- State transition or parser failure: delimiters or execution markers are interpreted as control syntax instead of inert data.",
            "- Why the bug matters: the application hands authority to untrusted input at exactly the point where instructions are parsed.",
        ],
        "memory-corruption": [
            "- Trust boundary: attacker-controlled bytes enter code that assumes lengths, indexes, or object lifetimes are valid.",
            "- Vulnerable component: a parser, allocator interaction, or native memory manipulation path.",
            "- State transition or parser failure: a bounds, lifetime, or ownership check fails before memory access proceeds.",
            "- Why the bug matters: corrupted memory can alter control flow, authorization, or process stability.",
        ],
        "path-traversal": [
            "- Trust boundary: a user-controlled path crosses into filesystem resolution.",
            "- Vulnerable component: normalization, decoding, or root-directory enforcement logic.",
            "- State transition or parser failure: encoded or relative path segments survive validation and resolve outside the intended root.",
            "- Why the bug matters: attackers reach files or directories that the application never meant to expose.",
        ],
        "supply-chain": [
            "- Trust boundary: third-party code or metadata crosses from maintainers and registries into your build or runtime.",
            "- Vulnerable component: dependency resolution, artifact verification, or plugin execution paths.",
            "- State transition or parser failure: signatures, versions, or manifests are trusted without enough policy enforcement.",
            "- Why the bug matters: compromise lands upstream but executes downstream inside otherwise trusted environments.",
        ],
        "generic": [
            "- Trust boundary: untrusted input reaches sensitive code paths or privileged components.",
            "- Vulnerable component: the exposed parser, service, or validation layer described by the public record.",
            "- State transition or parser failure: safety checks are incomplete or occur after dangerous processing begins.",
            "- Why the bug matters: the bug changes control flow, authorization, or memory safety in a security-relevant way.",
        ],
    }
    return ["## 4. Deep Technical Breakdown", ""] + lookup[category]


def _visual_lines(record: ThreatRecord) -> list[str]:
    category = _category(record)
    if category in {"auth", "ai", "injection"}:
        return [
            "## 5. Visualization",
            "",
            "```mermaid",
            "flowchart LR",
            '  input["Untrusted input"] --> gate["Validation or orchestration layer"]',
            '  gate --> decision{"Boundary check?"}',
            '  decision -->|incorrect allow| sink["Privileged action or dangerous code path"]',
            '  decision -->|correct deny| reject["Rejected input"]',
            "```",
        ]
    if category in {"memory-corruption", "deserialization", "path-traversal"}:
        return [
            "## 5. Visualization",
            "",
            "```text",
            "Observed/Illustrative",
            "0x00  [ length ] [ flags ]",
            "0x04  [ untrusted bytes or path tokens .................. ]",
            "      ^ parsing or normalization begins here",
            "```",
        ]
    return [
        "## 5. Visualization",
        "",
        "```mermaid",
        "flowchart TD",
        '  source["External input"] --> parser["Parser / validator"]',
        '  parser --> sink["Sensitive component"]',
        "```",
    ]


def _byte_lines(record: ThreatRecord) -> list[str]:
    category = _category(record)
    if category == "path-traversal":
        example = [
            "Offset  Size  Field              Example              Meaning",
            "0x00    N     encoded_path       2e 2e 2f 65 74 63   Relative segment before normalization",
            "0x06    N     normalized_path    ../etc/config       What the resolver eventually sees",
        ]
    elif category == "ai":
        example = [
            "Offset  Size  Field              Example              Meaning",
            "0x00    N     system_rules       <trusted text>       Control-plane instructions",
            "0x10    N     retrieved_context  <external docs>      Semi-trusted augmentation",
            "0x20    N     user_input         <placeholder>        Untrusted data-plane content",
        ]
    else:
        example = [
            "Offset  Size  Field          Example        Meaning",
            "0x00    2     length         0x0010         Declared parser length",
            "0x02    2     flags          0x0001         Validation or mode bits",
            "0x04    N     data           41 41 41 41    Untrusted bytes begin here",
        ]
    return ["## 6. Safe Byte-Level Teaching Example", "", "```text", *example, "```"]


def _detection_lines(record: ThreatRecord, supporting: list[ThreatRecord]) -> list[str]:
    lines = ["## 7. Detection and Mitigation", ""]
    if _is_exploited(record, supporting):
        lines.append("- Detection ideas: prioritize exposed instances and collect signs of exploitation before routine patch rollout.")
    else:
        lines.append("- Detection ideas: search for vulnerable versions, exposed services, and abnormal requests around the affected component.")
    category = _category(record)
    if category == "auth":
        lines.append("- Hardening or patching guidance: review token validation, session binding, and any cached authorization decisions.")
    elif category == "ai":
        lines.append("- Hardening or patching guidance: separate system prompts, retrieval context, and user data; gate tools with explicit allowlists.")
    elif category == "supply-chain":
        lines.append("- Hardening or patching guidance: pin versions, verify signatures, and review artifact provenance before deployment.")
    else:
        lines.append("- Hardening or patching guidance: apply vendor fixes, validate compensating controls, and reduce reachable attack surface.")
    lines.append("- Operational triage advice: confirm ownership, patch window, exposure, and customer-facing blast radius before you publish conclusions.")
    return lines


def _unknown_lines(record: ThreatRecord) -> list[str]:
    lines = ["## 8. Unknowns", ""]
    if not record.metadata.get("references"):
        lines.append("- Missing evidence: the public record is thin on vendor-specific attack-path detail.")
    else:
        lines.append("- Missing evidence: public references may still omit product-specific deployment context.")
    lines.append("- Competing explanations: the exact root cause may differ from the inferred category until a vendor advisory or writeup confirms it.")
    lines.append("- What to verify next: affected versions, internet exposure, vendor remediation notes, and whether exploitation has been observed in your fleet.")
    return lines


def render_threat_brief_markdown(record: ThreatRecord, supporting: list[ThreatRecord] | None = None) -> str:
    supporting_records = supporting or []
    priority = max(record_priority(item) for item in [record, *supporting_records])
    lines = [
        f"# Threat Brief: {record.canonical_id}",
        "",
        f"Priority score: {priority}",
        "",
    ]
    sections = [
        _snapshot_lines(record, supporting_records),
        _evidence_lines(record, supporting_records),
        ["## 3. Simple Explanation", "", _simple_explanation(record, supporting_records)],
        _deep_breakdown_lines(record),
        _visual_lines(record),
        _byte_lines(record),
        _detection_lines(record, supporting_records),
        _unknown_lines(record),
    ]
    for section in sections:
        lines.extend(section)
        lines.extend(["", ""])
    return "\n".join(lines).strip()


def render_technique_brief_markdown(record: ThreatRecord) -> str:
    mitigations = record.metadata.get("mitigations") or []
    procedures = record.metadata.get("procedure_examples") or []
    detection = record.metadata.get("detection_strategy") or "No detection strategy captured from the public ATT&CK page."
    lines = [
        f"# Technique Brief: {record.canonical_id}",
        "",
        "## 1. Threat Snapshot",
        "",
        f"- What happened: {record.title}",
        "- Why it matters now: ATT&CK techniques are useful for detection design, reporting alignment, and adversary-behavior framing.",
        "- Exact date or date range: MITRE ATT&CK technique pages are living references; treat page contents as current at fetch time.",
        "- One-line confidence statement: High confidence for the technique description; procedure examples still need threat-specific corroboration.",
        "",
        "## 2. Evidence",
        "",
        f"- MITRE ATT&CK technique page with URL: {record.url}",
        "",
        "## 3. Simple Explanation",
        "",
        record.summary,
        "",
        "## 4. Deep Technical Breakdown",
        "",
        "- Trust boundary: the technique shows how an attacker crosses from foothold to a more privileged or useful state.",
        "- Vulnerable component: the operating system, interpreter, service, or administrative workflow involved in the technique.",
        "- State transition or parser failure: attacker actions move the system from benign operation into attacker-controlled execution or persistence.",
        "- Why the bug or behavior matters: defenders can map this behavior to logging, control points, and mitigation decisions.",
        "",
        "## 5. Visualization",
        "",
        "```mermaid",
        "flowchart TD",
        '  access["Initial access"] --> technique["Technique execution"]',
        '  technique --> objective["Persistence, execution, privilege, or collection"]',
        '  objective --> detection["Detection opportunities"]',
        "```",
        "",
        "## 6. Safe Byte-Level Teaching Example",
        "",
        "```text",
        "Field            Example                Meaning",
        "command          harmless-placeholder   Illustrative operator input",
        "interpreter      /bin/sh                Execution surface being abused or monitored",
        "audit_signal     process_start          What defenders should collect",
        "```",
        "",
        "## 7. Detection and Mitigation",
        "",
        f"- Detection ideas: {detection}",
        f"- Hardening or patching guidance: {mitigations[0] if mitigations else 'Review ATT&CK mitigations and platform guardrails for this behavior.'}",
        f"- Operational triage advice: {'; '.join(procedures[:2]) if procedures else 'Use procedure examples only as behavior cues, not as attribution proof.'}",
        "",
        "## 8. Unknowns",
        "",
        "- Missing evidence: ATT&CK techniques do not prove a specific campaign or exploit path on their own.",
        "- Competing explanations: the same telemetry can map to multiple techniques until you add case-specific context.",
        "- What to verify next: platform-specific logging coverage, control effectiveness, and any procedure examples tied to your threat model.",
    ]
    return "\n".join(lines)


def brief_to_json(record: ThreatRecord, supporting: list[ThreatRecord] | None = None) -> str:
    supporting_records = supporting or []
    payload = {
        "primary": record.to_dict(),
        "supporting": [item.to_dict() for item in supporting_records],
        "generated_at": isoformat(datetime.now(timezone.utc)),
    }
    return json.dumps(payload, indent=2)
