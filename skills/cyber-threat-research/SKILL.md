---
name: "cyber-threat-research"
description: "Use when the user wants current cybersecurity threat research, CVE deep dives, MITRE ATT&CK analysis, or learner-friendly technical explainers with verified sources, diagrams, and safe byte-level examples. Pull current data from primary sources such as CISA KEV, NVD, CVE.org, and MITRE, with Dark Reading or similar reputable reporting used only as enrichment."
---

# Cyber Threat Research

Use this skill for current threat-intel synthesis, deep vulnerability explainers, ATT&CK technique breakdowns, and learning-oriented cyber research that stays technically precise without turning into exploit instructions.

## Guardrails

- Browse or fetch current sources. Do not answer "latest" cyber questions from memory.
- Prefer primary sources for factual claims: CISA, NVD, CVE.org, MITRE ATT&CK, vendor advisories, and official incident writeups.
- Use Dark Reading and similar outlets as corroborating context, not as the source of truth for exploit internals.
- Every major claim should be labeled mentally as `Confirmed`, `Inferred`, or `Unknown`.
- Do not invent shellcode, weaponized payloads, intrusion steps, or exploit chains. If bytes matter, use sanitized teaching examples unless the exact layout is already public in a specification or official artifact.
- Focus on understanding, detection, mitigation, and defender tradeoffs.

## Quick start

1. Run `python -m cyber_threat_bot latest --days 7 --per-source 8 --format markdown` to collect a current signal pack.
2. If the user names a CVE, run `python -m cyber_threat_bot cve CVE-YYYY-NNNN --format markdown`.
3. If you need ATT&CK grounding, run `python -m cyber_threat_bot technique T#### --format markdown`.
4. Read the relevant reference file only when needed:
   - `references/source-catalog.md` for the live-source map
   - `references/report-template.md` for the final answer shape
   - `references/visualization-patterns.md` for mermaid, ASCII, and byte-layout patterns

## Workflow

1. Gather the current signal pack with the CLI.
2. Select the one to three most important items by exploitation status, severity, recency, and user relevance.
3. Verify each selected item against primary sources and vendor material.
4. Explain each threat at four layers:
   - Plain-English story: what is happening and why it matters
   - Component internals: which service, parser, auth check, trust boundary, or state machine fails
   - Low-level teaching layer: packet field, memory layout, serialized object frame, request boundary, or parser token stream
   - Defender lens: detection, mitigations, operational risk, and patch urgency
5. Include at least one visualization for substantial analyses.
6. Include a safe byte-level or structure-level example when the concept benefits from it.
7. Close with confidence level, unknowns, and what evidence would change the assessment.

## Accuracy rules

- Use absolute dates in your answer when discussing recent events.
- If the reporting outlet conflicts with a primary source, the primary source wins.
- If a low-level mechanism is uncertain, say so directly and describe multiple plausible explanations instead of pretending certainty.
- Only map to ATT&CK techniques when the behavior is actually supported by evidence.

## Teaching style

- Keep the first explanation simple enough for a newer practitioner.
- Immediately follow with the deeper systems explanation.
- Use visualizations that show control flow, trust boundaries, or state transitions.
- Use byte examples to explain structure, not to provide a runnable exploit.
- Prefer mermaid diagrams and compact ASCII layouts over decorative visuals.

## Recommended output shape

Use the template in `references/report-template.md` unless the user asks for a different format.

