# Report Template

Use this template for substantial threat analyses.

## 1. Threat Snapshot

- What happened
- Why it matters now
- Exact date or date range
- A one-line confidence statement

## 2. Evidence

- Source 1 with URL
- Source 2 with URL
- Source 3 with URL

## 3. Simple Explanation

Explain the threat as if teaching an early-career security engineer. Keep the first pass clear and low-jargon.

## 4. Deep Technical Breakdown

- Trust boundary
- Vulnerable component
- State transition or parser failure
- Why the bug changes control flow, authorization, or memory safety

## 5. Visualization

Prefer one of:

- Mermaid flowchart for data or control flow
- Mermaid sequence diagram for actor interaction
- ASCII layout for packet, object, or memory structure

## 6. Safe Byte-Level Teaching Example

Only include this when it helps. Use a sanitized structure, not a weaponized payload.

```text
Offset  Size  Field          Example        Meaning
0x00    2     length         0x0010         Declared parser length
0x02    2     flags          0x0001         Validation mode
0x04    N     data           41 41 41 41    Untrusted bytes begin here
```

## 7. Detection and Mitigation

- Detection ideas
- Hardening or patching guidance
- Operational triage advice

## 8. Unknowns

- Missing evidence
- Competing explanations
- What you would verify next

