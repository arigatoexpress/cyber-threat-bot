# Cyber Threat Bot

[![ci](https://github.com/arigatoexpress/cyber-threat-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/arigatoexpress/cyber-threat-bot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)

An open-source cyber research bot that does three useful jobs:

- collects current threat signals from reputable live sources
- turns specific CVEs or ATT&CK techniques into structured analyst briefs
- converts urgent threats into fixed-scope service offers you can actually sell

This is the pragmatic wedge for a Mythos-class security agent: not just "more autonomy," but better signal selection, better reporting, and revenue-ready outputs.

## Included sources

| Source | Use | Access |
| --- | --- | --- |
| CISA Known Exploited Vulnerabilities catalog | Exploitation-in-the-wild signal and remediation due dates | Public JSON |
| NVD CVE API 2.0 | CVE metadata, CVSS, CWEs, and references | Public API |
| MITRE ATT&CK technique pages | Behavior framing, mitigations, detections, and procedure examples | Public HTML |
| Dark Reading RSS | Current reporting context for prioritization | Public RSS |

Dark Reading is used for current reporting and prioritization. Primary factual claims should still come from CISA, NVD, CVE.org, MITRE, and vendor advisories.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

threat-bot latest --days 7 --per-source 8 --format markdown
threat-bot brief CVE-2026-1340 --format markdown
threat-bot technique T1059 --format markdown
threat-bot offers --profile profiles/ai-saas.json --format markdown
```

## Example output

```text
## Threat Queue

| Rank | Source | Signal | Why it matters | Next defensive action |
| --- | --- | --- | --- | --- |
| 1 | CISA KEV | Publicly tracked exploited vulnerability | Confirm exposure and remediation owner | Patch, mitigate, or document non-exposure |
| 2 | NVD | High-severity CVE with public references | Prioritize asset inventory review | Validate affected versions and compensating controls |
| 3 | MITRE ATT&CK | Technique brief | Helps map detections to observed behavior | Review logging and response coverage |
```

## Commands

- `threat-bot latest`
  - Pulls current signals, merges overlapping evidence, and ranks the queue by urgency.
- `threat-bot cve CVE-YYYY-NNNN`
  - Fetches an NVD-backed CVE starter with references, weaknesses, and safe teaching angles.
- `threat-bot technique T####`
  - Pulls a MITRE ATT&CK technique page and extracts mitigations, detection notes, and procedure examples.
- `threat-bot brief <CVE|T####>`
  - Produces a structured research brief with snapshot, evidence, technical breakdown, visualization, safe byte sketch, mitigation guidance, and unknowns.
- `threat-bot offers`
  - Translates live threats into service offers with buyer, price anchor, delivery plan, and a path to $1M+ in annualized revenue.

## What you get

- Cross-source CVE deduplication and priority scoring
- Defensive deep-dive briefs that follow a research-friendly template
- MITRE ATT&CK lookups for behavior framing
- Commercial output for operators, consultants, MSSPs, or vCISO teams
- A reusable skill at `skills/cyber-threat-research/`
- A sample commercial profile at `profiles/ai-saas.json`
- A sales playbook at `GO_TO_MARKET.md`
- Community docs: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, and GitHub issue / PR templates

## Installing the skill

Copy or symlink `skills/cyber-threat-research` into your skill directory, or keep the repo checked out and reference the skill from here. The skill expects network access and local Python execution so it can call `python -m cyber_threat_bot ...`.

## Safety posture

The project is designed for learning, analysis, and defense. It avoids exploit PoCs and weaponized payload generation. Byte-level examples are sanitized teaching artifacts unless directly backed by a public specification or official vendor artifact.

## NVD notice

This product uses data from the NVD API but is not endorsed or certified by the NVD.
