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

The supported install path uses `scripts/install.sh`, which always installs
into a project-local `.venv` using the venv's own `python -m pip`. This
avoids the common gotcha where `pip` and `python3` resolve to different
interpreters on the same machine, which silently breaks editable installs.

```bash
./scripts/install.sh                # creates .venv and installs in editable mode
source .venv/bin/activate

threat-bot latest --days 7 --per-source 8 --format markdown
threat-bot brief CVE-2026-1340 --format markdown
threat-bot technique T1059 --format markdown
threat-bot offers --profile profiles/ai-saas.json --format markdown
```

Optional extras:

```bash
./scripts/install.sh --with-dev      # pytest, ruff, pre-commit
./scripts/install.sh --with-http     # fastapi/uvicorn for the HTTP server
./scripts/install.sh --python 3.12   # pin a specific interpreter
```

The legacy invocation still works for anyone using the source tree directly:

```bash
PYTHONPATH=src python3 -m cyber_threat_bot latest --days 7
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

## HTTP server (Cloud Run)

A lightweight stdlib-only HTTP surface is available for container deployment:

```bash
python app.py                  # listens on $PORT or 8080 by default
```

Endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz/` | Liveness probe; returns last refresh timestamp |
| `GET` | `/threats?source=kev\|nvd\|mitre\|all` | Latest cached threats per source (lazy-warmed on first hit) |
| `POST` | `/refresh` | Refetch all sources; idempotent; returns per-source counts and errors |

Container build:

```bash
docker build -t cyber-threat-bot .
docker run --rm -p 8080:8080 cyber-threat-bot
curl http://localhost:8080/healthz/
```

Deploy to Cloud Run via `gcloud builds submit --config cloudbuild.yaml`.

## Installing the skill

Copy or symlink `skills/cyber-threat-research` into your skill directory, or keep the repo checked out and reference the skill from here. The skill expects network access and local Python execution so it can call `python -m cyber_threat_bot ...`.

## Operator: 4h refresh on Mac

To keep a fresh threat snapshot at `~/.sapphire/cyber-threat-bot/latest.json`
(consumable by Sapphire plugin tools without re-fetching upstream feeds),
install the LaunchAgent:

```bash
cp infra/com.sapphire.cyber-threat-bot.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.sapphire.cyber-threat-bot.plist

# Confirm it's loaded:
launchctl list | grep cyber-threat-bot

# View logs:
tail -f /tmp/cyber-threat-bot.out.log /tmp/cyber-threat-bot.err.log
```

Refresh cadence: every 4 hours (`StartInterval = 14400`), with `RunAtLoad`
so the first refresh happens immediately on `bootstrap`.

Pause without uninstalling (matches Sapphire's routine pause pattern from
PR #392):

```bash
mkdir -p ~/.sapphire/routine_pause
touch ~/.sapphire/routine_pause/cyber-threat-bot   # pause
rm ~/.sapphire/routine_pause/cyber-threat-bot      # resume
```

Uninstall:

```bash
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.sapphire.cyber-threat-bot.plist
rm ~/Library/LaunchAgents/com.sapphire.cyber-threat-bot.plist
```

The agent invokes `scripts/refresh.sh`, which prefers the editable
install (`.venv/bin/threat-bot`) and falls back to
`PYTHONPATH=src python3 -m cyber_threat_bot` so both supported invocation
paths work.

## Safety posture

The project is designed for learning, analysis, and defense. It avoids exploit PoCs and weaponized payload generation. Byte-level examples are sanitized teaching artifacts unless directly backed by a public specification or official vendor artifact.

## NVD notice

This product uses data from the NVD API but is not endorsed or certified by the NVD.
