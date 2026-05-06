# Cyber Threat Bot

[![ci](https://github.com/arigatoexpress/cyber-threat-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/arigatoexpress/cyber-threat-bot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
[![Live](https://img.shields.io/badge/live-cloud--run-2ea44f)](https://cyber-threat-bot-691674245427.us-central1.run.app/healthz/)

**A primary-source threat intel bot that ranks the queue you have to clear today, not the feed you can scroll forever.**
We aggregate CISA KEV, NVD, and MITRE ATT&CK into a deduplicated, EPSS-scored, actionability-ranked queue with a sales-ready output format.
Recorded Future and Mandiant cost six figures and read like compliance theater. This costs nothing, runs on Cloud Run, and tells you what to patch.

---

## Live

| Surface | URL | Status |
|---|---|---|
| Health probe | <https://cyber-threat-bot-691674245427.us-central1.run.app/healthz/> | `{"status":"ok","schema_version":"3"}` |
| Threat snapshot | `GET /threats?source=all` | lazy-warmed JSON |
| Refresh | `POST /refresh` | idempotent re-fetch |

Refreshed every **4 hours** by Cloud Scheduler. The Mac LaunchAgent (`com.sapphire.cyber-threat-bot`) keeps a local mirror at `~/.sapphire/cyber-threat-bot/latest.json` for offline analyst work and Sapphire plugin tools.

## What sets this apart

| | This | Recorded Future / Mandiant | Common KEV mirrors |
|---|---|---|---|
| **Cost** | $0 (public APIs) | six figures / yr | $0 |
| **Sources** | CISA KEV + NVD + MITRE ATT&CK + Dark Reading RSS | proprietary scrapers | KEV only |
| **Cross-source dedup** | yes — by CVE, then by CWE/vendor correlation | yes | no |
| **EPSS scoring** | yes (FIRST.org EPSS API) | yes | no |
| **Composite actionability score** | KEV + CVSS + EPSS + age, transparently weighted | opaque | no |
| **Commercial output** | offers translated to fixed-scope service packages with price anchors | analyst hours | none |
| **Deployable in 5 min** | yes (`gcloud builds submit`) | enterprise procurement | depends |

The differentiator is **rank order**. Most feeds give you a firehose; this gives you the four CVEs you should patch before lunch and a one-page service offer to pitch a client tomorrow.

## Quickstart (5 minutes)

```bash
# 1. Install (creates project-local .venv, sidesteps the python3-vs-pip mismatch)
./scripts/install.sh
source .venv/bin/activate

# 2. Pull a ranked queue
threat-bot latest --days 7 --per-source 8 --format markdown

# 3. Brief a specific CVE or technique
threat-bot brief CVE-2026-1340 --format markdown
threat-bot technique T1059 --format markdown

# 4. Translate the queue into a sellable service offer
threat-bot offers --profile profiles/ai-saas.json --format markdown
```

Optional extras: `--with-dev` (pytest, ruff, pre-commit) · `--with-http` (FastAPI server) · `--python 3.12`.

The legacy invocation still works for source-tree users:
`PYTHONPATH=src python3 -m cyber_threat_bot latest --days 7`.

## Commands

| Command | Output |
|---|---|
| `threat-bot latest` | Cross-source ranked queue, dedup'd, scored |
| `threat-bot cve CVE-YYYY-NNNN` | NVD-backed CVE record + references |
| `threat-bot technique T####` | MITRE ATT&CK technique brief |
| `threat-bot brief <CVE\|T####>` | Full research brief: snapshot, evidence, technical breakdown, sanitized byte sketch, mitigations, unknowns |
| `threat-bot offers` | Live threats → service offers with buyer, price anchor, delivery plan |

## Sources

| Source | Use | Access |
|---|---|---|
| CISA KEV | Exploitation-in-the-wild signal + remediation due dates | Public JSON |
| NVD CVE API 2.0 | CVE metadata, CVSS, CWEs, references | Public API |
| MITRE ATT&CK | Behavior framing, mitigations, detections | Public HTML |
| FIRST.org EPSS | 30-day exploitation probability per CVE | Public API |
| Dark Reading RSS | Current reporting context | Public RSS |

Primary factual claims are anchored to CISA, NVD, CVE.org, MITRE, and vendor advisories. Dark Reading is for prioritization context, not citation.

## HTTP server (Cloud Run)

```bash
# Local
python app.py                     # listens on $PORT or 8080

# Container
docker build -t cyber-threat-bot .
docker run --rm -p 8080:8080 cyber-threat-bot
curl http://localhost:8080/healthz/

# Deploy to Cloud Run
gcloud builds submit --config cloudbuild.yaml
```

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz/` | Liveness; returns last refresh timestamp |
| `GET` | `/threats?source=kev\|nvd\|mitre\|all` | Latest cached threats per source |
| `POST` | `/refresh` | Idempotent re-fetch; returns per-source counts and errors |

## Mac operator install (4h refresh LaunchAgent)

Keeps `~/.sapphire/cyber-threat-bot/latest.json` warm for Sapphire plugin tools without re-fetching upstream feeds.

```bash
cp infra/com.sapphire.cyber-threat-bot.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.sapphire.cyber-threat-bot.plist
launchctl list | grep cyber-threat-bot
tail -f /tmp/cyber-threat-bot.out.log /tmp/cyber-threat-bot.err.log
```

Pause without uninstalling (matches Sapphire's PR #392 routine-pause pattern):
```bash
touch ~/.sapphire/routine_pause/cyber-threat-bot     # pause
rm    ~/.sapphire/routine_pause/cyber-threat-bot     # resume
```

## Architecture

```
sources         dedup           score              output
-------         -----           -----              ------
CISA KEV   ─┐                                  ┌── CLI / markdown
NVD        ─┤── cross-source ── KEV+CVSS+      ├── /threats JSON
MITRE      ─┤   correlation    EPSS+age        ├── service offers
EPSS       ─┘   (CWE, vendor)  composite       └── Sapphire JSON mirror
                               actionability
```

`src/cyber_threat_bot/` — collectors, dedup, scoring, formatters. Stdlib-first HTTP server. No frameworks unless you opt in to `--with-http`.

## Status

- **203 tests passing** (`pytest tests/ -q`); ruff-clean; CI gates merge.
- Cross-source dedup + correlation by CWE/vendor — PR #15 (merged).
- EPSS scoring on every CVE record — PR #14 (merged).
- Composite actionability score (KEV + CVSS + EPSS + age) — `feat/severity-v2` (in progress).
- Cloud Run deploy live; 4h Cloud Scheduler refresh wired.

### Roadmap

- Severity v2 composite score lands on `master`, gated by snapshot regression tests.
- Vendor advisory ingestion (Microsoft, Cisco, Atlassian) for the high-value tail KEV misses.
- One-shot Slack/Telegram digest mode for `latest` + `offers`.
- Optional Sigma rule emit per technique brief.

## Cross-link

This bot is the **threat-intel silo** of Sapphire's [Brain](https://sapphirealpha.xyz/api/brain/synthesis) — Sapphire pulls our snapshot every cycle and folds it into the cross-silo health score alongside trading, regime, and infrastructure feeds. Sapphire is the orchestration layer; this satellite stands alone.

- [Sapphire](https://github.com/arigatoexpress/Sapphire) — capital intelligence + content + autonomous ops monorepo
- [regional-intel-workbench](https://github.com/arigatoexpress/regional-intel-workbench) — public-source regional analyst console
- [wildfire-watch](https://github.com/arigatoexpress/wildfire-watch) — county-scale autonomous drone fleet for wildfire detection

## Safety posture

Built for learning, analysis, and defense. No exploit PoCs. No weaponized payload generation. Byte-level examples are sanitized teaching artifacts unless directly backed by a public spec or official vendor artifact.

## Attribution

This product uses data from the NVD API but is not endorsed or certified by the NVD. EPSS data courtesy of FIRST.org.

## License

[MIT](LICENSE).
