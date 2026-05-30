# Cyber Threat Bot

[![ci](https://github.com/arigatoexpress/cyber-threat-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/arigatoexpress/cyber-threat-bot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
[![Live](https://img.shields.io/badge/live-cloud--run-2ea44f)](https://cyber-threat-bot-691674245427.us-central1.run.app/healthz/)

**A primary-source threat intel bot that ranks the queue you have to clear today, not the feed you can scroll forever.**

Aggregates CISA KEV, NVD, and MITRE ATT&CK into a deduplicated, EPSS-scored, actionability-ranked queue with a sales-ready output format.

## Quick start (5 minutes)

```bash
# 1. Install
./scripts/install.sh
source .venv/bin/activate

# 2. Pull a ranked queue
threat-bot latest --days 7 --per-source 8 --format markdown

# 3. Brief a specific CVE or technique
threat-bot brief CVE-2026-1340 --format markdown
threat-bot technique T1059 --format markdown

# 4. Translate into a sellable service offer
threat-bot offers --profile profiles/ai-saas.json --format markdown
```

Optional extras: `--with-dev` (pytest, ruff, pre-commit) · `--with-http` (FastAPI server) · `--python 3.12`.

## What this does

1. Fetches CISA KEV, NVD CVE, MITRE ATT&CK, and FIRST.org EPSS in parallel.
2. Deduplicates by CVE, then correlates by CWE and vendor.
3. Scores each threat with a composite actionability metric (KEV + CVSS + EPSS + age).
4. Outputs ranked queues, analyst briefs, and service offers.

## Architecture

```
CISA KEV ─┐
NVD      ─┤── parallel fetch ── dedup + correlate ── score ── output
MITRE    ─┤                                          (CLI / JSON / offers)
EPSS     ─┘
```

## Key features

- **Cross-source dedup** — Merges CISA, NVD, and MITRE by CVE and CWE/vendor correlation.
- **EPSS scoring** — 30-day exploitation probability from FIRST.org on every CVE.
- **Composite actionability** — Transparent KEV + CVSS + EPSS + age weighting.
- **Commercial output** — Live threats translated to fixed-scope service packages with price anchors.
- **Cloud Run deploy** — `gcloud builds submit --config cloudbuild.yaml` in under 5 minutes.

## Tech stack

- Python 3.11+
- `http.server.ThreadingHTTPServer` (production runtime; no FastAPI/Flask dependency by default)
- pytest, ruff
- Docker + Cloud Build + Cloud Run

## HTTP server

```bash
# Local
python app.py                     # listens on $PORT or 8080

# Container
docker build -t cyber-threat-bot .
docker run --rm -p 8080:8080 cyber-threat-bot
```

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz/` | Liveness |
| `GET` | `/threats?source=kev\|nvd\|mitre\|all` | Latest cached threats |
| `POST` | `/refresh` | Idempotent re-fetch |

## Safety posture

Built for learning, analysis, and defense. No exploit PoCs. No weaponized payload generation. Uses public APIs only.

## Agent collaborators

See [AGENTS.md](AGENTS.md) for architecture details, safety boundaries, deployment procedures, and conventions.

## Attribution

This product uses data from the NVD API but is not endorsed or certified by the NVD. EPSS data courtesy of FIRST.org.

## License

[MIT](LICENSE).
