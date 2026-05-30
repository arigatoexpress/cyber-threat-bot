# AGENTS.md — cyber-threat-bot

> Project-specific guidance for AI agents working on this repository.

## What this repo does

Cyber Threat Bot aggregates CISA KEV, NVD CVE, MITRE ATT&CK, and FIRST.org EPSS into a deduplicated, scored, and ranked threat queue. It exposes a lightweight HTTP server and a CLI for analyst briefs and service offers.

## Key directories and files

```
cyber-threat-bot/
├── src/cyber_threat_bot/      # Application code
│   ├── server.py              # stdlib http.server (ThreadingHTTPServer)
│   ├── sources.py             # CISA KEV, NVD, MITRE fetchers
│   ├── epss.py                # EPSS enrichment client
│   ├── correlation.py         # Clustering by CWE/vendor/product/tag
│   ├── severity_v2.py         # Actionability scoring & tiering
│   ├── briefs.py              # Analyst brief generation
│   ├── cli.py                 # CLI entrypoint
│   └── models.py              # ThreatRecord, Evidence dataclasses
├── tests/                     # pytest suites (225+)
├── docs/openapi.yaml          # API surface specification
├── cloudbuild.yaml            # GCP Cloud Build → Cloud Run
├── Dockerfile                 # Slim Python 3.12, non-root user
└── infra/                     # macOS LaunchAgent plist
```

## How to run tests / dev server

```bash
# Install
uv pip install -e '.[dev]'

# Tests
pytest tests/ -q
pytest tests/ -q --cov=src --cov-report=xml --cov-fail-under=60

# Lint
ruff check src tests

# Local server
python app.py                 # listens on PORT, default 8080

# Container
docker build -t cyber-threat-bot .
docker run --rm -p 8080:8080 cyber-threat-bot
```

## Safety boundaries (DO NOT CHANGE)

1. **Never commit secrets** — No API keys, service-account JSONs, or webhook tokens in code.
2. **No network exfiltration** — Do not send data to endpoints outside the documented upstream sources.
3. **Do not push to `master` directly** — All changes go through PRs on `feat/*` or `fix/*` branches.
4. **Do not disable tests or lower coverage thresholds** to make CI pass.
5. **Cold-start budget** — The container stays small for Cloud Run; any change that increases cold-start above ~5s is a regression.

## Current status

- 225+ tests passing; ruff-clean; CI gates merge.
- Cloud Run deploy live with 4h Cloud Scheduler refresh.
- Composite actionability score (`feat/severity-v2`) in progress.

## Conventions

- `from __future__ import annotations` at the top of every module.
- Type hints on public functions and methods.
- Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `ci:`.
- Keep runtime deps lightweight; `pyproject.toml` is the source of truth.
