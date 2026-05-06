# AGENTS.md — cyber-threat-bot

> Project-specific guidance for AI agents working on this repository.
> This complements the human-facing `README.md` and `CONTRIBUTING.md`.

---

## Architecture

### Layout

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
├── tests/                     # 225+ pytest suites
├── docs/openapi.yaml          # API surface specification
├── cloudbuild.yaml            # GCP Cloud Build → Cloud Run
├── Dockerfile                 # Slim Python 3.12, non-root user
└── infra/                     # macOS LaunchAgent plist
```

### Runtime Design

- **No FastAPI/Flask runtime dependency** in production. The server is
  `http.server.ThreadingHTTPServer` so the container stays small and
  cold-start latency is minimal.
- **In-memory cache** (`ThreatCache`) with thread-safe snapshots.
- **Lazy warm-up**: the first `/threats` request populates the cache if it
  has never been refreshed, so Cloud Run cold starts don't block on three
  upstream HTTP calls.
- **Parallel refresh**: `refresh_all()` uses `concurrent.futures.ThreadPoolExecutor`
  to fetch CISA/NVD/MITRE concurrently, then enriches and writes under a
  `threading.Lock`.

### Data Flow

```
Upstream APIs (CISA KEV, NVD, MITRE)
           ↓
   ThreadPoolExecutor (parallel fetch)
           ↓
   EPSS enrichment → confidence annotation → actionability scoring
           ↓
   ThreatCache (in-memory, locked write)
           ↓
   /threats  /threats/correlate  /threats/prioritized
```

---

## Safety Boundaries

### Red Lines

1. **Never commit secrets** — no API keys, service-account JSONs, or
   `WEBHOOK_URL` tokens in code. Use environment variables or GitHub secrets.
2. **Never run destructive commands without asking** — prefer `trash` over `rm`.
3. **No network exfiltration** — do not send data to endpoints outside the
   documented upstream sources (CISA, NVD, MITRE, EPSS) and configured
   webhooks.
4. **Do not push to `master` directly** — all changes go through PRs on
   `feat/*` or `fix/*` branches.
5. **Do not disable tests or lower coverage thresholds** to make CI pass.

### Production Safety

- Cloud Run is configured `--min-instances=0`, so traffic spikes scale from
  zero. Any change that increases cold-start time above ~5s is a regression.
- The container runs as `UID 10001` (`ctb` user). Do not add steps to the
  `Dockerfile` that require root at runtime.
- `cloudbuild.yaml` deploys with `--allow-unauthenticated`. If you add
  auth endpoints, coordinate with the Cloud Run IAM policy, not just app-level
  checks.

---

## Conventions

### Code Style

- **Ruff** for linting (`line-length = 120`, `target-version = "py311"`).
- **Type hints** on public functions and methods.
- **Docstrings** for modules, classes, and public APIs.
- `from __future__ import annotations` at the top of every module.

### Commits

Use **Conventional Commits**:

```
feat: add parallel fetch in refresh_all
fix: handle EPSS timeout gracefully
docs: update openapi.yaml with /threats/prioritized
ci: add container smoke tests to workflow
test: cover ThreadPoolExecutor error isolation
```

Keep commits atomic. One logical change per commit.

### Testing

- Run the full suite before opening a PR:
  ```bash
  ruff check src tests
  pytest tests/ -q --cov=src --cov-report=xml --cov-fail-under=60
  ```
- Server tests (`test_server.py`) must never hit real upstream APIs.
  Stub fetchers via `ThreatHandler.fetchers` or `cache.refresh_all(fetchers=...)`.
- Add tests for threading and parallelism behavior when modifying
  `server.py` or `ThreatCache`.

### Dependency Management

- `pyproject.toml` is the source of truth.
- Use `uv pip install -e '.[dev]'` for local development.
- `cloudbuild.yaml` uses `pip install -e .` inside the container build;
  keep runtime deps lightweight.

---

## Deployment Procedures

### CI/CD Pipeline

GitHub Actions (`.github/workflows/ci.yml`):

1. **lint** — `ruff check src tests`
2. **test** — `pytest` with `--cov=src --cov-fail-under=60`
3. **smoke** — Build Docker image, start container, `curl /healthz`
4. **deploy** — Trigger Cloud Build (only on `master` push, after test+smoke pass)

All jobs respect the `SAPPHIRE_RUNNER` no-spend gate.

### Deploy Job Details

- Uses **Google Cloud Workload Identity Federation** (keyless auth).
- Required GitHub repository variables:
  - `CYBER_THREAT_BOT_DEPLOY_ENABLED=true`
  - `GCP_WORKLOAD_IDENTITY_PROVIDER`
  - `GCP_SERVICE_ACCOUNT`
  - `GCP_PROJECT_ID`
- The deploy job runs:
  ```bash
  gcloud builds submit --config cloudbuild.yaml
  ```

### Cloud Build → Cloud Run

`cloudbuild.yaml` performs three steps:

1. `docker build` → tags `gcr.io/$PROJECT_ID/cyber-threat-bot:$SHORT_SHA` and `:latest`
2. `docker push --all-tags`
3. `gcloud run deploy` in `us-central1`

Runtime flags:
- `--memory=512Mi --cpu=1`
- `--min-instances=0 --max-instances=3`
- `--port=8080 --allow-unauthenticated`

### Rollback

If a deployment is bad, roll back via Cloud Run revisions:

```bash
gcloud run revisions list --service=cyber-threat-bot --region=us-central1
gcloud run services update-traffic cyber-threat-bot \
  --region=us-central1 \
  --to-revisions=REVISION_NAME=100
```

Or trigger a revert commit on `master` and let CI redeploy.

---

## Agent Quick Reference

| Task | Command |
|------|---------|
| Run tests | `pytest tests/ -q` |
| Run tests + coverage | `pytest tests/ -q --cov=src --cov-report=xml --cov-fail-under=60` |
| Lint | `ruff check src tests` |
| Local server | `python app.py` (listens on `PORT`, default 8080) |
| Build container | `docker build -t cyber-threat-bot:latest .` |
| Trigger Cloud Build | `gcloud builds submit --config cloudbuild.yaml` |

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `PORT` | HTTP server port (default 8080) |
| `HOST` | Bind address (default 0.0.0.0) |
| `LOG_LEVEL` | Python logging level (default INFO) |
| `WEBHOOK_URL` | Optional webhook for actionable alerts |
| `EPSS_DISABLED` | Set to `1` to skip EPSS lookups in tests |
| `CYBER_THREAT_BOT_TIMEOUT` | Per-request HTTP timeout override |

---

## Heartbeat / Maintenance Notes

- This is a **satellite repo** under the Sapphire umbrella. Respect the
  no-spend posture: never force a fallback to paid GitHub Actions runners.
- Dependabot is configured for weekly `pip` and `github-actions` updates.
- If you add a new upstream source, update `docs/openapi.yaml` and add a
  stub fetcher in `test_server.py`.
- Keep `Dockerfile` layer caching in mind: put stable steps (apt, pip install)
  before copy-everything steps.
