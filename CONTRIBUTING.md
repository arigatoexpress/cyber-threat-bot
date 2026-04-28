# Contributing to cyber-threat-bot

Thanks for the interest. This project ships a lightweight,
threat-led research bot built on public defensive-security feeds.
Contributions of all sizes are welcome.

## Quick start for contributors

```bash
git clone https://github.com/arigatoexpress/cyber-threat-bot
cd cyber-threat-bot
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

Then run the sanity checks:

```bash
ruff check src tests
PYTHONPATH=src pytest tests/ -q
```

Both must pass before opening a PR.

## How we work

- **Open an issue first** for anything bigger than a typo or a
  one-line behaviour fix. The shape of the change is more
  important than the patch.
- **Keep PRs small.** A 50-line PR with a one-line test and a
  one-paragraph description merges in a day. A 500-line PR with
  no tests sits.
- **Tests are not optional.** New behaviour requires new tests.
  Bug fixes require a test that fails on `master` and passes on
  your branch. We prefer focused unit tests over slow integration
  tests for upstream-feed code.
- **No live API calls in tests.** Mock CISA / NVD / MITRE ATT&CK
  / Dark Reading responses with fixtures. Live feed coverage
  belongs in a separate, manually-runnable script.
- **Match the existing style.** `ruff` is the only linter; defer
  to it on stylistic disagreements.

## Branch and PR conventions

- Branch off `master`.
- Branch name: `feat/<scope>`, `fix/<scope>`, `docs/<scope>`,
  `chore/<scope>`.
- Commit subject: imperative mood, ≤72 chars. Body explains the
  *why*, references the issue.
- PR title mirrors the squash-merge subject.
- PR body includes: summary, blast-radius, test plan, rollback note.

## What we will and will not accept

**We will accept**:

- New upstream sources, as long as they are public, free, and
  cite-able (CISA, NVD, MITRE ATT&CK, EPSS, Abuse.ch URLhaus,
  GreyNoise community, vendor advisory feeds with a defined ToS).
- New output formats (SARIF, STIX, CSV, etc.) that downstream
  consumers (CI pipelines, SIEMs, MSP dashboards) can immediately
  use.
- Performance and rate-limit improvements, especially when they
  reduce load on upstream feeds.
- Better tests, documentation, and examples.

**We will not accept**:

- Sources that require authentication tokens we cannot publish
  (paid feeds, scraping behind login walls).
- Output that includes attacker-controlled HTML, JS, or
  shell-fragment code without escaping.
- Changes that disable or weaken the rate-limit / retry logic
  in `sources.py`.
- New features without tests.

## Releasing

Maintainers cut releases by tagging `vX.Y.Z` on `master`. The
[`CHANGELOG.md`](CHANGELOG.md) is updated in the same commit. PyPI
publishing is gated by a GitHub release.

## License

By contributing you agree that your contribution will be licensed
under the project [`LICENSE`](LICENSE) (MIT).
