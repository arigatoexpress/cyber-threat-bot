# Changelog

All notable changes to `cyber-threat-bot` are documented here. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `SECURITY.md` with private-disclosure instructions and operational
  guidance for adopters.
- `CONTRIBUTING.md` covering dev setup, test expectations, and PR
  conventions.
- `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1).
- GitHub issue templates and pull-request template.
- README badges (CI, license, Python support).
- README example-output and external-feed table.

### Changed
- CI workflow gated behind `vars.SAPPHIRE_RUNNER` to stop hosted
  Actions billing failures and route runs to the self-hosted runner
  when configured (PR #7).

## [0.2.0] - 2026-04

### Added
- CLI commands: `latest`, `cve`, `technique`, `brief`, `offers`.
- Sources: CISA KEV, NVD CVE API 2.0, MITRE ATT&CK pages, Dark
  Reading RSS.
- Severity ranking, deduplication, retry budget, per-source timeout.
- Markdown + JSON output paths.
- Ruff + pytest CI pipeline.

[Unreleased]: https://github.com/arigatoexpress/cyber-threat-bot/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/arigatoexpress/cyber-threat-bot/releases/tag/v0.2.0
