# Security Policy

`cyber-threat-bot` is a defensive-security tool. Security issues are
treated as the highest priority of any change to this codebase.

## Supported Versions

Active development happens on the `master` branch. The current published
version is tracked in [`pyproject.toml`](pyproject.toml) and tagged in
[GitHub Releases](https://github.com/arigatoexpress/cyber-threat-bot/releases).
We accept security reports against the latest tagged minor release and
the current `master`.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in
`cyber-threat-bot`, please **do not** open a public issue. Instead,
report it privately:

- Email: [aristotlespec@gmail.com](mailto:aristotlespec@gmail.com)
  with subject prefix `[cyber-threat-bot SECURITY]`
- Or use [GitHub's private vulnerability reporting](https://github.com/arigatoexpress/cyber-threat-bot/security/advisories/new)

We will acknowledge receipt within 72 hours and aim to triage within 5
business days. After triage, we will agree on a coordinated disclosure
timeline (typically 30–90 days depending on severity and complexity).

## What's in scope

- Dependency vulnerabilities surfaced by `pip-audit` against
  `pyproject.toml`.
- Code in `src/cyber_threat_bot/` — including SSRF / URL-validation
  bypasses in `sources.py`, RCE / unsafe-deserialization in any
  parser, prompt-injection vectors in the brief / offer generators
  that could escalate to template-injection in downstream consumers.
- Misuse of credentials or environment variables that could leak
  through CLI output, logs, or generated briefs.

## What's out of scope

- The reputability of the upstream feeds (CISA, NVD, MITRE ATT&CK,
  Dark Reading). We aggregate; we do not vouch for upstream content.
- Output that is correct given the input feed but inconvenient. File
  a regular issue.
- The provided ruleset / policy / offer-template content. We accept
  refinements via PRs, not security advisories.

## Operational guidance for adopters

- Run `cyber-threat-bot` on data that is already public (CISA, NVD,
  MITRE). It does not require any inbound access to the host running
  it.
- Outbound HTTP rate-limits are intentional. If you increase them, you
  are responsible for honouring upstream feeds' rate limits and terms
  of use.
- Treat the markdown / JSON / SARIF output as untrusted text when
  embedding it in dashboards or pipelines — the upstream feeds
  occasionally include attacker-controlled content.

## Coordinated disclosure track record

We will publish a security advisory in
[GitHub Security Advisories](https://github.com/arigatoexpress/cyber-threat-bot/security/advisories)
for every confirmed vulnerability after the patched release lands.
