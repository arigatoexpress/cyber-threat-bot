# Source Catalog

Verified on April 8, 2026.

## Primary sources

- `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - Current CISA Known Exploited Vulnerabilities JSON feed.
  - Use for: confirmed exploitation in the wild, operational urgency, remediation due dates.

- `https://services.nvd.nist.gov/rest/json/cves/2.0`
  - NVD CVE API 2.0.
  - Use for: recent CVEs, CVSS, CWE mappings, references, official normalization.
  - For recent CVEs, query with both `pubStartDate` and `pubEndDate`.

- `https://www.cve.org/CVERecord?id=CVE-YYYY-NNNN`
  - Official CVE Program record page.
  - Use for: cross-checking descriptions, CNA ownership, record state.

- `https://attack.mitre.org/techniques/T####/`
  - MITRE ATT&CK technique page.
  - Use for: behavior framing, mitigations, detection strategy, and procedure examples.

- Vendor advisories and incident reports
  - Use for: patch instructions, product-specific attack path details, and confirmed impact.

## Reputable enrichment

- `https://www.darkreading.com/rss.xml`
  - Public Dark Reading RSS feed.
  - Use for: current reporting, industry signal detection, and prioritization hints.
  - Do not treat Dark Reading alone as sufficient proof of exploit details.

## Practical source order

1. CISA KEV if exploitation is claimed.
2. NVD and CVE.org for the normalized CVE record.
3. Vendor advisory for product-specific details.
4. MITRE ATT&CK for behavior framing.
5. Dark Reading for extra context and related reporting.

## Reliability rules

- Prefer official artifacts over media summaries.
- Do not infer ATT&CK mappings from vibes alone.
- If a source is current but thin, keep the claim thin.
- If the only available data is media reporting, say that plainly.

