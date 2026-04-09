from datetime import datetime, timezone

from cyber_threat_bot.briefs import render_threat_brief_markdown
from cyber_threat_bot.profiles import CustomerProfile
from cyber_threat_bot.render import render_latest_markdown
from cyber_threat_bot.revenue import build_revenue_opportunities, render_revenue_markdown
from cyber_threat_bot.sources import merge_records, parse_attack_technique_html, parse_cisa_kev, parse_darkreading_rss, parse_nvd


def test_parse_darkreading_rss_reads_items():
    xml_text = """
    <rss version="2.0">
      <channel>
        <item>
          <title><![CDATA[Test Threat Story]]></title>
          <link>https://www.darkreading.com/threat-intelligence/test-story</link>
          <description><![CDATA[A concise description.]]></description>
          <pubDate>Wed, 08 Apr 2026 20:21:32 GMT</pubDate>
          <category>Threat Intelligence</category>
        </item>
      </channel>
    </rss>
    """
    records = parse_darkreading_rss(xml_text, limit=3)
    assert len(records) == 1
    assert records[0].title == "Test Threat Story"
    assert records[0].published_at.year == 2026


def test_parse_nvd_extracts_score_and_cwe():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-9999",
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Remote code execution due to unsafe deserialization."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
                    "references": [{"url": "https://vendor.example/advisory"}],
                }
            }
        ]
    }
    records = parse_nvd(payload, limit=5)
    assert records[0].score == 9.8
    assert "CWE-502" in records[0].metadata["weaknesses"]


def test_merge_records_combines_evidence_for_same_cve():
    cisa_payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-9999",
                "vendorProject": "Acme",
                "product": "Portal",
                "vulnerabilityName": "Auth Bypass",
                "shortDescription": "Observed exploitation in the wild.",
                "dateAdded": "2026-04-08T10:00:00Z",
                "dueDate": "2026-04-29",
                "knownRansomwareCampaignUse": "Unknown",
            }
        ]
    }
    nvd_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-9999",
                    "published": "2026-04-07T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Authentication bypass due to improper state validation."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "vectorString": "x"}}]},
                }
            }
        ]
    }
    cisa_records = parse_cisa_kev(cisa_payload, now=datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc))
    nvd_records = parse_nvd(nvd_payload)
    merged = merge_records(cisa_records + nvd_records)
    assert len(merged) == 1
    assert merged[0].exploited is True
    assert "nvd" in merged[0].metadata["source_set"]


def test_render_latest_markdown_contains_mermaid():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-9999",
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Prompt injection through unsafe tool routing."}],
                    "metrics": {},
                }
            }
        ]
    }
    record = parse_nvd(payload)[0]
    output = render_latest_markdown([record])
    assert "```mermaid" in output
    assert "Teaching angle" in output


def test_parse_attack_technique_html_extracts_sections():
    html = """
    <html>
      <body>
        <h1>Command and Scripting Interpreter</h1>
        <div class="description-body">Adversaries may abuse command interpreters.</div>
        <h2>Mitigations</h2>
        <table><tr><th>ID</th><th>Name</th></tr><tr><td>M1026</td><td>Privileged Account Management</td></tr></table>
        <h2>Procedure Examples</h2>
        <table><tr><th>ID</th><th>Name</th></tr><tr><td>G001</td><td>Example Group</td></tr></table>
        <h2>Detection Strategy</h2>
        <p>Monitor suspicious shell invocation.</p>
      </body>
    </html>
    """
    record = parse_attack_technique_html(html, "T1059")
    assert record.canonical_id == "T1059"
    assert "Monitor suspicious shell invocation." in record.metadata["detection_strategy"]


def test_render_threat_brief_contains_report_sections():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1234",
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Authentication bypass in a multi-tenant admin portal."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "vectorString": "x"}}]},
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-287"}]}],
                }
            }
        ]
    }
    record = parse_nvd(payload)[0]
    output = render_threat_brief_markdown(record)
    assert "## 1. Threat Snapshot" in output
    assert "## 4. Deep Technical Breakdown" in output
    assert "## 7. Detection and Mitigation" in output


def test_revenue_board_prioritizes_profile_matches():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-2222",
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Prompt injection in an AI agent platform with unsafe tool routing for GitHub actions."}
                    ],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "vectorString": "x"}}]},
                }
            }
        ]
    }
    record = parse_nvd(payload)[0]
    profile = CustomerProfile(
        name="AI SaaS",
        owned_technologies=["GitHub"],
        priority_tags=["ai", "rce"],
        priority_keywords=["agent", "tool routing"],
        package_sizes=[3000, 9000, 18000],
    )
    opportunities = build_revenue_opportunities([record], profile)
    assert opportunities[0].offer_name == "Agent Guardrail Assessment"
    output = render_revenue_markdown(profile, opportunities)
    assert "Million-Dollar Path" in output
    assert "$18,000" in output


def test_revenue_keyword_matching_uses_boundaries():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-3333",
                    "published": "2026-04-08T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Remote code execution in a public web portal."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "x"}}]},
                }
            }
        ]
    }
    record = parse_nvd(payload)[0]
    profile = CustomerProfile(excluded_keywords=["ot"])
    opportunities = build_revenue_opportunities([record], profile)
    assert "Deprioritized by: ot" not in opportunities[0].reasons
