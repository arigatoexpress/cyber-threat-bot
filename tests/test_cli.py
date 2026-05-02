"""Tests for src/cyber_threat_bot/cli.py.

Argparse + dispatch coverage. The actual heavy work (collect_latest_records,
fetch_nvd_cve, fetch_attack_technique, build_revenue_opportunities) is
patched out — we only need to exercise the wiring here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from cyber_threat_bot import cli
from cyber_threat_bot.models import ThreatRecord


def _stub_record(canonical_id: str = "CVE-2026-9999", source_type: str = "cve") -> ThreatRecord:
    return ThreatRecord(
        source="nvd",
        source_type=source_type,
        canonical_id=canonical_id,
        title="Stub vulnerability",
        url=f"https://nvd.nist.gov/vuln/detail/{canonical_id}",
        published_at=None,
        summary="A test vulnerability.",
        score=7.5,
        exploited=False,
        tags=["rce"],
        metadata={"vendor_project": "acme", "product": "widget"},
    )


# ---------------------------------------------------------------------------
# build_parser — argparse wiring
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_parser_requires_subcommand(self) -> None:
        parser = cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_latest_defaults(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["latest"])
        assert args.command == "latest"
        assert args.days == 7
        assert args.per_source == 8
        assert args.format == "markdown"
        assert args.out is None

    def test_cve_requires_id(self) -> None:
        parser = cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["cve"])

    def test_offers_accepts_profile_and_json(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            ["offers", "--days", "14", "--profile", "/tmp/p.json", "--format", "json"]
        )
        assert args.command == "offers"
        assert args.days == 14
        assert args.profile == "/tmp/p.json"
        assert args.format == "json"


# ---------------------------------------------------------------------------
# _write_output
# ---------------------------------------------------------------------------


class TestWriteOutput:
    def test_writes_to_path_creating_parents(self, tmp_path: Path, capsys: Any) -> None:
        target = tmp_path / "nested" / "out.md"
        cli._write_output("# hello\n", str(target))
        assert target.read_text(encoding="utf-8") == "# hello\n"
        captured = capsys.readouterr()
        assert "Wrote" in captured.out

    def test_prints_to_stdout_when_no_path(self, capsys: Any) -> None:
        cli._write_output("payload", None)
        captured = capsys.readouterr()
        assert captured.out.strip() == "payload"


# ---------------------------------------------------------------------------
# main() dispatch — patches the heavy work, asserts the right func is called
# ---------------------------------------------------------------------------


class TestMainDispatch:
    def test_latest_markdown(self, capsys: Any) -> None:
        with patch.object(cli, "collect_latest_records", return_value=[_stub_record()]):
            rc = cli.main(["latest"])
        assert rc == 0
        out = capsys.readouterr().out
        # The markdown header is fixed; verify some recognizable string is present
        assert "Cyber Threat" in out or "CVE-2026-9999" in out

    def test_latest_json(self, capsys: Any) -> None:
        with patch.object(cli, "collect_latest_records", return_value=[_stub_record()]):
            rc = cli.main(["latest", "--format", "json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload[0]["canonical_id"] == "CVE-2026-9999"

    def test_cve_writes_to_file(self, tmp_path: Path) -> None:
        target = tmp_path / "cve.md"
        with patch.object(cli, "fetch_nvd_cve", return_value=_stub_record("CVE-2026-1234")):
            rc = cli.main(["cve", "CVE-2026-1234", "--out", str(target)])
        assert rc == 0
        assert target.exists()
        body = target.read_text(encoding="utf-8")
        assert "CVE-2026-1234" in body

    def test_brief_rejects_unknown_target(self) -> None:
        with pytest.raises(ValueError, match="Unsupported brief target"):
            cli.main(["brief", "NOT-A-TARGET"])

    def test_brief_cve_path_pulls_supporting_records(self, capsys: Any) -> None:
        primary = _stub_record("CVE-2026-1111")
        with (
            patch.object(cli, "fetch_nvd_cve", return_value=primary),
            patch.object(cli, "find_cisa_kev_record", return_value=None),
            patch.object(cli, "search_darkreading", return_value=[]),
        ):
            rc = cli.main(["brief", "CVE-2026-1111", "--format", "json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        # brief_to_json wraps under "primary"; just verify it parses + contains the id
        assert "CVE-2026-1111" in capsys.readouterr().out or "CVE-2026-1111" in str(payload)

    def test_brief_technique_path(self, capsys: Any) -> None:
        technique_record = _stub_record("T1059", source_type="technique")
        with patch.object(cli, "fetch_attack_technique", return_value=technique_record):
            rc = cli.main(["brief", "T1059", "--format", "json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["primary"]["canonical_id"] == "T1059"

    def test_offers_default_profile(self, capsys: Any) -> None:
        with (
            patch.object(cli, "collect_latest_records", return_value=[_stub_record()]),
            patch.object(cli, "build_revenue_opportunities", return_value=[]),
            patch.object(
                cli, "render_revenue_markdown", return_value="# Offers\n"
            ),
        ):
            rc = cli.main(["offers"])
        assert rc == 0
        assert "Offers" in capsys.readouterr().out
