"""Static checks for the LaunchAgent plist + refresh script.

These don't actually launch anything (CI may not even be on macOS); they
just guard against shape regressions in the plist that have bitten
Sapphire LaunchAgents before:

- non-XML / missing DOCTYPE
- Label drift from the file name
- StartInterval missing or wrong type
- script paths the launchd job will try to exec aren't actually present
"""

from __future__ import annotations

import plistlib
import re
import stat
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
PLIST = REPO / "infra" / "com.sapphire.cyber-threat-bot.plist"
REFRESH_SCRIPT = REPO / "scripts" / "refresh.sh"


def test_plist_exists() -> None:
    assert PLIST.exists(), f"missing plist at {PLIST}"


def test_plist_parses_as_valid_xml_plist() -> None:
    with PLIST.open("rb") as fh:
        data = plistlib.load(fh)
    assert isinstance(data, dict), "plist root must be a dict"


def test_plist_label_matches_filename() -> None:
    with PLIST.open("rb") as fh:
        data = plistlib.load(fh)
    expected = PLIST.stem  # com.sapphire.cyber-threat-bot
    assert data["Label"] == expected, f"Label drift: {data['Label']} vs file {expected}"


def test_plist_runs_every_4_hours() -> None:
    with PLIST.open("rb") as fh:
        data = plistlib.load(fh)
    assert data["StartInterval"] == 4 * 60 * 60, "expected 4h cadence"
    assert isinstance(data["StartInterval"], int)


def test_plist_program_arguments_reference_refresh_script() -> None:
    with PLIST.open("rb") as fh:
        data = plistlib.load(fh)
    args = data.get("ProgramArguments", [])
    assert isinstance(args, list) and args, "ProgramArguments missing"
    joined = " ".join(args)
    assert "scripts/refresh.sh" in joined, f"plist must invoke scripts/refresh.sh, got {joined}"


def test_refresh_script_exists_and_is_executable() -> None:
    assert REFRESH_SCRIPT.exists(), f"missing refresh script at {REFRESH_SCRIPT}"
    mode = REFRESH_SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR, "refresh.sh must be executable"


def test_refresh_script_honors_pause_flag() -> None:
    """The script must exit early if ~/.sapphire/routine_pause/cyber-threat-bot exists."""
    body = REFRESH_SCRIPT.read_text(encoding="utf-8")
    assert "routine_pause/cyber-threat-bot" in body
    # Must exit 0 (not error) so launchd doesn't backoff a paused agent.
    assert re.search(r"PAUSE_FLAG.+\n.+exit 0", body, re.DOTALL), (
        "pause path must exit 0 to avoid launchd ThrottleInterval backoff"
    )


def test_refresh_script_uses_set_euo_pipefail() -> None:
    body = REFRESH_SCRIPT.read_text(encoding="utf-8")
    assert "set -euo pipefail" in body, "refresh.sh should fail-fast on errors"


def test_refresh_script_supports_both_invocation_paths() -> None:
    """Mirrors the install-script contract: editable install OR PYTHONPATH=src."""
    body = REFRESH_SCRIPT.read_text(encoding="utf-8")
    assert ".venv/bin/threat-bot" in body
    assert "-m cyber_threat_bot" in body
    assert "PYTHONPATH=" in body


def test_plist_log_paths_writable_locations() -> None:
    with PLIST.open("rb") as fh:
        data = plistlib.load(fh)
    for key in ("StandardOutPath", "StandardErrorPath"):
        path = data.get(key, "")
        assert path, f"{key} missing"
        # /tmp or $HOME/... — never a path that requires root.
        assert path.startswith(("/tmp/", "/Users/", "/var/")), f"{key}={path} likely unwritable"


@pytest.mark.parametrize("key", ["RunAtLoad", "StartInterval", "Label", "ProgramArguments"])
def test_plist_required_keys_present(key: str) -> None:
    with PLIST.open("rb") as fh:
        data = plistlib.load(fh)
    assert key in data, f"plist missing required key: {key}"
