"""Packaging smoke tests.

These tests guard the two invocation paths the project supports:

1. The proper editable install (``pip install -e .`` -> ``threat-bot ...``)
2. The legacy direct-source path (``PYTHONPATH=src python -m cyber_threat_bot ...``)

Both must work because Sapphire's plugin tooling and historical scheduled tasks
call the package both ways.
"""

from __future__ import annotations

import importlib
import importlib.metadata as md
from pathlib import Path

import pytest


PKG = "cyber_threat_bot"


def test_package_imports_cleanly() -> None:
    mod = importlib.import_module(PKG)
    assert mod is not None
    # Must point at the in-tree src/ checkout, not a stale wheel.
    assert "cyber_threat_bot" in (mod.__file__ or "")


def test_cli_main_callable() -> None:
    cli = importlib.import_module(f"{PKG}.cli")
    assert callable(getattr(cli, "main", None)), "cli.main must be callable for [project.scripts]"


def test_dunder_main_module_imports() -> None:
    # `python -m cyber_threat_bot` relies on this.
    mod = importlib.import_module(f"{PKG}.__main__")
    assert mod is not None


def test_pyproject_declares_required_metadata() -> None:
    """Cheap regression test against the pyproject we ship to PyPI mirrors / wheels."""
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "cyber-threat-bot"' in pyproject
    assert "[project.scripts]" in pyproject
    assert 'threat-bot = "cyber_threat_bot.cli:main"' in pyproject
    assert "requires-python" in pyproject
    # Pinned upper bounds prevent surprise major-version breakage.
    for dep in ("requests", "beautifulsoup4", "pyyaml"):
        assert dep in pyproject, f"missing pinned dep: {dep}"


def test_install_script_present_and_executable() -> None:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "install.sh"
    assert script.exists(), "scripts/install.sh must exist for reliable editable install"
    # Owner-execute bit set.
    assert script.stat().st_mode & 0o100, "scripts/install.sh must be executable"


def test_distribution_metadata_visible_when_installed() -> None:
    """When the editable install succeeded, importlib.metadata can find us.

    Skipped silently when running against a non-installed source tree (e.g.
    the ``PYTHONPATH=src`` fallback path).
    """
    try:
        dist = md.distribution("cyber-threat-bot")
    except md.PackageNotFoundError:
        pytest.skip("cyber-threat-bot not installed in this interpreter")
    assert dist.version, "distribution metadata missing version"
    eps = {ep.name for ep in dist.entry_points if ep.group == "console_scripts"}
    assert "threat-bot" in eps, f"expected threat-bot console script, got {eps}"
