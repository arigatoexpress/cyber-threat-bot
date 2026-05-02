"""Pytest configuration shared by all test modules.

This file intentionally prepends ``src/`` to ``sys.path`` even when an editable
install is active. Both invocation paths must keep working:

* ``./scripts/install.sh`` followed by ``.venv/bin/pytest`` (preferred)
* ``PYTHONPATH=src python3 -m pytest`` (legacy / CI fallback)

Without this, the legacy invocation breaks on machines where ``pip`` and
``python3`` resolve to different interpreters and editable install state is
not visible to the chosen interpreter.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
