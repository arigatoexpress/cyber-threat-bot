"""Cloud Run / container entrypoint.

Cloud Run conventions look for ``app.py`` at the repo root. This is a thin
shim around :mod:`cyber_threat_bot.server` so the runtime command stays
``python app.py`` regardless of how the package is installed.
"""

from __future__ import annotations

from cyber_threat_bot.server import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
