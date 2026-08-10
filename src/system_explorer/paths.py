"""Where packaged data lives, resolved once.

The operator UI ships *inside* the package. It used to be found with
`Path(__file__).parent.parent / "ui"` from both the agent and the hub, which
resolves in a git checkout and silently 404s from a wheel or /usr/lib —
exactly the failure a non-Nix installation hits first. Now the same
directory is package data, so the checkout and the installed tree are the
same shape and there is one definition of it.

Deliberately a plain Path rather than importlib.resources: StaticFiles and
FileResponse want a real filesystem path, and every supported install (nix
store, dpkg, rpm, pip, editable checkout) unpacks the package as
directories. A zipimport install would need as_file() and is not a target —
these are systemd services, not zipapps.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
UI_DIR = PACKAGE_DIR / "ui"
