"""VaultScope scoring & report aggregator.

Stage 5: merges the Stage 4a/4b/4c outputs per session into one record, derives
the risk score / threat matrix / AI confidence score, and renders the executive
and technical reports (Jinja2 -> WeasyPrint/ReportLab). P3, Block B / @p4ralyn.
"""

import os
import sys

__all__ = ["ensure_native_libs"]

# Homebrew installs pango/glib outside the default dyld search path, and
# ctypes.util.find_library does not look in /opt/homebrew/lib. Without this,
# `import weasyprint` dies with "cannot load library 'gobject-2.0-0'".
_MACOS_LIB_DIRS = ("/opt/homebrew/lib", "/usr/local/lib")


def ensure_native_libs() -> None:
    """Make Homebrew's pango/glib discoverable to WeasyPrint's ctypes lookup.

    ``ctypes.macholib.dyld`` reads ``DYLD_FALLBACK_LIBRARY_PATH`` from
    ``os.environ`` on every call, so setting it here -- before WeasyPrint is
    imported -- is enough; no shell-level export or venv activation is needed.
    No-op off macOS.
    """
    if sys.platform != "darwin":
        return
    var = "DYLD_FALLBACK_LIBRARY_PATH"
    current = [p for p in os.environ.get(var, "").split(os.pathsep) if p]
    missing = [d for d in _MACOS_LIB_DIRS if os.path.isdir(d) and d not in current]
    if missing:
        os.environ[var] = os.pathsep.join(missing + current)


ensure_native_libs()
