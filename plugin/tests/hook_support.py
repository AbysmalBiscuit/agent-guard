"""The plugin root and the `python3 <plugin root>/agent_guard` invocation."""

import os
import subprocess
import sys
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from agent_guard.tools import pinned_binary  # noqa: E402

HOOK = [sys.executable, str(PLUGIN_ROOT / "agent_guard")]

# mise finds its installs under HOME. The hook tests give each run a temporary
# HOME, so pin the data directory of the real HOME before any test replaces it.
os.environ.setdefault(
    "MISE_DATA_DIR",
    str(Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "mise"),
)


def requires_pinned(name):
    """Skip a test that runs the real `name` when mise cannot resolve its pin."""
    return unittest.skipUnless(pinned_binary(name), f"requires the mise-pinned {name}")


def run_hook(payload, args=(), **kwargs):
    """One hook invocation. `args` follows the package path, as `("--codex",)` does."""
    return subprocess.run([*HOOK, *args], input=payload, **kwargs)
