"""The plugin root and the `python3 <plugin root>/agent_guard` invocation."""

import os
import subprocess
import sys
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from agent_guard.tools import pinned_binary, tool_version  # noqa: E402, F401

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


def stub_mise(directory, pins=None):
    """A directory holding a stub `mise` to put first on PATH. Its `which <tool>`
    prints `pins[tool]` and fails for a tool without a pin, as a missing pin does."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    cases = "".join(
        f'  "{name}") printf "%s\\n" "{path}" ;;\n' for name, path in (pins or {}).items()
    )
    mise = directory / "mise"
    mise.write_text(
        '#!/bin/sh\n[ "$3" = which ] || exit 1\ncase "$4" in\n' + cases + "  *) exit 1 ;;\nesac\n",
        encoding="utf-8",
    )
    mise.chmod(0o755)
    return str(directory)


def run_hook(payload, args=(), **kwargs):
    """One hook invocation. `args` follows the package path, as `("--codex",)` does."""
    return subprocess.run([*HOOK, *args], input=payload, **kwargs)
