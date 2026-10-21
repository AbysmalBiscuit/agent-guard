"""The plugin root and the `python3 <plugin root>/agent_guard` invocation."""

import subprocess
import sys
from pathlib import Path

import agent_guard

PLUGIN_ROOT = Path(agent_guard.__file__).resolve().parent.parent
HOOK = [sys.executable, str(PLUGIN_ROOT / "agent_guard")]


def run_hook(payload, flag=(), **kwargs):
    """One hook invocation. `flag` follows the package path, as `("--codex",)` does."""
    return subprocess.run([*HOOK, *flag], input=payload, **kwargs)
