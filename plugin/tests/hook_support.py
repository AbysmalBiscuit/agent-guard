"""The plugin root and the `python3 <plugin root>/agent_guard` invocation."""

import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

HOOK = [sys.executable, str(PLUGIN_ROOT / "agent_guard")]


def run_hook(payload, args=(), **kwargs):
    """One hook invocation. `args` follows the package path, as `("--codex",)` does."""
    return subprocess.run([*HOOK, *args], input=payload, **kwargs)
