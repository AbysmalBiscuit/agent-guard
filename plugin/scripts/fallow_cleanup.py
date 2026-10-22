#!/usr/bin/env python3
"""Remove the ending session's project audit caches, leaving busy caches intact."""

import json
import subprocess
import sys
from pathlib import Path

# The plugin root is the parent of scripts/. The hook launches this file as a
# script, so add the root here.
_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from agent_guard.tools import pinned_binary  # noqa: E402


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict) or payload.get("hook_event_name") != "SessionEnd":
            return
        declared = payload.get("cwd")
        if not isinstance(declared, str) or not declared:
            return
        root = Path(declared)
        fallow = pinned_binary("fallow")
        if not root.is_absolute() or not root.is_dir() or fallow is None:
            return
        subprocess.run(
            [fallow, "audit-cache", "remove", "--root", str(root), "--yes"],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return


if __name__ == "__main__":
    main()
