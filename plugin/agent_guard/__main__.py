"""Run the package as a script.

`python3 <plugin root>/agent_guard` puts this directory on `sys.path`. Replace
that entry with the plugin root, then import the entry point by package name.
"""

import sys
from pathlib import Path

_package = Path(__file__).resolve().parent
_root = _package.parent
sys.path[0] = str(_root)

from agent_guard.dispatch import main  # noqa: E402

try:
    main()
except SystemExit:
    raise
except BaseException:
    # A broken check degrades to silence rather than wedging the session.
    sys.exit(0)
