"""Run the package as a script."""

import sys
from pathlib import Path

_package = Path(__file__).resolve().parent
_root = _package.parent
# Checks import modules from plugin/scripts, which stays ahead of the
# plugin root so agent_guard resolves as a package.
sys.path[:1] = [str(_root / "scripts"), str(_root)]

from agent_guard.dispatch import main  # noqa: E402

try:
    main()
except SystemExit:
    raise
except BaseException:
    # A broken check degrades to silence rather than wedging the session.
    sys.exit(0)
