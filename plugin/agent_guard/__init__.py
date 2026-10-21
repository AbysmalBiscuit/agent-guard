"""The hook core.

The harnesses run this package with plain `python3` on the package directory.
Importing it loads the clusters the tests and the entry point share.
"""

from . import _state as _state
from ._state import *  # noqa: F403
from .changeset import *  # noqa: F403
from .config import *  # noqa: F403
from .contract import *  # noqa: F403
from .dispatch import main as main
from .doctor import *  # noqa: F403
from .file_checks import *  # noqa: F403
from .paths import *  # noqa: F403
from .process import *  # noqa: F403

# Harness flags are read once, at import, off the process argv.
CODEX = _state.CODEX
GROK = _state.GROK
