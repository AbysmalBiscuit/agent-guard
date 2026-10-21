"""Where the install and the state directory live.

Resolved from this package, so the plugin directory relocates as one unit.
"""

import os
import re
from pathlib import Path

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = _PLUGIN_ROOT / "scripts"
CONFIG_DIR = Path(os.environ.get("AGENT_GUARD_CONFIG_DIR") or _PLUGIN_ROOT)
STATE_DIR = (
    Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "agent-guard"
)

CONFIG_NAME = "config.toml"
_ENV_PREFIX = "AGENT_GUARD_"

# Rules come in layers, each named by its directory in a tree: the tracked one
# first, then a machine-local overlay beside it that outranks it. Later roots add
# rules and tighten settings, and a tree opts in by creating one of these
# directories; nothing in the global install changes.
ROOT_NAMES = (".agents/plugins/agent-guard", ".agents/plugins/agent-guard.local")

TEST_PATH = re.compile(r"(test|spec)\.|/tests?/|__tests__")
BARREL_OR_TEST = re.compile(r"(test|spec)\.|/tests?/|__tests__|/index\.tsx?$")
