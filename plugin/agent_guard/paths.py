"""Where the install, the state directory and the mandatory tier live.

Resolved from this package, so the plugin directory relocates as one unit.
An environment override that repoints the install cannot move the mandatory
tier.
"""

import os
import re
from pathlib import Path

# The plugin root is this package's parent. SELF keeps the script path the
# cleanup helper was launched from, so a relocated install still finds it.
_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SELF = _PLUGIN_ROOT / "scripts" / "agent_guard.py"
CONFIG_DIR = Path(os.environ.get("AGENT_GUARD_CONFIG_DIR") or _PLUGIN_ROOT)
STATE_DIR = (
    Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "agent-guard"
)

# The tier no setting reaches. Resolved from this file's own directory rather
# than CONFIG_DIR, so the environment override that repoints the install cannot
# move it, and read from the global install alone, so a checkout can neither add
# a script that runs on every call nor drop one that must.
MANDATORY_DIR = _PLUGIN_ROOT / "mandatory"
MANDATORY_TIMEOUT = 5
# AGENT_GUARD_IN_PROCESS=0 puts every check back in its own subprocess, for
# bisecting a check that misbehaves only when it shares this interpreter.
IN_PROCESS = (os.environ.get("AGENT_GUARD_IN_PROCESS") or "1").strip() not in ("0", "off")

CONFIG_NAME = "config.toml"
_ENV_PREFIX = "AGENT_GUARD_"

# Rules come in layers, each named by its directory in a tree: the tracked one
# first, then a machine-local overlay beside it that outranks it. Later roots add
# rules and tighten settings, and a tree opts in by creating one of these
# directories; nothing in the global install changes.
ROOT_NAMES = (".agents/plugins/agent-guard", ".agents/plugins/agent-guard.local")

TEST_PATH = re.compile(r"(test|spec)\.|/tests?/|__tests__")
BARREL_OR_TEST = re.compile(r"(test|spec)\.|/tests?/|__tests__|/index\.tsx?$")
