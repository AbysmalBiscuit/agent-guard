"""Run the agent_guard package for hook sessions that still name this path."""

# A harness session keeps the hook command it read at start, so a session
# that began before the package layout still runs this file after an update.

import runpy
from pathlib import Path

runpy.run_path(str(Path(__file__).resolve().parents[1] / "agent_guard"), run_name="__main__")
