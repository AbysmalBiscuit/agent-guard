"""Run the package as a script. This entry arms the watchdog and the log."""

import atexit
import json
import sys
from pathlib import Path

_package = Path(__file__).resolve().parent
_root = _package.parent
# scripts/ stays ahead of the plugin root so a helper import resolves, and
# agent_guard still resolves as a package from the plugin root.
sys.path[:1] = [str(_root / "scripts"), str(_root)]

from agent_guard import _state  # noqa: E402
from agent_guard.adapters import HARNESSES  # noqa: E402
from agent_guard.dispatch import decide, run_doctor  # noqa: E402


def harness_name(argv):
    if "--codex" in argv:
        return "codex"
    if "--grok" in argv:
        return "grok"
    return "claude"


def main(argv=None, stdin=None):
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin if stdin is None else stdin
    atexit.register(_state.release_log)
    name = harness_name(argv)
    positional = [arg for arg in argv if not arg.startswith("--")]
    if positional[:1] == ["doctor"]:
        run_doctor(Path.cwd())
        return 0

    raw = stdin.read()
    if not raw.strip():
        return 0
    try:
        payload = json.loads(raw)
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0

    translate, write = HARNESSES[name]
    if positional:
        payload["hook_event_name"] = positional[0]
    event = translate(payload)
    if event is None:
        return 0
    if event.get("hook_event_name") == "PreToolUse":
        _state.arm_watchdog(_state.deadline(6))
    elif event.get("hook_event_name") == "PostToolUse":
        _state.arm_watchdog(_state.deadline(9))
    try:
        decision = decide(event)
        _state.release_log()
        write(decision, event.get("hook_event_name") or "")
    except BaseException:
        # A broken check, or a stdout the harness already closed, degrades to
        # silence rather than wedging the session. The watchdog stays outside
        # this guard: arming it is what bounds the run.
        _state.release_log()
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
