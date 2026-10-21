"""Dispatch one hook event from the payload on stdin."""

import json
import sys
from pathlib import Path

from . import _state
from .changeset import check_changeset
from .config import LAYERS, Settings, discover_roots, load_config
from .contract import GROK_TOOL_NAMES
from .doctor import doctor
from .file_checks import check_file, check_tool, run_mandatory
from .paths import SELF
from .process import run


def main():
    args = [arg for arg in sys.argv[1:] if arg not in ("--codex", "--grok")]
    argv_event = args[0] if args else ""
    if argv_event == "doctor":
        doctor(Path.cwd())

    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)
    try:
        payload = json.loads(raw)
    except ValueError:
        sys.exit(0)

    event = argv_event or payload.get("hook_event_name") or ""
    session = payload.get("session_id") or "nosession"
    agent_type = payload.get("agent_type") or payload.get("subagentType") or ""
    if _state.GROK:
        tool_name = payload.get("tool_name") or ""
        payload["tool_name"] = GROK_TOOL_NAMES.get(tool_name, tool_name)
        # Grok also fires Stop at session teardown, where it ignores the answer.
        if event == "Stop" and payload.get("reason") != "end_turn":
            sys.exit(0)

    cwd = Path.cwd()
    declared = payload.get("cwd") or ""
    if declared and Path(declared).is_dir():
        cwd = Path(declared).resolve()

    tool_input = payload.get("tool_input") or {}
    _state.log(
        1,
        "invoke",
        hook=event,
        tool=payload.get("tool_name"),
        agent=agent_type or None,
        session=session[:8],
        cwd=str(cwd),
    )
    _state.log(3, "input", command=tool_input.get("command"), path=tool_input.get("file_path"))

    if event == "SessionEnd":
        run(
            [sys.executable, str(SELF.parent / "fallow_cleanup.py")],
            stdin=json.dumps({**payload, "hook_event_name": event}),
            cwd=cwd,
            timeout=12,
        )
        sys.exit(0)

    # Ahead of discovery and the config, so no root and no setting is between
    # this tier and the call it refuses. A config.toml that will not even parse
    # cannot take it out either.
    if event == "PreToolUse":
        _state.arm_watchdog(_state.deadline(6))
        run_mandatory(payload, cwd)

    roots = discover_roots(cwd)
    cfg = load_config(roots)
    _state.set_log_level(cfg)
    settings = Settings(cfg)

    # Registered in user settings, so it is reachable from every project on the
    # machine. Carrying an agent-guard directory somewhere above the working
    # directory is the whole opt-in, and a tree that has opted in runs every
    # layer. Everywhere else only the layers named in `always` run, so a rule
    # about the machine reaches every directory while a project's conventions
    # still wait to be asked for.
    scoped = len(roots) > 1
    allowed = frozenset(LAYERS) if scoped else settings.always
    if not allowed:
        sys.exit(0)

    if event == "PreToolUse":
        # The watchdog is already armed by the mandatory tier above. A check that
        # has not answered by then has nothing worth waiting for.
        if "tool_checks" not in allowed:
            sys.exit(0)
        check_tool(payload, roots, settings, cwd)
    elif event == "PostToolUse":
        # One event drives two layers, so it carries the permitted set down
        # rather than deciding here.
        layers = allowed & frozenset(("rules", "checks"))
        if not layers:
            sys.exit(0)
        _state.arm_watchdog(_state.deadline(9))
        check_file(payload, roots, settings, cwd, layers)
    elif event in ("Stop", "SubagentStop"):
        if "changeset" not in allowed:
            sys.exit(0)
        check_changeset(event, session, agent_type, roots, settings, cwd)
    sys.exit(0)
