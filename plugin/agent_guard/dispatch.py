"""One entry point that takes a hook event and returns a decision."""

import json
import sys
from pathlib import Path

from . import _state
from .changeset import check_changeset
from .config import LAYERS, Settings, discover_roots, load_config
from .contract import SILENT, Decision
from .doctor import doctor
from .file_checks import check_file, check_tool, run_mandatory
from .paths import SCRIPTS_DIR
from .process import run


def decide(payload):
    """The decision for one hook event.

    `payload` is the event after an adapter has translated its tool names.
    """
    if not isinstance(payload, dict):
        return SILENT
    event = payload.get("hook_event_name") or ""

    session = payload.get("session_id") or "nosession"
    agent_type = payload.get("agent_type") or payload.get("subagentType") or ""
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
            [sys.executable, str(SCRIPTS_DIR / "fallow_cleanup.py")],
            stdin=json.dumps({**payload, "hook_event_name": event}),
            cwd=cwd,
            timeout=12,
        )
        return SILENT

    # Ahead of discovery and the config, so no root and no setting is between
    # this tier and the call it refuses. A config.toml that will not even parse
    # cannot take it out either.
    mandatory = run_mandatory(payload, cwd) if event == "PreToolUse" else SILENT
    # A mandatory finding ends the run. The call never reaches a later tier.
    if mandatory.context or mandatory.permission != "allow":
        return mandatory

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
        return mandatory

    if event == "PreToolUse":
        if "tool_checks" not in allowed:
            return mandatory
        checked = check_tool(payload, roots, settings, cwd)
        if checked.permission != "allow" or checked.context:
            return checked
        return mandatory
    if event == "PostToolUse":
        # One event drives two layers, so it carries the permitted set down
        # rather than deciding here.
        layers = allowed & frozenset(("rules", "checks"))
        if not layers:
            return SILENT
        return check_file(payload, roots, settings, cwd, layers)
    if event in ("Stop", "SubagentStop"):
        if "changeset" not in allowed:
            return SILENT
        return check_changeset(session, agent_type, roots, settings, cwd)
    return SILENT


def run_doctor(cwd):
    """Print what a checkout resolves to. The process entry owns the exit."""
    doctor(cwd)
    return Decision()
