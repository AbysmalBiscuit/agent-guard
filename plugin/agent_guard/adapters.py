"""How each harness names its tools and writes a decision."""

import json
import sys

GROK_TOOL_NAMES = {"run_terminal_command": "Bash", "search_replace": "Edit", "write": "Write"}
_FIELDS = {
    "hookEventName": "hook_event_name",
    "sessionId": "session_id",
    "toolName": "tool_name",
    "toolInput": "tool_input",
    "subagentType": "agent_type",
}


def claude_event(payload):
    return _normalized(payload), "claude"


def codex_event(payload):
    return _normalized(payload), "codex"


def grok_event(payload):
    event = _normalized(payload)
    tool_name = event.get("tool_name") or ""
    event["tool_name"] = GROK_TOOL_NAMES.get(tool_name, tool_name)
    return event, "grok"


def _normalized(payload):
    event = dict(payload)
    for source, target in _FIELDS.items():
        if source in event and not event.get(target):
            event[target] = event[source]
    return event


def write_claude(decision, event):
    """The Claude Code permission envelope. Silence writes nothing."""
    _write_permission(decision, event)


def _write_permission(decision, event):
    if decision.permission == "allow" and not decision.context:
        return
    out = {"hookEventName": event}
    if decision.permission == "deny":
        out["permissionDecision"] = "deny"
        out["permissionDecisionReason"] = decision.reason
    elif decision.permission == "ask":
        out["permissionDecision"] = "ask"
        out["permissionDecisionReason"] = decision.reason
    out["additionalContext"] = decision.context
    _write({"hookSpecificOutput": out})


def write_codex(decision, event):
    """Codex tool events use the permission envelope. Stop uses a continuation."""
    if event in ("Stop", "SubagentStop"):
        _write_stop(decision)
        return
    _write_permission(decision, event)


def write_grok(decision, event):
    """Grok Build tool events use the permission envelope. Stop uses a continuation."""
    if event in ("Stop", "SubagentStop"):
        _write_stop(decision)
        return
    _write_permission(decision, event)


def _write_stop(decision):
    if decision.permission == "allow" and not decision.context:
        return
    if decision.permission == "deny":
        _write({"decision": "block", "reason": decision.context})
        return
    _write({"systemMessage": decision.context})


def _write(out):
    sys.stdout.write(json.dumps(out, separators=(",", ":")) + "\n")
    sys.stdout.flush()


HARNESSES = {
    "claude": (claude_event, write_claude),
    "codex": (codex_event, write_codex),
    "grok": (grok_event, write_grok),
}
