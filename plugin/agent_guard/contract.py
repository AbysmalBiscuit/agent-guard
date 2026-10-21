"""The hook JSON contract, and the git facts every layer reads."""

import json
import re
import sys

from . import _state
from .process import have, run, succeeds

# A tool-check's exit code for the ask tier: stdout with this hands the call to
# the human, where any other non-zero refuses it outright.
ASK_EXIT = 2


# Tools that run a shell command, across the harnesses this hook is registered
# under. The mandatory tier is scoped to these.
SHELL_TOOLS = frozenset({"Bash", "PowerShell", "exec_command", "shell_command", "shell"})

# Grok Build tools whose input matches a Claude Code tool's, renamed so every
# check, including those in a project's own roots, reads one vocabulary.
GROK_TOOL_NAMES = {"run_terminal_command": "Bash", "search_replace": "Edit", "write": "Write"}


def emit_silent():
    sys.exit(0)


def emit(event, context, deny="", ask=""):
    """`deny` refuses the call, `ask` hands it to the human, and a call carrying
    both is refused: a check that says no outranks one that says maybe.

    The reason is repeated in `additionalContext` by the caller, so a harness
    that does not implement the ask decision still tells the model why the call
    was questioned rather than dropping the finding on the floor."""
    if (_state.CODEX or _state.GROK) and event in ("Stop", "SubagentStop"):
        out = {"decision": "block", "reason": context} if deny else {"systemMessage": context}
        sys.stdout.write(json.dumps(out, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    out = {"hookEventName": event}
    if deny:
        out["permissionDecision"] = "deny"
        out["permissionDecisionReason"] = deny
    elif ask:
        out["permissionDecision"] = "ask"
        out["permissionDecisionReason"] = ask
    out["additionalContext"] = context
    sys.stdout.write(json.dumps({"hookSpecificOutput": out}, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    sys.exit(0)


def git_base(settings, cwd):
    """The merge-base with the upstream branch, matching the changeset audit.
    With no upstream it falls back to HEAD, so the scope degrades to the
    uncommitted working tree rather than back to the whole file."""
    if settings.base_override:
        return settings.base_override
    upstream = run(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], cwd=cwd
    ).strip()
    base = run(["git", "merge-base", "HEAD", upstream or "origin/HEAD"], cwd=cwd).strip()
    return base or run(["git", "rev-parse", "HEAD"], cwd=cwd).strip()


_HUNK = re.compile(r"^@@ \S+ \+(\d+)(?:,(\d+))?")


def changed_lines(path, base, cwd):
    """Line numbers one file gained since the branch's base. An empty set is a
    real answer meaning the branch added no lines to it; None means git cannot
    answer at all (no repository, or a file it has never tracked), which the
    caller reads as "every line is the agent's"."""
    if not have("git") or not succeeds(["git", "rev-parse", "--git-dir"], cwd=cwd):
        return None
    if not succeeds(["git", "ls-files", "--error-unmatch", "--", path], cwd=cwd):
        return None
    if not base:
        return None
    added = set()
    diff = run(["git", "diff", "--unified=0", base, "--", path], cwd=cwd)
    for line in diff.splitlines():
        m = _HUNK.match(line)
        if not m:
            continue
        start = int(m.group(1))
        count = 1 if m.group(2) is None else int(m.group(2))
        added.update(range(start, start + count))
    return added
