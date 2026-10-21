"""The decision a tier returns, and the git facts every layer reads."""

import re
from dataclasses import dataclass

from .process import have, run, succeeds

# A tool-check's exit code for the ask tier: stdout with this hands the call to
# the human, where any other non-zero refuses it outright.
ASK_EXIT = 2


# Tools that run a shell command, across the harnesses this hook is registered
# under. The mandatory tier is scoped to these.
SHELL_TOOLS = frozenset({"Bash", "PowerShell", "exec_command", "shell_command", "shell"})


@dataclass(frozen=True)
class Decision:
    """What one event decided, before a harness writes it.

    `permission` is deny, ask or allow. Silence is an allow with empty context.
    """

    permission: str = "allow"
    context: str = ""
    reason: str = ""


SILENT = Decision()


def denied(context, reason):
    return Decision("deny", context, reason)


def asked(context, reason):
    return Decision("ask", context, reason)


def advised(context):
    return Decision("allow", context)


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
