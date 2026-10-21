#!/usr/bin/env python3
"""agent-guard tool-check: the `rg -r<flags>` footgun.

In ripgrep, `-r`/`--replace` takes the following characters as replacement text
and only rewrites printed output (rg never edits files). Carrying over the grep
habit, `rg -rn` is parsed as --replace=n and silently prints matches with `n`
substituted instead of showing line numbers — no error, plausible wrong output.
Same trap for -rl (-l), -rc (-c), and reversed clusters (-nr).

Blocks a single-dash short-flag cluster containing `r` plus at least one other
letter, but only as an argument to an `rg` command. The spaced forms
`rg -r 'text' PAT` and `rg --replace 'text' PAT` stay legal, and the word "rg"
inside a quoted string (e.g. a commit message) is ignored.
"""

import re

from ..contract import Decision, denied
from ..shell_commands import read_commands

BAD_CLUSTER = re.compile(r"^-[a-zA-Z]*r[a-zA-Z]*$")


def bad_flag(cmd):
    """Return the offending flag cluster in `cmd`, or None."""
    for command in read_commands(cmd):
        if command.name != "rg":
            continue
        for arg in command.args:
            if len(arg) >= 3 and BAD_CLUSTER.match(arg):
                return arg
    return None


def check(payload):
    """The decision for one shell command, or silence for any other tool."""
    if not isinstance(payload, dict) or payload.get("tool_name") != "Bash":
        return Decision()
    tool_input = payload.get("tool_input")
    cmd = (tool_input or {}).get("command") or "" if isinstance(tool_input, dict) else ""
    if not cmd:
        return Decision()

    hit = bad_flag(cmd)
    if not hit:
        return Decision()

    message = (
        f"rg recurses by default and has no recursive flag. In '{hit}', -r is "
        "--replace: it swallows the remaining letters as replacement text and "
        "silently prints matches with that text substituted instead of applying "
        "-n/-l/-c (rg never edits files, but the output is wrong and looks fine). "
        "Pass the flags separately: -n (line numbers), -l (files with matches), "
        "-c (count). For a real replacement use the spaced form: "
        "rg -r 'text' PATTERN or rg --replace 'text' PATTERN."
    )
    return denied(message, message)
