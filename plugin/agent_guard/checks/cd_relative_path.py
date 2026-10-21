#!/usr/bin/env python3
"""agent-guard tool-check: a path read relative to a `cd` in the same command.

The permission analyzer resolves a command's file operands against the session's
working directory, not against a `cd` earlier in the same compound command. With
any Read() deny rule configured it cannot prove the unresolved path misses the
denied set, so `cd DIR && rg PAT relfile` stops and waits for a human every time.
The absolute form of the same read carries no such cost.

Fires only when the command after the `cd` is a file reader, so the `cd` exists
purely to shorten the path. A build or a test runner genuinely needs its working
directory and is left alone.
"""

import os
import re

from ..contract import Decision, denied
from ..shell_commands import read_commands

# Commands that move the shell, PowerShell's spellings of it included.
CD_NAMES = {"cd", "chdir", "set-location", "sl", "pushd", "push-location"}
# Readers whose operands name files. Their meaning survives moving the directory
# into the path, which is what makes the rewrite mechanical.
READERS = {
    "rg",
    "fd",
    "cat",
    "head",
    "tail",
    "wc",
    "ls",
    "stat",
    "du",
    "file",
    "nl",
    "sed",
    "awk",
    "get-content",
    "gc",
    "select-string",
    "sls",
    "get-childitem",
    "gci",
    "dir",
}
# Tools whose first operand is a pattern or a script rather than a path, so
# only the operands after it name files.
PATTERN_FIRST = {"rg", "fd", "sed", "awk", "select-string", "sls"}
# An operand that names a file even when it isn't there to be stat'd: it holds
# a separator, starts a dotfile or a `./` prefix, or ends in an extension.
PATH_SHAPE = re.compile(r"[/\\]|^\.|\.[A-Za-z0-9_]{1,8}$")
# A drive letter or a UNC share roots a Windows path.
WINDOWS_ROOT = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
# Options taking a separate operand, so the operand is not read as a path.
OPTS_WITH_VALUE = {
    "-e",
    "--regexp",
    "-g",
    "--glob",
    "-t",
    "--type",
    "-T",
    "--type-not",
    "-m",
    "--max-count",
    "-A",
    "--after-context",
    "-B",
    "--before-context",
    "-C",
    "--context",
    "-r",
    "--replace",
    "-f",
    "--file",
    "--pre",
    "--max-depth",
    "--iglob",
    "--sort",
    "--colors",
    "-d",
    "-E",
    "--exclude",
}
# The same for PowerShell, matched without regard to case. Kept apart from the
# POSIX set because case carries meaning there: rg's `-A` takes a value and its
# `-a` does not.
PS_OPTS_WITH_VALUE = {
    "-pattern",
    "-include",
    "-exclude",
    "-filter",
    "-encoding",
    "-context",
    "-totalcount",
    "-tail",
    "-first",
    "-last",
    "-depth",
    "-delimiter",
}
# PowerShell parameters whose value is the path being read, so the value is an
# operand rather than a flag's argument.
PATH_OPTS = {"-path", "-literalpath", "-filepath"}
# fd hands everything after these to a child command, so the operands stop
# being paths and the shape is no longer mechanical.
EXEC_FLAGS = {"-x", "--exec", "-X", "--exec-batch"}


def rooted(path):
    """True for a path anchored at a root, in any of the flavors agents write.

    `os.path.isabs` answers for the host the check runs on, and the hosts
    disagree in both directions: Python 3.13's ntpath calls the MSYS `/c/Users`
    form relative, and posixpath calls `C:\\Users` relative. Both forms reach
    the same check on a Windows box depending on which shell wrote them, so the
    question is about the path, not about the machine.
    """
    return path.startswith(("/", "\\")) or bool(WINDOWS_ROOT.match(path))


def commands(script):
    """Every command in the script, quoting respected.

    A backslash stays a path separator: posix escaping turns `C:\\Users\\Lev`
    into `C:UsersLev` and hides the path.
    """
    return read_commands(script, keep_backslashes=True)


def leading_cd(parsed):
    """The directory a leading `cd` moves to, or None."""
    if len(parsed) < 2:
        return None
    first = parsed[0]
    if not first.args or first.name not in CD_NAMES:
        return None
    # A path carrying an escaped space arrives as several tokens once escaping
    # is off, and rejoining them costs nothing when it was one word already.
    args = [token for token in first.args if token != "--" and token.lower() not in PATH_OPTS]
    target = os.path.expanduser(" ".join(args))
    return target if rooted(target) else None


def segment_operands(command, directory):
    """The relative paths one command would open, given the `cd` target."""
    name = command.name
    if name not in READERS:
        return []

    named, operands, skip, wants_path = [], [], False, False
    for token in command.args:
        if skip:
            skip = False
            continue
        if wants_path:
            wants_path = False
            named.append(token)
            continue
        lowered = token.lower()
        if token in EXEC_FLAGS:
            return []
        if lowered in PATH_OPTS:
            wants_path = True
            continue
        if token in OPTS_WITH_VALUE or lowered in PS_OPTS_WITH_VALUE:
            skip = True
            continue
        if token.startswith("-") and token != "-":
            continue
        operands.append(token)
    if name in PATTERN_FIRST and operands:
        operands = operands[1:]  # the first operand is the pattern
    # A path named by its parameter is a path whatever the positions said.
    operands = named + operands

    # Existence is a hint, not a requirement. A command probing for a file that
    # is not there resolves no better than one reading a file that is, and on a
    # shell whose paths the checking process cannot stat, such as an MSYS
    # `/c/...` path under native Windows, nothing would ever resolve.
    return [
        operand
        for operand in operands
        if not rooted(operand)
        and (PATH_SHAPE.search(operand) or os.path.exists(os.path.join(directory, operand)))
    ]


def relative_operands(parsed, directory):
    """The first reader after the `cd` that opens a relative path, and its hits.

    Every command in the line is inspected, not just the one right after the
    `cd`: a `git` or a search buried later in a `&&` chain runs in the changed
    directory just the same.
    """
    for command in parsed[1:]:
        if command.name == "git":
            return "git", []
        hits = segment_operands(command, directory)
        if hits:
            return command.name, hits
    return "", []


def check(payload):
    """The decision for one shell command, or silence for any other tool."""
    if not isinstance(payload, dict) or payload.get("tool_name") != "Bash":
        return Decision()
    tool_input = payload.get("tool_input")
    command = str((tool_input or {}).get("command") or "") if isinstance(tool_input, dict) else ""
    if not command.strip():
        return Decision()

    parsed = commands(command)
    directory = leading_cd(parsed)
    if directory is None:
        return Decision()

    name, hits = relative_operands(parsed, directory)
    if name == "git":
        message = (
            "agent-guard: git after a cd into another directory always stops for "
            "manual approval, because git runs that directory's hooks. Pass the "
            f"directory to git instead: `git -C {directory} ...`."
        )
        return denied(message, message)
    if not hits:
        return Decision()

    example = os.path.join(directory, hits[0])
    message = (
        f"agent-guard: `{hits[0]}` is relative to the `cd`, and the permission "
        "analyzer resolves paths against the session's working directory instead. "
        "With Read() deny rules configured it cannot clear an unresolved path, so "
        "this stops and waits for a human.\n\n"
        f"Drop the cd and write the path out: `{name} ... {example}`."
    )
    return denied(message, message)
