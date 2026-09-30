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

import json
import os
import re
import shlex
import sys

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
# Operators that end one command and begin the next. A newline does too, but
# it never reaches the lexer: `commands` separates physical lines first.
SEPARATORS = {"||", "&&", "|", "|&", ";", ";;", "&", "(", ")"}
# Operators whose target is a stream rather than an operand to read.
REDIRECTS = {">", ">>", ">|", ">&", "<", "<<", "<<<", "<&", "&>", "&>>"}
FD_NUMBER = re.compile(r"^\d+$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")
# Words that leave the real command word still ahead.
KEYWORDS = {
    "do",
    "then",
    "else",
    "elif",
    "if",
    "while",
    "until",
    "done",
    "fi",
    "!",
    "sudo",
    "command",
    "env",
    "time",
    "timeout",
    "nice",
    "stdbuf",
    "nohup",
}


def command_name(word):
    """The bare command word: no directory, no `.exe`, lowercased.

    PowerShell matches command names without regard to case, and a name can
    arrive with either separator now that a backslash survives lexing.
    """
    base = re.split(r"[\\/]", word)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


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
    """Every command in the script, each a token list, quoting respected.

    A newline ends a command exactly as `;` does, but `whitespace_split` counts
    it as whitespace, so lines have to be separated before lexing. Left joined,
    a `cd` on its own line would absorb the next line's words and read them as
    part of its target.
    """
    parsed = []
    for line in script.splitlines():
        parsed.extend(line_commands(line))
    return parsed


def line_commands(line):
    """One physical line's commands.

    Splitting the raw text on a regex cuts inside a quoted argument: an rg
    pattern holding an alternation `|` breaks into fragments with unbalanced
    quotes, and the fragment carrying the real path stops being parseable, so
    the whole line reads as harmless.
    """
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    # Nothing here is executed, so a backslash is worth more as a path
    # separator than as an escape: posix escaping turns `C:\Users\Lev` into
    # `C:UsersLev` and hides the path from every test below.
    lexer.escape = ""
    parsed, current, redirected = [], [], False
    try:
        for token in lexer:
            if redirected:
                redirected = False
                continue
            if token in SEPARATORS:
                parsed.append(current)
                current = []
            elif token in REDIRECTS:
                # A redirect's target is not an operand, and the file
                # descriptor written in front of it is not a word.
                if current and FD_NUMBER.match(current[-1]):
                    current.pop()
                redirected = True
            else:
                current.append(token)
    except ValueError:
        pass  # an unbalanced quote ends the parse; keep what came before it
    parsed.append(current)
    return [tokens for tokens in parsed if tokens]


def leading_cd(parsed):
    """The directory a leading `cd` moves to, or None."""
    if len(parsed) < 2:
        return None
    tokens = parsed[0]
    if len(tokens) < 2 or command_name(tokens[0]) not in CD_NAMES:
        return None
    # A path carrying an escaped space arrives as several tokens once escaping
    # is off, and rejoining them costs nothing when it was one word already.
    args = [token for token in tokens[1:] if token != "--" and token.lower() not in PATH_OPTS]
    target = os.path.expanduser(" ".join(args))
    return target if rooted(target) else None


def segment_operands(tokens, directory):
    """The relative paths one command would open, given the `cd` target."""
    name = command_name(tokens[0])
    if name not in READERS:
        return []

    named, operands, skip, wants_path = [], [], False, False
    for token in tokens[1:]:
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
    for tokens in parsed[1:]:
        # A loop or conditional body puts the real command a few words in, and
        # an env assignment does too.
        while tokens and (tokens[0] in KEYWORDS or ASSIGNMENT.match(tokens[0])):
            tokens = tokens[1:]
        if not tokens:
            continue
        if command_name(tokens[0]) == "git":
            return "git", []
        hits = segment_operands(tokens, directory)
        if hits:
            return command_name(tokens[0]), hits
    return "", []


def main():
    if (sys.argv[1] if len(sys.argv) > 1 else "") != "Bash":
        return 0
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    command = str((payload.get("tool_input") or {}).get("command") or "")
    if not command.strip():
        return 0

    parsed = commands(command)
    directory = leading_cd(parsed)
    if directory is None:
        return 0

    name, hits = relative_operands(parsed, directory)
    if name == "git":
        print(
            "agent-guard: git after a cd into another directory always stops for "
            "manual approval, because git runs that directory's hooks. Pass the "
            f"directory to git instead: `git -C {directory} ...`."
        )
        return 1
    if not hits:
        return 0

    example = os.path.join(directory, hits[0])
    print(
        f"agent-guard: `{hits[0]}` is relative to the `cd`, and the permission "
        "analyzer resolves paths against the session's working directory instead. "
        "With Read() deny rules configured it cannot clear an unresolved path, so "
        "this stops and waits for a human.\n\n"
        f"Drop the cd and write the path out: `{name} ... {example}`."
    )
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:
        # A broken check degrades to silence rather than denying real work.
        sys.exit(0)
