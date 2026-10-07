#!/usr/bin/env python3
"""PreToolUse/Bash guard: the shell commands AGENTS.md rules out.

Two families, both denied rather than advised, because each has an exact
mechanical replacement and a suggestion an agent can skip is one it will skip:

  legacy search tools   find, grep over files, ls -R, the sg alias, and the
                        pipelines that chain two tools where one already does
                        the whole job
  git stash             parallel agents share the working tree, so stashing
                        pulls the ground out from under a session that never
                        agreed to it

Denials are computed from the command as parsed, so the reason can name the
replacement rather than restate the rule. Anything that will not parse is let
through: refusing work over a quoting edge case teaches agents to route around
the hook, and the cost of a missed `grep` is one line of output.

`grep` reading a stream is left alone. `ps aux | grep sshd` is not a search of
file contents and rewriting it buys nothing; the rule is about searching the
filesystem, so it fires on -r and on a file operand.

The `rg -r<flags>` footgun has a hook of its own and is deliberately absent here.
"""

import json
import re
import shlex
import shutil
import sys

# Pipes, lists, subshells, redirections and process substitutions all start a
# fresh command position, so `<(fd .)` is read exactly like `| fd .`.
OPERATOR = re.compile(r"^[|&;()<>{}\n]+$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")
# Words that keep the next one in command position.
WRAPPERS = {
    "sudo",
    "command",
    "builtin",
    "exec",
    "env",
    "time",
    "timeout",
    "nice",
    "ionice",
    "stdbuf",
    "nohup",
    "watch",
    "noglob",
    "then",
    "do",
    "else",
    "elif",
    "if",
    "while",
    "until",
    "!",
}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
DURATION = re.compile(r"^\d+[smhd]?$")

# git's own options, which sit before the subcommand. The first group takes a
# separate operand; the second does not.
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
# grep options taking a separate operand, so the pattern is not mistaken for one.
GREP_OPTS_WITH_VALUE = {"-e", "-f", "-m", "-A", "-B", "-C", "-d", "--include", "--exclude"}
GREP_RECURSIVE = {"-r", "-R", "--recursive", "--dereference-recursive"}
LS_RECURSIVE = {"-R", "--recursive"}


class Segment:
    """One command position: the command word, its arguments, and the operator
    that introduced it. `op` is "|" only for a genuine pipe, so the pipeline
    rules cannot fire across a `;` or a `&&`."""

    def __init__(self, op, name, args):
        self.op = op
        self.name = name
        self.args = args


def tokenize(command):
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def segments(command, depth=0):
    """Every command position in the line, in order. An unparseable line yields
    nothing, so the guard falls silent rather than guessing."""
    if depth > 2:
        return []
    try:
        tokens = tokenize(command)
    except ValueError:
        return []

    found = []
    op, current = "", None
    for i, token in enumerate(tokens):
        if OPERATOR.match(token):
            op, current = ("|" if token == "|" else token), None
            continue
        if current is None:
            # Env assignments and wrapper options leave the real command word
            # still ahead: `timeout 10 grep …` is a grep call.
            if ASSIGNMENT.match(token) or token in WRAPPERS:
                continue
            if token.startswith("-") or DURATION.match(token):
                continue
            current = Segment(op, token.rsplit("/", 1)[-1], [])
            found.append(current)
            continue
        current.args.append(token)
        # `bash -c '<line>'` hides a whole line inside one argument.
        if current.name in SHELLS and token == "-c" and i + 1 < len(tokens):
            found.extend(segments(tokens[i + 1], depth + 1))
    return found


def operands(args, opts_with_value):
    """Arguments that are not options or option operands."""
    rest, skip = [], False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in opts_with_value:
            skip = True
            continue
        if arg.startswith("-") and arg != "-":
            continue
        rest.append(arg)
    return rest


def find_rewrite(args):
    """The fd command for a find call, or None when find was doing something fd
    cannot express in one line."""
    paths, kind, glob = [], "f", None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-name", "-iname") and i + 1 < len(args):
            glob, i = args[i + 1], i + 2
            continue
        if arg == "-type" and i + 1 < len(args):
            kind, i = args[i + 1], i + 2
            continue
        if arg.startswith("-"):
            return None
        paths.append(arg)
        i += 1

    where = " ".join(p for p in paths if p != ".")
    if glob is None:
        return f"fd -t {kind} {where}".strip()
    ext = re.fullmatch(r"\*\.([A-Za-z0-9_]+)", glob)
    selector = f"-e {ext.group(1)}" if ext else f"-g '{glob}'"
    if kind != "f":
        selector = f"-t {kind} {selector}"
    return f"fd {selector} {where}".strip()


def git_subcommand(args):
    rest = operands(args, GIT_OPTS_WITH_VALUE)
    return rest[0] if rest else ""


def legacy_tool(seg):
    """A search tool this machine has a better answer for, when that answer is installed."""
    if seg.name == "find" and shutil.which("fd"):
        rewrite = find_rewrite(seg.args)
        detail = (
            f"Run `{rewrite}` instead."
            if rewrite
            else "Use fd: -e for an extension, -g for a glob, -t f / -t d for a "
            "kind, -x to run a command per file, --changed-within for a time window."
        )
        return f"find is replaced by fd on this machine. {detail}"

    if seg.name in ("grep", "egrep", "fgrep") and shutil.which("rg"):
        recursive = any(a in GREP_RECURSIVE for a in seg.args)
        # The first bare word is the pattern; a second one is a path, which makes
        # this a search of the filesystem rather than of a stream.
        searches_files = len(operands(seg.args, GREP_OPTS_WITH_VALUE)) > 1
        if not (recursive or searches_files):
            return None
        return (
            "grep over files is replaced by rg, which recurses by default and "
            "honours .gitignore. Drop the -r and call rg directly: "
            "`rg PATTERN path/`, `rg -t py PATTERN` for one language, "
            "`rg -l PATTERN` for filenames only."
        )

    if seg.name == "sg":
        return (
            "sg is the setgid command, not ast-grep. Call `ast-grep` by its full "
            "name: `ast-grep -p 'PATTERN'`, or `ast-grep -p 'PAT' -r 'NEW'` to rewrite."
        )

    if seg.name == "ls" and any(a in LS_RECURSIVE for a in seg.args) and shutil.which("fd"):
        return (
            "ls -R is replaced by fd: `fd -t f` for every file, `fd -t d` for "
            "directories. Plain `ls -la` for one directory is fine."
        )
    return None


def redundant_pipeline(prev, seg):
    """Two tools chained where one already does the whole job."""
    if seg.op != "|":
        return None
    sink = seg.name in ("rg", "grep", "egrep", "fgrep")

    if prev.name == "cat" and sink and shutil.which("rg"):
        files = " ".join(operands(prev.args, set())) or "FILE"
        return (
            f"rg reads files directly. Run `rg PATTERN {files}` instead of piping "
            "cat into a matcher."
        )

    if prev.name == "fd" and seg.name == "xargs" and any(a in ("rg", "grep") for a in seg.args):
        return (
            "rg already recurses, so there is nothing for fd to feed it. Search "
            "the files in one call: `rg -t py PATTERN` by language, or "
            "`rg -g '*.py' PATTERN` by glob."
        )

    if prev.name == "fd" and sink:
        return (
            "fd matches on the name itself, so a second filter is redundant. "
            "Pass the pattern to fd: `fd PATTERN path/`."
        )

    if prev.name == "rg" and "--files" in prev.args and sink and shutil.which("fd"):
        return "`rg --files | rg PATTERN` is `fd PATTERN`. Call fd directly."

    if prev.name == "rg" and seg.name == "cut":
        return (
            "rg prints the filenames on its own: use `rg -l PATTERN` instead of "
            "cutting the field out of the match lines."
        )
    return None


def git_stash(seg):
    """Stash rewrites the shared working tree. Inspecting an existing stash does
    not, so the read-only subcommands stay legal."""
    if seg.name != "git" or git_subcommand(seg.args) != "stash":
        return None
    rest = operands(seg.args, GIT_OPTS_WITH_VALUE)
    if len(rest) > 1 and rest[1] in ("list", "show"):
        return None
    return (
        "git stash moves the shared working tree, and parallel agents are often "
        "working in it. To read another revision, read it in place: "
        "`git show REV:path`. To compare, `git diff REV -- path`. If the working "
        "tree genuinely has to be clean first, say so and ask Lev."
    )


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

    reasons, previous = [], None
    for seg in segments(command):
        reasons.extend(reason for reason in (legacy_tool(seg), git_stash(seg)) if reason)
        if previous is not None:
            reason = redundant_pipeline(previous, seg)
            if reason:
                reasons.append(reason)
        previous = seg

    if not reasons:
        return 0
    # dict.fromkeys rather than a set: one command hitting the same rule twice
    # should say it once, in the order the rules fired.
    print("agent-guard: this command is ruled out by AGENTS.md.\n")
    print("\n\n".join(dict.fromkeys(reasons)))
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:
        # A broken check degrades to silence rather than denying real work.
        sys.exit(0)
