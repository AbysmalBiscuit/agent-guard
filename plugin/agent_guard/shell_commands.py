"""One reader for the commands a shell line runs.

Every tool check that asks "which commands does this line run" reads the line
here, so wrappers, assignments, redirects, `bash -c` and `xargs` are handled
once and the checks keep only their rules.
"""

import io
import re
import shlex
from dataclasses import dataclass

PUNCTUATION = "();<>|&\n"
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")
DURATION = re.compile(r"^\d+[smhd]?$")
# A short-option cluster that carries `-c`, such as `-c`, `-lc` or `-ec`.
SHELL_SCRIPT_FLAG = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")
# Words that leave the real command word still ahead.
WRAPPERS = {
    "sudo",
    "doas",
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
# Wrapper options whose next word is the wrapper's operand, not the command.
WRAPPER_OPTS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"},
    "timeout": {"-k", "-s", "--kill-after", "--signal"},
    "nice": {"-n"},
    "ionice": {"-c", "-n"},
    "stdbuf": {"-i", "-o", "-e"},
    "watch": {"-n"},
}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
# xargs options whose next word is their operand, not the utility.
XARGS_OPTS = {
    "-a",
    "-d",
    "-E",
    "-e",
    "-I",
    "-i",
    "-L",
    "-l",
    "-n",
    "-P",
    "-s",
    "--arg-file",
    "--delimiter",
    "--eof",
    "--replace",
    "--max-lines",
    "--max-args",
    "--max-procs",
    "--max-chars",
}
MAX_DEPTH = 3


@dataclass(frozen=True)
class Command:
    """One command the line runs.

    `name` is `word` without its directory and `.exe`, in lower case. `op` is
    the operator that introduced the command, empty for the first command and
    for a command that `bash -c` or `xargs` runs.
    """

    name: str
    args: tuple[str, ...]
    op: str = ""
    word: str = ""


def command_name(word):
    """The bare command word: no directory, no `.exe`, compared in one case."""
    base = re.split(r"[\\/]", word)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def read_commands(script, keep_backslashes=False, partial=True, depth=0):
    """Each command the script runs, in order.

    `keep_backslashes` reads a backslash as a path separator, not an escape.
    An unclosed quote ends the read: with `partial` the commands before it
    stay, without it the script yields nothing.
    """
    if depth > MAX_DEPTH or not script or not script.strip():
        return []
    tokens, closed = _tokens(script, keep_backslashes)
    if not closed and not partial:
        return []
    return _commands(tokens, keep_backslashes, depth)


class _Source(io.StringIO):
    """Input whose comments stop short of the newline, so it still ends the command."""

    def readline(self, size=-1):
        line = super().readline(size)
        if line.endswith("\n"):
            self.seek(self.tell() - 1)
            return line[:-1]
        return line


def _tokens(script, keep_backslashes):
    """The script's words and operators, and whether every quote closed."""
    lexer = shlex.shlex(_Source(script), posix=True, punctuation_chars=PUNCTUATION)
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    if keep_backslashes:
        lexer.escape = ""
    tokens = []
    try:
        for token in lexer:
            tokens.append(token)  # noqa: PERF402 - keeps the tokens before an unclosed quote
    except ValueError:
        return tokens, False
    return tokens, True


def _operator(token):
    """ "redirect", "separator", or "" for a word."""
    if token in ("{", "}"):
        return "separator"
    if not token or any(char not in PUNCTUATION for char in token):
        return ""
    # `<(` and `>(` open a process substitution, which runs a command.
    if any(char in "<>" for char in token) and not token.endswith("("):
        return "redirect"
    return "separator"


def _commands(tokens, keep_backslashes, depth):
    found = []
    words, op, wrapper, skip, herestring, stdin = [], "", "", False, False, None

    def close():
        if words:
            found.extend(_expand(words, op, stdin, keep_backslashes, depth))

    for token in tokens:
        kind = _operator(token)
        if kind == "separator":
            close()
            words, op, wrapper, skip, herestring, stdin = [], token, "", False, False, None
            continue
        if kind == "redirect":
            # The file descriptor written in front of a redirect is not a word.
            if len(words) > 1 and words[-1].isdigit():
                words.pop()
            skip, herestring = True, token == "<<<"
            continue
        if skip:
            if herestring:
                stdin = token
            skip, herestring = False, False
            continue
        if not words:
            if token in WRAPPERS:
                wrapper = token
                continue
            if ASSIGNMENT.match(token):
                continue
            if token.startswith("-") or DURATION.match(token):
                skip = "=" not in token and token in WRAPPER_OPTS.get(wrapper, ())
                continue
        words.append(token)
    close()
    return found


def _expand(words, op, stdin, keep_backslashes, depth):
    """The command, then the commands it runs: a shell's script, xargs' utility.

    A shell runs its `-c` script, or else the here-string it reads.
    """
    command = Command(command_name(words[0]), tuple(words[1:]), op, words[0])
    found = [command]
    if command.name in SHELLS:
        script = _shell_script(command.args)
        if script is None:
            script = stdin
        if script is not None:
            found.extend(read_commands(script, keep_backslashes, depth=depth + 1))
    elif command.name == "xargs":
        start = _xargs_utility(command.args)
        if start is not None:
            found.extend(_commands(list(command.args[start:]), keep_backslashes, depth))
    return found


def _shell_script(args):
    """The script a shell's `-c` runs, or None."""
    flagged = False
    for arg in args:
        if flagged and not arg.startswith("-"):
            return arg
        if SHELL_SCRIPT_FLAG.match(arg):
            flagged = True
    return None


def _xargs_utility(args):
    """The index of the utility xargs runs, or None when it runs the default."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-") or arg == "-":
            break
        index += 2 if arg in XARGS_OPTS else 1
    return index if index < len(args) else None
