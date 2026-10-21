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
UNMODELLED = re.compile(r"\$'|`|\\\n|(?<!<)<<(?!<)")
# A heredoc operator and its delimiter word, quoted or not.
HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([^\s;&|<>()'\"]+)\2")
# A short-option cluster that carries `-c`, such as `-c`, `-lc` or `-ec`.
SHELL_SCRIPT_FLAG = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")
# `env -S` or `--split-string`: alone, in a cluster such as `-iS`, or with the string attached.
ENV_SPLIT = re.compile(r"^(?:--split-string(?:=|$)|-[A-Za-z]*S)(.*)$", re.DOTALL)
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
    "env": {"-u", "-C", "--unset", "--chdir"},
    "timeout": {"-k", "-s", "--kill-after", "--signal"},
    "nice": {"-n"},
    "ionice": {"-c", "-n"},
    "stdbuf": {"-i", "-o", "-e"},
}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WATCH_OPTS = {"-n", "--interval"}
SSH_OPTS = {
    "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L",
    "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
}  # fmt: skip
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

    `name` is the command word without its directory and `.exe`, in lower
    case. `op` is the operator that introduced the command, empty for the
    first command and for a command that another command runs.
    """

    name: str
    args: tuple[str, ...]
    op: str = ""


def command_name(word):
    """The bare command word: no directory, no `.exe`, compared in one case."""
    base = re.split(r"[\\/]", word)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def read_commands(script, keep_backslashes=False, partial=True, keep_heredocs=False, depth=0):
    """Each command the script runs, in order.

    `keep_backslashes` reads a backslash as a path separator, not an escape.
    An unclosed quote ends the read: with `partial` the commands before it
    stay, without it the script yields nothing. A heredoc body is text, not
    commands, unless `keep_heredocs` asks to read it as commands.
    """
    if depth > MAX_DEPTH or not script or not script.strip():
        return []
    if not keep_heredocs:
        script = _drop_heredoc_bodies(script, keep_backslashes)
    tokens, closed = _tokens(script, keep_backslashes)
    if not closed and not partial:
        return []
    return _commands(tokens, keep_backslashes, depth)


def vouches_for(script, keep_backslashes=False):
    """True when every quote closes and the script holds no quoting the reader skips.

    The reader does not read `$'...'` quotes, backticks, line continuations or
    heredoc bodies the way bash does, so a command can hide in them.
    """
    _, closed = _tokens(script, keep_backslashes)
    return closed and not UNMODELLED.search(script)


class _Source(io.StringIO):
    """Input whose comments stop short of the newline, so it still ends the command."""

    def readline(self, size=-1):
        line = super().readline(size)
        if line.endswith("\n"):
            self.seek(self.tell() - 1)
            return line[:-1]
        return line


def _drop_heredoc_bodies(script, keep_backslashes):
    """The script without the body lines of its heredocs.

    Quotes and comments are tracked, so a `<<` inside them opens no heredoc.
    """
    kept, pending, quote, index = [], [], "", 0
    while index < len(script):
        char = script[index]
        if quote:
            if char == quote:
                quote = ""
            elif char == "\\" and quote == '"':
                kept.append(script[index : index + 2])
                index += 2
                continue
        elif char in "'\"":
            quote = char
        elif char == "\\" and not keep_backslashes:
            kept.append(script[index : index + 2])
            index += 2
            continue
        elif char == "#" and (index == 0 or script[index - 1] in " \t\n;&|("):
            end = script.find("\n", index)
            end = len(script) if end < 0 else end
            kept.append(script[index:end])
            index = end
            continue
        elif script.startswith("<<", index) and not script.startswith("<<<", index):
            match = HEREDOC.match(script, index)
            if match:
                pending.append((match.group(3), match.group(1) == "-"))
                kept.append(match.group(0))
                index = match.end()
                continue
        elif char == "\n" and pending:
            kept.append(char)
            index = _skip_bodies(script, index + 1, pending)
            pending = []
            continue
        kept.append(char)
        index += 1
    return "".join(kept)


def _skip_bodies(script, index, pending):
    """The index past the bodies that start at `index`, one per pending delimiter."""
    for delimiter, strip_tabs in pending:
        while index < len(script):
            end = script.find("\n", index)
            end = len(script) if end < 0 else end
            line = script[index:end]
            index = end + 1
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                break
    return index


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
    split = False

    def close():
        if words:
            found.extend(_expand(words, op, stdin, keep_backslashes, depth))

    for token in tokens:
        kind = _operator(token)
        if kind == "separator":
            close()
            words, op, wrapper, skip, herestring, stdin = [], token, "", False, False, None
            split = False
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
        if split:
            # env splits the string into a command and runs it with the words after it, as eval does.
            words, split = ["eval", token], False
            continue
        if not words:
            if wrapper == "env" and (match := ENV_SPLIT.match(token)):
                if match.group(1):
                    words = ["eval", match.group(1)]
                else:
                    split = True
                continue
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
    """The command, then the commands it runs.

    A shell runs its `-c` script, or else the here-string it reads. `su -c`
    runs its script, and `eval`, `watch` and `ssh HOST` run their operands
    joined into one script. xargs runs its utility.
    """
    command = Command(command_name(words[0]), tuple(words[1:]), op)
    args = command.args
    found = [command]
    script = None
    if command.name in SHELLS:
        script = _shell_script(args)
        if script is None:
            script = stdin
    elif command.name == "su":
        script = _shell_script(args)
    elif command.name == "eval":
        script = " ".join(args)
    elif command.name == "watch":
        start = _first_operand(args, WATCH_OPTS)
        if start is not None:
            script = " ".join(args[start:])
    elif command.name == "ssh":
        host = _first_operand(args, SSH_OPTS)
        if host is not None:
            script = " ".join(args[host + 1 :])
    elif command.name == "xargs":
        start = _first_operand(args, XARGS_OPTS)
        if start is not None:
            found.extend(_commands(list(args[start:]), keep_backslashes, depth))
    if script is not None:
        found.extend(read_commands(script, keep_backslashes, depth=depth + 1))
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


def _first_operand(args, opts_with_value):
    """The index of the first argument that is not an option, or None."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-") or arg == "-":
            break
        index += 2 if arg in opts_with_value else 1
    return index if index < len(args) else None
