#!/usr/bin/env python3
"""agent-guard tool-check: decryption and key-file access through Bash.

Permission rules gate the Read and Edit tools, not shell commands. A command
can invoke age directly, reach plaintext through a chezmoi subcommand that
resolves template functions, or cat an identity file, none of which a
Read(...) deny rule sees. A denial here stops the call before permission rules
are evaluated, so this holds where a Bash(age *) deny rule would not: it
matches on the resolved basename, so an absolute path, a quoted inner command,
or a .exe suffix does not slip past.

Binary names are only matched in command position, so a search for the string
"age" is left alone. Wrapper commands such as sudo and sh -c are unwrapped and
their payload re-checked.

Not covered: a binary reached through a shell variable or renamed on disk.
"""

import re

from ..contract import Decision, denied
from ..shell_commands import read_commands, vouches_for

DECRYPT_BINARIES = {
    "age",
    "rage",
    "age-keygen",
    "rage-keygen",
    "sops",
}

# chezmoi subcommands that reach plaintext without invoking age as a separate
# process, either by resolving template functions or by decrypting the source
# state to compare against it. The write-side commands also block on a TTY
# passphrase prompt, which hangs a non-interactive tool call.
CHEZMOI_BLOCKED = {
    "apply": "writes decrypted files and prompts on a TTY",
    "archive": "emits plaintext secrets",
    "cat": "emits plaintext secrets",
    "cat-config": "emits plaintext secrets",
    "data": "emits plaintext secrets",
    "decrypt": "emits plaintext secrets",
    "diff": "decrypts the source state to compare",
    "dump": "emits plaintext secrets",
    "execute-template": "emits plaintext secrets",
    "init": "runs scripts and prompts on a TTY",
    "secret": "emits plaintext secrets",
    "update": "writes decrypted files and prompts on a TTY",
    "verify": "decrypts the source state to compare",
}

SECRET_PATH = re.compile(
    r"""
      \.config/chezmoi/[^\s]*key[^\s]*\.txt
    | \.config/age/
    | (^|/)\.age/
    | \.agekey($|[\s"'])
    | (^|/)identity\.txt$
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Every word of the line, redirect targets included, for the identity-file scan.
TOKEN = re.compile(r"'[^']*'|\"[^\"]*\"|[^\s;|&()<>]+")
# Quote marks and backticks, each read as a command boundary in the fallback.
QUOTING = re.compile(r"\$?'|\"|`")


def unquote(token):
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def command_violation(command):
    """Why one command reaches plaintext, or None."""
    if command.name in DECRYPT_BINARIES:
        return f"{command.name} decrypts secrets"
    if command.name == "chezmoi":
        for arg in command.args:
            if arg.startswith("-"):
                continue
            if arg in CHEZMOI_BLOCKED:
                return f"chezmoi {arg} {CHEZMOI_BLOCKED[arg]}"
            break
    return None


def find_violation(command):
    for token in TOKEN.findall(command):
        bare = unquote(token).replace("\\", "/")
        if SECRET_PATH.search(bare):
            return f"{bare} is an age identity file"

    # A backslash stays a path separator, so `C:\tools\age.exe` keeps its name.
    items = read_commands(command, keep_backslashes=True)
    if not vouches_for(command, keep_backslashes=True):
        # Fail closed: read the line again with every quote removed and every
        # heredoc body read as commands, so a command the reader misreads still shows.
        items += read_commands(QUOTING.sub(";", command), keep_backslashes=True, keep_heredocs=True)
    for item in items:
        reason = command_violation(item)
        if reason is not None:
            return reason

    return None


def check(payload):
    """The decision for one shell command, or silence for any other tool."""
    if not isinstance(payload, dict) or payload.get("tool_name") != "Bash":
        return Decision()
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return Decision()

    reason = find_violation(command)
    if reason is None:
        return Decision()

    message = (
        f"Blocked: {reason}. Decrypting secrets and reading age identities is not "
        "permitted. Ask Lev to run this command directly if it is needed."
    )
    return denied(message, message)
