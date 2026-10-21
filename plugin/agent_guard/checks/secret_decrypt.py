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

from agent_guard.contract import Decision, denied

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

RUNNERS = {
    "bash",
    "command",
    "dash",
    "doas",
    "env",
    "exec",
    "ksh",
    "nice",
    "nohup",
    "sh",
    "stdbuf",
    "sudo",
    "time",
    "timeout",
    "xargs",
    "zsh",
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

SEGMENT = re.compile(r"\|\||&&|[;|&\n]")
TOKEN = re.compile(r"'[^']*'|\"[^\"]*\"|[^\s;|&()<>]+")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

MAX_DEPTH = 3


def unquote(token):
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def normalize(token):
    """Reduce a token to a bare command name for comparison."""
    bare = re.split(r"[/\\]", unquote(token))[-1].lower()
    return bare[:-4] if bare.endswith(".exe") else bare


def check_segment(segment, depth):
    tokens = TOKEN.findall(segment)
    index = 0
    while index < len(tokens) and ASSIGNMENT.match(tokens[index]):
        index += 1
    if index >= len(tokens):
        return None

    name = normalize(tokens[index])

    if name in DECRYPT_BINARIES:
        return f"{name} decrypts secrets"

    if name == "chezmoi":
        for candidate in tokens[index + 1 :]:
            bare = unquote(candidate)
            if bare.startswith("-"):
                continue
            if bare in CHEZMOI_BLOCKED:
                return f"chezmoi {bare} {CHEZMOI_BLOCKED[bare]}"
            break
        return None

    if name in RUNNERS and depth < MAX_DEPTH:
        rest = [t for t in tokens[index + 1 :] if not t.startswith("-")]
        if not rest:
            return None
        return find_violation(" ".join(unquote(t) for t in rest), depth + 1)

    return None


def find_violation(command, depth=0):
    for token in TOKEN.findall(command):
        bare = unquote(token).replace("\\", "/")
        if SECRET_PATH.search(bare):
            return f"{bare} is an age identity file"

    for segment in SEGMENT.split(command):
        reason = check_segment(segment, depth)
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
