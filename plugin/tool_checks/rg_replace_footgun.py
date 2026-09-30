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

import json
import re
import shlex
import sys

BAD_CLUSTER = re.compile(r"^-[a-zA-Z]*r[a-zA-Z]*$")
# Pipes, lists, subshells, groups, redirections and process substitutions all
# start a fresh command position: `<(rg …)` must arm the check just like `| rg`.
OPERATORS = re.compile(r"^[|&;()<>{}\n]+$")
# Wrappers that keep the next word in command position.
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
    "xargs",
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


def tokenize(cmd):
    lexer = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def bad_flag(cmd, depth=0):
    """Return the offending flag cluster in `cmd`, or None."""
    if depth > 2:
        return None
    try:
        toks = tokenize(cmd)
    except ValueError:
        return regex_fallback(cmd)

    in_rg = False
    cmd_pos = True
    shell = None

    for i, t in enumerate(toks):
        if OPERATORS.match(t):
            in_rg, cmd_pos, shell = False, True, None
            continue

        if cmd_pos:
            # Env assignments, wrapper options and their operands (timeout 10,
            # nice -n 5) all leave us still looking for the real command word.
            if re.match(r"^[A-Za-z_][A-Za-z_0-9]*=", t):
                continue
            if t in WRAPPERS:
                continue
            if t.startswith("-") or DURATION.match(t):
                continue

            cmd_pos = False
            name = t.rsplit("/", 1)[-1]
            in_rg = name == "rg"
            shell = name if name in SHELLS else None
            continue

        # `bash -c '<nested command>'` — scan the nested string too.
        if shell and t == "-c" and i + 1 < len(toks):
            hit = bad_flag(toks[i + 1], depth + 1)
            if hit:
                return hit
            continue

        if in_rg and len(t) >= 3 and BAD_CLUSTER.match(t):
            return t

    return None


def regex_fallback(cmd):
    """Unbalanced quotes etc. — scan each shell segment for `rg ... -r<flags>`."""
    for seg in re.split(r"[|;&\n(){}]+", cmd):
        m = re.search(r"(?:^|\s|/)rg\s", seg)
        if not m:
            continue
        for t in seg[m.end() :].split():
            if len(t) >= 3 and BAD_CLUSTER.match(t):
                return t
    return None


def main():
    if (sys.argv[1] if len(sys.argv) > 1 else "") != "Bash":
        return 0
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    cmd = (payload.get("tool_input") or {}).get("command") or ""
    if not cmd:
        return 0

    hit = bad_flag(cmd)
    if not hit:
        return 0

    print(
        f"rg recurses by default and has no recursive flag. In '{hit}', -r is "
        "--replace: it swallows the remaining letters as replacement text and "
        "silently prints matches with that text substituted instead of applying "
        "-n/-l/-c (rg never edits files, but the output is wrong and looks fine). "
        "Pass the flags separately: -n (line numbers), -l (files with matches), "
        "-c (count). For a real replacement use the spaced form: "
        "rg -r 'text' PATTERN or rg --replace 'text' PATTERN."
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
