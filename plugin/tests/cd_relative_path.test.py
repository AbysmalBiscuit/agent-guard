#!/usr/bin/env python3
"""Cases for tool_checks/cd_relative_path.py. Run directly: python3 <this file>.

Held here rather than beside the check, because tool_checks/ globs every *.py
in it and would run this file as a check on each Bash call.

Four layers, each answering a question the layer above cannot:

  corpus     the shapes that must block and the ones that must not
  property   invariants over generated inputs, including the advice the check
             prints being advice the check itself accepts
  fuzz       the check never raises, because `__main__` turns a raised
             exception into exit 0 and a crash would otherwise be invisible
  mutation   the corpus has teeth: breaking the check must break the suite
"""

import contextlib
import io
import json
import ntpath
import os
import pathlib
import random
import sys
import types

CHECK = pathlib.Path(__file__).parent.parent / "tool_checks" / "cd_relative_path.py"
SOURCE = CHECK.read_text(encoding="utf-8")

POSIX_DIR = "/home/lev/Git/lev/devkit"
MSYS_DIR = "/c/Users/Lev/proj"
WIN_DIR = "C:\\Users\\Lev\\proj"


def load(source=None):
    """The check as an importable module, optionally from mutated source."""
    module = types.ModuleType("check_under_test")
    module.__file__ = str(CHECK)
    exec(compile(source or SOURCE, str(CHECK), "exec"), module.__dict__)
    return module


def verdict(module, command):
    """Run the real entry point and return ("block" | "pass", printed advice).

    Going through main() rather than the helpers keeps the payload parsing and
    the exit codes in the test, which is where the hook contract lives.
    """
    argv, stdin = sys.argv, sys.stdin
    sys.argv = ["cd_relative_path.py", "Bash"]
    sys.stdin = io.StringIO(json.dumps({"tool_input": {"command": command}}))
    printed = io.StringIO()
    try:
        with contextlib.redirect_stdout(printed):
            code = module.main()
    finally:
        sys.argv, sys.stdin = argv, stdin
    return ("block" if code == 1 else "pass"), printed.getvalue()


MUST_BLOCK = [
    # A quoted alternation used to split the line apart and hide the path.
    (
        f'cd {POSIX_DIR} && rg -n "pub fn (parse_shell|commands_enabled|resolve_rules)" '
        f"-A 40 crates/devkit-common/src/harness.rs | head -170"
    ),
    f"cd {POSIX_DIR} && rg -n 'baseline' src/bin/devkit/run/mod.rs | head -120",
    f"cd {POSIX_DIR} && cat Cargo.toml",
    f"cd {POSIX_DIR} && head -20 README.md",
    f"cd {POSIX_DIR} && sed -n '1,20p' Cargo.toml",
    f"cd {POSIX_DIR} && fd -e rs . crates/",
    f"cd {POSIX_DIR} && rg -n 'x' -g '*.rs' crates/devkit-config/src/lib.rs",
    f"cd {POSIX_DIR} && rg -n 'x' Cargo.toml 2>/dev/null",
    # `git` is blocked whatever its operands, because it runs the hooks of the
    # directory it lands in. It can sit anywhere in the chain.
    f"cd {POSIX_DIR}; git diff 7ede803 2501e42 -- crates/ | head -60",
    f'cd {POSIX_DIR} && echo "looking"; git diff HEAD~1',
    f"cd {POSIX_DIR} && for r in a b; do git show $r:Cargo.toml; done",
    # MSYS paths, which native-Windows ntpath calls relative rather than absolute.
    (
        f'cd {MSYS_DIR}; rg -n "alacritty|crlf|eol|\\.toml" .chezmoiattributes 2>/dev/null;'
        f' echo "--- attrs? ---"; fd -H "chezmoiattributes" . | head'
    ),
    f'cd {MSYS_DIR} && rg -n "pub fn (a|b|c)" -A 40 crates/x/src/y.rs | head -170',
    f"cd {MSYS_DIR} && cat Cargo.toml",
    # Native Windows paths, whose backslashes posix escaping used to eat.
    f'cd {WIN_DIR} && rg -n "a|b" crates\\x\\src\\y.rs',
    'cd C:/Users/Lev/proj && rg -n "a|b" crates/x/src/y.rs',
    # PowerShell: its own verbs, its abbreviations, and its casing.
    f'cd {WIN_DIR}; Select-String -Pattern "a|b" -Path crates\\x.rs',
    f"Set-Location {WIN_DIR}; Get-Content crates\\x.rs",
    f"Set-Location -Path {WIN_DIR}; gc crates\\x.rs",
    f'sl {WIN_DIR}; sls "pub fn (a|b|c)" crates\\x.rs',
    f"Push-Location {WIN_DIR}; Get-Content -LiteralPath .\\Cargo.toml",
    f'cd {WIN_DIR}; SELECT-STRING -PATTERN "a|b" -PATH crates\\x.rs',
    f"Set-Location {WIN_DIR}; gci -Recurse src\\bin",
    f"Set-Location {WIN_DIR}; git diff HEAD~1",
    f'cd {WIN_DIR}; C:\\bin\\rg.exe -n "a|b" crates\\x.rs',
    # A newline separates commands like `;` does. The reader is on its own line.
    f"cd {POSIX_DIR}\nrg -n 'a|b' crates/x.rs",
    f"cd {POSIX_DIR}\ncargo build\ncat Cargo.toml",
    f"cd {POSIX_DIR}\necho building\nhead -20 README.md\necho done",
    f"cd {MSYS_DIR}\nSet-Location ignored\ngc crates\\x.rs",
    f"cd {POSIX_DIR}\ngit diff HEAD~1",
]

MUST_PASS = [
    # No cd, so nothing resolves against the wrong directory.
    f"rg -n 'baseline' {POSIX_DIR}/Cargo.toml",
    f"git -C {POSIX_DIR} diff HEAD~1",
    "rg -n 'git' /home/lev/.claude/settings.json",
    f"Get-Content {WIN_DIR}\\crates\\x.rs",
    # A cd whose commands need the working directory rather than shortening a path.
    f"cd {POSIX_DIR} && cargo build",
    f"cd {POSIX_DIR} && npm test",
    f"cd {POSIX_DIR} && echo done",
    f"cd {MSYS_DIR} && cargo build",
    f"Set-Location {WIN_DIR}; cargo build",
    # A cd whose reader already writes the path out.
    f"cd {POSIX_DIR} && rg -n 'x' {POSIX_DIR}/Cargo.toml",
    f"cd {POSIX_DIR} && rg -n 'pipe|alt' /abs/only.rs",
    f"cd {MSYS_DIR} && rg -n 'a|b' {MSYS_DIR}/crates/x.rs",
    f"Set-Location {WIN_DIR}; Get-Content {WIN_DIR}\\crates\\x.rs",
    # Readers naming no path at all.
    f"cd {POSIX_DIR} && rg -n 'needle'",
    f'Set-Location {WIN_DIR}; Select-String -Pattern "a|b"',
    # fd's first positional is the pattern, not a path.
    f"cd {POSIX_DIR} && fd -e rs crates/",
    # The operands stop being paths once they are handed to a child command.
    f"cd {POSIX_DIR} && fd -e rs -x wc -l",
    # A redirect's target is a stream, not something the reader opens.
    f"cd {POSIX_DIR} && rg --files > /tmp/out.txt",
    "cd /nonexistent-dir-xyz && ls",
    # A `cd` on its own line must not absorb the following lines. This shape,
    # a shell script with a leading cd and later assignments and readers, was
    # read as one enormous command whose cd target ran to the end of the file.
    (
        "cd /home/lev\n"
        'echo "=== bare python startup ==="\n'
        "hyperfine -w 5 -r 30 -N 'python3 -c pass' | rg 'Time' | head -2\n"
    ),
    f"cd {POSIX_DIR}\ncargo build\nnpm test\n",
    f"cd {POSIX_DIR}\nP=/abs/p.json\nhead -2 /abs/p.json\n",
    f"cd {POSIX_DIR}\n\n\ncargo build\n",
    f"cd {POSIX_DIR}\nrg -n 'a|b' {POSIX_DIR}/crates/x.rs\n",
]


def run_corpus(module, report):
    """Failures across both lists. `report` prints them; pass a no-op to count."""
    failures = 0
    for command in MUST_BLOCK:
        if verdict(module, command)[0] != "block":
            report(f"MISS (should block): {command}")
            failures += 1
    for command in MUST_PASS:
        got, advice = verdict(module, command)
        if got != "pass":
            report(f"FALSE POSITIVE: {command} -> {advice.strip().splitlines()[0]}")
            failures += 1
    return failures


# Metacharacters inside a quoted argument must not reach the splitter. Each of
# these is a pattern an agent would plausibly search for.
QUOTED_PATTERNS = [
    "a|b",
    "pub fn (parse|commands|resolve)",
    "a|b|c|d|e",
    "foo;bar",
    "a && b",
    "x > y",
    "(a|b)&&(c|d)",
    "a  |  b",
    "|leading",
    "trailing|",
]

FUZZ_VOCABULARY = [
    "cd",
    "rg",
    "fd",
    "cat",
    "git",
    "head",
    "Set-Location",
    "Get-Content",
    "sls",
    "&&",
    "||",
    ";",
    "|",
    "&",
    "(",
    ")",
    ">",
    ">>",
    "<",
    "2>",
    "2>&1",
    "-n",
    "-A",
    "40",
    "-Path",
    "-Pattern",
    "--",
    "-",
    "-x",
    POSIX_DIR,
    WIN_DIR,
    MSYS_DIR,
    "crates/x.rs",
    "crates\\x.rs",
    ".",
    "..",
    '"a|b"',
    "'a|b'",
    '"unterminated',
    "''",
    '""',
    "\\",
    "$(x)",
    "`x`",
    "~",
    "\n",
]


def properties(module, report):
    """Invariants that hold over generated inputs, not just the listed ones."""
    failures = 0

    # A quoted argument is opaque: whatever metacharacters it holds, the check
    # still sees the reader and the relative path. This is the bug that shipped.
    for pattern in QUOTED_PATTERNS:
        for quote in ('"', "'"):
            if quote in pattern:
                continue
            command = (
                f"cd {POSIX_DIR} && rg -n {quote}{pattern}{quote} "
                f"-A 40 crates/x/src/y.rs | head -170"
            )
            if verdict(module, command)[0] != "block":
                report(f"QUOTE LEAK: {command}")
                failures += 1

    for command in MUST_BLOCK:
        parsed = module.commands(command)
        directory = module.leading_cd(parsed)
        if directory is None:
            report(f"NO CD FOUND: {command}")
            failures += 1
            continue
        _, hits = module.relative_operands(parsed, directory)
        if not hits:
            continue  # the git branch, whose advice is `git -C` rather than a path

        # The advice names an operand that is really in the command, rather
        # than one the parser invented.
        if hits[0] not in command:
            report(f"UNGROUNDED ADVICE: {hits[0]!r} not in {command}")
            failures += 1

        # Taking the advice makes progress. A line naming several relative
        # paths still blocks on the next one, which is right, but it must never
        # block on the operand just fixed or the agent loops forever.
        fixed = command.replace(hits[0], os.path.join(directory, hits[0]), 1)
        parsed = module.commands(fixed)
        again = module.leading_cd(parsed)
        _, remaining = module.relative_operands(parsed, again) if again else ("", [])
        if remaining and remaining[0] == hits[0]:
            report(f"ADVICE LOOPS on {hits[0]!r}: {fixed}")
            failures += 1

    return failures


def fuzz(module, report, rounds=3000, seed=20260904):
    """The check must never raise, and must answer only 0 or 1.

    `__main__` catches BaseException and exits 0, so a crash in production is
    indistinguishable from approval. Calling main() directly lets it through.
    """
    rng = random.Random(seed)
    failures = 0
    for _ in range(rounds):
        command = " ".join(rng.choice(FUZZ_VOCABULARY) for _ in range(rng.randint(1, 14)))
        try:
            code = verdict(module, command)[0]
        except Exception as error:
            report(f"RAISED: {command!r} -> {type(error).__name__}: {error}")
            failures += 1
            continue
        if code not in ("block", "pass"):
            report(f"BAD EXIT: {command!r} -> {code!r}")
            failures += 1
    return failures


def windows_host(module, report):
    """The corpus again with ntpath semantics, as on native Windows.

    There, `os.path.join` on an MSYS directory produces a path that never
    resolves, so anything leaning on the filesystem answers wrongly.
    """
    real = module.os.path
    module.os.path = ntpath
    try:
        return run_corpus(module, report)
    finally:
        module.os.path = real


# Each mutant breaks one decision the check makes. If the suite still passes,
# that decision is untested and the mutant says so.
MUTANTS = [
    (
        "quote-blind splitter",
        "    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)",
        (
            '    return [s.split() for s in re.split(r"\\s*(?:\\|\\||&&|\\||;)\\s*", line) '
            "if s.split()]\n"
            "    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)"
        ),
    ),
    ("posix backslash escaping", '    lexer.escape = ""', '    lexer.escape = "\\\\"'),
    (
        "newline not a separator",
        "    for line in script.splitlines():",
        "    for line in [script]:",
    ),
    (
        "posix-only rooting",
        '    return path.startswith(("/", "\\\\")) or bool(WINDOWS_ROOT.match(path))',
        '    return path.startswith("/")',
    ),
    (
        "case-sensitive command names",
        '    base = re.split(r"[\\\\/]", word)[-1].lower()',
        '    base = re.split(r"[\\\\/]", word)[-1]',
    ),
    ("named paths dropped", "    operands = named + operands", "    operands = list(operands)"),
    ("first segment only", "    for tokens in parsed[1:]:", "    for tokens in parsed[1:2]:"),
    (
        "pattern operand treated as a path",
        "    if name in PATTERN_FIRST and operands:",
        "    if False and operands:",
    ),
    ("shape hint ignored", "PATH_SHAPE.search(operand) or ", ""),
]


def mutation(report):
    """Every mutant must be caught by the corpus or the properties."""
    survivors = 0
    for label, original, replacement in MUTANTS:
        if original not in SOURCE:
            report(f"STALE MUTANT (anchor gone, rewrite it): {label}")
            survivors += 1
            continue
        mutated = SOURCE.replace(original, replacement, 1)
        silent = lambda *_: None  # noqa: E731 - a mutant's own failures are the signal
        try:
            module = load(mutated)
            caught = run_corpus(module, silent) or properties(module, silent)
        except Exception:
            caught = True
        if not caught:
            report(f"SURVIVED (that decision is untested): {label}")
            survivors += 1
    return survivors


failures = 0
report = print
module = load()

failures += run_corpus(module, report)
failures += windows_host(module, report)
failures += properties(module, report)
failures += fuzz(module, report)
failures += mutation(report)

checks = len(MUST_BLOCK) + len(MUST_PASS)
print(
    "%d corpus (x2 hosts), %d properties, %d fuzz, %d mutants: %s"
    % (
        checks,
        len(MUST_BLOCK) + len(QUOTED_PATTERNS),
        3000,
        len(MUTANTS),
        "ok" if not failures else "%d FAILURES" % failures,
    )
)
sys.exit(1 if failures else 0)
