#!/usr/bin/env python3
"""Cases for run_script in scripts/agent_guard.py. Run directly: python3 <this file>.

run_script executes a check inside the runner's own interpreter instead of
spawning a Python for it. That buys roughly a 4x speedup on a Bash call and
nothing else, so every case here asks the same question: does the check observe
what a subprocess would have given it, and does the runner observe what a
subprocess would have returned?

Four layers:

  parity      each fixture, and each shipped tool-check, run both ways and
              diffed against the real subprocess rather than against a
              hand-written expectation
  delivery    argv, stdin, cwd, stderr and a sibling import, which a subprocess
              provides for free and this path has to reproduce deliberately
  isolation   what a shared interpreter can leak that separate processes could
              not: a check's imports, its edits to sys.argv/sys.path/cwd, and a
              helper of the same name in another root
  mutation    the cases have teeth: breaking run_script must break the suite

Subprocess results are captured once and replayed, so the mutants are compared
against an oracle none of them can reach.
"""

import contextlib
import io
import os
import pathlib
import sys
import tempfile
import types

SCRIPT = pathlib.Path(__file__).parent.parent / "scripts" / "agent_guard.py"
CHECKS = pathlib.Path(__file__).parent.parent / "tool_checks"
SOURCE = SCRIPT.read_text(encoding="utf-8")

# Long enough that a check cannot finish inside it, short enough to pay per mutant.
WEDGE = 0.25


def load(source=None):
    """agent-guard as a module, optionally from mutated source."""
    module = types.ModuleType("guard_under_test")
    module.__file__ = str(SCRIPT)
    exec(compile(source or SOURCE, str(SCRIPT), "exec"), module.__dict__)
    module.__dict__["IN_PROCESS"] = True
    return module


# Every contract the check protocol has a word for, plus the two ways a check
# can fail before its own `__main__` guard exists to catch it.
FIXTURES = {
    "silent.py": "import sys\nsys.exit(0)\n",
    "advisory.py": "print('advice')\n",
    "deny.py": "import sys\nprint('denied')\nsys.exit(1)\n",
    "code3.py": "import sys\nsys.exit(3)\n",
    "exit_none.py": "import sys\nsys.exit(None)\n",
    "exit_message.py": "import sys\nsys.exit('reason')\n",
    "fallthrough.py": "print('no exit call')\n",
    "crash.py": "print('before')\nraise RuntimeError('boom')\n",
    "syntaxerr.py": "def broken(\n",
    "guarded.py": (
        "import sys\n"
        "def main():\n"
        "    raise RuntimeError('boom')\n"
        "if __name__ == '__main__':\n"
        "    try:\n"
        "        sys.exit(main())\n"
        "    except SystemExit:\n"
        "        raise\n"
        "    except BaseException:\n"
        "        sys.exit(0)\n"
    ),
    "echo.py": (
        "import os, sys\n"
        "print('argv=%s' % sys.argv[1])\n"
        "print('stdin=%s' % sys.stdin.read().strip())\n"
        "print('cwd=%s' % os.path.basename(os.getcwd()))\n"
    ),
    "noisy.py": ("import sys\nsys.stderr.write('diagnostics\\n')\nprint('only this')\n"),
    "sibling.py": "from helper import VALUE\nprint(VALUE)\n",
    "vandal.py": (
        "import os, sys\n"
        "sys.argv.append('extra')\n"
        "sys.path.insert(0, '/nowhere')\n"
        "os.chdir(os.path.dirname(os.path.abspath(__file__)))\n"
        "sys.stdin.read()\n"
    ),
    "stdlib.py": "import colorsys\nprint('ok')\n",
    "wedged.py": "import time\ntime.sleep(30)\n",
}

PAYLOADS = [
    '{"tool_input":{"command":"cd /home/lev/Git/lev/devkit && rg -n foo src/lib.rs"}}',
    '{"tool_input":{"command":"rg -rn TODO src/"}}',
    '{"tool_input":{"command":"grep -r TODO ."}}',
    '{"tool_input":{"command":"ls -la"}}',
    "not json at all",
    "",
]

# The wedged case only means something where the in-process timeout can fire.
# Windows has no SIGALRM, and there the process watchdog is the only backstop.
TIMED = hasattr(__import__("signal"), "SIGALRM")

oracle = {}


def build(directory, value):
    """A directory of fixture checks, with a helper for `sibling.py` to import."""
    root = pathlib.Path(directory)
    for name, source in FIXTURES.items():
        (root / name).write_text(source, encoding="utf-8")
    (root / "helper.py").write_text(f"VALUE = {value!r}\n", encoding="utf-8")
    return root


def expected(guard, path, argument, stdin, cwd, timeout):
    """What a subprocess returns for this call, spawned once and remembered."""
    key = (str(path), argument, stdin, cwd, timeout)
    if key not in oracle:
        oracle[key] = guard.run_full(
            [sys.executable, str(path), argument], timeout=timeout, cwd=cwd, stdin=stdin
        )
    return oracle[key]


@contextlib.contextmanager
def sandbox(roots):
    """Undo what a run of the suite leaves behind in this interpreter.

    A mutant is allowed to be as broken as it likes, including leaking a
    fixture module into sys.modules, and the next run has to start clean or the
    surviving-mutant tally reports the previous mutant's damage."""
    argv, search, cwd, loaded = list(sys.argv), list(sys.path), os.getcwd(), set(sys.modules)
    try:
        yield
    finally:
        sys.argv[:], sys.path[:] = argv, search
        with contextlib.suppress(OSError):
            os.chdir(cwd)
        for name in set(sys.modules) - loaded:
            origin = getattr(sys.modules.get(name), "__file__", None) or ""
            if any(origin.startswith(str(root)) for root in roots):
                del sys.modules[name]


def suite(guard, root, second):
    """Every case, against one build of run_script. Returns what went wrong."""
    broken = []

    def fail(message):
        broken.append(message)

    def call(path, argument="Bash", stdin="", cwd=None, timeout=5.0):
        return guard.run_script(path, argument, stdin, cwd or str(path.parent), timeout)

    def parity(path, label, argument="Bash", stdin="", cwd=None, timeout=5.0):
        cwd = cwd or str(path.parent)
        mine = guard.run_script(path, argument, stdin, cwd, timeout)
        theirs = expected(guard, path, argument, stdin, cwd, timeout)
        if mine != theirs:
            fail(f"DIVERGES {label}\n  in-process: {mine!r}\n  subprocess: {theirs!r}")

    for name in FIXTURES:
        if name == "wedged.py":
            continue
        parity(root / name, name, stdin='{"tool_input":{"command":"ls"}}')

    # A payload only reaches a check through stdin, and only the second argv
    # entry tells it which tool fired.
    out, code = call(root / "echo.py", argument="Edit", stdin="  payload  ", cwd=str(root))
    if (out, code) != (f"argv=Edit\nstdin=payload\ncwd={root.name}\n", 0):
        fail(f"DELIVERY wrong: {(out, code)!r}")

    # Diagnostics a check writes to stderr are not advice, and must not be
    # served to the agent as though they were.
    out, _ = call(root / "noisy.py")
    if out != "only this\n":
        fail(f"STDERR leaked into stdout: {out!r}")

    # A check importing a helper from beside it is the shape that broke: a
    # subprocess gets its script's directory on sys.path and this path did not.
    out, code = call(root / "sibling.py")
    if (out, code) != ("root-a\n", 0):
        fail(f"SIBLING IMPORT failed: {(out, code)!r}")

    # Nothing the check touched survives it.
    argv, stdin_stream, search, cwd = sys.argv, sys.stdin, list(sys.path), os.getcwd()
    call(root / "vandal.py")
    if sys.argv is not argv or sys.stdin is not stdin_stream:
        fail("VANDAL kept sys.argv or sys.stdin")
    if sys.path != search:
        fail("VANDAL kept a sys.path entry")
    if os.getcwd() != cwd:
        fail("VANDAL kept the working directory")
        os.chdir(cwd)

    # Staying in one interpreter is worth having only because the standard
    # library is not re-imported per check, so eviction stops at the check's
    # own directory.
    sys.modules.pop("colorsys", None)
    call(root / "stdlib.py")
    if "colorsys" not in sys.modules:
        fail("STDLIB evicted: colorsys was dropped from sys.modules")

    before = set(sys.modules)
    call(root / "sibling.py")
    leaked = [
        name
        for name in set(sys.modules) - before
        if (getattr(sys.modules.get(name), "__file__", None) or "").startswith(str(root))
    ]
    if leaked:
        fail(f"MODULE LEAK: {leaked}")

    # Two roots shipping a same-named helper must not serve each other's copy,
    # in either order and on a repeat visit.
    for path, want in (
        (root / "sibling.py", "root-a\n"),
        (second / "sibling.py", "root-b\n"),
        (root / "sibling.py", "root-a\n"),
        (second / "sibling.py", "root-b\n"),
    ):
        out, _ = call(path)
        if out != want:
            fail(f"CROSS-ROOT bleed: {path.parent} served {out!r}, wanted {want!r}")

    # A check that never returns is reported as silence, the same way a
    # subprocess that outran its timeout always was.
    if TIMED:
        parity(root / "wedged.py", "wedged.py", timeout=WEDGE)

    # Returning None is how run_script says "not this way", so the caller falls
    # back to a subprocess instead of dropping the check.
    if call(root / "missing.py") is not None:
        fail("UNREADABLE check did not fall back")
    guard.IN_PROCESS = False
    try:
        if call(root / "advisory.py") is not None:
            fail("AGENT_GUARD_IN_PROCESS=0 did not fall back")
    finally:
        guard.IN_PROCESS = True

    # The checks that actually ship. A fixture can only prove the mechanism;
    # these prove the checks still work through it.
    for check in sorted(CHECKS.glob("*.py")):
        for payload in PAYLOADS:
            parity(check, f"{check.name} <- {payload[:40]}", stdin=payload)

    return broken


# Each mutant is a plausible simplification of run_script that the cases above
# must refuse. A mutant no case kills is a case that was never testing anything.
MUTANTS = [
    ("sibling directory not on the path", "sys.path.insert(0, home)", "pass"),
    ("imported helpers never evicted", "del sys.modules[name]", "pass"),
    (
        "eviction reaches the standard library",
        "if origin.startswith(home + os.sep):",
        "if True:",
    ),
    (
        "stdin left as the runner's",
        "sys.stdin = io.StringIO(stdin)",
        "sys.stdin = io.StringIO('')",
    ),
    ("argv left as the runner's", "sys.argv = [str(path), argument]", "pass"),
    (
        "stderr folded into the advice",
        "contextlib.redirect_stderr(io.StringIO())",
        "contextlib.redirect_stderr(captured)",
    ),
    (
        "working directory not moved",
        "os.chdir(cwd)",
        "os.chdir(os.getcwd())",
    ),
    (
        "string exit read as success",
        "(0 if stop.code is None else 1)",
        "0",
    ),
    ("output before a crash discarded", "return captured.getvalue(), 1", 'return "", 1'),
    ("a crash read as silence", "return captured.getvalue(), 1", 'return "", 0'),
    (
        "a timeout read as a denial",
        '        return "", 0\n    except BaseException:',
        '        return "", 1\n    except BaseException:',
    ),
    (
        "no fallback for an unreadable check",
        "        return None\n\n    captured",
        "        return '', 0\n\n    captured",
    ),
    (
        "no-op: the suite must pass unchanged",
        "captured = io.StringIO()",
        "captured = io.StringIO()",
    ),
]


def main():
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        root, second = build(a, "root-a"), build(b, "root-b")
        guard = load()

        with sandbox((root, second)):
            failures = suite(guard, root, second)
        for message in failures:
            print(message)

        survivors = []
        for label, original, replacement in MUTANTS:
            noop = original == replacement
            if SOURCE.count(original) != 1:
                survivors.append(f"{label} (anchor no longer matches source)")
                continue
            mutant = load(SOURCE.replace(original, replacement))
            try:
                # A mutant is free to write to the real stderr; that is not a
                # result, and it should not be mistaken for one on the console.
                with sandbox((root, second)), contextlib.redirect_stderr(io.StringIO()):
                    killed = bool(suite(mutant, root, second))
            except BaseException:
                killed = True  # a mutant that cannot even run is caught
            if killed == noop:
                survivors.append(label)

        for label in survivors:
            print(f"MUTANT SURVIVED: {label}")

    print(
        "%d fixtures, %d shipped checks x %d payloads, %d mutants: %s"
        % (
            len(FIXTURES),
            len(list(CHECKS.glob("*.py"))),
            len(PAYLOADS),
            len(MUTANTS),
            "ok" if not failures and not survivors else "FAILED",
        )
    )
    return 1 if failures or survivors else 0


if __name__ == "__main__":
    sys.exit(main())
