#!/usr/bin/env python3
"""The core runs a project script in a subprocess, never in its own interpreter.

A script in a project root still gets the tool name as argv and the payload on
stdin, and its stdout and exit code still mean silence, advice, ask or deny.
The core does not exec that source, so a script cannot change this process.
"""

import pathlib
import sys
import tempfile
import textwrap

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from agent_guard.file_checks import script_verdict
from agent_guard.process import run_full


def fail(message):
    print(message)
    return 1


def main():
    source = pathlib.Path(__file__).resolve().parents[1] / "agent_guard"
    core = "\n".join(path.read_text(encoding="utf-8") for path in source.glob("*.py"))
    if "exec(compile(" in core or "def run_script(" in core:
        return fail("the core still executes check source")

    script = textwrap.dedent(
        """\
        import os
        import sys
        print(sys.argv[1])
        print(sys.stdin.read().strip())
        print(os.path.basename(os.getcwd()))
        sys.exit(2)
        """
    )
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "ask.py"
        path.write_text(script, encoding="utf-8")
        out, code = run_full(
            [sys.executable, str(path), "Bash"],
            timeout=5,
            cwd=directory,
            stdin='{"tool_input":{"command":"ls"}}',
        )

    payload = '{"tool_input":{"command":"ls"}}'
    if (out, code) != (f"Bash\n{payload}\n{pathlib.Path(directory).name}\n", 2):
        return fail(f"script contract broke: {(out, code)!r}")
    decision = script_verdict(out, code)
    if decision.permission != "ask":
        return fail(f"ask exit was not an ask: {decision.permission}")
    print("project script stays a subprocess: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
