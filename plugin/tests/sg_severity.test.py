#!/usr/bin/env python3
"""Cases for the ast-grep severity mapping in scripts/agent_guard.py.

A rule declares its tier in its own file, and the runner has to carry that
declaration into the report. "hint" is what a rule that declares nothing
reports, so it has to land in the default tier rather than the quietest one.
"""

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

GUARD = pathlib.Path(__file__).parent.parent / "scripts" / "agent_guard.py"

RULE = """id: {name}
language: typescript
{severity}message: {name} fired
rule: {{ pattern: "const {name} = {number}" }}
"""

SOURCE = "const loud = 1;\nconst plain = 2;\nconst quiet = 3;\nconst bare = 4;\n"
DECLARED = (("loud", 1, "error"), ("plain", 2, "warning"), ("quiet", 3, "info"), ("bare", 4, None))


def report():
    """The context the hook emits for a tree carrying the four rules above."""
    with tempfile.TemporaryDirectory() as base:
        rules = pathlib.Path(base, ".agents", "plugins", "agent-guard", "rules")
        rules.mkdir(parents=True)
        for name, number, severity in DECLARED:
            rules.joinpath(f"{name}.yml").write_text(
                RULE.format(
                    name=name,
                    number=number,
                    severity=f"severity: {severity}\n" if severity else "",
                ),
                encoding="utf-8",
            )
        target = pathlib.Path(base, "x.ts")
        target.write_text(SOURCE, encoding="utf-8")
        payload = json.dumps(
            {
                "hook_event_name": "PostToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": str(target)},
                "cwd": base,
            }
        )
        done = subprocess.run(
            [sys.executable, str(GUARD)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=base,
        )
        if not done.stdout.strip():
            return ""
        return json.loads(done.stdout)["hookSpecificOutput"]["additionalContext"]


HAS_AST_GREP = shutil.which("ast-grep") is not None
OUT = report() if HAS_AST_GREP else ""


def test_a_declared_severity_becomes_the_matching_prefix():
    assert "[error:loud]" in OUT, OUT
    assert "[warn:plain]" in OUT, OUT
    assert "[info:quiet]" in OUT, OUT


def test_a_rule_declaring_nothing_stays_a_violation():
    assert "[warn:bare]" in OUT, OUT
    assert "[info:bare]" not in OUT, OUT


def test_the_tiers_reach_their_own_headings():
    error, warn, note = (
        OUT.index("[error:loud]"),
        OUT.index("[warn:plain]"),
        OUT.index("[info:quiet]"),
    )
    assert error < warn < note, OUT
    assert "well past the line" in OUT, OUT
    assert "none of these is a violation" in OUT, OUT


if __name__ == "__main__":
    if not HAS_AST_GREP:
        print("skip  ast-grep is not installed")
        sys.exit(0)
    failures = 0
    for name, case in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            case()
            print(f"ok   {name}")
        except AssertionError as bad:
            failures += 1
            print(f"FAIL {name}: {bad}")
        except Exception as bad:
            failures += 1
            print(f"FAIL {name}: {type(bad).__name__}: {bad}")
    print(f"\n{failures} failed")
    sys.exit(1 if failures else 0)
