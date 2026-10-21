#!/usr/bin/env python3
"""The check contract, called as a package function and as a project script.

Built-in checks are functions. A test calls one with a tool-call dict and reads
the findings or the verdict it returns. A script in a project root keeps the
stdin, stdout and exit-code contract, including advisory output, ask and deny.
"""

import os
import pathlib
import sys
import tempfile
import textwrap
import unittest

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

os.environ["XDG_STATE_HOME"] = tempfile.mkdtemp(prefix="agent-guard-contract-")

from agent_guard import decide  # noqa: E402
from agent_guard.checks.comment_length import check as comment_length_check  # noqa: E402
from agent_guard.checks.shell_conventions import check as shell_conventions_check  # noqa: E402
from agent_guard.checks.text_quality import check as text_quality_check  # noqa: E402
from agent_guard.contract import ASK_EXIT, FINDING_LINE, SHELL_TOOLS  # noqa: E402
from agent_guard.file_checks import check_tool  # noqa: E402

EM_DASH = "\u2014"


def event(name, tool, tool_input, cwd):
    return {
        "hook_event_name": name,
        "session_id": f"contract-{name}-{tool}",
        "cwd": str(cwd),
        "tool_name": tool,
        "tool_input": tool_input,
    }


def project_root(parent, script):
    root = pathlib.Path(parent)
    checks = root / ".agents" / "plugins" / "agent-guard" / "tool_checks"
    checks.mkdir(parents=True)
    (checks / "project_rule.py").write_text(textwrap.dedent(script), encoding="utf-8")
    return root


class BuiltinChecksAreFunctions(unittest.TestCase):
    def test_text_quality_check_returns_a_denial_for_an_em_dash(self):
        verdict = text_quality_check(
            {"tool_name": "Write", "tool_input": {"content": f"pages 3{EM_DASH}5\n"}}
        )

        self.assertEqual(verdict.permission, "deny")
        self.assertIn("em dash", verdict.context)

    def test_shell_conventions_check_returns_a_denial_for_grep(self):
        verdict = shell_conventions_check(
            {"tool_name": "Bash", "tool_input": {"command": "grep -r TODO src"}}
        )

        self.assertEqual(verdict.permission, "deny")
        self.assertIn("rg", verdict.context)

    def test_comment_length_check_returns_a_finding_line(self):
        findings = comment_length_check("# narration\n" * 4 + "value = 1\n", "notes.py")

        self.assertTrue(findings)
        self.assertRegex(findings[0], r":\d+  \[")
        self.assertTrue(FINDING_LINE.search(findings[0]))
        self.assertIn("comment-length", findings[0])


class ProjectRootScriptsKeepTheContract(unittest.TestCase):
    def test_a_project_script_advises_asks_and_denies(self):
        script = """\
            import json
            import sys

            payload = json.loads(sys.stdin.read() or "{}")
            marker = (payload.get("tool_input") or {}).get("command") or ""
            if marker == "advise":
                print("project advice")
            elif marker == "ask":
                print("project question")
                sys.exit(2)
            elif marker == "deny":
                print("project denial")
                sys.exit(1)
            """
        with tempfile.TemporaryDirectory() as directory:
            root = project_root(directory, script)
            cases = (
                ("advise", "allow", "project advice"),
                ("ask", "ask", "project question"),
                ("deny", "deny", "project denial"),
            )
            for marker, permission, text in cases:
                with self.subTest(marker=marker):
                    decision = decide(event("PreToolUse", "Bash", {"command": marker}, root))
                    self.assertEqual(decision.permission, permission)
                    self.assertIn(text, decision.context)

    def test_a_blank_and_a_failing_script_do_not_invent_a_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = project_root(directory, "import sys\nsys.exit(0)\n")
            decision = decide(event("PreToolUse", "Bash", {"command": "   "}, root))
            self.assertEqual(decision.permission, "allow")
            self.assertEqual(decision.context, "")

            crashing = project_root(
                pathlib.Path(directory) / "crash",
                "raise RuntimeError('boom')\n",
            )
            decision = decide(event("PreToolUse", "Bash", {"command": "ls"}, crashing))
            self.assertEqual(decision.permission, "deny")
            self.assertIn("failed to run", decision.context)


class OneDefinition(unittest.TestCase):
    def test_the_ask_exit_code_is_the_contract_constant(self):
        self.assertEqual(ASK_EXIT, 2)
        self.assertIn("Bash", SHELL_TOOLS)
        match = FINDING_LINE.search("  notes.py:4  [warn:comment-length] long")
        assert match is not None
        self.assertEqual(match.group(1), "4")

    def test_check_tool_reads_a_project_ask_as_the_contract_exit(self):
        script = """\
            import sys
            print("ask me")
            sys.exit(2)
            """
        with tempfile.TemporaryDirectory() as directory:
            root = project_root(directory, script)

            class Settings:
                tool_checks = True

            decision = check_tool(
                {"tool_name": "Bash", "tool_input": {"command": "ls"}},
                [root / ".agents" / "plugins" / "agent-guard"],
                Settings(),
                root,
            )

        self.assertEqual(decision.permission, "ask")


if __name__ == "__main__":
    unittest.main()
