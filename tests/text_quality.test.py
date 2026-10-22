#!/usr/bin/env python3
"""Cases for agent_guard.checks.text_quality.

Which half of a call is read matters most: the text a call adds is checked and
the text it removes is not, or the rule would refuse the very edit that takes
an em dash back out. After that, each tier's exit code has to survive the trip
through the hook and reach the harness as the decision it stands for. Every
character under test is written as an escape, so this file is ASCII.
"""

import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "plugin"))

from agent_guard.checks import text_quality as check_module
from agent_guard.contract import ASK_EXIT
from hook_support import run_hook

EM_DASH = "\u2014"
EN_DASH = "\u2013"
INTERPUNCT = "\u00b7"

_PERMISSION_CODE = {"deny": 1, "ask": ASK_EXIT, "allow": 0}


def check(tool, tool_input):
    verdict = check_module.check(
        {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}
    )
    return verdict.context.strip(), _PERMISSION_CODE[verdict.permission]


class RefusedCharacters(unittest.TestCase):
    def test_em_dash_in_a_shell_command_is_denied(self):
        out, code = check(
            "Bash", {"command": f'git commit -m "adds a thing {EM_DASH} and another"'}
        )

        self.assertEqual(code, 1)
        self.assertIn("em dash", out)

    def test_en_dash_in_written_file_content_is_denied(self):
        out, code = check("Write", {"file_path": "notes.md", "content": f"pages 3{EN_DASH}5\n"})

        self.assertEqual(code, 1)
        self.assertIn("en dash", out)

    def test_replacement_text_of_an_edit_is_denied(self):
        out, code = check("Edit", {"old_string": "before", "new_string": f"after {EM_DASH} more"})

        self.assertEqual(code, 1)
        self.assertIn("em dash", out)

    def test_one_edit_of_a_multi_edit_is_enough(self):
        out, code = check(
            "MultiEdit",
            {"edits": [{"new_string": "clean"}, {"new_string": f"dirty {EM_DASH} here"}]},
        )

        self.assertEqual(code, 1)
        self.assertIn("em dash", out)

    def test_added_patch_lines_are_denied(self):
        patch = f"*** Begin Patch\n*** Update File: a.md\n+a line {EM_DASH} here\n*** End Patch"
        out, code = check("apply_patch", {"command": patch})

        self.assertEqual(code, 1)
        self.assertIn("em dash", out)


class TextTheCallDoesNotAdd(unittest.TestCase):
    def test_removing_a_dash_through_an_edit_is_allowed(self):
        out, code = check(
            "Edit", {"old_string": f"before {EM_DASH} after", "new_string": "before, after"}
        )

        self.assertEqual((out, code), ("", 0))

    def test_removed_patch_lines_are_allowed(self):
        patch = (
            f"*** Begin Patch\n*** Update File: a.md\n"
            f"-a line {EM_DASH} here\n+a line, here\n*** End Patch"
        )
        out, code = check("apply_patch", {"command": patch})

        self.assertEqual((out, code), ("", 0))

    def test_a_search_is_not_a_write(self):
        out, code = check("Grep", {"pattern": EM_DASH, "path": "."})

        self.assertEqual((out, code), ("", 0))

    def test_an_escape_is_not_the_character(self):
        out, code = check("Write", {"content": 'DASH = "\\u2014"\n'})

        self.assertEqual((out, code), ("", 0))


class InterpunctWarns(unittest.TestCase):
    def test_interpunct_in_content_runs_with_a_suggestion(self):
        out, code = check("Write", {"content": f"home {INTERPUNCT} docs {INTERPUNCT} api\n"})

        self.assertEqual(code, 0)
        self.assertIn("interpunct", out)
        self.assertIn("comma", out)

    def test_a_refusal_outranks_a_warning(self):
        out, code = check("Write", {"content": f"a {INTERPUNCT} b {EM_DASH} c\n"})

        self.assertEqual(code, 1)
        self.assertIn("em dash", out)


class TheShippedRules(unittest.TestCase):
    """Adding a line to REFUSE, ASK or WARN is all it takes to enforce it, so
    every rule is exercised rather than a chosen few."""

    def assert_tier(self, rules, expected_code):
        for key in rules(check_module):
            with self.subTest(rule=check_module.label(key)):
                out, code = check("Write", {"content": f"a {key} b"})

                self.assertEqual(code, expected_code)
                self.assertIn(check_module.label(key), out)

    def test_every_refused_rule_is_denied_by_name(self):
        self.assert_tier(lambda module: module.REFUSE, 1)

    def test_every_asked_rule_reaches_the_human(self):
        self.assert_tier(lambda module: module.ASK, ASK_EXIT)

    def test_every_warned_rule_runs_and_says_why(self):
        self.assert_tier(lambda module: module.WARN, 0)


class RuleValues(unittest.TestCase):
    def test_a_plain_value_is_the_swap_the_agent_is_told_to_make(self):
        with patch.dict(check_module.WARN, {"utilize": "use"}):
            verdict = check_module.judge("we utilize it")

        self.assertEqual(verdict.permission, "allow")
        self.assertIn('"utilize"', verdict.context)
        self.assertIn("Write `use` instead.", verdict.context)

    def test_matching_ignores_case(self):
        with patch.dict(check_module.WARN, {"frobnicate": "poke"}):
            verdict = check_module.judge("Frobnicate it first")

        self.assertEqual(verdict.permission, "allow")
        self.assertIn("Write `poke` instead.", verdict.context)
        self.assertIn("Frobnicate it first", verdict.context)

    def test_an_empty_value_says_to_delete(self):
        with patch.dict(check_module.WARN, {"very": ""}):
            verdict = check_module.judge("a very big deal")

        self.assertIn("Delete it.", verdict.context)

    def test_an_explained_value_is_read_as_written(self):
        with patch.dict(
            check_module.WARN, {"utilize": check_module.Explain("Say what it does instead.")}
        ):
            verdict = check_module.judge("we utilize it")

        self.assertIn("Say what it does instead.", verdict.context)
        self.assertNotIn("Write `", verdict.context)


class ThroughTheHook(unittest.TestCase):
    """The whole path, so the exit codes are read as decisions rather than as
    two numbers a caller happens to agree on."""

    def decision(self, tool, tool_input):
        with tempfile.TemporaryDirectory() as directory:
            payload = {
                "session_id": "test-session",
                "cwd": directory,
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": tool_input,
            }
            result = run_hook(
                json.dumps(payload),
                capture_output=True,
                text=True,
                cwd=directory,
                timeout=20,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip(), "hook returned no output")
        return json.loads(result.stdout)["hookSpecificOutput"]

    def test_em_dash_reaches_the_harness_as_a_denial(self):
        out = self.decision("Write", {"file_path": "a.md", "content": f"x {EM_DASH} y\n"})

        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("em dash", out["permissionDecisionReason"])

    def test_interpunct_runs_and_reaches_the_agent_as_advice(self):
        out = self.decision("Write", {"file_path": "a.md", "content": f"x {INTERPUNCT} y\n"})

        self.assertNotIn("permissionDecision", out)
        self.assertIn("interpunct", out["additionalContext"])

    def test_a_warning_lets_the_call_run_and_reaches_the_agent(self):
        word = next(iter(check_module.WARN))
        out = self.decision("Write", {"file_path": "a.md", "content": f"x {word} y\n"})

        self.assertNotIn("permissionDecision", out)
        self.assertIn(word, out["additionalContext"])

    def test_clean_content_is_not_questioned(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = {
                "session_id": "test-session",
                "cwd": directory,
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": "a.md", "content": "x, y\n"},
            }
            result = run_hook(
                json.dumps(payload),
                capture_output=True,
                text=True,
                cwd=directory,
                timeout=20,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
