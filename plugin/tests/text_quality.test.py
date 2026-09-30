#!/usr/bin/env python3
"""Cases for tool_checks/text_quality.py.

Which half of a call is read matters most: the text a call adds is checked and
the text it removes is not, or the rule would refuse the very edit that takes
an em dash back out. After that, each tier's exit code has to survive the trip
through the hook and reach the harness as the decision it stands for. Every
character under test is written as an escape, so this file is ASCII.
"""

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parent.parent
CHECK = ROOT / "tool_checks" / "text_quality.py"
GUARD = ROOT / "scripts" / "agent_guard.py"

EM_DASH = "\u2014"
EN_DASH = "\u2013"
INTERPUNCT = "\u00b7"

ASK_EXIT = 2


def load_check():
    """The check as a module, for its rules and its judge."""
    spec = importlib.util.spec_from_file_location("check_under_test", CHECK)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(tool, tool_input):
    payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}
    result = subprocess.run(
        [sys.executable, str(CHECK), tool],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return result.stdout.strip(), result.returncode


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
        module = load_check()
        for key in rules(module):
            with self.subTest(rule=module.label(key)):
                out, code = check("Write", {"content": f"a {key} b"})

                self.assertEqual(code, expected_code)
                self.assertIn(module.label(key), out)

    def test_every_refused_rule_is_denied_by_name(self):
        self.assert_tier(lambda module: module.REFUSE, 1)

    def test_every_asked_rule_reaches_the_human(self):
        self.assert_tier(lambda module: module.ASK, ASK_EXIT)

    def test_every_warned_rule_runs_and_says_why(self):
        self.assert_tier(lambda module: module.WARN, 0)


class RuleValues(unittest.TestCase):
    def test_a_plain_value_is_the_swap_the_agent_is_told_to_make(self):
        module = load_check()
        module.WARN["utilize"] = "use"

        message, code = module.judge("we utilize it")

        self.assertEqual(code, 0)
        self.assertIn('"utilize"', message)
        self.assertIn("Write `use` instead.", message)

    def test_matching_ignores_case(self):
        module = load_check()
        module.WARN["frobnicate"] = "poke"

        message, code = module.judge("Frobnicate it first")

        self.assertEqual(code, 0)
        self.assertIn("Write `poke` instead.", message)
        self.assertIn("Frobnicate it first", message)

    def test_an_empty_value_says_to_delete(self):
        module = load_check()
        module.WARN["very"] = ""

        message, _ = module.judge("a very big deal")

        self.assertIn("Delete it.", message)

    def test_an_explained_value_is_read_as_written(self):
        module = load_check()
        module.WARN["utilize"] = module.Explain("Say what it does instead.")

        message, _ = module.judge("we utilize it")

        self.assertIn("Say what it does instead.", message)
        self.assertNotIn("Write `", message)


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
            result = subprocess.run(
                [sys.executable, str(GUARD)],
                input=json.dumps(payload),
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
        word = next(iter(load_check().WARN))
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
            result = subprocess.run(
                [sys.executable, str(GUARD)],
                input=json.dumps(payload),
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
