#!/usr/bin/env python3
"""Cases for agent_guard.checks.rg_replace_footgun."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_guard.checks.rg_replace_footgun import check


def verdict(command):
    return check({"tool_name": "Bash", "tool_input": {"command": command}})


class RgReplaceFootgunTests(unittest.TestCase):
    def test_rg_exe_is_refused_like_rg(self):
        plain = verdict("rg -rn foo")
        for command in ("rg.exe -rn foo", "RG.EXE -rn foo", "C:/tools/rg.exe -rn foo"):
            with self.subTest(command=command):
                got = verdict(command)
                self.assertEqual(got.permission, "deny")
                self.assertEqual(got.permission, plain.permission)
                self.assertIn("'-rn'", got.context)

    def test_a_spaced_replace_and_a_quoted_mention_pass(self):
        for command in ("rg -r 'text' PAT", "rg --replace text PAT", 'git commit -m "rg -rn foo"'):
            with self.subTest(command=command):
                self.assertEqual(verdict(command).permission, "allow")

    def test_a_heredoc_body_is_not_a_command(self):
        self.assertEqual(verdict("cat <<EOF\nrg -rn foo\nEOF").permission, "allow")

    def test_empty_and_blank_stay_silent(self):
        for command in ("", "   ", "   \n  "):
            with self.subTest(command=command):
                self.assertEqual(verdict(command).permission, "allow")


if __name__ == "__main__":
    unittest.main()
