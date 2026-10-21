#!/usr/bin/env python3
"""Cases for agent_guard.checks.shell_conventions, each with a PATH of only the tools it names."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_guard.checks.shell_conventions import check


class ShellConventionsTests(unittest.TestCase):
    def run_check(self, command, tools):
        with tempfile.TemporaryDirectory() as bin_dir:
            for tool in tools:
                stub = Path(bin_dir) / tool
                stub.write_text("#!/bin/sh\n", encoding="utf-8")
                stub.chmod(0o755)
            saved = os.environ.get("PATH")
            os.environ["PATH"] = bin_dir
            try:
                return check({"tool_name": "Bash", "tool_input": {"command": command}})
            finally:
                if saved is None:
                    os.environ.pop("PATH", None)
                else:
                    os.environ["PATH"] = saved

    def assert_denied(self, command, tools, says):
        verdict = self.run_check(command, tools)
        self.assertEqual(verdict.permission, "deny", command)
        self.assertIn(says, verdict.context)

    def assert_allowed(self, command, tools):
        verdict = self.run_check(command, tools)
        self.assertEqual((verdict.permission, verdict.context), ("allow", ""), command)

    def test_find_and_ls_recursive_need_fd(self):
        for command in ("find . -name '*.py'", "ls -R src"):
            self.assert_denied(command, ["fd"], "fd")
            self.assert_allowed(command, ["rg"])

    def test_grep_over_files_needs_rg(self):
        for command in ("grep -r TODO src", "cat a.py | grep TODO"):
            self.assert_denied(command, ["rg"], "rg")
            self.assert_allowed(command, ["fd"])

    def test_rg_files_pipeline_needs_fd(self):
        self.assert_denied("rg --files | rg test", ["rg", "fd"], "fd")
        self.assert_allowed("rg --files | rg test", ["rg"])

    def test_git_stash_denied_without_search_tools(self):
        self.assert_denied("git stash", [], "git stash")


if __name__ == "__main__":
    unittest.main()
