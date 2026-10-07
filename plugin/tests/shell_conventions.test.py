#!/usr/bin/env python3
"""Cases for tool_checks/shell_conventions.py, each with a PATH of only the tools it names."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECK = Path(__file__).resolve().parents[1] / "tool_checks" / "shell_conventions.py"


class ShellConventionsTests(unittest.TestCase):
    def run_check(self, command, tools):
        with tempfile.TemporaryDirectory() as bin_dir:
            for tool in tools:
                stub = Path(bin_dir) / tool
                stub.write_text("#!/bin/sh\n", encoding="utf-8")
                stub.chmod(0o755)
            return subprocess.run(
                [sys.executable, str(CHECK), "Bash"],
                input=json.dumps({"tool_input": {"command": command}}),
                capture_output=True,
                check=False,
                text=True,
                env={**os.environ, "PATH": bin_dir},
                timeout=10,
            )

    def assert_denied(self, command, tools, says):
        result = self.run_check(command, tools)
        self.assertEqual(result.returncode, 1, command)
        self.assertIn(says, result.stdout)

    def assert_allowed(self, command, tools):
        result = self.run_check(command, tools)
        self.assertEqual((result.returncode, result.stdout), (0, ""), command)

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
