#!/usr/bin/env python3
"""Stop-hook cases for the file-length changeset check."""

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from hook_support import PLUGIN_ROOT as PLUGIN
from hook_support import run_hook

WARN_MESSAGE = "split this file by responsibility, and move tests into focused files"
BLOCK_MESSAGE = "split this file by responsibility, and move tests into focused files"


def commit_all(root, message):
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Agent Guard Test",
            "-c",
            "user.email=agent-guard@example.com",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            message,
        ],
        cwd=root,
        check=True,
    )


def init_repo(root):
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "agent-guard@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Agent Guard Test"], cwd=root, check=True)


def stop_hook(root, session="test-session", extra_env=None):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AGENT_GUARD_"):
            env.pop(key)
    env["HOME"] = str(root / "home")
    env["AGENT_GUARD_CONFIG_DIR"] = str(PLUGIN)
    env["AGENT_GUARD_LOG"] = "0"
    env["XDG_STATE_HOME"] = str(root / "state")
    if extra_env:
        env.update(extra_env)
    payload = {
        "session_id": session,
        "cwd": str(root),
        "hook_event_name": "Stop",
    }
    return run_hook(
        json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=root,
        env=env,
        timeout=30,
    )


def enable(root, body):
    nearer = root / ".agents" / "plugins" / "agent-guard"
    nearer.mkdir(parents=True)
    (nearer / "config.toml").write_text(body, encoding="utf-8")


def write_lines(path, count):
    path.write_text("".join(f"line {number}\n" for number in range(1, count + 1)), encoding="utf-8")


def length_config(warn_message="", block_message="", extra=""):
    messages = ""
    if warn_message:
        messages += f'warn_message = "{warn_message}"\n'
    if block_message:
        messages += f'block_message = "{block_message}"\n'
    return f"""\
fallow = false
block = true

[file_length]
enabled = true
{messages}
[[file_length.limits]]
extensions = '\\.py$'
warn = 4
block_lines = 8
{extra}"""


ON = length_config()


def context_of(result):
    payload = json.loads(result.stdout)
    return payload["hookSpecificOutput"]["additionalContext"]


class FileLengthTests(unittest.TestCase):
    def test_a_long_changed_file_stays_silent_when_the_check_is_off(self):
        """The check is off until a tree turns it on. A changed file past both
        limits, a blank file, a path of only spaces, and an untracked notes.txt
        all stay silent."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "short.py", 2)
            commit_all(root, "base")
            write_lines(root / "long.py", 1200)
            (root / "blank.py").write_text("   \n", encoding="utf-8")
            (root / "   ").write_text("x\n", encoding="utf-8")
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_a_file_past_warn_warns_and_one_past_block_blocks(self):
        """A changed file above the warn limit warns, and one above the block
        limit blocks. Both use the default messages. A file at the warn limit
        stays quiet, and a file the branch did not change stays quiet."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "old.py", 20)
            commit_all(root, "base")
            write_lines(root / "at_warn.py", 4)
            write_lines(root / "warn.py", 5)
            write_lines(root / "block.py", 9)
            enable(root, ON)

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        specific = output["hookSpecificOutput"]
        self.assertEqual(specific["permissionDecision"], "deny")
        report = specific["additionalContext"]
        self.assertIn("warn.py", report)
        self.assertIn("5 lines", report)
        self.assertIn(WARN_MESSAGE, report)
        self.assertIn("block.py", report)
        self.assertIn("9 lines", report)
        self.assertIn(BLOCK_MESSAGE, report)
        self.assertNotIn("at_warn.py", report)
        self.assertNotIn("old.py", report)
        self.assertIn(BLOCK_MESSAGE, specific["permissionDecisionReason"])

    def test_a_project_message_replaces_the_default(self):
        """A tree's warn and block messages replace the defaults on both the
        report and the refusal."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "warn.py", 5)
            write_lines(root / "block.py", 9)
            enable(
                root,
                length_config(
                    "move the extra helpers out",
                    "this file is past the block line",
                ),
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        report = specific["additionalContext"]
        self.assertIn("move the extra helpers out", report)
        self.assertIn("this file is past the block line", report)
        self.assertNotIn(WARN_MESSAGE, report)
        self.assertNotIn(BLOCK_MESSAGE, report)
        self.assertIn("this file is past the block line", specific["permissionDecisionReason"])
        self.assertNotIn(BLOCK_MESSAGE, specific["permissionDecisionReason"])

    def test_a_path_limit_applies_and_an_accepted_file_fails_only_when_it_grows(self):
        """A path limit and a glob limit replace the type limit for those files.
        An accepted file stays quiet at its recorded size and blocks once it
        grows past that size. A blank path and an unmatched glob stay quiet."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            src = root / "src"
            src.mkdir()
            write_lines(src / "app.py", 6)
            write_lines(src / "kept.py", 6)
            write_lines(src / "grown.py", 7)
            write_lines(root / "plain.py", 6)
            (root / "   .py").write_text("x\n", encoding="utf-8")
            enable(
                root,
                length_config(
                    extra="""\
[[file_length.limits]]
pattern = "src/app.py"
warn = 10
block_lines = 20

[[file_length.limits]]
pattern = "src/*.py"
accept = true
lines = 6
"""
                ),
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        report = specific["additionalContext"]
        self.assertIn("plain.py", report)
        self.assertIn("grown.py", report)
        self.assertIn("accepted at 6", report)
        self.assertNotIn("app.py", report)
        self.assertNotIn("kept.py", report)
        self.assertNotIn("   .py", report)
        self.assertEqual(specific["permissionDecision"], "deny")

    def test_block_false_reports_the_block_level_without_refusing(self):
        """The block level still names the file when the global block setting
        is off. Stop finishes, and the report keeps the default block message."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "block.py", 9)
            (root / "blank.py").write_text("\n", encoding="utf-8")
            enable(root, ON.replace("block = true\n", "block = false\n", 1))

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", specific)
        report = specific["additionalContext"]
        self.assertIn("block.py", report)
        self.assertIn("9 lines", report)
        self.assertIn(BLOCK_MESSAGE, report)
        self.assertNotIn("blank.py", report)

    def test_a_blank_message_keeps_the_default(self):
        """A blank override is not a message. The default stays, and a broken
        extension regex, an empty limits list, and an untracked notes.txt stay
        silent beside a file the check does report."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "block.py", 9)
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
            enable(
                root,
                length_config(extra="").replace(
                    "enabled = true\n",
                    "enabled = true\nwarn_message = ''\nblock_message = '   '\n",
                    1,
                ),
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn(BLOCK_MESSAGE, report)
        self.assertNotIn("notes.txt", report)


if __name__ == "__main__":
    unittest.main()
