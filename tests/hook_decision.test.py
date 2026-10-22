#!/usr/bin/env python3
"""Each tier answers through the package entry point. Run directly: python3 <this file>."""

import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import uuid

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parent.parent / "plugin"
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

# Read before the package resolves its state directory.
os.environ["XDG_STATE_HOME"] = tempfile.mkdtemp(prefix="agent-guard-decisions-")

from agent_guard import decide  # noqa: E402
from agent_guard.__main__ import main  # noqa: E402


def event(name, tool, tool_input, cwd, **fields):
    return {
        "hook_event_name": name,
        "session_id": f"in-process-{name}-{tool}",
        "cwd": str(cwd),
        "tool_name": tool,
        "tool_input": tool_input,
        **fields,
    }


def blocking_changeset(root):
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    (root / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "add", "seed.txt"], cwd=root, check=True)
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
            "seed",
        ],
        cwd=root,
        check=True,
    )
    guard = root / ".agents" / "plugins" / "agent-guard"
    checks = guard / "changeset_checks"
    checks.mkdir(parents=True)
    (guard / "config.toml").write_text("block = true\nfallow = false\n", encoding="utf-8")
    (checks / "project-rule.py").write_text('print("project violation")\n', encoding="utf-8")


def run_main(argv, source, stdout=None):
    out = io.StringIO() if stdout is None else stdout
    with contextlib.redirect_stdout(out):
        code = main(argv, source)
    printed = out.getvalue() if hasattr(out, "getvalue") else ""
    return code, printed


class HookDecisionTests(unittest.TestCase):
    def test_mandatory_tier_returns_a_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            decision = decide(
                event("PreToolUse", "Bash", {"command": "age -d secrets.age"}, directory)
            )

        self.assertEqual(decision.permission, "deny")
        self.assertIn("Decrypting secrets", decision.context)

    def test_tool_check_tier_returns_a_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            decision = decide(
                event(
                    "PreToolUse",
                    "Bash",
                    {"command": "rg -rn foo src", "description": "search"},
                    directory,
                )
            )

        self.assertEqual(decision.permission, "deny")
        self.assertIn("--replace", decision.context)

    def test_per_file_tier_returns_the_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            target = root / "notes.py"
            # Four stacked comments are a warning. The file is untracked, so
            # every line counts as the branch's own.
            target.write_text("# narration\n" * 4 + "value = 1\n", encoding="utf-8")
            decision = decide(
                event(
                    "PostToolUse",
                    "Write",
                    {"file_path": str(target), "content": target.read_text(encoding="utf-8")},
                    root,
                )
            )

        self.assertEqual(decision.permission, "allow")
        self.assertIn("comment-length", decision.context)
        self.assertIn("notes.py", decision.context)

    def test_changeset_tier_returns_a_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            blocking_changeset(root)
            # The worktree's own untracked files are present beside this temp
            # checkout. The payload cwd keeps the audit on the temp tree.
            decision = decide(
                event(
                    "Stop",
                    "",
                    {},
                    root,
                    session_id=f"changeset-{uuid.uuid4()}",
                    stop_hook_active=False,
                ),
            )

        self.assertEqual(decision.permission, "deny")
        self.assertIn("project violation", decision.context)
        self.assertIn("violates a rule", decision.reason)

    def test_empty_blank_and_failing_input_stay_silent(self):
        class Blank:
            def read(self):
                return "   \n"

        class Broken:
            def read(self):
                return "{not json"

        class EmptyObject:
            def read(self):
                return "{}"

        class ListPayload:
            def read(self):
                return "[]"

        for argv, source in (
            ([], Blank()),
            (["--codex"], Broken()),
            (["--grok"], EmptyObject()),
            ([], ListPayload()),
        ):
            with self.subTest(argv=argv):
                code, printed = run_main(argv, source)
                self.assertEqual(code, 0)
                self.assertEqual(printed, "")
        self.assertEqual(
            decide(
                {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}
            ).permission,
            "allow",
        )
        self.assertEqual(decide("not-an-event").permission, "allow")

    def test_positional_event_overrides_the_payload_before_translation(self):
        # The payload names PostToolUse. The positional name wins first, so
        # the mandatory tier still sees a shell call and denies it.
        with tempfile.TemporaryDirectory() as directory:
            code, printed = run_main(
                ["PreToolUse"],
                io.StringIO(
                    json.dumps(
                        {
                            "hook_event_name": "PostToolUse",
                            "session_id": "override",
                            "cwd": directory,
                            "tool_name": "Bash",
                            "tool_input": {"command": "age -d secrets.age"},
                        }
                    )
                ),
            )

        self.assertEqual(code, 0)
        output = json.loads(printed)["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("Decrypting secrets", output["additionalContext"])

    def test_a_stdout_error_stays_silent(self):
        class Closed:
            def write(self, _text):
                raise OSError("stdout closed")

            def flush(self):
                raise OSError("stdout closed")

        with tempfile.TemporaryDirectory() as directory:
            code, _printed = run_main(
                [],
                io.StringIO(
                    json.dumps(
                        {
                            "hook_event_name": "PreToolUse",
                            "session_id": "stdout",
                            "cwd": directory,
                            "tool_name": "Bash",
                            "tool_input": {"command": "age -d secrets.age"},
                        }
                    )
                ),
                stdout=Closed(),
            )

        self.assertEqual(code, 0)

    def test_grok_teardown_writes_nothing(self):
        # Grok fires Stop at session teardown and ignores the answer. The
        # adapter yields no event, so the process entry writes nothing even
        # when the payload would otherwise block.
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            blocking_changeset(root)
            code, printed = run_main(
                ["--grok"],
                io.StringIO(
                    json.dumps(
                        {
                            "hook_event_name": "Stop",
                            "reason": "shutdown",
                            "session_id": f"teardown-{uuid.uuid4()}",
                            "cwd": str(root),
                            "stop_hook_active": False,
                        }
                    )
                ),
            )

        self.assertEqual(code, 0)
        self.assertEqual(printed, "")


if __name__ == "__main__":
    unittest.main()
