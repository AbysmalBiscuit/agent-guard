#!/usr/bin/env python3
"""Grok Build hook compatibility cases. Run directly: python3 <this file>."""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from hook_support import PLUGIN_ROOT, run_hook

EN_DASH = chr(0x2013)


def grok_payload(event, cwd, **fields):
    """An event as Grok serializes it: camelCase keys, the snake_case aliases it
    adds for Claude hooks, and `hook_event_name` carrying Claude's spelling."""
    snake = {
        "hookEventName": "hook_event_name",
        "sessionId": "session_id",
        "toolName": "tool_name",
        "toolInput": "tool_input",
    }
    payload = {
        "hookEventName": "".join("_" + c.lower() if c.isupper() else c for c in event)[1:],
        "sessionId": f"grok-{event}",
        "cwd": str(cwd),
        "workspaceRoot": str(cwd),
        "timestamp": "2026-10-12T12:00:00Z",
        "permissionMode": "default",
        **fields,
    }
    for camel, alias in snake.items():
        if camel in payload:
            payload[alias] = payload[camel]
    payload["hook_event_name"] = event
    return payload


def invoke(payload, cwd):
    env = os.environ.copy()
    env["XDG_STATE_HOME"] = str(pathlib.Path(cwd) / "state")
    return run_hook(
        json.dumps(payload),
        args=("--grok",),
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        timeout=15,
    )


class GrokToolTests(unittest.TestCase):
    def test_terminal_command_reaches_shell_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = grok_payload(
                "PreToolUse",
                directory,
                toolName="run_terminal_command",
                toolUseId="call-1",
                toolInput={"command": "rg -rn foo src", "description": "search"},
                toolInputTruncated=False,
            )
            result = invoke(payload, directory)

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("--replace", output["permissionDecisionReason"])

    def test_former_script_path_still_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = grok_payload(
                "PreToolUse",
                directory,
                toolName="run_terminal_command",
                toolInput={"command": "rg -rn foo src", "description": "search"},
            )
            env = os.environ.copy()
            env["XDG_STATE_HOME"] = str(pathlib.Path(directory) / "state")
            result = subprocess.run(
                [sys.executable, str(PLUGIN_ROOT / "scripts" / "agent_guard.py"), "--grok"],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                cwd=directory,
                env=env,
                timeout=15,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")

    def test_search_replace_reaches_edit_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = grok_payload(
                "PreToolUse",
                directory,
                toolName="search_replace",
                toolUseId="call-2",
                toolInput={
                    "file_path": str(pathlib.Path(directory) / "notes.md"),
                    "old_string": "pages 3 to 5",
                    "new_string": f"pages 3{EN_DASH}5",
                },
                toolInputTruncated=False,
            )
            result = invoke(payload, directory)

        self.assertEqual(result.returncode, 0, result.stderr)
        context = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("3 to 5", context)


class GrokStopTests(unittest.TestCase):
    def test_stop_advice_does_not_keep_the_agent_working(self):
        output = json.loads(self.run_stop_hook("Stop", block=False))

        self.assertNotIn("hookSpecificOutput", output)
        self.assertIn("project violation", output["systemMessage"])

    def test_subagent_stop_block_uses_continuation_decision(self):
        output = json.loads(self.run_stop_hook("SubagentStop", block=True))

        self.assertEqual(output["decision"], "block")
        self.assertIn("project violation", output["reason"])

    def test_session_end_stop_is_skipped(self):
        output = self.run_stop_hook("Stop", block=True, reason="shutdown")

        self.assertEqual(output, "")

    def run_stop_hook(self, event, block, reason="end_turn"):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
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
            (guard / "config.toml").write_text(
                f"block = {str(block).lower()}\nfallow = false\n",
                encoding="utf-8",
            )
            (checks / "project-rule.py").write_text(
                'print("project violation")\n', encoding="utf-8"
            )
            if event == "Stop":
                fields = {"reason": reason, "stopHookActive": False}
            else:
                fields = {
                    "phase": "gate",
                    "subagentId": "agent-1",
                    "subagentType": "explore",
                    "stopHookActive": False,
                }
            result = invoke(grok_payload(event, root, **fields), root)

        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout


if __name__ == "__main__":
    unittest.main()
