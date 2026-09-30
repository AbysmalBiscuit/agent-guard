#!/usr/bin/env python3
"""Codex hook compatibility cases. Run directly: python3 <this file>."""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

PLUGIN_ROOT = pathlib.Path(__file__).parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "agent_guard.py"


class CodexCompatibilityTests(unittest.TestCase):
    def test_apply_patch_payload_scans_each_written_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first.md"
            second = root / "second.md"
            first.write_text(("x" * 60 + "\n") * 3, encoding="utf-8")
            second.write_text(("y" * 60 + "\n") * 3, encoding="utf-8")
            payload = {
                "session_id": "test-session",
                "turn_id": "test-turn",
                "cwd": str(root),
                "hook_event_name": "PostToolUse",
                "tool_name": "apply_patch",
                "tool_input": {
                    "command": (
                        "*** Begin Patch\n"
                        "*** Add File: first.md\n"
                        "+content\n"
                        "*** Add File: second.md\n"
                        "+content\n"
                        "*** End Patch"
                    )
                },
                "tool_response": "Done!",
                "model": "gpt-test",
            }

            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--codex"],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                cwd=root,
                timeout=15,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("first.md", context)
        self.assertIn("second.md", context)

    def test_codex_stop_block_uses_continuation_decision(self):
        output = self.run_stop_hook("Stop", block=True)

        self.assertEqual(output["decision"], "block")
        self.assertIn("project violation", output["reason"])

    def test_codex_stop_advice_uses_system_message(self):
        output = self.run_stop_hook("SubagentStop", block=False)

        self.assertIn("project violation", output["systemMessage"])

    def run_stop_hook(self, event, block):
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
            payload = {
                "session_id": f"test-{event}-{block}",
                "turn_id": "test-turn",
                "cwd": str(root),
                "hook_event_name": event,
                "model": "gpt-test",
                "stop_hook_active": False,
            }
            if event == "SubagentStop":
                payload.update(
                    {
                        "agent_id": "test-agent",
                        "agent_type": "worker",
                        "agent_transcript_path": None,
                    }
                )
            env = os.environ.copy()
            env["XDG_STATE_HOME"] = str(root / "state")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--codex"],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                cwd=root,
                env=env,
                timeout=15,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout, "hook returned no output")
        return json.loads(result.stdout)


if __name__ == "__main__":
    unittest.main()
