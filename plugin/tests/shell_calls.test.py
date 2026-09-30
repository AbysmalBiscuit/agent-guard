"""Run shell-call collection through its stdin hook entry point."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "shell_calls.py"


class ShellCallsTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.logs = self.root / "Nextcloud" / "agent-guard" / "shell-calls"
        self.env = {
            **os.environ,
            "AGENT_GUARD_SHELL_LOG_DIR": str(self.logs),
            "AGENT_GUARD_SHELL_LOG": "1",
            "AGENT_GUARD_MACHINE_ID": "test-machine",
        }

    def invoke(self, payload, harness="claude-code", env=None):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--harness", harness],
            input=json.dumps(payload),
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            env=env or self.env,
            cwd=self.root,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == ""
        return result

    def records(self):
        return [json.loads(p.read_text(encoding="utf-8")) for p in self.logs.rglob("*.json")]

    def payload(self, command="printf 'hello\\n'") -> dict[str, object]:
        return {
            "hook_event_name": "PreToolUse",
            "session_id": "12345678-aaaa-bbbb-cccc-123456789abc",
            "agent_id": "child-1",
            "agent_type": "researcher",
            "tool_name": "Bash",
            "tool_use_id": "call-1",
            "cwd": "/repo",
            "tool_input": {"command": command, "timeout": 30000},
        }

    def test_full_multiline_command_and_context_survive_without_execution(self):
        command = f"printf 'bad' > '{self.root / 'must-not-exist'}'\n" + "# ü 漢\n" * 20000
        payload = self.payload(command)
        self.invoke(payload)
        records = self.records()
        assert len(records) == 1
        row = records[0]
        assert row["command"] == command
        assert row["session_id"] == "12345678-aaaa-bbbb-cccc-123456789abc"
        assert row["agent_id"] == "child-1"
        assert row["tool_use_id"] == "call-1"
        assert row["cwd"] == "/repo"
        assert row["harness"] == "claude-code"
        assert row["payload"] == payload
        assert not (self.root / "must-not-exist").exists()

    def test_codex_native_and_normalized_payloads_preserve_execution_options(self):
        for tool, tool_input in [
            (
                "exec_command",
                {
                    "cmd": "echo hi",
                    "workdir": "/other",
                    "shell": "/bin/bash",
                    "login": False,
                    "tty": True,
                },
            ),
            ("Bash", {"command": "echo hi", "timeout": 1000}),
            ("shell_command", {"command": "Write-Output hi", "workdir": "C:\\repo"}),
        ]:
            with self.subTest(tool=tool):
                payload = self.payload()
                payload["tool_name"] = tool
                payload["tool_input"] = tool_input
                self.invoke(payload, "codex")
        rows = self.records()
        assert len(rows) == 3
        by_tool = {r["tool_name"]: r for r in rows}
        assert by_tool["exec_command"]["cwd"] == "/other"
        assert by_tool["exec_command"]["payload"]["tool_input"]["login"] is False
        assert by_tool["shell_command"]["cwd"] == "C:\\repo"
        assert all(r["harness"] == "codex" for r in rows)

    def test_resumes_keep_session_folder_and_parallel_calls_do_not_overwrite(self):
        payload = self.payload()
        self.invoke(payload)
        original_parent = next(self.logs.rglob("*.json")).parent
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda _: self.invoke(payload), range(18)))
        paths = list(self.logs.rglob("*.json"))
        assert len(paths) == 19
        assert {p.parent for p in paths} == {original_parent}
        assert len({r["event_id"] for r in self.records()}) == 19

    def test_machine_and_harness_partition_same_session(self):
        self.invoke(self.payload())
        self.invoke(self.payload(), "codex")
        self.invoke(self.payload(), env={**self.env, "AGENT_GUARD_MACHINE_ID": "other-machine"})
        assert len({p.parent for p in self.logs.rglob("*.json")}) == 3

    def test_session_directories_remain_distinct_on_case_insensitive_filesystems(self):
        for session in ["ABC", "abc"]:
            payload = self.payload()
            payload["session_id"] = session
            self.invoke(payload)
        assert len({str(p.parent).lower() for p in self.logs.rglob("*.json")}) == 2

    def test_non_shell_unrelated_events_and_disabled_capture_do_not_log(self):
        edit = self.payload()
        edit["tool_name"] = "Write"
        self.invoke(edit)
        post = self.payload()
        post["hook_event_name"] = "SessionStart"
        self.invoke(post)
        self.invoke(self.payload(), env={**self.env, "AGENT_GUARD_SHELL_LOG": "0"})
        assert self.records() == []

    def test_codex_pre_and_post_pair_across_turns_without_inventing_success(self):
        pre = self.payload("Write-Output 'ü 漢'")
        pre.update(turn_id="turn-before", model="test-model", permission_mode="default")
        self.invoke(pre, "codex")
        post = {**pre, "hook_event_name": "PostToolUse", "turn_id": "turn-after"}
        post["tool_response"] = "ü 漢\n" * 20000
        self.invoke(post, "codex")
        rows = {row.get("hook_event_name"): row for row in self.records()}
        assert len(rows) == 2
        before, after = rows["PreToolUse"], rows["PostToolUse"]
        assert before["schema_version"] == after["schema_version"] == 2
        assert before["capture_stage"] == "attempted"
        assert after["capture_stage"] == "result"
        assert before["event_id"] != after["event_id"]
        assert before["call_key"] == after["call_key"]
        assert len(before["call_key"]) == 64
        assert before["turn_id"] == "turn-before"
        assert after["turn_id"] == "turn-after"
        assert after["model"] == "test-model"
        assert after["permission_mode"] == "default"
        assert after["payload"] == post
        assert after["result"]["response_kind"] == "text"
        assert after["result"]["exit_code"] is None
        assert after["result"]["is_error"] is None
        assert after["result"]["duration_ms"] is None

    def test_claude_powershell_failure_keeps_error_and_interrupt_metadata(self):
        payload = self.payload("Get-Content missing.txt")
        payload.update(
            hook_event_name="PostToolUseFailure",
            tool_name="PowerShell",
            error="Exit code 1\nfile not found",
            is_interrupt=False,
            duration_ms=42,
        )
        self.invoke(payload)
        assert len(self.records()) == 1
        row = self.records()[0]
        assert row["capture_stage"] == "failure"
        assert row["result"]["error"] == payload["error"]
        assert row["result"]["is_error"] is True
        assert row["result"]["is_interrupt"] is False
        assert row["result"]["duration_ms"] == 42
        assert row["result"]["exit_code"] is None
        assert row["payload"] == payload
        assert row["shell"] is None

    def test_context_fields_preserve_provenance_and_explicit_result_values(self):
        payload = self.payload()
        payload.update(
            hook_event_name="PostToolUse",
            transcript_path="/transcript.jsonl",
            prompt_id="prompt-1",
            tool_input={"cmd": "echo hi", "workdir": "../other", "shell": "pwsh", "login": False},
            tool_response={"stdout": "hi", "stderr": "", "exit_code": 0, "interrupted": False},
        )
        self.invoke(payload, "codex")
        assert len(self.records()) == 1
        row = self.records()[0]
        assert row["hook_cwd"] == "/repo"
        assert row["cwd"] == "../other"
        assert row["cwd_source"] == "tool_input.workdir"
        assert row["requested_workdir"] == "../other"
        assert row["shell"] == row["requested_shell"] == "pwsh"
        assert row["shell_source"] == "tool_input.shell"
        assert row["transcript_path"] == "/transcript.jsonl"
        assert row["prompt_id"] == "prompt-1"
        assert row["result"]["exit_code"] == 0
        assert row["result"]["is_interrupt"] is False
        assert row["result"]["response_kind"] == "object"

    def test_call_key_distinguishes_agents_and_requires_session_and_call_id(self):
        for agent in ("child-1", "child-2"):
            payload = self.payload()
            payload["agent_id"] = agent
            self.invoke(payload)
        assert len({row.get("call_key") for row in self.records()}) == 2
        payload = self.payload()
        del payload["tool_use_id"]
        self.invoke(payload)
        row = next(row for row in self.records() if row["tool_use_id"] is None)
        assert row["call_key"] is None
        assert "missing_tool_use_id" in row["capture_notes"]

    def test_unsafe_ids_cannot_escape_the_log_directory(self):
        payload = self.payload()
        payload["session_id"] = "../../outside"
        self.invoke(payload, env={**self.env, "AGENT_GUARD_MACHINE_ID": "C:\\CON/../"})
        assert len(self.records()) == 1
        assert self.records()[0]["session_id"] == "../../outside"
        assert not (self.root / "outside").exists()

    def test_missing_session_and_command_are_recorded_as_missing(self):
        payload = self.payload()
        del payload["session_id"]
        payload["tool_input"] = {"unexpected": "new harness shape"}
        self.invoke(payload)
        row = self.records()[0]
        assert row["session_id"] is None
        assert row["command"] is None
        assert "missing_session_id" in row["capture_notes"]
        assert "missing_command" in row["capture_notes"]

    def test_unwritable_destination_and_bad_payload_never_deny(self):
        self.logs.parent.mkdir(parents=True)
        self.logs.write_text("not a directory", encoding="utf-8")
        result = self.invoke(self.payload())
        assert "shell-call log" in result.stderr
        for raw in ["{", "[]", "null", "[" * 2000 + "0" + "]" * 2000]:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--harness", "codex"],
                input=raw,
                capture_output=True,
                check=False,
                text=True,
                env=self.env,
                timeout=10,
            )
            assert result.returncode == 0, result.stderr
            assert result.stdout == ""


if __name__ == "__main__":
    unittest.main()
