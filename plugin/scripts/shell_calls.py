#!/usr/bin/env python3
"""Collect shell tool attempts, results and failures as immutable Nextcloud records."""

import argparse
import hashlib
import json
import os
import platform
import re
import socket
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

SHELL_TOOLS = {"Bash", "PowerShell", "exec_command", "shell_command", "shell"}
EVENT_STAGES = {
    "PreToolUse": "attempted",
    "PostToolUse": "result",
    "PostToolUseFailure": "failure",
}


def flavor() -> str:
    if os.name == "nt":
        return "windows"
    try:
        if "microsoft" in Path("/proc/version").read_text().lower():
            return "wsl"
    except OSError:
        pass
    return sys.platform


def destination(system: str) -> Path:
    override = os.environ.get("AGENT_GUARD_SHELL_LOG_DIR")
    if override:
        return Path(override).expanduser()
    cloud = Path("/mnt/c/Users/Lev/Nextcloud") if system == "wsl" else Path.home() / "Nextcloud"
    if not cloud.is_dir():
        raise OSError("Nextcloud directory is unavailable; set AGENT_GUARD_SHELL_LOG_DIR")
    return cloud / "agent-guard" / "shell-calls"


def component(prefix: str, value: str) -> str:
    readable = re.sub(r"[^a-zA-Z0-9_-]", "_", value)[:40]
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{readable}-{digest}"


def text_field(obj: dict, *keys: str) -> str | None:
    for key in keys:
        value = obj.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def result_metadata(payload: dict, event: str) -> dict | None:
    if event == "PreToolUse":
        return None
    response = payload.get("tool_response")
    fields = response if isinstance(response, dict) else {}
    exit_code = fields.get("exit_code")
    duration = payload.get("duration_ms", fields.get("duration_ms"))
    is_error = payload.get("is_error", fields.get("is_error"))
    interrupted = payload.get("is_interrupt", fields.get("interrupted"))
    if "tool_response" not in payload:
        kind = "missing"
    elif isinstance(response, str):
        kind = "text"
    elif isinstance(response, dict):
        kind = "object"
    else:
        kind = "null" if response is None else type(response).__name__
    return {
        "response_kind": kind,
        "exit_code": exit_code if type(exit_code) is int else None,
        "duration_ms": duration if type(duration) in {int, float} else None,
        "is_error": True
        if event == "PostToolUseFailure"
        else is_error
        if isinstance(is_error, bool)
        else None,
        "is_interrupt": interrupted if isinstance(interrupted, bool) else None,
        "error": text_field(payload, "error"),
    }


def collect(payload: dict, harness: str) -> None:
    event = payload.get("hook_event_name")
    if event not in EVENT_STAGES:
        return
    if payload.get("tool_name") not in SHELL_TOOLS:
        return
    if os.environ.get("AGENT_GUARD_SHELL_LOG", "1").strip().lower() in {
        "0",
        "false",
        "off",
        "no",
    }:
        return

    system = flavor()
    hostname = socket.gethostname().lower()
    machine = os.environ.get("AGENT_GUARD_MACHINE_ID") or f"{hostname}-{system}"
    session = text_field(payload, "session_id")
    agent = text_field(payload, "agent_id")
    tool_use_id = text_field(payload, "tool_use_id", "call_id", "tool_call_id")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    command = text_field(tool_input, "command", "cmd") or text_field(payload, "command")
    hook_cwd = text_field(payload, "cwd")
    requested_workdir = text_field(tool_input, "workdir", "cwd")
    cwd = requested_workdir or hook_cwd
    cwd_source = next(
        (f"tool_input.{key}" for key in ("workdir", "cwd") if text_field(tool_input, key)),
        "payload.cwd" if hook_cwd else None,
    )
    shell = text_field(tool_input, "shell") or text_field(payload, "shell")
    shell_source = (
        "tool_input.shell"
        if text_field(tool_input, "shell")
        else "payload.shell"
        if shell
        else None
    )
    notes = []
    if session is None:
        notes.append("missing_session_id")
    if command is None:
        notes.append("missing_command")
    if cwd is None:
        notes.append("missing_cwd")
    if tool_use_id is None:
        notes.append("missing_tool_use_id")
    call_key = None
    if session is not None and tool_use_id is not None:
        identity = json.dumps([harness, machine, session, agent, tool_use_id], ensure_ascii=False)
        call_key = hashlib.sha256(identity.encode("utf-8")).hexdigest()

    now = datetime.now(UTC)
    event_id = uuid.uuid4().hex
    record = {
        "schema_version": 2,
        "event_id": event_id,
        "recorded_at": now.isoformat(timespec="microseconds"),
        "hook_event_name": event,
        "capture_stage": EVENT_STAGES[event],
        "call_key": call_key,
        "harness": harness,
        "session_id": session,
        "agent_id": agent,
        "agent_type": payload.get("agent_type"),
        "tool_use_id": tool_use_id,
        "turn_id": text_field(payload, "turn_id"),
        "prompt_id": text_field(payload, "prompt_id"),
        "model": text_field(payload, "model"),
        "permission_mode": text_field(payload, "permission_mode"),
        "transcript_path": text_field(payload, "transcript_path"),
        "tool_name": payload.get("tool_name"),
        "command": command,
        "cwd": cwd,
        "cwd_source": cwd_source,
        "hook_cwd": hook_cwd,
        "requested_workdir": requested_workdir,
        "shell": shell,
        "shell_source": shell_source,
        "requested_shell": shell,
        "result": result_metadata(payload, event),
        "machine_id": machine,
        "hostname": hostname,
        "platform": system,
        "os_release": platform.release(),
        "hook_process_cwd": str(Path.cwd()),
        "environment_hints": {
            key: os.environ[key]
            for key in ("SHELL", "COMSPEC", "MSYSTEM", "WSL_DISTRO_NAME")
            if key in os.environ
        },
        "capture_notes": notes,
        "payload": payload,
    }
    folder = (
        destination(system)
        / harness
        / component("session", session or f"missing-{event_id}")
        / component("machine", machine)
    )
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-{event_id}.json"
    content = json.dumps(record, ensure_ascii=False, indent=2) + "\n"
    scratch = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=folder, prefix=".capture-", suffix=".tmp", delete=False
        ) as handle:
            scratch = Path(handle.name)
            handle.write(content)
        os.replace(scratch, target)
    finally:
        if scratch is not None:
            scratch.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", choices=("claude-code", "codex"), required=True)
    args = parser.parse_args()
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        if isinstance(payload, dict):
            collect(payload, args.harness)
    except Exception as error:
        # Logging cannot turn an otherwise valid tool call into a denial.
        print(f"agent-guard shell-call log: {type(error).__name__}: {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
