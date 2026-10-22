"""One registry of the external tools the audit runs, and the run function."""

import os
import shutil
import subprocess
from pathlib import Path

from .process import record_python_problem
from .tools import pinned_binary, tool_version


class ExternalTool:
    """One tool the audit launches, at the version `mise.toml` pins.

    `extensions` and `baseline` are the defaults a tree keeps until it names
    its own. `own_venv` lets a tree's `.venv/bin/<tool>` run before the pin.
    `runtime` names the pinned interpreter the tool's launcher finds on PATH."""

    def __init__(self, name, extensions, baseline="", own_venv=False, runtime=None):
        self.name = name
        self.extensions = extensions
        self.baseline = baseline
        self.own_venv = own_venv
        self.runtime = runtime


EXTERNAL_TOOLS = (
    ExternalTool("complexipy", r"\.py$", "complexipy-snapshot.json", own_venv=True),
    ExternalTool("lizard", r"\.(py|ts|tsx)$", "whitelizard.txt", own_venv=True),
    ExternalTool("vulture", r"\.py$", "vulture-whitelist.py", own_venv=True),
    ExternalTool("jscpd", r"\.py$", runtime="node"),
    ExternalTool("pyscn", r"\.py$", own_venv=True),
)

_BY_NAME = {tool.name: tool for tool in EXTERNAL_TOOLS}


def _missing_pin(tool):
    """The first pin the tool needs that mise cannot name, or None."""
    for name in (tool.name, tool.runtime):
        if name is not None and pinned_binary(name) is None:
            return name
    return None


def tool_reason(tool):
    """Why the audit cannot start one tool, without the consequence."""
    if shutil.which("mise") is None:
        return f"{tool.name}: mise is not on PATH"
    pin = _missing_pin(tool) or tool.name
    subject = tool.name if pin == tool.name else f"{tool.name}: {pin}"
    return f"{subject}: pin {tool_version(pin) or 'unset'} is not installed"


def tool_problem(tool):
    """The doctor line for one tool the audit cannot start."""
    return f"{tool_reason(tool)}, so the analysis stayed silent"


def _own_venv(tool, cwd):
    """The tree's `.venv/bin/<tool>` when the tool prefers it and the file can
    run. Otherwise None."""
    if not tool.own_venv:
        return None
    own = Path(cwd) / ".venv" / "bin" / tool.name
    if own.is_file() and os.access(own, os.X_OK):
        return own
    return None


def tool_argv(name, cwd):
    """The argv that starts one tool, or None when mise cannot name its pin.

    A missing pin is recorded for doctor. The audit that called this stays
    silent."""
    tool = _BY_NAME[name]
    own = _own_venv(tool, cwd)
    if own is not None:
        return [str(own)]
    if _missing_pin(tool) is not None:
        record_python_problem(tool_problem(tool), cwd)
        return None
    return [pinned_binary(name)]


def _runtime_env(name):
    """The environment with the tool's pinned runtime first on PATH, or None
    to inherit the hook's own."""
    runtime = _BY_NAME[name].runtime
    binary = pinned_binary(runtime) if runtime else None
    if binary is None:
        return None
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([str(Path(binary).parent), env.get("PATH", "")])
    return env


def run_external(name, argv, timeout, cwd):
    """Stdout of one registry tool. A timeout or a failed start is recorded
    for doctor and returns empty, so the audit stays silent."""
    try:
        done = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=_runtime_env(name),
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except subprocess.TimeoutExpired:
        record_python_problem(
            f"{name} timed out after {timeout}s, so the analysis stayed silent", cwd
        )
        return ""
    except Exception:
        record_python_problem(f"{name} failed to start, so the analysis stayed silent", cwd)
        return ""
    if done.returncode != 0 and not (done.stdout or "").strip():
        record_python_problem(
            f"{name} exited {done.returncode} with no output, so the analysis stayed silent",
            cwd,
        )
        return ""
    return done.stdout or ""


def missing_tool_notes(enabled, cwd):
    """One doctor line per enabled tool the audit cannot start."""
    return [
        f"{tool_reason(tool)}, so {tool.name} stays silent"
        for tool in EXTERNAL_TOOLS
        if tool.name in enabled and _own_venv(tool, cwd) is None and _missing_pin(tool) is not None
    ]
