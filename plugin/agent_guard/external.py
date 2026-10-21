"""One registry of the external tools the audit runs, and the run function."""

import os
import shutil
import subprocess
from pathlib import Path

from .process import record_python_problem
from .tools import TOOL_IDS, pinned_binary, tool_version


class Launcher:
    """How one runner starts a pinned tool.

    `own_venv` lets a tree's `.venv/bin/<tool>` run before the launcher."""

    def __init__(self, name, label, argv, own_venv=False):
        self.name = name
        self.label = label
        self.argv = argv
        self.own_venv = own_venv

    def command(self, binary, tool):
        return [binary, *self.argv(tool)]


def _uvx_argv(tool):
    return ["--from", f"{tool.name}=={tool.version}", tool.name]


def _bunx_argv(tool):
    return ["--bun", f"{tool.name}@{tool.version}"]


UVX = Launcher("uvx", "uv", _uvx_argv, own_venv=True)
BUNX = Launcher("bunx", "bunx", _bunx_argv)


class ExternalTool:
    """One tool the audit launches.

    `extensions` and `baseline` are the defaults a tree keeps until it names
    its own."""

    def __init__(self, name, version, launcher, extensions, baseline=""):
        self.name = name
        self.version = version
        self.launcher = launcher
        self.extensions = extensions
        self.baseline = baseline


EXTERNAL_TOOLS = (
    ExternalTool(
        "complexipy", tool_version("complexipy"), UVX, r"\.py$", "complexipy-snapshot.json"
    ),
    ExternalTool("lizard", tool_version("lizard"), UVX, r"\.(py|ts|tsx)$", "whitelizard.txt"),
    ExternalTool("vulture", tool_version("vulture"), UVX, r"\.py$", "vulture-whitelist.py"),
    ExternalTool("jscpd", tool_version("jscpd"), BUNX, r"\.py$"),
    ExternalTool("pyscn", tool_version("pyscn"), UVX, r"\.py$"),
)

_BY_NAME = {tool.name: tool for tool in EXTERNAL_TOOLS}


def _launcher_override(launcher):
    raw = os.environ.get("AGENT_GUARD_LAUNCHERS") or ""
    for item in raw.split(","):
        key, sep, value = item.partition("=")
        if sep and key.strip() == launcher.name:
            return value.strip()
    return None


def _launcher_path(tool):
    override = _launcher_override(tool.launcher)
    if override is not None:
        path = Path(override)
        return str(path) if path.is_file() and os.access(path, os.X_OK) else None
    return shutil.which(tool.launcher.name)


def tool_reason(tool):
    """Why the audit cannot start one tool, without the consequence."""
    name = tool.name
    if _launcher_override(tool.launcher) is not None or name not in TOOL_IDS:
        return f"{name}: {tool.launcher.label} is not on PATH"
    if shutil.which("mise") is None:
        return f"{name}: mise is not on PATH"
    pin = tool_version(name) or "unset"
    return f"{name}: pin {pin} is not installed"


def tool_problem(tool):
    """The doctor line for one tool the audit cannot start."""
    return f"{tool_reason(tool)}, so the analysis stayed silent"


def tool_binary(tool):
    """The binary the audit runs for one registry tool.

    The mise pin wins over a copy earlier on PATH. A launcher override wins
    over the pin, so a test can point the launcher at a stand-in."""
    if _launcher_override(tool.launcher) is not None:
        return _launcher_path(tool)
    return pinned_binary(tool.name)


def _own_venv(tool, cwd):
    """The tree's `.venv/bin/<tool>` when that launcher prefers it and the
    file can run. Otherwise None."""
    if not tool.launcher.own_venv:
        return None
    own = Path(cwd) / ".venv" / "bin" / tool.name
    if own.is_file() and os.access(own, os.X_OK):
        return own
    return None


def tool_argv(name, cwd):
    """The argv that starts one tool, or None when its launcher cannot start.

    A missing launcher is recorded for doctor. The audit that called this
    stays silent."""
    tool = _BY_NAME[name]
    launcher = tool.launcher
    own = _own_venv(tool, cwd)
    if own is not None:
        return [str(own)]
    binary = tool_binary(tool)
    if binary is None:
        record_python_problem(tool_problem(tool), cwd)
        return None
    if _launcher_override(launcher) is None:
        return [binary]
    return launcher.command(binary, tool)


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


def missing_launcher_notes(enabled, cwd):
    """One doctor line per launcher that an enabled tool cannot start."""
    by_launcher = {}
    for tool in EXTERNAL_TOOLS:
        if tool.name not in enabled or _own_venv(tool, cwd) is not None:
            continue
        by_launcher.setdefault(tool.launcher.name, []).append(tool)
    lines = []
    for tools in by_launcher.values():
        if tool_binary(tools[0]) is not None:
            continue
        names = ", ".join(tool.name for tool in tools)
        lines.append(f"{tool_reason(tools[0])}, so {names} stays silent")
    return lines
