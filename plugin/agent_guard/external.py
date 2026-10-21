"""One registry of the external tools the audit runs, and the run function."""

import os
import shutil
import subprocess
from pathlib import Path

from .process import record_python_problem


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
    ExternalTool("complexipy", "8.0.1", UVX, r"\.py$", "complexipy-snapshot.json"),
    ExternalTool("lizard", "1.24.1", UVX, r"\.(py|ts|tsx)$", "whitelizard.txt"),
    ExternalTool("vulture", "2.16", UVX, r"\.py$", "vulture-whitelist.py"),
    ExternalTool("jscpd", "5.4.2", BUNX, r"\.py$"),
    ExternalTool("pyscn", "1.32.5", UVX, r"\.py$"),
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
    binary = _launcher_path(tool)
    if binary is None:
        record_python_problem(
            f"{name}: {launcher.label} is not on PATH, so the analysis stayed silent", cwd
        )
        return None
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


def missing_launcher_note(enabled, cwd):
    """One doctor line per launcher that an enabled tool cannot start."""
    lines = []
    seen = set()
    for tool in EXTERNAL_TOOLS:
        launcher = tool.launcher
        if tool.name not in enabled or launcher.name in seen:
            continue
        if _own_venv(tool, cwd) is not None:
            continue
        if _launcher_path(tool) is not None:
            continue
        names = ", ".join(
            other.name
            for other in EXTERNAL_TOOLS
            if other.launcher.name == launcher.name
            and other.name in enabled
            and _own_venv(other, cwd) is None
        )
        if not names:
            continue
        lines.append(f"{launcher.label} is not on PATH, so {names} stays silent")
        seen.add(launcher.name)
    return lines
