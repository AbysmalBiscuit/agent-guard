"""Bounded process calls."""

import contextlib
import os
import re
import shutil
import subprocess
from pathlib import Path

from .paths import STATE_DIR


def have(tool):
    return shutil.which(tool) is not None


# Last Python analysis problem, keyed by tree so one Stop cannot clear another's.
PYTHON_TOOL_PROBLEM = "python-tool-problem"


def _problem_key(cwd):
    return re.sub(r"[^A-Za-z0-9]", "_", str(Path(cwd).resolve()))


def _problem_path(cwd):
    return STATE_DIR / f"{PYTHON_TOOL_PROBLEM}-{_problem_key(cwd)}"


def record_python_problem(text, cwd):
    path = _problem_path(cwd)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        prior = path.read_text(encoding="utf-8").strip() if path.is_file() else ""
        path.write_text(f"{prior}\n{text}".strip() + "\n", encoding="utf-8")
    except OSError:
        pass


def python_tool_problem(cwd):
    path = _problem_path(cwd)
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def clear_python_problem(cwd):
    """Drop this tree's tool note. A later Stop records a new one only if it fails."""
    with contextlib.suppress(OSError):
        _problem_path(cwd).unlink(missing_ok=True)


def run(cmd, timeout=20, cwd=None, stdin=None, env=None):
    """Stdout, or an empty string for any failure. Every external call is bounded
    so a wedged tool cannot outlive the hook."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            input=stdin,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except Exception:
        return ""
    return p.stdout or ""


def run_full(cmd, timeout=20, cwd=None, stdin=None, env=None):
    """Stdout and exit code together, for callers whose contract reads both. A
    failure to spawn at all reports code 0, so a missing interpreter stays
    silent rather than denying every call."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            input=stdin,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except Exception:
        return "", 0
    return p.stdout or "", p.returncode


def succeeds(cmd, timeout=20, cwd=None):
    try:
        done = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd, check=False)
    except Exception:
        return False
    return done.returncode == 0
