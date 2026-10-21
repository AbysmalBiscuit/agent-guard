"""Bounded process calls and in-process check execution."""

import contextlib
import io
import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from .config import JSCPD_VERSION, PYTHON_TOOL_VERSIONS
from .paths import IN_PROCESS, STATE_DIR


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


def tool_command(name, cwd):
    """The argv that launches one analysis tool, or None when it cannot start.

    The tree's own .venv copy wins. Otherwise uvx runs the version pinned here.
    jscpd is a Node tool, so it runs through bunx at the pinned version."""
    if name == "jscpd":
        bunx = shutil.which("bunx")
        if bunx is None:
            record_python_problem("jscpd: bunx is not on PATH, so the analysis stayed silent", cwd)
            return None
        return [bunx, "--bun", f"jscpd@{JSCPD_VERSION}"]
    own = Path(cwd) / ".venv" / "bin" / name
    if own.is_file() and os.access(own, os.X_OK):
        return [str(own)]
    uvx = shutil.which("uvx")
    if uvx is None:
        record_python_problem(f"{name}: uv is not on PATH, so the analysis stayed silent", cwd)
        return None
    version = PYTHON_TOOL_VERSIONS[name]
    return [uvx, "--from", f"{name}=={version}", name]


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


@contextlib.contextmanager
def alarm(seconds):
    """Raise inside the block once `seconds` pass, where the platform allows it.

    Windows has no SIGALRM, and there the process watchdog is the only backstop:
    a wedged check takes the run down with it instead of being skipped. Both
    outcomes are silence, which is the direction a broken check should fail."""
    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def fire(*_):
        raise TimeoutError(f"check ran longer than {seconds}s")

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def run_script(path, argument, stdin, cwd, timeout):
    """One check's stdout and exit code, run in this interpreter.

    Spawning a Python per check costs more than every check does put together,
    and the checks are small pure-stdlib scripts, so they run here instead. The
    source is executed with `__name__` set to "__main__" so the script's own
    guard runs exactly as it would in a subprocess and its exit code arrives as
    SystemExit; nothing about the contract changes.

    Returns None when the script cannot be run this way, so the caller falls
    back to a subprocess rather than skipping a check for a reason that has
    nothing to do with what the check is for."""
    in_process = IN_PROCESS
    if not in_process:
        return None
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return None

    captured = io.StringIO()
    namespace = {"__name__": "__main__", "__file__": str(path), "__doc__": None}
    argv, stdin_stream, directory = sys.argv, sys.stdin, os.getcwd()
    search, loaded = list(sys.path), set(sys.modules)
    home = str(path.parent)
    code = 0
    try:
        sys.argv = [str(path), argument]
        sys.stdin = io.StringIO(stdin)
        # An interpreter running a script puts its directory first, and a check
        # that imports a helper beside it depends on that.
        sys.path.insert(0, home)
        with contextlib.suppress(OSError):
            os.chdir(cwd)
        with (
            alarm(timeout),
            contextlib.redirect_stdout(captured),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            exec(compile(source, str(path), "exec"), namespace)  # noqa: S102
    except SystemExit as stop:
        # An interpreter exits 0 for `sys.exit(None)` and 1 for `sys.exit(str)`,
        # after printing the string to stderr. A check that denies that way
        # denies here too.
        code = stop.code if isinstance(stop.code, int) else (0 if stop.code is None else 1)
    except TimeoutError:
        # A subprocess that outran its timeout was reported as silence, and a
        # check the agent cannot wait for should not become a refusal.
        return "", 0
    except BaseException:
        # A check's own guard turns its crashes into silence, so reaching here
        # means the guard itself never ran: a syntax error, or an import that
        # failed. The interpreter would have exited 1, and the mandatory tier
        # reads that as a denial on purpose. Report it the same way, keeping
        # whatever the check managed to print: a subprocess that died mid-run
        # still delivered the stdout it had already written.
        return captured.getvalue(), 1
    finally:
        sys.argv, sys.stdin, sys.path[:] = argv, stdin_stream, search
        # Helpers a check imported are dropped again, so two roots shipping a
        # module of the same name do not serve each other's copy. Anything from
        # outside the check's own directory, the standard library above all,
        # stays cached: re-importing it per check is what this call is avoiding.
        for name in set(sys.modules) - loaded:
            origin = getattr(sys.modules.get(name), "__file__", None) or ""
            if origin.startswith(home + os.sep):
                del sys.modules[name]
        with contextlib.suppress(OSError):
            os.chdir(directory)
    return captured.getvalue(), code


def succeeds(cmd, timeout=20, cwd=None):
    try:
        done = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd, check=False)
    except Exception:
        return False
    return done.returncode == 0
