"""Harness flags and the log, shared by every cluster.

A flag on argv selects the harness before any payload is read. The log level
is settled from the environment before a checkout is.
"""

import atexit
import contextlib
import json
import os
import sys
import threading
import tomllib
from datetime import datetime
from pathlib import Path

from .paths import CONFIG_DIR, CONFIG_NAME

_watchdog = None
CODEX = "--codex" in sys.argv[1:]
GROK = "--grok" in sys.argv[1:]


def _env_setting(key):
    """What the environment says one setting is, empty when it says nothing."""
    return (os.environ.get("AGENT_GUARD_" + key.upper()) or "").strip().lower()


def _global_setting(key):
    """What the install's own config.toml says, for a run that ends before a
    checkout's can be read. Reading a checkout's this early would put a repo
    file between the mandatory tier and the call it refuses."""
    try:
        with (CONFIG_DIR / CONFIG_NAME).open("rb") as handle:
            return str(tomllib.load(handle).get(key, "")).strip().lower()
    except (OSError, tomllib.TOMLDecodeError):
        return ""


# How much to write to ~/agent-guard.log. Nothing, "0" or "off" writes nothing,
# so the hook costs nothing when nobody is watching.
_LEVELS = {
    "0": 0,
    "off": 0,
    "false": 0,
    "1": 1,
    "on": 1,
    "true": 1,
    "info": 1,
    "2": 2,
    "debug": 2,
    "3": 3,
    "trace": 3,
}
LOG_PATH = Path.home() / "agent-guard.log"
_level = _LEVELS.get(_env_setting("log"))
_held = []


def set_log_level(cfg):
    """Settle the level from the layered config, then release what was held.

    The lines a run opens with come before any root has been read, because the
    mandatory tier answers ahead of discovery so that no repo file stands
    between it and the call it refuses. Holding them is what lets a checkout's
    own config.toml still decide whether they are written.
    """
    global _level
    if _level is None:
        _level = _LEVELS.get(str(cfg.get("log", "")).strip().lower(), 0)
    release_log()


def release_log():
    """Write the held lines the settled level allows, once.

    A run that exits before discovery, a mandatory refusal above all, settles
    for the global level instead: a checkout that never got read cannot be the
    one to silence it.
    """
    global _held
    held, _held = _held, []
    level = _level if _level is not None else _LEVELS.get(_global_setting("log"), 0)
    for line_level, line in held:
        if line_level <= level:
            write_log(line)


def log(level, event, **fields):
    """Hold or append one line, by the level in force.

    Logging is a debugging aid and never a reason to fail, so a line that cannot
    be written is dropped rather than reported. Levels are 1 for the decision a
    call reached, 2 for each check's verdict, and 3 for the command text itself,
    which is held back until then because a command line can carry a secret.
    """
    if _level is not None and level > _level:
        return
    stamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
    rest = " ".join(
        f"{key}={value if isinstance(value, int) else json.dumps(str(value))}"
        for key, value in fields.items()
        if value is not None
    )
    line = f"{stamp} [{level}] {event} {rest}".rstrip() + "\n"
    if _level is None:
        _held.append((level, line))
        return
    write_log(line)


def write_log(line):
    with contextlib.suppress(BaseException), LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line)


# Every exit short of the watchdog's runs this, so a refusal that ends the run
# before discovery still reaches the log.
atexit.register(release_log)


def arm_watchdog(seconds):
    """The harness timeout kills the process it spawned, which stops helping the
    moment this one outlives the session that spawned it. Owning the deadline
    here bounds an orphan too."""
    global _watchdog
    if _watchdog is not None:
        _watchdog.cancel()
    _watchdog = threading.Timer(seconds, lambda: os._exit(0))
    _watchdog.daemon = True
    _watchdog.start()


def deadline(fallback):
    """Seconds before the watchdog fires. AGENT_GUARD_DEADLINE may lengthen this
    but not shorten it past the floor: a deadline short enough to kill the
    process before the mandatory tier has answered would be a way to switch that
    tier off, and that tier exists to have no off switch."""
    try:
        requested = float(os.environ.get("AGENT_GUARD_DEADLINE") or fallback)
    except ValueError:
        requested = fallback
    return max(requested, 6.0)
