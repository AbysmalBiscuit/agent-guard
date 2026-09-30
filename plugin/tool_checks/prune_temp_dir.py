#!/usr/bin/env python3
"""agent-guard tool-check: prune Claude's redirected temp directory by age.

Nothing else cleans this path. Disk Cleanup and Storage Sense expand %TEMP%
from the Windows environment, which still points at AppData/Local/Temp, so the
directory settings.json redirects Claude to would grow without bound. 7 days
matches the LastAccess rule Windows applies to its own temp folder.

The walk belongs here rather than on SessionEnd because ten thousand entries
cost seconds on Windows, and on SessionEnd those seconds are the whole delay
between asking to quit and getting the shell back. A stamp holds the work to
once a day and is written before the first deletion, so a session starting
while another prunes sees a fresh stamp and leaves.

This reports nothing in every case. The advisory and deny paths belong to
checks that have something to say about the call being made.
"""

import os
import sys
import time
from pathlib import Path

STAMP_NAME = ".agent-guard-prune"
INTERVAL_SECONDS = 24 * 60 * 60
DEFAULT_MAX_AGE_DAYS = 7
# Windows has no SIGALRM, so agent-guard cannot time a check out there and a
# slow walk stalls the tool call instead of being skipped. Stop at this point
# and let the next run carry on from wherever the tree then stands.
DEADLINE_SECONDS = 3.0


def target():
    """The directory to prune, or None when no safe candidate is present.

    The AppData/Temp suffix is the whole safety argument: it is where
    settings.json redirects TEMP to, and it is not the Windows temp directory
    at AppData/Local/Temp, which this must never touch.
    """
    named = os.environ.get("TEMP") or os.environ.get("TMP") or ""
    candidates = [Path(named)] if named else []
    candidates.append(Path.home() / "AppData" / "Temp")
    for path in candidates:
        try:
            resolved = path.resolve()
            parts = resolved.parts
        except OSError:
            continue
        if parts[-2:] == ("AppData", "Temp") and resolved.is_dir():
            return resolved
    return None


def claim(stamp, now):
    """True when this run owns the prune, having just stamped it as taken."""
    try:
        if now - stamp.stat().st_mtime < INTERVAL_SECONDS:
            return False
    except OSError:
        pass
    try:
        stamp.write_bytes(b"")
    except OSError:
        return False
    return True


def prune(root, cutoff, deadline):
    """Delete files last modified before `cutoff`, then whatever directories
    that leaves empty.

    Directories go deepest first, which is what collapses a whole branch of
    empty directories in one pass. Depth is path length: a child is always
    longer than its parent, whichever separator the platform joined it with.
    """
    directories = []
    stack = [str(root)]
    while stack:
        if time.monotonic() > deadline:
            return
        try:
            entries = list(os.scandir(stack.pop()))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    directories.append(entry.path)
                    stack.append(entry.path)
                elif entry.stat(follow_symlinks=False).st_mtime < cutoff:
                    os.unlink(entry.path)
            except OSError:
                continue

    for path in sorted(directories, key=len, reverse=True):
        try:
            os.rmdir(path)
        except OSError:
            continue


def max_age_days():
    try:
        return float(os.environ.get("CLAUDE_TEMP_MAX_AGE_DAYS") or DEFAULT_MAX_AGE_DAYS)
    except ValueError:
        return DEFAULT_MAX_AGE_DAYS


def main():
    root = target()
    if root is None:
        return 0
    now = time.time()
    # The stamp lives in the pruned tree and is written at `now`, so the cutoff
    # can never select it however long pruning has been stalled.
    if not claim(root / STAMP_NAME, now):
        return 0
    prune(root, now - max_age_days() * 86400, time.monotonic() + DEADLINE_SECONDS)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:
        # A broken check degrades to silence rather than denying real work.
        sys.exit(0)
