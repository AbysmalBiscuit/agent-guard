#!/usr/bin/env python3
"""Cases for tool_checks/prune_temp_dir.py. Run directly: python3 <this file>.

Held here rather than beside the check, because tool_checks/ globs every *.py
in it and would run this file as a check on each Bash call.

The check deletes files, so the cases that matter are the ones saying what it
refuses to touch: a directory that is not the redirected temp root, a file
younger than the cutoff, a directory something still lives in, and the stamp
that stops it running twice in a day.
"""

import contextlib
import io
import os
import pathlib
import sys
import tempfile
import time
import types

CHECK = pathlib.Path(__file__).parent.parent / "tool_checks" / "prune_temp_dir.py"
DAY = 86400


def load():
    module = types.ModuleType("check_under_test")
    module.__file__ = str(CHECK)
    exec(compile(CHECK.read_text(encoding="utf-8"), str(CHECK), "exec"), module.__dict__)
    return module


@contextlib.contextmanager
def sandbox(leaf=("AppData", "Temp")):
    """A temp root the check will accept, with the environment pointed at it."""
    with tempfile.TemporaryDirectory() as base:
        root = pathlib.Path(base, *leaf)
        root.mkdir(parents=True)
        saved = {k: os.environ.get(k) for k in ("TEMP", "TMP", "HOME", "USERPROFILE")}
        os.environ.update(TEMP=str(root), TMP=str(root), HOME=base, USERPROFILE=base)
        try:
            yield root
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def backdate(path, days):
    when = time.time() - days * DAY
    os.utime(path, (when, when))


def write(path, days=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")
    if days is not None:
        backdate(path, days)
    return path


def run(module):
    """The check's exit code and whatever it printed."""
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = module.main()
    return code, captured.getvalue()


def test_refuses_a_root_that_is_not_the_redirected_temp():
    module = load()
    for leaf in (("AppData", "Local", "Temp"), ("Temp",), ("Documents",)):
        with sandbox(leaf) as root:
            stale = write(root / "old.txt", days=30)
            assert module.target() is None, leaf
            assert run(module) == (0, "")
            assert stale.exists(), f"{leaf} was pruned"


def test_deletes_only_files_past_the_cutoff():
    module = load()
    with sandbox() as root:
        stale = write(root / "old.txt", days=30)
        fresh = write(root / "new.txt", days=1)
        edge = write(root / "edge.txt", days=6.9)
        assert run(module) == (0, "")
        assert not stale.exists()
        assert fresh.exists() and edge.exists()


def test_collapses_emptied_directories_and_keeps_occupied_ones():
    module = load()
    with sandbox() as root:
        write(root / "a" / "b" / "c" / "old.txt", days=30)
        write(root / "kept" / "new.txt", days=1)
        assert run(module) == (0, "")
        assert not (root / "a").exists(), "a branch left empty should collapse whole"
        assert (root / "kept" / "new.txt").exists()


def test_the_stamp_holds_the_next_run_off_and_survives_the_prune():
    module = load()
    with sandbox() as root:
        assert run(module) == (0, "")
        stamp = root / module.STAMP_NAME
        assert stamp.exists(), "the first run should claim the day"

        missed = write(root / "old.txt", days=30)
        assert run(module) == (0, "")
        assert missed.exists(), "a second run the same day should do nothing"

        backdate(stamp, 2)
        assert run(module) == (0, "")
        assert not missed.exists()
        assert stamp.exists(), "the stamp must outlive the prune it started"


def test_a_stalled_prune_does_not_delete_its_own_stamp():
    module = load()
    with sandbox() as root:
        stamp = write(root / module.STAMP_NAME, days=30)
        assert run(module) == (0, "")
        assert stamp.exists()


def test_the_cutoff_is_configurable():
    module = load()
    with sandbox() as root:
        doomed = write(root / "old.txt", days=3)
        os.environ["CLAUDE_TEMP_MAX_AGE_DAYS"] = "1"
        try:
            assert run(module) == (0, "")
        finally:
            del os.environ["CLAUDE_TEMP_MAX_AGE_DAYS"]
        assert not doomed.exists()


def test_a_missing_root_is_silence_not_a_crash():
    module = load()
    keys = ("TEMP", "TMP", "HOME", "USERPROFILE")
    saved = {k: os.environ.get(k) for k in keys}
    os.environ.update(TEMP="", TMP="", HOME="/nowhere-at-all", USERPROFILE="/nowhere-at-all")
    try:
        assert run(module) == (0, "")
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == "__main__":
    failures = 0
    for name, case in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            case()
            print(f"ok   {name}")
        except AssertionError as bad:
            failures += 1
            print(f"FAIL {name}: {bad}")
        except Exception as bad:
            failures += 1
            print(f"FAIL {name}: {type(bad).__name__}: {bad}")
    print(f"\n{failures} failed")
    sys.exit(1 if failures else 0)
