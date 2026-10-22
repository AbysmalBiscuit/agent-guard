#!/usr/bin/env python3
"""Stop-hook cases for the Python clone and cycle analyses."""

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from hook_support import PLUGIN_ROOT as PLUGIN
from hook_support import requires_pinned, run_hook, stub_mise, tool_version

CLONE = textwrap.dedent(
    """\
    def duplicated_work(items):
        total = 0
        for item in items:
            if item > 0:
                total += item * 2
            else:
                total -= 1
        return total
    """
)

OLD_CLONE = textwrap.dedent(
    """\
    def inherited_work(items):
        total = 0
        for item in items:
            if item > 10:
                total += item * 3
            else:
                total -= 2
        return total
    """
)


def commit_all(root, message):
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Agent Guard Test",
            "-c",
            "user.email=agent-guard@example.com",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            message,
        ],
        cwd=root,
        check=True,
    )


def init_repo(root):
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "agent-guard@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Agent Guard Test"], cwd=root, check=True)


def stop_hook(root, session="test-session", extra_env=None, timeout=90, state_home=None):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AGENT_GUARD_"):
            env.pop(key)
    env["HOME"] = str(root / "home")
    env["AGENT_GUARD_CONFIG_DIR"] = str(PLUGIN)
    env["AGENT_GUARD_LOG"] = "0"
    if state_home is None:
        env["XDG_STATE_HOME"] = str(root / "state")
    else:
        env.pop("XDG_STATE_HOME", None)
        env["HOME"] = str(state_home)
    if extra_env:
        env.update(extra_env)
    payload = {
        "session_id": session,
        "cwd": str(root),
        "hook_event_name": "Stop",
    }
    return run_hook(
        json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=root,
        env=env,
        timeout=timeout,
    )


def enable(root, body):
    nearer = root / ".agents" / "plugins" / "agent-guard"
    nearer.mkdir(parents=True)
    (nearer / "config.toml").write_text(body, encoding="utf-8")


def doctor_hook(root, extra_env=None):
    """`doctor` in the same tree the Stop hook just audited."""
    env = {
        **os.environ,
        "HOME": str(root / "home"),
        "AGENT_GUARD_CONFIG_DIR": str(PLUGIN),
        "XDG_STATE_HOME": str(root / "state"),
        "AGENT_GUARD_LOG": "0",
    }
    env.update(extra_env or {})
    return run_hook(
        None,
        args=("doctor",),
        capture_output=True,
        text=True,
        cwd=root,
        env=env,
        timeout=20,
    )


def install_stand_in(root, name, body):
    """A stand-in for one registry tool, for a stub mise to pin."""
    path = root / "stand-ins" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


JSCPD = textwrap.dedent(
    """\
    fallow = false

    [python]
    jscpd = true
    """
)

JSCPD_TS = textwrap.dedent(
    """\
    fallow = false

    [python]
    jscpd = true
    jscpd_extensions = '\\.tsx?$'
    """
)

JSCPD_MJS = textwrap.dedent(
    """\
    fallow = false

    [python]
    jscpd = true
    jscpd_extensions = '\\.mjs$'
    """
)

JSCPD_MTS = textwrap.dedent(
    """\
    fallow = false

    [python]
    jscpd = true
    jscpd_extensions = '\\.(mts|cts)$'
    """
)

JSCPD_TS_ONLY = textwrap.dedent(
    """\
    fallow = false

    [python]
    jscpd = true
    jscpd_extensions = '\\.ts$'
    """
)

JSCPD_SRC_TS = textwrap.dedent(
    """\
    fallow = false

    [python]
    jscpd = true
    jscpd_extensions = '^src/.*\\.ts$'
    """
)

TS_CLONE = textwrap.dedent(
    """\
    export function duplicatedWork(items: number[]): number {
      let total = 0;
      for (const item of items) {
        if (item > 0) {
          total += item * 2;
        } else {
          total -= 1;
        }
      }
      return total;
    }
    """
)

PYSCN = textwrap.dedent(
    """\
    fallow = false

    [python]
    pyscn = true
    """
)


class PythonChangesetTests(unittest.TestCase):
    def test_global_layer_alone_leaves_a_python_changeset_silent(self):
        """With only the global layer, a Python changeset gets no report. The
        analyses stay off until a tree names them. A blank file, a broken
        file, and an untracked notes.txt stay silent too."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "a.py").write_text(CLONE, encoding="utf-8")
            (pkg / "old_a.py").write_text("from pkg import b\n\nx = 1\n", encoding="utf-8")
            (pkg / "b.py").write_text("from pkg import old_a\n\ny = 1\n", encoding="utf-8")
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            commit_all(root, "base")
            (pkg / "copy.py").write_text(CLONE, encoding="utf-8")
            (pkg / "c.py").write_text("from pkg import d\n\nx = 2\n", encoding="utf-8")
            (pkg / "d.py").write_text("from pkg import c\n\ny = 2\n", encoding="utf-8")
            (pkg / "blank.py").write_text("   \n", encoding="utf-8")
            (pkg / "broken.py").write_text("def (\n", encoding="utf-8")
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    @requires_pinned("jscpd")
    def test_jscpd_reports_a_new_clone_once_per_session(self):
        """A clone group is reported when one instance sits on a line the branch
        added, in fallow's clone-report shape, and a second Stop in the same
        session stays silent. A clone both of whose instances predate the branch
        stays silent too."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "a.py").write_text(CLONE, encoding="utf-8")
            (pkg / "old.py").write_text(OLD_CLONE, encoding="utf-8")
            (pkg / "also.py").write_text(OLD_CLONE, encoding="utf-8")
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            commit_all(root, "base")
            (pkg / "copy.py").write_text(CLONE, encoding="utf-8")
            enable(root, JSCPD)

            first = stop_hook(root, session="dupes")
            second = stop_hook(root, session="dupes")

        self.assertEqual(first.returncode, 0, first.stderr)
        report = json.loads(first.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("duplicated lines across 2 sites (", report)
        self.assertIn("duplicated lines across 2 sites (", report)
        self.assertIn("pkg/a.py:1", report)
        self.assertIn("pkg/copy.py:1", report)
        self.assertNotIn("pkg/also.py", report)
        self.assertNotIn("pkg/old.py", report)
        self.assertEqual(second.stdout, "")

    @requires_pinned("jscpd")
    def test_jscpd_reports_a_typescript_clone_on_an_added_line(self):
        """`\\.tsx?$` reports a clone across `.ts` and `.tsx`, naming both paths.

        A Python clone, a blank `.ts` file, a `.ts` file of spaces, and
        notes.txt stay out of the report. The blank file and the spaces file
        also put `ts` on the changed-file suffix list.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            src = root / "src"
            src.mkdir()
            (src / "work.ts").write_text(TS_CLONE, encoding="utf-8")
            (root / "notes.py").write_text(CLONE, encoding="utf-8")
            commit_all(root, "base")
            (src / "copy.tsx").write_text(TS_CLONE, encoding="utf-8")
            (src / "blank.ts").write_text("", encoding="utf-8")
            (src / "spaces.ts").write_text("   \n", encoding="utf-8")
            (root / "notes_copy.py").write_text(CLONE, encoding="utf-8")
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
            enable(root, JSCPD_TS)

            result = stop_hook(root, session="ts-dupes")

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("duplicated lines across 2 sites (", report)
        self.assertIn("src/work.ts:1", report)
        self.assertIn("src/copy.tsx:1", report)
        self.assertNotIn(".py", report)

    @requires_pinned("jscpd")
    def test_jscpd_reports_a_tsx_copy_of_a_committed_ts_block(self):
        """`\\.tsx?$` reports a `.tsx` copy of a `.ts` block committed on the
        base. The added file is the only change. Both paths appear in the
        report. A Python clone, a blank argument file, a file of spaces, and
        an untracked notes.txt stay out."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            src = root / "src"
            src.mkdir()
            (src / "work.ts").write_text(TS_CLONE, encoding="utf-8")
            (root / "notes.py").write_text(CLONE, encoding="utf-8")
            commit_all(root, "base")
            (src / "copy.tsx").write_text(TS_CLONE, encoding="utf-8")
            (src / "blank").write_text("", encoding="utf-8")
            (src / "spaces file.ts").write_text("   \n", encoding="utf-8")
            (root / "notes_copy.py").write_text(CLONE, encoding="utf-8")
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
            enable(root, JSCPD_TS)

            result = stop_hook(root, session="tsx-of-ts")

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("duplicated lines across 2 sites (", report)
        self.assertIn("src/work.ts:1", report)
        self.assertIn("src/copy.tsx:1", report)
        self.assertNotIn(".py", report)

    @requires_pinned("jscpd")
    def test_jscpd_reports_an_mjs_clone_on_an_added_line(self):
        """A Stop audit with jscpd_extensions set to `.mjs` reports a duplicated
        block when one copy sits on a line the branch added. A Python clone in
        the same tree stays out of the report."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            src = root / "src"
            src.mkdir()
            (src / "work.mjs").write_text(TS_CLONE, encoding="utf-8")
            (root / "notes.py").write_text(CLONE, encoding="utf-8")
            commit_all(root, "base")
            (src / "copy.mjs").write_text(TS_CLONE, encoding="utf-8")
            (root / "notes_copy.py").write_text(CLONE, encoding="utf-8")
            enable(root, JSCPD_MJS)

            result = stop_hook(root, session="mjs-dupes")

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("duplicated lines across 2 sites (", report)
        self.assertIn("src/work.mjs:1", report)
        self.assertIn("src/copy.mjs:1", report)
        self.assertNotIn(".py", report)

    @requires_pinned("jscpd")
    def test_jscpd_reports_an_mts_clone_on_an_added_line(self):
        """`\\.(mts|cts)$` selects those files, and a duplicated `.mts` block
        on an added line is reported. A Python clone stays out of the report."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            src = root / "src"
            src.mkdir()
            (src / "work.mts").write_text(TS_CLONE, encoding="utf-8")
            (root / "notes.py").write_text(CLONE, encoding="utf-8")
            commit_all(root, "base")
            (src / "copy.mts").write_text(TS_CLONE, encoding="utf-8")
            (root / "notes_copy.py").write_text(CLONE, encoding="utf-8")
            enable(root, JSCPD_MTS)

            result = stop_hook(root, session="mts-dupes")

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("duplicated lines across 2 sites (", report)
        self.assertIn("src/work.mts:1", report)
        self.assertIn("src/copy.mts:1", report)
        self.assertNotIn(".py", report)

    @requires_pinned("jscpd")
    def test_jscpd_leaves_a_cts_copy_of_a_ts_block_out_of_the_report(self):
        """`\\.ts$` selects `.ts` only. A `.cts` copy of an added `.ts` block
        stays out of the report."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            src = root / "src"
            src.mkdir()
            (src / "work.ts").write_text(TS_CLONE, encoding="utf-8")
            (src / "other.ts").write_text("export const kept = 1;\n", encoding="utf-8")
            commit_all(root, "base")
            (src / "copy.ts").write_text("export const kept = 1;\n", encoding="utf-8")
            (src / "also.cts").write_text(TS_CLONE, encoding="utf-8")
            enable(root, JSCPD_TS_ONLY)

            result = stop_hook(root, session="cts-out")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    @requires_pinned("jscpd")
    def test_jscpd_scans_typescript_inside_an_anchored_extension(self):
        """`^src/.*\\.ts$` selects TypeScript under src, so a clone there is
        reported."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            src = root / "src"
            src.mkdir()
            (src / "work.ts").write_text(TS_CLONE, encoding="utf-8")
            (root / "outside.ts").write_text(TS_CLONE, encoding="utf-8")
            commit_all(root, "base")
            (src / "copy.ts").write_text(TS_CLONE, encoding="utf-8")
            (root / "outside_copy.ts").write_text(TS_CLONE, encoding="utf-8")
            enable(root, JSCPD_SRC_TS)

            result = stop_hook(root, session="anchored-ts")

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("src/work.ts:1", report)
        self.assertIn("src/copy.ts:1", report)

    @requires_pinned("pyscn")
    def test_pyscn_reports_only_a_cycle_the_base_lacked(self):
        """A cycle is reported when the base revision did not have it. A cycle
        already present at the base stays silent. The same holds when the state
        directory is the default under HOME, with XDG_STATE_HOME unset."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            home = root / "home"
            home.mkdir()
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "old_a.py").write_text("from pkg import b\n\nx = 1\n", encoding="utf-8")
            (pkg / "b.py").write_text("from pkg import old_a\n\ny = 1\n", encoding="utf-8")
            commit_all(root, "base")
            (pkg / "c.py").write_text("from pkg import d\n\nx = 2\n", encoding="utf-8")
            (pkg / "d.py").write_text("from pkg import c\n\ny = 2\n", encoding="utf-8")
            enable(root, PYSCN)

            result = stop_hook(root, session="cycles", state_home=home)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("pkg.c", report)
        self.assertIn("pkg.d", report)
        self.assertNotIn("old_a", report)
        self.assertNotIn("pkg.b", report)

    def test_a_missing_pin_leaves_the_audit_silent_and_shows_in_doctor(self):
        """A pin mise cannot resolve leaves Stop silent. doctor names each
        analysis that stayed silent, with the pin it could not find."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "a.py").write_text(CLONE, encoding="utf-8")
            commit_all(root, "base")
            (pkg / "copy.py").write_text(CLONE, encoding="utf-8")
            (pkg / "c.py").write_text("from pkg import d\n\nx = 2\n", encoding="utf-8")
            (pkg / "d.py").write_text("from pkg import c\n\ny = 2\n", encoding="utf-8")
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [python]
                    jscpd = true
                    pyscn = true
                    """
                ),
            )
            unpinned = {"PATH": f"{stub_mise(root / 'mise')}:{os.environ['PATH']}"}
            hook = stop_hook(root, session="bare", extra_env=unpinned)
            doctor = doctor_hook(root, unpinned)

        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertEqual(hook.stdout, "")
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        for name in ("jscpd", "pyscn"):
            self.assertIn(
                f"{name}: pin {tool_version(name)} is not installed, so the analysis stayed silent",
                doctor.stdout,
            )

    def test_a_tool_timeout_stays_silent_and_doctor_records_it(self):
        """A pinned tool that does not finish inside its budget leaves Stop
        silent, and doctor shows that analysis's last failure."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            sleep = shutil.which("sleep")
            self.assertIsNotNone(sleep)
            stall = install_stand_in(root, "stall", f"#!/bin/sh\nexec {sleep} 30\n")
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "a.py").write_text("x = 1\n", encoding="utf-8")
            commit_all(root, "base")
            (pkg / "copy.py").write_text("y = 2\n", encoding="utf-8")
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [python]
                    jscpd = true
                    timeout = 1
                    """
                ),
            )
            # The stand-in never starts node, so any executable fills its pin.
            mise = stub_mise(root / "mise", {"jscpd": stall, "node": stall})
            hook = stop_hook(
                root,
                session="timeout",
                extra_env={"PATH": f"{mise}:{os.environ['PATH']}"},
                timeout=20,
            )
            doctor = doctor_hook(root)

        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertEqual(hook.stdout, "")
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertIn("jscpd timed out after", doctor.stdout)

    def test_a_vulture_timeout_shows_in_the_stop_output(self):
        """Vulture reads the whole tree, so a run past its budget names the
        timeout in the Stop output instead of passing as no dead code."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            sleep = shutil.which("sleep")
            self.assertIsNotNone(sleep)
            stall = install_stand_in(root, "stall", f"#!/bin/sh\nexec {sleep} 30\n")
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "a.py").write_text("x = 1\n", encoding="utf-8")
            commit_all(root, "base")
            (pkg / "b.py").write_text("def never_called():\n    return 2\n", encoding="utf-8")
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [python]
                    vulture = true
                    timeout = 1
                    """
                ),
            )
            mise = stub_mise(root / "mise", {"vulture": stall})
            hook = stop_hook(
                root,
                session="vulture-timeout",
                extra_env={"PATH": f"{mise}:{os.environ['PATH']}"},
                timeout=20,
            )
            doctor = doctor_hook(root)

        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertIn("vulture timed out after", hook.stdout)
        self.assertIn("vulture timed out after", doctor.stdout)


if __name__ == "__main__":
    unittest.main()
