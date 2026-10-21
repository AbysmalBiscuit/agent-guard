#!/usr/bin/env python3
"""Stop-hook cases for the Python clone and cycle analyses."""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

SCRIPT = pathlib.Path(__file__).parent.parent / "agent_guard"
PLUGIN = pathlib.Path(__file__).parent.parent

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
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(payload),
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


JSCPD = textwrap.dedent(
    """\
    fallow = false

    [python]
    jscpd = true
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

    @unittest.skipUnless(shutil.which("bunx"), "requires bunx")
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

    @unittest.skipUnless(shutil.which("uvx"), "requires uvx")
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

    def test_a_missing_runner_leaves_the_audit_silent_and_shows_in_doctor(self):
        """With bunx and uvx off PATH the Stop hook says nothing, and doctor
        names both analyses as silent."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            (root / "bin").mkdir()
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
            git = shutil.which("git")
            self.assertIsNotNone(git)
            (root / "bin" / "git").symlink_to(git)
            bare = {"PATH": str(root / "bin")}
            hook = stop_hook(root, session="bare", extra_env=bare)
            doctor = subprocess.run(
                [sys.executable, str(SCRIPT), "doctor"],
                capture_output=True,
                text=True,
                cwd=root,
                env={
                    **os.environ,
                    "HOME": str(root / "home"),
                    "AGENT_GUARD_CONFIG_DIR": str(PLUGIN),
                    "XDG_STATE_HOME": str(root / "state"),
                    "PATH": str(root / "bin"),
                    "AGENT_GUARD_LOG": "0",
                },
                timeout=20,
            )

        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertEqual(hook.stdout, "")
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertIn("jscpd: bunx is not on PATH, so the analysis stayed silent", doctor.stdout)
        self.assertIn("pyscn: uv is not on PATH, so the analysis stayed silent", doctor.stdout)

    def test_a_runner_timeout_stays_silent_and_doctor_records_it(self):
        """A runner that does not finish inside its budget leaves Stop silent,
        and doctor shows that analysis's last failure."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            bindir = root / "bin"
            bindir.mkdir()
            git = shutil.which("git")
            sleep = shutil.which("sleep")
            self.assertIsNotNone(git)
            self.assertIsNotNone(sleep)
            (bindir / "git").symlink_to(git)
            for name in ("bunx", "uvx"):
                wrapper = bindir / name
                wrapper.write_text(f"#!/bin/sh\nexec {sleep} 30\n", encoding="utf-8")
                wrapper.chmod(0o755)
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
            hook = stop_hook(root, session="timeout", extra_env={"PATH": str(bindir)}, timeout=20)
            doctor = subprocess.run(
                [sys.executable, str(SCRIPT), "doctor"],
                capture_output=True,
                text=True,
                cwd=root,
                env={
                    **os.environ,
                    "HOME": str(root / "home"),
                    "AGENT_GUARD_CONFIG_DIR": str(PLUGIN),
                    "XDG_STATE_HOME": str(root / "state"),
                    "PATH": str(bindir),
                    "AGENT_GUARD_LOG": "0",
                },
                timeout=20,
            )

        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertEqual(hook.stdout, "")
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertIn("jscpd timed out after", doctor.stdout)


if __name__ == "__main__":
    unittest.main()
