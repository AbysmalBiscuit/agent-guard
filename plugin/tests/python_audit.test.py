#!/usr/bin/env python3
"""Stop-hook cases for the optional Python changeset analyses."""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

PLUGIN = pathlib.Path(__file__).parent.parent
SCRIPT = PLUGIN / "scripts" / "agent_guard.py"

NOISY = textwrap.dedent(
    """\
    def calm():
        return 1


    def noisy(a, b, c, d, e, f):
        x = 0
        if a:
            if b:
                if c:
                    if d:
                        for i in range(3):
                            if i:
                                x += 1
                            else:
                                x -= 1
                        if e:
                            x += 2
                    elif f:
                        x += 3
                else:
                    x += 4
            else:
                x += 5
        else:
            x += 6
        return x


    def unused_helper():
        return 2
    """
)

CALM = textwrap.dedent(
    """\
    def used(value):
        return value + 1


    def caller():
        return used(1)
    """
)


def commit(project, name, text):
    path = project / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if not (project / ".git").exists():
        subprocess.run(["git", "init", "--quiet"], cwd=project, check=True)
    subprocess.run(["git", "add", "--", name], cwd=project, check=True)
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
            "seed",
        ],
        cwd=project,
        check=True,
    )


def doctor_without_uv(_project, checkout):
    """doctor in a fresh tree, with uv and the analysis tools off PATH."""
    with tempfile.TemporaryDirectory() as directory:
        fresh = pathlib.Path(directory) / "project"
        fresh.mkdir()
        return doctor(fresh, checkout, env_extra={"PATH": "/usr/bin:/bin"})


def doctor(project, checkout, env_extra=None):
    """Stdout of `agent_guard.py doctor` inside a tree that opted in."""
    nearer = project / ".agents" / "plugins" / "agent-guard"
    nearer.mkdir(parents=True)
    (nearer / "config.toml").write_text(checkout, encoding="utf-8")
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AGENT_GUARD_"):
            env.pop(key)
    home = project.parent / "home"
    home.mkdir(exist_ok=True)
    env.update(
        HOME=str(home),
        AGENT_GUARD_CONFIG_DIR=str(PLUGIN),
        XDG_STATE_HOME=str(project.parent / "state"),
        AGENT_GUARD_LOG="0",
    )
    env.update(env_extra or {})
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "doctor"],
        capture_output=True,
        text=True,
        cwd=project,
        env=env,
        timeout=20,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


def stop(project, checkout=None, env_extra=None, config_dir=None):
    """Stdout of one Stop call against `project`. `checkout` is the tree's
    config.toml. None leaves only the global layer."""
    if checkout is not None:
        nearer = project / ".agents" / "plugins" / "agent-guard"
        nearer.mkdir(parents=True)
        (nearer / "config.toml").write_text(checkout, encoding="utf-8")
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AGENT_GUARD_"):
            env.pop(key)
    home = project.parent / "home"
    home.mkdir(exist_ok=True)
    env.update(
        HOME=str(home),
        AGENT_GUARD_CONFIG_DIR=str(config_dir or PLUGIN),
        XDG_STATE_HOME=str(project.parent / "state"),
        AGENT_GUARD_LOG="0",
    )
    env.update(env_extra or {})
    payload = {
        "session_id": "python-audit",
        "cwd": str(project),
        "hook_event_name": "Stop",
        "reason": "end_turn",
    }
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=project,
        env=env,
        timeout=90,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


def tree_config(analysis):
    return (
        "fallow = false\n"
        "log = 0\n"
        "[python]\n"
        f"{analysis} = true\n"
        f'{analysis}_extensions = "\\\\.py$"\n'
        "lizard_arguments = 5\n"
    )


class PythonAuditTests(unittest.TestCase):
    def test_no_python_setting_leaves_a_python_changeset_silent(self):
        """Only the global layer. A Python changeset with an over-threshold
        function and dead code still produces no Stop output."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "pkg.py").write_text(NOISY, encoding="utf-8")
            out = stop(project)
        self.assertEqual(out, "")

    def test_complexipy_reports_only_the_function_the_changeset_touched(self):
        out = self.pair("complexipy")
        self.assertIn("touched.py", out)
        self.assertIn("noisy", out)
        self.assertIn("cognitive complexity 31", out)
        self.assertNotIn("untouched.py", out)
        self.assertNotIn("also_noisy", out)

    def test_lizard_reports_only_the_function_the_changeset_touched(self):
        out = self.pair("lizard")
        self.assertIn("touched.py", out)
        self.assertIn("noisy", out)
        self.assertIn("6 parameters", out)
        self.assertNotIn("untouched.py", out)
        self.assertNotIn("also_noisy", out)

    def test_vulture_reports_only_dead_code_the_branch_added(self):
        out = self.pair("vulture")
        self.assertIn("touched.py", out)
        self.assertIn("unused_helper", out)
        self.assertIn("dead code", out)
        self.assertNotIn("untouched.py", out)
        self.assertNotIn("unused_old", out)

    def test_complexipy_stays_silent_on_a_baselined_function(self):
        snapshot = textwrap.dedent(
            """\
            [
              {
                "path": "touched.py",
                "file_name": "touched.py",
                "functions": [{"name": "noisy", "complexity": 31}]
              }
            ]
            """
        )
        out = self.pair("complexipy", extra=[("complexipy-snapshot.json", snapshot)])
        self.assertNotIn("noisy", out)
        self.assertNotIn("cognitive complexity", out)

    def test_lizard_stays_silent_on_a_baselined_function(self):
        out = self.pair("lizard", extra=[("whitelizard.txt", "noisy\n")])
        self.assertNotIn("noisy", out)
        self.assertNotIn("parameters", out)

    def test_doctor_names_the_analyses_a_tree_turned_on_and_where(self):
        checkout = (
            "fallow = false\n"
            "[python]\n"
            "complexipy = true\n"
            "vulture = true\n"
            'complexipy_extensions = "\\\\.py$"\n'
            'vulture_baseline = "dead.py"\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            out = doctor(project, checkout)
        self.assertIn("complexipy   on", out)
        self.assertIn("vulture      on", out)
        self.assertIn("lizard       off", out)
        self.assertIn(str(project / ".agents" / "plugins" / "agent-guard"), out)
        self.assertIn("dead.py", out)
        without_uv = doctor_without_uv(project, checkout)
        self.assertIn("uv is not on PATH", without_uv)
        self.assertIn("stays silent", without_uv)

    def test_a_blank_extension_and_a_failing_tool_stay_silent(self):
        """An empty extension matches nothing. A tool that exits non-zero on a
        broken file does not become a finding."""
        blank = 'fallow = false\nlog = 0\n[python]\ncomplexipy = true\ncomplexipy_extensions = ""\n'
        broken = "def broken(:\n    return\n"
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "touched.py").write_text(NOISY, encoding="utf-8")
            (project / "notes.txt").write_text("not a source file\n", encoding="utf-8")
            self.assertEqual(stop(project, blank), "")
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "touched.py").write_text(broken, encoding="utf-8")
            self.assertEqual(stop(project, tree_config("complexipy")), "")

    def test_lizard_on_typescript_stays_quiet_on_python(self):
        """A tree picks the file types. Lizard set to TypeScript ignores the
        Python offender the changeset added."""
        checkout = (
            "fallow = false\n"
            "log = 0\n"
            "[python]\n"
            "lizard = true\n"
            'lizard_extensions = "\\\\.tsx?$"\n'
            "lizard_arguments = 5\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "touched.py").write_text(NOISY, encoding="utf-8")
            out = stop(project, checkout)
        self.assertNotIn("noisy", out)
        self.assertNotIn("parameters", out)

    def test_a_missing_uv_leaves_the_audit_silent(self):
        """uv and the tools are off PATH. The tree asked for an analysis, and
        the hook still exits with no findings."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "touched.py").write_text(NOISY, encoding="utf-8")
            out = stop(
                project,
                tree_config("complexipy"),
                env_extra={"PATH": "/usr/bin:/bin"},
            )
        self.assertEqual(out, "")

    def test_vulture_stays_silent_on_a_baselined_name(self):
        out = self.pair("vulture", extra=[("vulture-whitelist.py", "unused_helper\n")])
        self.assertNotIn("unused_helper", out)

    def pair(self, analysis, extra=None):
        """One analysis on. The changeset adds touched.py. An identical
        offender is already committed in untouched.py."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "untouched.py", NOISY)
            (project / "touched.py").write_text(NOISY, encoding="utf-8")
            for name, text in extra or []:
                (project / name).write_text(text, encoding="utf-8")
            return stop(project, tree_config(analysis))


if __name__ == "__main__":
    unittest.main()
