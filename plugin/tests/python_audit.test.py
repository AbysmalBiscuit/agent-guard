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

OLD = textwrap.dedent(
    """\
    class Box:
        def kept(self, a, b, c, d, e, f):
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


    def kept_unused():
        return 9
    """
)

FRESH = textwrap.dedent(
    """\
    class Box:
        def fresh(self, a, b, c, d, e, f):
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


    def fresh_unused():
        return 3
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


def commit_files(project, files):
    if not (project / ".git").exists():
        subprocess.run(["git", "init", "--quiet"], cwd=project, check=True)
    names = []
    for name, text in files:
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        names.append(name)
    subprocess.run(["git", "add", "--", *names], cwd=project, check=True)


def commit(project, name, text):
    commit_files(project, [(name, text)])
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


def hook_env(project, checkout=None, env_extra=None, config_dir=None):
    """Environment one hook call runs in. `checkout` is the tree's config.toml."""
    if checkout is not None:
        nearer = project / ".agents" / "plugins" / "agent-guard"
        nearer.mkdir(parents=True, exist_ok=True)
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
    return env


def doctor(project, checkout, env_extra=None):
    """Stdout of `agent_guard.py doctor` inside a tree that opted in."""
    env = hook_env(project, checkout, env_extra)
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
    env = hook_env(project, checkout, env_extra, config_dir)
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
        self.assertIn("work.py", out)
        self.assertIn("Box::fresh", out)
        self.assertIn("cognitive complexity 31", out)
        self.assertNotIn("Box::kept", out)
        self.assertNotIn("parked.py", out)

    def test_lizard_reports_only_the_function_the_changeset_touched(self):
        out = self.pair("lizard")
        self.assertIn("work.py", out)
        self.assertIn("Box::fresh", out)
        self.assertIn("7 parameters", out)
        self.assertNotIn("Box::kept", out)
        self.assertNotIn("parked.py", out)

    def test_vulture_reports_only_dead_code_the_branch_added(self):
        out = self.pair("vulture")
        self.assertIn("work.py", out)
        self.assertIn("fresh_unused", out)
        self.assertIn("dead code", out)
        self.assertNotIn("kept_unused", out)
        self.assertNotIn("parked.py", out)

    def test_complexipy_stays_silent_on_a_baselined_function(self):
        snapshot = textwrap.dedent(
            """\
            [
              {
                "path": "work.py",
                "functions": [{"name": "Box::fresh", "complexity": 31}]
              },
              {
                "path": "utils.py",
                "functions": [{"name": "fresh", "complexity": 31}]
              }
            ]
            """
        )
        out = self.pair("complexipy", extra=[("complexipy-snapshot.json", snapshot)])
        self.assertNotIn("Box::fresh", out)
        self.assertNotIn("cognitive complexity", out)

    def test_lizard_stays_silent_on_a_baselined_function(self):
        out = self.pair("lizard", extra=[("whitelizard.txt", "fresh\n")])
        self.assertNotIn("Box::fresh", out)
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
        origin = str(project / ".agents" / "plugins" / "agent-guard")
        self.assertIn("extensions : \\.py$  from " + origin, out)
        self.assertIn("baseline   : dead.py  from " + origin, out)
        self.assertIn("timeout    : 20", out)
        self.assertIn("from default", out)
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
            (project / "work.py").write_text(NOISY, encoding="utf-8")
            (project / "notes.txt").write_text("not a source file\n", encoding="utf-8")
            self.assertEqual(stop(project, blank), "")
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "work.py").write_text(broken, encoding="utf-8")
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
            (project / "work.py").write_text(NOISY, encoding="utf-8")
            out = stop(project, checkout)
        self.assertNotIn("Box::fresh", out)
        self.assertNotIn("parameters", out)

    def test_a_timeout_leaves_the_audit_silent_and_doctor_shows_it(self):
        """A tool that outruns its timeout adds no finding. The next doctor
        run, a separate process, still names that timeout."""
        checkout = "fallow = false\nlog = 0\n[python]\ncomplexipy = true\ntimeout = 0.01\n"
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "work.py").write_text(NOISY, encoding="utf-8")
            self.assertEqual(stop(project, checkout), "")
            reported = doctor(project, checkout)
        self.assertIn("complexipy timed out", reported)
        self.assertIn("stayed silent", reported)

    def test_a_missing_uv_leaves_the_audit_silent(self):
        """uv and the tools are off PATH. The tree asked for an analysis, and
        the hook still exits with no findings. The next doctor names the gap."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "work.py").write_text(NOISY, encoding="utf-8")
            checkout = tree_config("complexipy")
            out = stop(
                project,
                checkout,
                env_extra={"PATH": "/usr/bin:/bin"},
            )
            reported = doctor(project, checkout)
        self.assertEqual(out, "")
        self.assertIn("uv is not on PATH", reported)
        self.assertIn("stayed silent", reported)

    def test_a_clean_stop_clears_a_recorded_python_tool_problem(self):
        """A Stop that could not start uv records the gap. A later Stop that
        runs the tool and finds nothing clears that note, so doctor is quiet."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "work.py").write_text(CALM, encoding="utf-8")
            checkout = tree_config("lizard")
            blocked = stop(
                project,
                checkout,
                env_extra={"PATH": "/usr/bin:/bin"},
            )
            stale = doctor(project, checkout)
            # A repeat of the same diff skips the tools, so add a file the
            # second Stop has to read. The function stays under the threshold.
            (project / "again.py").write_text(CALM, encoding="utf-8")
            clean = stop(project, checkout)
            reported = doctor(project, checkout)
        self.assertEqual(blocked, "")
        self.assertIn("uv is not on PATH", stale)
        self.assertEqual(clean, "")
        self.assertNotIn("python tools", reported)
        self.assertNotIn("uv is not on PATH", reported)

    def test_an_empty_changeset_clears_a_recorded_python_tool_problem(self):
        """A Stop with no changed file still drops a note an earlier Stop left,
        so doctor does not keep a gap the tools no longer have work for."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            (project / "work.py").write_text(NOISY, encoding="utf-8")
            checkout = tree_config("lizard")
            blocked = stop(
                project,
                checkout,
                env_extra={"PATH": "/usr/bin:/bin"},
            )
            (project / "work.py").unlink()
            empty = stop(project, checkout)
            reported = doctor(project, checkout)
        self.assertEqual(blocked, "")
        self.assertEqual(empty, "")
        self.assertNotIn("python tools", reported)

    def test_a_tool_uv_cannot_fetch_stays_silent_and_doctor_shows_it(self):
        """uv is on PATH, but the pinned tool cannot be fetched. Stop prints
        nothing. The next doctor names that the tool produced no report."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            cache = pathlib.Path(directory) / "uv-cache"
            cache.mkdir()
            commit(project, "seed.py", CALM)
            (project / "work.py").write_text(NOISY, encoding="utf-8")
            checkout = tree_config("complexipy")
            out = stop(
                project,
                checkout,
                env_extra={"UV_OFFLINE": "1", "UV_CACHE_DIR": str(cache)},
            )
            reported = doctor(project, checkout)
        self.assertEqual(out, "")
        self.assertIn("complexipy", reported)
        self.assertIn("python tools", reported)
        self.assertIn("stayed silent", reported)

    def test_vulture_stays_silent_on_a_baselined_name(self):
        out = self.pair("vulture", extra=[("vulture-whitelist.py", "fresh_unused\n")])
        self.assertNotIn("fresh_unused", out)

    def pair(self, analysis, extra=None):
        """One analysis on. work.py already holds an old offender, including a
        class method. The changeset adds a second offender in that same file,
        and an identical offender already committed in parked.py."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "work.py", OLD)
            commit(project, "parked.py", NOISY)
            (project / "work.py").write_text(OLD + "\n" + FRESH, encoding="utf-8")
            for name, text in extra or []:
                (project / name).write_text(text, encoding="utf-8")
            return stop(project, tree_config(analysis))


if __name__ == "__main__":
    unittest.main()
