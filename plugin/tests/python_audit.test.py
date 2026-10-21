#!/usr/bin/env python3
"""Stop-hook cases for the optional Python changeset analyses."""

import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

from hook_support import PLUGIN_ROOT as PLUGIN
from hook_support import requires_pinned, run_hook

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
    """doctor in a fresh tree, with the uvx launcher missing.

    The launchers seam points at a path that is not a file, so doctor uses
    the same rule the runtime uses."""
    with tempfile.TemporaryDirectory() as directory:
        fresh = pathlib.Path(directory) / "project"
        fresh.mkdir()
        missing = fresh / "no-uvx"
        return doctor(
            fresh,
            checkout,
            env_extra={"AGENT_GUARD_LAUNCHERS": f"uvx={missing}"},
        )


def doctor_without_bunx(_project, checkout):
    """doctor in a fresh tree, with the bunx launcher missing."""
    with tempfile.TemporaryDirectory() as directory:
        fresh = pathlib.Path(directory) / "project"
        fresh.mkdir()
        missing = fresh / "no-bunx"
        return doctor(
            fresh,
            checkout,
            env_extra={"AGENT_GUARD_LAUNCHERS": f"bunx={missing}"},
        )


def hook_env(project, checkout=None, env_extra=None, config_dir=None, state_home=None):
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
        XDG_STATE_HOME=str(state_home or (project.parent / "state")),
        AGENT_GUARD_LOG="0",
    )
    env.update(env_extra or {})
    return env


def doctor(project, checkout, env_extra=None, state_home=None):
    """Stdout of `agent_guard doctor` inside a tree that opted in."""
    env = hook_env(project, checkout, env_extra, state_home=state_home)
    result = run_hook(
        None,
        args=("doctor",),
        capture_output=True,
        text=True,
        cwd=project,
        env=env,
        timeout=20,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


def stop(project, checkout=None, env_extra=None, config_dir=None, state_home=None):
    """Stdout of one Stop call against `project`. `checkout` is the tree's
    config.toml. None leaves only the global layer."""
    env = hook_env(project, checkout, env_extra, config_dir, state_home)
    payload = {
        "session_id": "python-audit",
        "cwd": str(project),
        "hook_event_name": "Stop",
        "reason": "end_turn",
    }
    result = run_hook(
        json.dumps(payload),
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
    def test_one_tree_keeps_its_tool_note_when_another_clears(self):
        """The tool note is keyed by the tree. A clean Stop in a second tree
        leaves the first tree's doctor line in place."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            commit(first, "seed.py", CALM)
            commit(second, "seed.py", CALM)
            (first / "work.py").write_text(NOISY, encoding="utf-8")
            (second / "again.py").write_text(CALM, encoding="utf-8")
            checkout = tree_config("lizard")
            state = root / "state"
            stop(
                first,
                checkout,
                env_extra={"PATH": "/usr/bin:/bin", "MISE_LIZARD": str(root / "no-pin")},
                state_home=state,
            )
            stop(second, checkout, state_home=state)
            reported = doctor(first, checkout, state_home=state)
        self.assertIn("pin", reported)
        self.assertIn("stayed silent", reported)

    @requires_pinned("vulture")
    def test_a_new_file_committed_on_the_branch_still_reports(self):
        """A file the merge-base never had, committed on the branch, is still
        the changeset. Stop names the offender it added."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            commit(project, "seed.py", CALM)
            subprocess.run(["git", "branch", "-M", "main"], cwd=project, check=True)
            subprocess.run(["git", "checkout", "-q", "-b", "topic"], cwd=project, check=True)
            commit(project, "added.py", NOISY)
            subprocess.run(
                ["git", "update-ref", "refs/remotes/origin/main", "main"],
                cwd=project,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "config",
                    "--add",
                    "remote.origin.fetch",
                    "+refs/heads/*:refs/remotes/origin/*",
                ],
                cwd=project,
                check=True,
            )
            subprocess.run(
                ["git", "branch", "--set-upstream-to=origin/main"],
                cwd=project,
                check=True,
            )
            out = stop(project, tree_config("vulture"))
        self.assertIn("added.py", out)
        self.assertIn("unused_helper", out)

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

    @requires_pinned("complexipy")
    def test_complexipy_reports_only_the_function_the_changeset_touched(self):
        out = self.pair("complexipy")
        self.assertIn("work.py", out)
        self.assertIn("Box::fresh", out)
        self.assertIn("cognitive complexity 31", out)
        self.assertNotIn("Box::kept", out)
        self.assertNotIn("parked.py", out)

    @requires_pinned("lizard")
    def test_lizard_reports_only_the_function_the_changeset_touched(self):
        out = self.pair("lizard")
        self.assertIn("work.py", out)
        self.assertIn("Box::fresh", out)
        self.assertIn("7 parameters", out)
        self.assertNotIn("Box::kept", out)
        self.assertNotIn("parked.py", out)

    @requires_pinned("vulture")
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
        bunx_checkout = checkout + "jscpd = true\n"
        without_bunx = doctor_without_bunx(project, bunx_checkout)
        self.assertIn("is not on PATH, so jscpd stays silent", without_bunx)

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

    @requires_pinned("complexipy")
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
                env_extra={"PATH": "/usr/bin:/bin", "MISE_COMPLEXIPY": str(project / "no-pin")},
            )
            reported = doctor(project, checkout)
        self.assertEqual(out, "")
        self.assertIn("pin", reported)
        self.assertIn("stayed silent", reported)

    @requires_pinned("lizard")
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
                env_extra={"PATH": "/usr/bin:/bin", "MISE_LIZARD": str(project / "no-pin")},
            )
            stale = doctor(project, checkout)
            # A repeat of the same diff skips the tools, so add a file the
            # second Stop has to read. The function stays under the threshold.
            (project / "again.py").write_text(CALM, encoding="utf-8")
            clean = stop(project, checkout)
            reported = doctor(project, checkout)
        self.assertEqual(blocked, "")
        self.assertIn("pin", stale)
        self.assertIn("stayed silent", stale)
        self.assertEqual(clean, "")
        self.assertNotIn("python tools", reported)
        self.assertNotIn("stayed silent", reported)

    @requires_pinned("lizard")
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
                env_extra={"PATH": "/usr/bin:/bin", "MISE_LIZARD": str(project / "no-pin")},
            )
            (project / "work.py").unlink()
            empty = stop(project, checkout)
            reported = doctor(project, checkout)
        self.assertEqual(blocked, "")
        self.assertEqual(empty, "")
        self.assertNotIn("python tools", reported)

    def test_a_tool_uv_cannot_fetch_stays_silent_and_doctor_shows_it(self):
        """The pinned tool starts and writes no report. Stop prints nothing.
        The next doctor names that the tool produced no report."""
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory) / "project"
            project.mkdir()
            stub = project / "complexipy"
            stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            stub.chmod(0o755)
            commit(project, "seed.py", CALM)
            (project / "work.py").write_text(NOISY, encoding="utf-8")
            checkout = tree_config("complexipy")
            out = stop(
                project,
                checkout,
                env_extra={"MISE_COMPLEXIPY": str(stub)},
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
