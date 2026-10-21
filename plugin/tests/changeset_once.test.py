#!/usr/bin/env python3
"""Stop reads the changeset once and shares it with every analysis."""

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from hook_support import PLUGIN_ROOT as PLUGIN
from hook_support import run_hook

GIT_SHIM = textwrap.dedent(
    """\
    #!/bin/sh
    printf '%s\\n' "$*" >> "$AGENT_GUARD_GIT_LOG"
    exec "$AGENT_GUARD_REAL_GIT" "$@"
    """
)

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


def install_git_shim(root):
    """A git on PATH that records each invocation, then runs the real git.

    The log sits outside the repo. A log inside it is itself a changeset."""
    real = shutil.which("git")
    bindir = root / "bin"
    bindir.mkdir()
    shim = bindir / "git"
    shim.write_text(GIT_SHIM, encoding="utf-8")
    shim.chmod(0o755)
    log = pathlib.Path(tempfile.mkdtemp(prefix="git-log-")) / "git-calls.log"
    log.write_text("", encoding="utf-8")
    return bindir, log, real


def stop_hook(root, session, bindir, log, real_git, path=None):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AGENT_GUARD_"):
            env.pop(key)
    env["HOME"] = str(root / "home")
    env["AGENT_GUARD_CONFIG_DIR"] = str(PLUGIN)
    env["AGENT_GUARD_LOG"] = "0"
    env["XDG_STATE_HOME"] = str(root / "state")
    env["PATH"] = path if path is not None else f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["AGENT_GUARD_GIT_LOG"] = str(log)
    env["AGENT_GUARD_REAL_GIT"] = real_git
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
        timeout=90,
    )


def enable(root, body):
    nearer = root / ".agents" / "plugins" / "agent-guard"
    nearer.mkdir(parents=True)
    (nearer / "config.toml").write_text(body, encoding="utf-8")


def diff_against_base(calls):
    """Every `git diff` against the base, including a name listing in that call."""
    counted = []
    for call in calls:
        parts = call.split()
        if "diff" not in parts:
            continue
        if any(not part.startswith("-") and part != "diff" for part in parts):
            counted.append(call)
    return counted


class ChangesetOnceTests(unittest.TestCase):
    def test_one_stop_diffs_the_base_once_for_many_findings(self):
        """One Stop runs `git diff` against the base once for every finding."""
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
            long = root / "notes.md"
            long.write_text("".join(f"line {number}\n" for number in range(1, 8)), encoding="utf-8")
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [python]
                    jscpd = true

                    [file_length]
                    enabled = true

                    [[file_length.limits]]
                    extensions = '\\.md$'
                    warn_lines = 3
                    """
                ),
            )
            checks = root / ".agents" / "plugins" / "agent-guard" / "changeset_checks"
            checks.mkdir()
            (checks / "note.py").write_text(
                "print('  notes.md  the changeset check spoke')\n",
                encoding="utf-8",
            )
            bindir, log, real = install_git_shim(root)
            result = stop_hook(root, "once", bindir, log, real)
            calls = log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("pkg/a.py:1", report)
        self.assertIn("pkg/copy.py:1", report)
        self.assertIn("notes.md", report)
        self.assertIn("the changeset check spoke", report)
        against_base = diff_against_base(calls)
        self.assertEqual(len(against_base), 1, calls)

    def test_the_base_revision_is_extracted_once_and_shared(self):
        """Two analyses that need the base revision share one extraction."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "old_a.py").write_text("from pkg import b\n\nx = 1\n", encoding="utf-8")
            (pkg / "b.py").write_text("from pkg import old_a\n\ny = 1\n", encoding="utf-8")
            commit_all(root, "base")
            (pkg / "c.py").write_text("from pkg import d\n\nx = 2\n", encoding="utf-8")
            (pkg / "d.py").write_text("from pkg import c\n\ny = 2\n", encoding="utf-8")
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [python]
                    pyscn = true
                    """
                ),
            )
            checks = root / ".agents" / "plugins" / "agent-guard" / "changeset_checks"
            checks.mkdir()
            (checks / "reads_base.py").write_text(
                textwrap.dedent(
                    """\
                    import pathlib
                    import sys

                    copy = pathlib.Path(sys.argv[2])
                    assert copy.is_dir(), sys.argv[2]
                    assert (copy / "pkg" / "old_a.py").is_file()
                    print("  base  the changeset check read the base")
                    """
                ),
                encoding="utf-8",
            )
            bindir, log, real = install_git_shim(root)
            result = stop_hook(root, "shared-base", bindir, log, real)
            calls = log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("pkg.c", report)
        self.assertIn("the changeset check read the base", report)
        archives = [call for call in calls if call.startswith("archive ")]
        self.assertEqual(len(archives), 1, calls)

    def test_each_analysis_filters_the_one_file_list_with_its_regex(self):
        """`\\.ya?ml$` and `^src/.*\\.go$` each select from the unsuffixed list."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "keep.txt").write_text("seed\n", encoding="utf-8")
            commit_all(root, "base")
            (root / "app.yaml").write_text(
                "".join(f"k: {n}\n" for n in range(1, 6)), encoding="utf-8"
            )
            (root / "app.yml").write_text(
                "".join(f"k: {n}\n" for n in range(1, 6)), encoding="utf-8"
            )
            src = root / "src"
            src.mkdir()
            (src / "main.go").write_text(
                "".join(f"// line {n}\n" for n in range(1, 6)), encoding="utf-8"
            )
            (root / "outside.go").write_text(
                "".join(f"// line {n}\n" for n in range(1, 6)), encoding="utf-8"
            )
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [file_length]
                    enabled = true

                    [[file_length.limits]]
                    extensions = '\\.ya?ml$'
                    warn_lines = 2

                    [[file_length.limits]]
                    extensions = '^src/.*\\.go$'
                    warn_lines = 2
                    """
                ),
            )
            bindir, log, real = install_git_shim(root)
            result = stop_hook(root, "regex-filter", bindir, log, real)
            calls = log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("app.yaml", report)
        self.assertIn("app.yml", report)
        self.assertIn("src/main.go", report)
        self.assertNotIn("outside.go", report)
        self.assertNotIn("notes.txt", report)
        listed = [call for call in calls if call.startswith(("diff ", "ls-files "))]
        self.assertTrue(listed, calls)
        self.assertFalse(
            any("*.ya" in call or "*.yml" in call or "*.go" in call for call in listed), calls
        )

    def test_length_uses_the_one_changed_file_list(self):
        """A length finding comes from the one list. Stop does not list again."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "keep.txt").write_text("seed\n", encoding="utf-8")
            commit_all(root, "base")
            (root / "long.py").write_text(
                "".join(f"x = {n}\n" for n in range(1, 7)), encoding="utf-8"
            )
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [file_length]
                    enabled = true

                    [[file_length.limits]]
                    extensions = '\\.py$'
                    warn_lines = 3
                    """
                ),
            )
            bindir, log, real = install_git_shim(root)
            result = stop_hook(root, "length-list", bindir, log, real)
            calls = log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("long.py", report)
        self.assertEqual(
            [call for call in calls if " diff " in f" {call} " or "ls-files --others" in call],
            [
                next(call for call in calls if " diff " in f" {call} "),
                "ls-files --others --exclude-standard -z",
            ],
            calls,
        )

    def test_edge_inputs_stay_one_diff(self):
        """A blank file, a path with repeated spaces, and an untracked notes
        file still share one diff. A failing changeset check is reported."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "seed.txt").write_text("seed\n", encoding="utf-8")
            commit_all(root, "base")
            (root / "blank.py").write_text("", encoding="utf-8")
            (root / "spaced  name.py").write_text("x = 1\n", encoding="utf-8")
            (root / "notes.txt").write_text("   \n", encoding="utf-8")
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [python]
                    jscpd = true
                    """
                ),
            )
            checks = root / ".agents" / "plugins" / "agent-guard" / "changeset_checks"
            checks.mkdir()
            (checks / "fail.py").write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
            bindir, log, real = install_git_shim(root)
            result = stop_hook(root, "edges", bindir, log, real)
            calls = log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(len(diff_against_base(calls)), 1, calls)

    def test_repeat_and_empty_stops_leave_no_base_copy(self):
        """A repeat Stop and an empty Stop extract no base and leave no copy.

        pyscn is on, which used to extract before the skip. The repeat still
        runs no archive."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "seed.py").write_text("x = 1\n", encoding="utf-8")
            (root / ".gitignore").write_text("state/\nbin/\n", encoding="utf-8")
            commit_all(root, "base")
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [python]
                    pyscn = true
                    """
                ),
            )
            bindir, log, real = install_git_shim(root)
            state = root / "state"
            empty = stop_hook(root, "empty-stop", bindir, log, real)
            empty_calls = log.read_text(encoding="utf-8").splitlines()
            empty_copies = list(state.glob("agent-guard/changeset-base-*"))
            (pkg / "seed.py").write_text("x = 2\n", encoding="utf-8")
            log.write_text("", encoding="utf-8")
            first = stop_hook(root, "repeat-stop", bindir, log, real)
            log.write_text("", encoding="utf-8")
            second = stop_hook(root, "repeat-stop", bindir, log, real)
            second_calls = log.read_text(encoding="utf-8").splitlines()
            copies = list(state.glob("agent-guard/changeset-base-*"))

        self.assertEqual(empty.returncode, 0, empty.stderr)
        self.assertEqual(empty.stdout, "")
        self.assertEqual(empty_copies, [])
        self.assertFalse(any(call.startswith("archive ") for call in empty_calls), empty_calls)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second.stdout, "")
        self.assertFalse(any(call.startswith("archive ") for call in second_calls), second_calls)
        self.assertEqual(copies, [])

    def test_a_script_that_reads_only_argv1_still_reports(self):
        """argv[2] is additive. A script that reads only argv[1] still reports."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "seed.txt").write_text("seed\n", encoding="utf-8")
            commit_all(root, "base")
            (root / "notes.md").write_text("changed\n", encoding="utf-8")
            enable(root, "fallow = false\n")
            checks = root / ".agents" / "plugins" / "agent-guard" / "changeset_checks"
            checks.mkdir()
            (checks / "argv1_only.py").write_text(
                "import sys\nprint('  notes.md  argv1 ' + sys.argv[1])\n",
                encoding="utf-8",
            )
            bindir, log, real = install_git_shim(root)
            result = stop_hook(root, "argv1", bindir, log, real)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertRegex(report, r"argv1 [0-9a-f]{40}")

    def test_a_tracked_spaced_path_and_a_non_ascii_path_stay_in_the_report(self):
        """A tracked path with a space, a non-ASCII path, and mnemonicPrefix
        all stay in the one changed-file list."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            subprocess.run(["git", "config", "diff.mnemonicPrefix", "true"], cwd=root, check=True)
            subprocess.run(["git", "config", "core.quotePath", "true"], cwd=root, check=True)
            spaced = root / "src" / "my file.go"
            spaced.parent.mkdir()
            spaced.write_text("package main\n", encoding="utf-8")
            foreign = root / "src" / "café.go"
            foreign.write_text("package main\n", encoding="utf-8")
            (root / "plain.go").write_text("package main\n", encoding="utf-8")
            commit_all(root, "base")
            spaced.write_text("".join(f"// line {n}\n" for n in range(1, 6)), encoding="utf-8")
            foreign.write_text("".join(f"// line {n}\n" for n in range(1, 6)), encoding="utf-8")
            (root / "plain.go").write_text(
                "".join(f"// line {n}\n" for n in range(1, 6)), encoding="utf-8"
            )
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [file_length]
                    enabled = true

                    [[file_length.limits]]
                    extensions = '\\.go$'
                    warn_lines = 2
                    """
                ),
            )
            bindir, log, real = install_git_shim(root)
            result = stop_hook(root, "spaced-path", bindir, log, real)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("src/my file.go", report)
        self.assertIn("src/café.go", report)
        self.assertIn("plain.go", report)

    def test_a_missing_tool_does_not_silence_the_other_analyses(self):
        """A tool that cannot start returns an empty result. The other
        analyses still report."""
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
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = true

                    [python]
                    jscpd = true
                    """
                ),
            )
            # fallow is absent from PATH, so that analysis exits before it
            # parses. jscpd still has to report the clone. git stays visible.
            bindir, log, real = install_git_shim(root)
            hidden = root / "no-fallow"
            hidden.mkdir()
            for name in ("git", "bunx", "bun", "uvx"):
                target = shutil.which(name)
                if target:
                    link = hidden / name
                    link.symlink_to(target)
            result = stop_hook(
                root,
                "missing-tool",
                bindir,
                log,
                real,
                path=f"{bindir}{os.pathsep}{hidden}",
            )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("pkg/a.py:1", report)
        self.assertIn("pkg/copy.py:1", report)

    def test_a_renamed_and_edited_file_keeps_its_findings(self):
        """A rename plus an edit is a delete and an add. The new path's
        findings stay in the report."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "old.py").write_text("x = 1\n", encoding="utf-8")
            commit_all(root, "base")
            subprocess.run(["git", "mv", "old.py", "new.py"], cwd=root, check=True)
            (root / "new.py").write_text(
                "".join(f"x = {number}\n" for number in range(1, 8)), encoding="utf-8"
            )
            enable(
                root,
                textwrap.dedent(
                    """\
                    fallow = false

                    [file_length]
                    enabled = true

                    [[file_length.limits]]
                    extensions = '\\.py$'
                    warn_lines = 3
                    """
                ),
            )
            bindir, log, real = install_git_shim(root)
            result = stop_hook(root, "rename-edit", bindir, log, real)
            calls = log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("new.py", report)
        self.assertIn("7 lines", report)
        self.assertTrue(any("--no-renames" in call for call in calls), calls)

    def test_a_changeset_check_reads_a_non_python_file_from_the_base_copy(self):
        """argv[2] is the full base tree. A check reads a non-Python file there."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "README.md").write_text("base readme\n", encoding="utf-8")
            (root / "seed.py").write_text("x = 1\n", encoding="utf-8")
            commit_all(root, "base")
            (root / "seed.py").write_text("x = 2\n", encoding="utf-8")
            enable(root, "fallow = false\n")
            checks = root / ".agents" / "plugins" / "agent-guard" / "changeset_checks"
            checks.mkdir()
            (checks / "readme.py").write_text(
                textwrap.dedent(
                    """\
                    import pathlib
                    import sys

                    copy = pathlib.Path(sys.argv[2])
                    text = (copy / "README.md").read_text(encoding="utf-8")
                    print("  README.md  " + text.strip())
                    """
                ),
                encoding="utf-8",
            )
            bindir, log, real = install_git_shim(root)
            result = stop_hook(root, "full-tree", bindir, log, real)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("base readme", report)

    def test_a_repeat_stop_with_changeset_checks_skips_the_archive(self):
        """A repeat Stop fingerprints the inputs first. The same changeset
        extracts no base copy."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "seed.py").write_text("x = 1\n", encoding="utf-8")
            (root / "README.md").write_text("base\n", encoding="utf-8")
            commit_all(root, "base")
            (root / "seed.py").write_text("x = 2\n", encoding="utf-8")
            enable(root, "fallow = false\n")
            checks = root / ".agents" / "plugins" / "agent-guard" / "changeset_checks"
            checks.mkdir()
            (checks / "note.py").write_text(
                "print('  seed.py  the check spoke')\n",
                encoding="utf-8",
            )
            bindir, log, real = install_git_shim(root)
            first = stop_hook(root, "skip-archive", bindir, log, real)
            log.write_text("", encoding="utf-8")
            second = stop_hook(root, "skip-archive", bindir, log, real)
            second_calls = log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(first.returncode, 0, first.stderr)
        first_report = json.loads(first.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("the check spoke", first_report)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second.stdout, "")
        self.assertFalse(any(call.startswith("archive ") for call in second_calls), second_calls)


if __name__ == "__main__":
    unittest.main()
