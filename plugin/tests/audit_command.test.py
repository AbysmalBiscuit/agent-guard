#!/usr/bin/env python3
"""`agent_guard audit` runs the Stop changeset audit by hand."""

import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

from hook_support import PLUGIN_ROOT as PLUGIN
from hook_support import run_hook

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


def enable(root, body):
    nearer = root / ".agents" / "plugins" / "agent-guard"
    nearer.mkdir(parents=True)
    (nearer / "config.toml").write_text(body, encoding="utf-8")


def audit(root, args=(), extra_env=None):
    """One `audit` invocation. The caller's cwd is the worktree, not `root`."""
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AGENT_GUARD_"):
            env.pop(key)
    env["HOME"] = str(root / "home")
    env["AGENT_GUARD_CONFIG_DIR"] = str(PLUGIN)
    env["AGENT_GUARD_LOG"] = "0"
    env["XDG_STATE_HOME"] = str(root / "state")
    if extra_env:
        env.update(extra_env)
    return run_hook(
        None,
        args=("audit", *args),
        capture_output=True,
        text=True,
        cwd=pathlib.Path.cwd(),
        env=env,
        timeout=90,
    )


class AuditCommandTests(unittest.TestCase):
    def test_audit_prints_a_duplicated_block_on_every_run(self):
        """A branch that added a duplicated block prints the finding and exits
        non-zero. A second run prints the same finding again."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "a.py").write_text(CLONE, encoding="utf-8")
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            commit_all(root, "base")
            (pkg / "copy.py").write_text(CLONE, encoding="utf-8")
            enable(root, "fallow = false\n\n[python]\njscpd = true\n")

            first = audit(root, (str(root),))
            second = audit(root, (str(root),))

        self.assertNotEqual(first.returncode, 0, first.stderr)
        self.assertIn("This branch introduced", first.stdout)
        self.assertNotIn("This agent", first.stdout)
        self.assertIn("duplicated lines across 2 sites", first.stdout)
        self.assertIn("pkg/copy.py:1", first.stdout)
        self.assertEqual(second.returncode, first.returncode)
        self.assertEqual(second.stdout, first.stdout)

    def test_audit_base_compares_with_the_named_ref(self):
        """`--base REF` compares the checkout with that ref. The same clone
        against the ref that already holds it prints nothing."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "a.py").write_text(CLONE, encoding="utf-8")
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            commit_all(root, "base")
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            (pkg / "copy.py").write_text(CLONE, encoding="utf-8")
            commit_all(root, "clone")
            tip = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            enable(root, "fallow = false\n\n[python]\njscpd = true\n")

            against_base = audit(root, ("--base", base, str(root)))
            against_tip = audit(root, ("--base", tip, str(root)))

        self.assertNotEqual(against_base.returncode, 0, against_base.stderr)
        self.assertIn("pkg/copy.py:1", against_base.stdout)
        self.assertEqual(against_tip.returncode, 0, against_tip.stderr)
        self.assertEqual(against_tip.stdout, "")

    def test_audit_on_a_clean_branch_exits_zero(self):
        """A clean opted-in branch prints nothing and exits 0. A blank path,
        a missing path, and a directory that is not a git checkout exit
        non-zero and name the problem."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "notes.txt").write_text("seed\n", encoding="utf-8")
            commit_all(root, "base")
            enable(root, "fallow = false\n")
            empty_bin = root / "empty-bin"
            empty_bin.mkdir()

            clean = audit(root, (str(root),))
            blank = audit(root, ("   ",))
            missing = audit(root, (str(root / "missing"),))
            no_git = audit(root, (str(root),), extra_env={"PATH": str(empty_bin)})

        with tempfile.TemporaryDirectory() as plain_dir:
            plain = pathlib.Path(plain_dir)
            not_git = audit(root, (str(plain),))

        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertEqual(clean.stdout, "")
        self.assertNotEqual(blank.returncode, 0)
        self.assertIn("path", blank.stderr.lower())
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("path", missing.stderr.lower())
        self.assertEqual(not_git.returncode, 2, not_git.stderr)
        self.assertEqual(not_git.stdout, "")
        self.assertIn(f"agent-guard: not a git checkout: {plain}", not_git.stderr)
        self.assertEqual(no_git.returncode, 2, no_git.stderr)
        self.assertEqual(no_git.stdout, "")
        self.assertIn(f"agent-guard: not a git checkout: {root}", no_git.stderr)

    def test_audit_exits_2_when_a_finding_would_block(self):
        """A changeset check finding blocks when the tree sets `block`. The
        command prints the finding and exits 2. A missing ref names the ref."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "seed.txt").write_text("seed\n", encoding="utf-8")
            commit_all(root, "base")
            enable(root, "block = true\nfallow = false\n")
            checks = root / ".agents" / "plugins" / "agent-guard" / "changeset_checks"
            checks.mkdir()
            (checks / "rule.py").write_text('print("project violation")\n', encoding="utf-8")

            blocked = audit(root, (str(root),))
            missing_ref = audit(root, ("--base", "does-not-exist", str(root)))

        self.assertEqual(blocked.returncode, 2, blocked.stderr)
        self.assertIn("project violation", blocked.stdout)
        self.assertEqual(missing_ref.returncode, 2)
        self.assertIn("does-not-exist", missing_ref.stderr)


if __name__ == "__main__":
    unittest.main()
